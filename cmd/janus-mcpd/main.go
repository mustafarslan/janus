// Command janus-mcpd is the Janus interception proxy for MCP.
//
// An agent launches janus-mcpd where it would have launched the tool server;
// janus-mcpd launches the real server as a child process and relays between
// them, recording every message in the evidence log before it is forwarded.
// Neither the agent nor the tool server is modified — onboarding an existing
// MCP server is a change to one command line.
//
// Phase 0 records and classifies. Refusing to forward an ungated irreversible
// call, and creating saga steps around effectful calls, is Phase 3/4 work; the
// classification this proxy already writes is what those gates will act on.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/callersig"
	"github.com/mustafarslan/janus/pkg/clockwire"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/mcp"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/tenancy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var version = "dev"

const usage = `janus-mcpd %s — MCP interception proxy

usage:
  janus-mcpd [flags] -- <tool-server-command> [args...]

The agent speaks MCP to this process on stdin/stdout; the tool server is
launched as a child and speaks MCP on its own stdin/stdout. Every message in
both directions is appended to the evidence log before it is forwarded.

flags:
`

func main() {
	var (
		evidenceDir    = flag.String("evidence", "./janus-evidence", "evidence segment directory")
		keyPath        = flag.String("key", "", "writer key file (default: <evidence>/../keys/writer.key)")
		sessionID      = flag.String("session", "", "session id recorded as the saga id (default: generated)")
		classFile      = flag.String("classes", "", "JSON file mapping tool names to effect classes, for a tool server that is not registered")
		registryDir    = flag.String("registry", "", "evidence directory to resolve the participant's active manifest from (preferred over -classes)")
		participant    = flag.String("participant", "tool_mcp_server", "participant id of the tool server being fronted")
		participantKey = flag.String("participant-key", "", "the fronted participant's key (janus-keys gen), declared in its manifest; what this proxy sends janus-orchd on its behalf is signed with it")
		syncMode       = flag.String("sync", "full", "durability barrier: full|data|none")
		tenant         = flag.String("tenant", "", "tenant this daemon writes for; stamped on every event and not settable by a caller")
		jurisdiction   = flag.String("jurisdiction", "", "jurisdiction code for the tenant (EU, DE, UK, ...)")
		orchdAddr      = flag.String("orchd", "",
			"address of janus-orchd; with it, effectful calls become gated saga steps "+
				"and reach the tool server only when their saga commits. Without it this "+
				"proxy records and classifies but forwards everything, which is the "+
				"Phase 0 behaviour")
		principal = flag.String("principal", "pr_bank", "principal the tool server acts for")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	clockFlags := clockwire.RegisterFlags(flag.CommandLine)
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), usage, version)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("janus-mcpd %s\n", version)
		return
	}
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	err := run(config{
		evidenceDir:   *evidenceDir,
		keyPath:       *keyPath,
		sessionID:     *sessionID,
		classFile:     *classFile,
		registryDir:   *registryDir,
		participantID: *participant, participantKey: *participantKey,
		syncName:     *syncMode,
		tenant:       *tenant,
		jurisdiction: *jurisdiction,
		argv:         flag.Args(),
		orchdAddr:    *orchdAddr,
		principal:    *principal,
		clockFlags:   clockFlags,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "janus-mcpd: %v\n", err)
		os.Exit(1)
	}
}

// config is what one proxy session needs. It is a struct rather than eight
// positional strings because the two that decide how tool calls are classified
// — the registry directory and the static file — are easy to swap by accident.
type config struct {
	evidenceDir    string
	keyPath        string
	sessionID      string
	classFile      string
	registryDir    string
	participantID  string
	participantKey string
	syncName       string
	tenant         string
	jurisdiction   string
	argv           []string
	orchdAddr      string
	principal      string
	// clockFlags carries -clock-sources and friends. This daemon writes its own
	// evidence directory, so it attests its own clock: an attestation measures
	// the clock of the process that took it, and borrowing janus-orchd's would
	// vouch for this host's timestamps with a measurement of another host's
	// clock.
	clockFlags *clockwire.Flags
}

func run(cfg config) error {
	mode, err := segment.ParseSyncMode(cfg.syncName)
	if err != nil {
		return err
	}
	classifier, manifestVersion, err := classifierFor(cfg)
	if err != nil {
		return err
	}
	sessionID := cfg.sessionID
	if sessionID == "" {
		sessionID = "mcp_" + randomSuffix()
	}
	argv := cfg.argv
	evidenceDir := cfg.evidenceDir

	// The tenant is the daemon's binding, not a label. Passing it through
	// Options.Labels would put it in the same bag as mcp.method, where the
	// proxy's own per-message labels could overwrite it (pkg/tenancy).
	tenant := tenancy.Tenant{ID: cfg.tenant, Jurisdiction: cfg.jurisdiction}

	// The interception edge records what a regulator actually asks about — every
	// tool call this proxy forwards — and until now every one of those records
	// carried no clock attestation reference, in deployments whose sagas carried
	// one. The proxy is long-lived, so it runs the monitor on a ticker the way
	// janus-orchd does rather than taking a single reading at startup.
	who := evidence.ParticipantRef{
		ID: cfg.participantID, ManifestVersion: manifestVersion, Kind: "TOOL",
	}
	clockCfg := cfg.clockFlags.Config(who)
	clockCfg.WarnIfUnattested("janus-mcpd", evidenceDir)
	clk, err := clockwire.New(clockCfg)
	if err != nil {
		return err
	}

	app, err := evidence.Open(evidence.Options{
		Dir:                 evidenceDir,
		KeyPath:             cfg.keyPath,
		SyncMode:            mode,
		Tenant:              tenant,
		ClockAttestationRef: clk.Ref,
	})
	if err != nil {
		return fmt.Errorf("open evidence log: %w", err)
	}
	defer func() {
		if cerr := app.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "janus-mcpd: closing evidence log: %v\n", cerr)
		}
	}()
	clk.Bind(app)
	// Before the first tool call is recorded: an event appended while the first
	// attestation is still in flight would silently carry no reference.
	clk.Start(context.Background())
	// Registered after the appender's close, so it runs before it: defers are
	// LIFO, and a tick that fired between the two would try to append to a
	// closed log. It would be refused rather than lost, but a shutdown that logs
	// a failure it caused itself is a shutdown somebody has to investigate.
	defer clk.Stop()

	// Pointed at a daemon, the classification decides rather than merely being
	// recorded. Without one this stays the proxy it has been since Phase 0:
	// everything recorded, everything forwarded. That is the honest fallback
	// for a tool server nobody has registered anything about, and it is stated
	// on startup so nobody mistakes one mode for the other.
	var router mcp.Router
	if cfg.orchdAddr != "" {
		conn, cerr := grpc.NewClient(cfg.orchdAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if cerr != nil {
			return fmt.Errorf("connecting to janus-orchd at %s: %w", cfg.orchdAddr, cerr)
		}
		defer func() { _ = conn.Close() }()

		client := orchd.NewClient(conn)
		if cfg.participantKey != "" {
			signer, serr := callersig.LoadSigner(cfg.participantID, cfg.participantKey)
			if serr != nil {
				return fmt.Errorf("loading the participant's key: %w", serr)
			}
			client = client.WithSigners(signer)
		}
		gw, gerr := mcp.NewGateway(mcp.GatewayOptions{
			Client: client, SessionID: sessionID, Participant: cfg.participantID,
			ManifestVersion: manifestVersion, Principal: cfg.principal,
		})
		if gerr != nil {
			return gerr
		}
		router = gw

		// The proxy is also the only thing that can reach this tool server, so
		// it registers as the deliverer for it. Nothing else can release an
		// effect to a tool server it has no connection to.
		stop, derr := serveDeliveries(context.Background(), client, cfg.participantID, gw)
		if derr != nil {
			return fmt.Errorf("registering as the deliverer for %s: %w", cfg.participantID, derr)
		}
		defer stop()
	}

	proxy, err := mcp.NewProxy(mcp.Options{
		Appender:   app,
		Classifier: classifier,
		Router:     router,
		SessionID:  sessionID,
		// The manifest version in `who` is empty when no registry was given,
		// and that is the honest answer: nothing pins these events to a
		// declaration, so nothing later can resolve what the tool was allowed
		// to do (invariant I8).
		Participant: who,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stderr = os.Stderr
	serverIn, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	serverOut, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tool server %q: %w", strings.Join(argv, " "), err)
	}

	if router == nil {
		fmt.Fprintln(os.Stderr, "janus-mcpd: no -orchd, so every call is forwarded; "+
			"classification is recorded but nothing acts on it")
	} else {
		fmt.Fprintf(os.Stderr, "janus-mcpd: routing effectful calls through %s\n", cfg.orchdAddr)
	}
	fmt.Fprintf(os.Stderr, "janus-mcpd %s: session %s, evidence %s, fronting %q\n",
		version, sessionID, evidenceDir, strings.Join(argv, " "))

	runErr := proxy.Run(ctx, os.Stdin, os.Stdout, serverIn, serverOut)
	waitErr := cmd.Wait()

	stats := proxy.Stats()
	fmt.Fprintf(os.Stderr, "janus-mcpd: %d messages to server, %d to client, %d tool calls (%d unregistered)\n",
		stats.ClientToServer, stats.ServerToClient, stats.ToolCalls, stats.Unclassified)

	if runErr != nil {
		return runErr
	}
	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) {
		return fmt.Errorf("tool server: %w", waitErr)
	}
	return nil
}

// classifierFor decides what a tool call is, and says under which declaration.
//
// The registry is the answer: a tool's effect class comes from its signed,
// evaluated, activated manifest, so the classification this proxy writes into
// the log is the one somebody is answerable for. The static file remains for a
// tool server nobody has registered yet — it classifies, it pins nothing, and
// the empty manifest version on every event it produces says so.
func classifierFor(cfg config) (mcp.Classifier, string, error) {
	if cfg.registryDir != "" {
		reg, err := registry.Replay(cfg.registryDir)
		if err != nil {
			return nil, "", fmt.Errorf("read the registry at %s: %w", cfg.registryDir, err)
		}
		active, ok := reg.Active(cfg.participantID)
		if !ok {
			// Fronting a participant with no active manifest is refused rather
			// than defaulted. Every tool call would fall through to the
			// fail-closed class, which looks like a working proxy right up to
			// the moment somebody wonders why nothing is allowed.
			return nil, "", fmt.Errorf("the registry at %s has no active manifest for %q; "+
				"register, evaluate and activate one, or pass -classes to front an "+
				"unregistered tool server", cfg.registryDir, cfg.participantID)
		}
		return reg.ClassifierFor(cfg.participantID), active.Version, nil
	}
	c, err := loadClasses(cfg.classFile)
	return c, "", err
}

// loadClasses reads a static tool-to-effect-class table, for a tool server that
// is not in the registry.
func loadClasses(path string) (mcp.Classifier, error) {
	if path == "" {
		return mcp.StaticClassifier{}, nil
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]string
	if err := json.Unmarshal(blob, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make(mcp.StaticClassifier, len(raw))
	for tool, name := range raw {
		full := "EFFECT_CLASS_" + strings.ToUpper(name)
		v, ok := janusv1.EffectClass_value[full]
		if !ok {
			return nil, fmt.Errorf("%s: unknown effect class %q for tool %q", path, name, tool)
		}
		out[tool] = janusv1.EffectClass(v)
	}
	return out, nil
}

func randomSuffix() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("pid%d", os.Getpid())
	}
	return hex.EncodeToString(b[:])
}

// serveDeliveries registers this proxy as the deliverer for its tool server and
// answers what the daemon sends it.
//
// The stream runs from the daemon to here, not the other way round, because the
// decision to release belongs with the log: EFFECT_RELEASING is appended before
// anything is attempted, and only the process that owns the log can append it.
func serveDeliveries(ctx context.Context, client *orchd.Client, target string,
	gw *mcp.Gateway) (func(), error) {

	ctx, cancel := context.WithCancel(ctx)
	stream, err := client.DeliverEffects(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	if err := stream.Send(&janusv1.DeliverEffectsRequest{
		Message: &janusv1.DeliverEffectsRequest_Register{
			Register: &janusv1.DelivererRegistration{Targets: []string{target}},
		},
	}); err != nil {
		cancel()
		return nil, err
	}

	go func() {
		for {
			msg, rerr := stream.Recv()
			if rerr != nil {
				return
			}
			receipt := &janusv1.DeliveryReceipt{EffectId: msg.GetEffectId()}
			r, derr := gw.Deliver(ctx, outbox.Effect{
				ID: msg.GetEffectId(), SagaID: msg.GetSagaId(), StepID: msg.GetStepId(),
				Target: msg.GetTarget(), Action: msg.GetAction(), IdemKey: msg.GetIdemKey(),
			})
			if derr != nil {
				receipt.Error, receipt.Retryable = derr.Error(), r.Retryable
			} else {
				receipt.Ref, receipt.Duplicate = r.Ref, r.Duplicate
				receipt.Retryable, receipt.Message = r.Retryable, r.Message
			}
			if serr := stream.Send(&janusv1.DeliverEffectsRequest{
				Message: &janusv1.DeliverEffectsRequest_Receipt{Receipt: receipt},
			}); serr != nil {
				return
			}
		}
	}()
	return cancel, nil
}
