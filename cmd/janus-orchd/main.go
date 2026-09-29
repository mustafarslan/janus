// janus-orchd owns an evidence directory and serves the operations everything
// else in Phase 4 needs.
//
// Run one per evidence directory. Running two is not a configuration mistake
// that degrades performance — it is refused, because one process writes an
// evidence directory and the second one to start will be told so by
// name.
//
// What this binary deliberately does not have is a way to inject participants,
// deliverers or answers. Those belong to whatever is on the other end of the
// wire; a daemon with a flag for "pretend this step succeeded" would be a
// daemon somebody eventually runs in production.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/clockwire"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/fence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/keys/remote"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/identity"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/tenancy"
	"google.golang.org/grpc"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "janus-orchd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dir        = flag.String("dir", "./janus-evidence", "evidence directory to own")
		policy     = flag.String("policy", "docs/policy/reference.json", "gate policy to admit sagas under")
		cadence    = flag.String("revalidation", "", "revalidation cadence by risk tier (JSON); empty schedules none")
		key        = flag.String("key", "", "signing key file; created if it does not exist")
		signerSock = flag.String("signer", "",
			"unix socket of a janus-signer holding the writer key. With it, no private key "+
				"is on this process's disk and no operation exists to fetch one. Mutually "+
				"exclusive with -key.")
		listen    = flag.String("listen", "127.0.0.1:7777", "address to serve on")
		id        = flag.String("id", "ag_orchd", "participant id this process records under")
		princ     = flag.String("principal", "pr_bank", "principal this process acts for")
		sync      = flag.String("sync", "full", "durability barrier: full, data, or none")
		tenant    = flag.String("tenant", "", "tenant this daemon serves; stamped on every event and refused if a caller tries to set it")
		juris     = flag.String("jurisdiction", "", "jurisdiction code for the tenant (EU, DE, UK, ...)")
		reqSigned = flag.Bool("require-caller-signatures", false,
			"refuse an unsigned answer, declaration, result or saga begin even from a participant whose "+
				"manifest declares no key. A participant that declares a key must always sign; "+
				"without this, keyless participants are taken at their word")
		relayers = flag.String("human-relayers", "",
			"comma-separated participants allowed to relay a person's answer (the console). Set, a "+
				"person's answer must be signed by one of them")
		sandbox = flag.String("sandbox-targets", "",
			"comma-separated delivery targets an exploratory saga may reach.\n"+
				"Empty means an exploratory saga releases nothing at all, which is the right\n"+
				"default for a mode whose whole meaning is \"not for real\"")
		pgDSN = flag.String("projection", "",
			"Postgres connection string for the projections; frontier gates are answered\n"+
				"from a scoped query instead of by replaying every saga. Empty replays the log,\n"+
				"which is slower and always correct")
		segBytes = flag.Int64("segment-bytes", 0,
			"rotate a segment once it reaches this size; zero means 16 MiB.\n"+
				"Rotation is what seals a segment, and a sealed segment is what the WORM\n"+
				"tier and a replica's signature checking act on")
		issuerJWKS multiFlag
		standby    = flag.String("standby-keys", "",
			"public key set (janus-keys pub) to declare in the log as standby writer keys.\n"+
				"A replica promoted later signs with one, and it must be declared here while\n"+
				"this primary is healthy: trust extends forward, so a key first introduced by\n"+
				"the promoted writer dangles from no in-chain declaration and an auditor\n"+
				"following from one root cannot reach it")
	)
	// The clock flags are the same three in every process that writes a log, so
	// they are registered from one place: six copies of the help text would
	// drift, and the text is where the reasoning lives.
	clockFlags := clockwire.RegisterFlags(flag.CommandLine)
	fenceFlags := fence.RegisterFlags(flag.CommandLine)
	flag.Var(&issuerJWKS, "issuer-jwks", "trust an OIDC issuer's signing keys, as\n"+
		"<issuer-url>=<path to that issuer's JWKS>. Repeatable, once per issuer.\n"+
		"Until an issuer is trusted here, every approval carrying an assertion is\n"+
		"refused with \"is not an issuer this log trusts\": identity.Verify needs an\n"+
		"ID token and verifying one needs the issuer's key in the log.\n"+
		"Configuration and not an RPC on purpose: whoever can add an issuer can mint\n"+
		"a token establishing any role, so it belongs to whoever controls the host\n"+
		"rather than to whoever holds a session. Revocation IS an RPC --\n"+
		"see janus-identity revoke-issuer -- because it removes authority.\n"+
		"The file is read, never fetched: a daemon that pulled a JWKS at start-up\n"+
		"would put a network dependency in the identity path, and a deployment\n"+
		"must be able to run air-gapped. Declaring a key already trusted records nothing, so\n"+
		"restarting with the same flags is a no-op; a DIFFERENT key under an id the\n"+
		"log already trusts is refused rather than overwritten")
	flag.Parse()

	issuerKeys, err := loadIssuerJWKS(issuerJWKS)
	if err != nil {
		return err
	}

	mode, err := syncMode(*sync)
	if err != nil {
		return err
	}
	var cad *registry.Cadence
	if *cadence != "" {
		cad, err = registry.LoadCadenceFile(*cadence)
		if err != nil {
			return fmt.Errorf("loading the revalidation cadence: %w", err)
		}
	}

	p, err := gate.LoadPolicyFile(*policy)
	if err != nil {
		return fmt.Errorf("loading the gate policy: %w", err)
	}
	signer, err := writerKey(*dir, *key, *signerSock)
	if err != nil {
		return err
	}

	var standbyKeys keys.PublicKeySet
	if *standby != "" {
		blob, err := os.ReadFile(*standby)
		if err != nil {
			return fmt.Errorf("reading the standby key set: %w", err)
		}
		if err := json.Unmarshal(blob, &standbyKeys); err != nil {
			return fmt.Errorf("parsing %s: %w", *standby, err)
		}
	}

	participant := evidence.ParticipantRef{
		ID: *id, Principal: *princ, Kind: "AGENT", ManifestVersion: "1.0.0",
	}
	clockCfg := clockFlags.Config(participant)
	clockCfg.WarnIfUnattested("janus-orchd", *dir)

	// The lease is taken before the appender opens, and a refusal here stops the
	// daemon. That is the point: "another writer holds this log" is something an
	// operator has to act on, and learning it at start-up costs nothing, while
	// learning it at the first seal means a segment's worth of appends already
	// happened on a directory this process was not entitled to write.
	fenceFlags.WarnIfUnfenced("janus-orchd")
	// Which tenure this writer serves, from the marker this node's promotion
	// left rather than from a flag somebody has to remember. A
	// directory that was never promoted has no epoch recorded and serves 0,
	// which is the original writer's.
	if err := fenceFlags.ResolveEpoch(*dir, flag.CommandLine); err != nil {
		return err
	}
	fenceCtx, cancelFence := context.WithCancel(context.Background())
	defer cancelFence()
	lease, err := fenceFlags.Open(fenceCtx, *id+"@"+*listen)
	if err != nil {
		return err
	}
	if lease != nil {
		log.Printf("janus-orchd: writer lease held on %s", *dir)
		go lease.Run(fenceCtx)
		// Released before the process exits so a standby does not have to wait
		// out the TTL after a clean shutdown. Best effort by construction: a
		// process that is killed does not get to run this, which is what the
		// TTL is for.
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := lease.Release(ctx); err != nil {
				log.Printf("janus-orchd: releasing the writer lease: %v", err)
			}
		}()
	}

	srv, err := orchd.New(orchd.Options{
		Fence: lease,
		Dir:   *dir, Signer: signer, SyncMode: mode, Policy: p, Cadence: cad,
		ClockSources: clockCfg.Sources, ClockInterval: clockCfg.Interval,
		ClockTolerance:          clockCfg.Tolerance,
		SegmentTargetBytes:      *segBytes,
		StandbyKeys:             standbyKeys,
		IssuerKeys:              issuerKeys,
		Tenant:                  tenancy.Tenant{ID: *tenant, Jurisdiction: *juris},
		ProjectionDSN:           *pgDSN,
		SandboxTargets:          splitList(*sandbox),
		Participant:             participant,
		RequireCallerSignatures: *reqSigned,
		HumanRelayers:           splitList(*relayers),
	})
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()
	if !*reqSigned {
		// Said at every start rather than once in a README: this is the
		// configuration in which a caller can still claim to be somebody.
		log.Printf("janus-orchd: participants whose manifests declare no key are taken at their " +
			"word -- any caller can answer, declare and report as them. Declare keys " +
			"(identity.public_keys) and run with -require-caller-signatures")
	}

	// The log is open now, so there is a writer marker to record a supplied
	// -fence-epoch against — which is what makes the flag needed once rather
	// than at every start. It could not happen at ResolveEpoch above: the lease
	// is taken before anything touches the directory, so at that point a
	// directory whose marker had been deleted has none to write to, and
	// insisting would refuse the start the flag exists to permit.
	//
	// Logged rather than fatal: this daemon is running and fenced at the right
	// epoch either way, and the cost of the write failing is one more start
	// that needs the flag.
	if err := fenceFlags.RecordEpoch(*dir); err != nil {
		log.Printf("janus-orchd: the epoch could not be recorded in %s, so the next start "+
			"will need -fence-epoch again: %v", *dir, err)
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", *listen, err)
	}
	grpcServer := grpc.NewServer()
	janusv1.RegisterOrchestratorServiceServer(grpcServer, srv)

	// A signal stops it gracefully: in-flight RPCs finish, so nothing is
	// acknowledged and then lost. A caller that got an answer keeps it.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	fmt.Printf("janus-orchd owns %s, serving on %s, policy %s, sync %s\n",
		*dir, lis.Addr(), p.ID, *sync)
	if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

func syncMode(s string) (segment.SyncMode, error) {
	switch s {
	case "full":
		return segment.SyncModeFull, nil
	case "data":
		return segment.SyncModeData, nil
	case "none":
		// Named rather than defaulted to. A deployment running without a
		// barrier has to have said so: the difference is invisible until the
		// power goes out, and then it is the only thing that matters.
		return segment.SyncModeNone, nil
	default:
		return 0, fmt.Errorf("unknown -sync %q: use full, data, or none", s)
	}
}

// writerKey resolves where this daemon's segment signatures come from.
//
// Two custody models, and the flags are mutually exclusive rather than one
// falling back to the other. A silent fallback is the failure that matters
// here: a deployment that meant to use the signer daemon, typed the socket path
// wrong, and got a freshly generated on-disk key would come up, run, and write
// a perfectly valid log — under a key nobody intended and nobody's trust set
// contains. It would be found at the first verification, which is months later.
func writerKey(dir, keyPath, socket string) (segment.Signer, error) {
	if socket != "" {
		if keyPath != "" {
			return nil, fmt.Errorf("-key and -signer both name a custody model; pass one")
		}
		s, err := remote.Dial(remote.Options{Socket: socket})
		if err != nil {
			return nil, fmt.Errorf("reaching the signer on %s: %w", socket, err)
		}
		fmt.Printf("janus-orchd signs with key %s, held by the signer on %s\n", s.KeyID(), socket)
		return s, nil
	}
	if keyPath == "" {
		keyPath = dir + "/orchd.key"
	}
	s, err := keys.LoadOrCreate(keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading the signing key: %w", err)
	}
	return s, nil
}

// splitList turns a comma-separated flag into a list, dropping blanks so that a
// trailing comma does not declare a target named "".
func splitList(in string) []string {
	var out []string
	for _, p := range strings.Split(in, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// multiFlag collects a flag given more than once.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// loadIssuerJWKS reads each -issuer-jwks <issuer>=<path> into keys to declare.
//
// The issuer is spelled out separately rather than read from the document,
// because a JWKS does not name its own issuer: the binding between "this URL is
// the issuer" and "these are its keys" is the operator's assertion, and a token
// is matched against it by its "iss" claim. Taking it from the file would mean
// trusting the file to say who it belongs to.
func loadIssuerJWKS(args []string) (map[string][]identity.IssuerKey, error) {
	if len(args) == 0 {
		return nil, nil
	}
	out := map[string][]identity.IssuerKey{}
	for _, arg := range args {
		issuer, path, ok := strings.Cut(arg, "=")
		if !ok || issuer == "" || path == "" {
			return nil, fmt.Errorf("-issuer-jwks %q: expected <issuer-url>=<path>. The issuer "+
				"is given separately because a JWKS does not name its own issuer, and a "+
				"token is matched to it by the \"iss\" claim", arg)
		}
		if _, dup := out[issuer]; dup {
			return nil, fmt.Errorf("-issuer-jwks: issuer %q given twice; put every key for "+
				"one issuer in one JWKS", issuer)
		}
		blob, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading the JWKS for %s: %w", issuer, err)
		}
		set, err := identity.ParseJWKS(blob)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out[issuer] = set
	}
	return out, nil
}
