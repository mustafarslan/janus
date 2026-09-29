// janus-a2ad is the agent-to-agent interception edge.
//
// It does two jobs that belong together because they are two halves of the same
// question — who is this agent, and may I talk to it.
//
// It *serves* discovery: an A2A AgentCard projected from this participant's
// active manifest, the Janus manifest alongside it as the superset, and
// a watch endpoint streaming registry events by sequence so an orchestrator can
// invalidate a cache without polling the whole registry.
//
// And it *forwards*: agent messages to a counterpart, with the Janus framing
// travelling on them and both directions recorded. Before anything is sent, the
// counterpart is checked — against the registry, never against the card it
// serves about itself.
//
// What it deliberately does not do is create sagas. At the tool edge a call is
// an effect and janus-mcpd turns one into a gated step; here a message is a
// message, and manufacturing a transaction two agents did not agree to have
// would put a commitment in the log that neither of them made.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mustafarslan/janus/pkg/a2a"
	"github.com/mustafarslan/janus/pkg/clockwire"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "janus-a2ad: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		registryDir = flag.String("registry", "./janus-evidence",
			"evidence directory the registry is read from")
		sessionDir = flag.String("evidence", "./janus-a2a-evidence",
			"evidence directory this proxy records messages into")
		listen = flag.String("listen", "127.0.0.1:8090", "address to serve on")
		self   = flag.String("participant", "", "participant id this endpoint advertises")
		// -manifest-version, not -version: the latter is the binary's own
		// version flag, and defining both panics at startup for every
		// invocation. Compiling proves nothing about a flag set.
		selfVersion = flag.String("manifest-version", "1.0.0",
			"manifest version this endpoint advertises")
		baseURL     = flag.String("base-url", "", "where this agent is reachable, as it should appear on its card")
		upstream    = flag.String("upstream", "", "the counterpart's A2A endpoint; without it this serves discovery only")
		counterpart = flag.String("counterpart", "", "participant id of the counterpart")
		cpVersion   = flag.String("counterpart-version", "", "manifest version pinned for the counterpart")
		principal   = flag.String("principal", "pr_bank", "principal this proxy acts for")
		syncMode    = flag.String("sync", "full", "durability barrier: full|data|none")
		showVer     = flag.Bool("version", false, "print version and exit")
	)
	clockFlags := clockwire.RegisterFlags(flag.CommandLine)
	flag.Parse()
	if *showVer {
		fmt.Println("janus-a2ad", version)
		return nil
	}
	if *self == "" {
		return errors.New("-participant is required: a discovery endpoint has to say who it " +
			"is advertising")
	}
	mode, err := segment.ParseSyncMode(*syncMode)
	if err != nil {
		return err
	}

	discovery, err := a2a.NewServer(a2a.ServerOptions{
		Dir: *registryDir, Participant: *self, Version: *selfVersion,
		BaseURL: baseOrListen(*baseURL, *listen),
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/.well-known/", discovery.Handler())
	mux.Handle("/registry/", discovery.Handler())

	// The forwarding half is optional. An agent that only publishes its card
	// and its manifest is a useful thing to run on its own, and requiring a
	// counterpart to serve discovery would mean an agent nobody is talking to
	// yet cannot be discovered.
	if *upstream != "" {
		if *counterpart == "" || *cpVersion == "" {
			return errors.New("-upstream needs -counterpart and -counterpart-version: an " +
				"agent whose manifest version is not recorded cannot be resolved at replay " +
				"time, and one that cannot be checked is not talked to")
		}
		target, perr := url.Parse(*upstream)
		if perr != nil {
			return fmt.Errorf("parsing -upstream: %w", perr)
		}
		// This proxy owns the session log, so it attests its own clock: an
		// attestation measures the clock of the process that took it, and
		// pointing these records at janus-orchd's attestation would vouch for
		// this host's timestamps with a measurement of another host's clock.
		// Long-lived, so the monitor runs on a ticker.
		who := evidence.ParticipantRef{
			ID: *self, ManifestVersion: *selfVersion, Principal: *principal, Kind: "AGENT",
		}
		clockCfg := clockFlags.Config(who)
		clockCfg.WarnIfUnattested("janus-a2ad", *sessionDir)
		clk, cerr := clockwire.New(clockCfg)
		if cerr != nil {
			return cerr
		}

		app, aerr := evidence.Open(evidence.Options{
			Dir: *sessionDir, SyncMode: mode, ClockAttestationRef: clk.Ref,
		})
		if aerr != nil {
			return fmt.Errorf("opening the session log: %w", aerr)
		}
		defer func() { _ = app.Close() }()
		clk.Bind(app)
		// Before the first message is recorded: a message appended while the
		// first attestation is still in flight would carry no reference.
		clk.Start(context.Background())
		defer clk.Stop()

		proxy, perr2 := a2a.NewProxy(a2a.ProxyOptions{
			Upstream: target, Counterpart: *counterpart, CounterpartVersion: *cpVersion,
			Verifier: a2a.NewVerifier(*registryDir), Appender: app,
			Self: who,
		})
		if perr2 != nil {
			return perr2
		}
		mux.Handle("/", proxy)
		fmt.Fprintf(os.Stderr, "janus-a2ad: forwarding to %s@%s at %s, messages recorded in %s\n",
			*counterpart, *cpVersion, *upstream, *sessionDir)
	} else {
		fmt.Fprintln(os.Stderr, "janus-a2ad: discovery only; pass -upstream to forward messages")
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", *listen, err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()

	fmt.Fprintf(os.Stderr, "janus-a2ad %s: advertising %s@%s on %s, registry %s\n",
		version, *self, *selfVersion, lis.Addr(), *registryDir)
	if err := server.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// baseOrListen falls back to the listen address when no public URL was given,
// so a card served in development still points somewhere that works.
func baseOrListen(baseURL, listen string) string {
	if baseURL != "" {
		return baseURL
	}
	return "http://" + listen
}
