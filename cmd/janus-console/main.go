// Command janus-console serves the operator's view of a Janus deployment
// (saga topology, HITL queue, evidence search).
//
// It is a view over an evidence directory. It holds no state of its own, keeps
// no cache, and re-derives everything it shows on every request, because a
// console with its own copy of the truth is a second system of record that will
// eventually disagree with the first.
//
// Two flags decide what it is allowed to do, and both default to the cautious
// answer.
//
// Without -identity-header the console is read-only. It cannot record an
// approval because it cannot say who is approving, and a console that filled
// that in for people would make separation of duty — the one four-eyes property
// that survives an adversary — a formality. With the flag, the identity comes
// from a header an authenticating proxy in front of the console sets, and the
// recorded answer says so in its auth_ref: the claim is recorded as a claim,
// not as something Janus established.
//
// Without -keys the evidence search checks the chain and the Merkle roots but
// not the segment signatures, and says so on the page. The verdict an auditor
// relies on comes from janus-verify, run against keys handed over separately.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mustafarslan/janus/pkg/callersig"
	"github.com/mustafarslan/janus/pkg/console"
	"github.com/mustafarslan/janus/pkg/evidence/cas"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/projection"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var version = "dev"

const usage = `janus-console %s — saga topology, the human queue, the frozen-effect
work list, and evidence search

usage:
  janus-console [flags]

The console reads an evidence directory. It is read-only unless an identity
header is configured, because it will not record an approval it cannot attribute.

flags:
`

func main() {
	var (
		dir      = flag.String("evidence", "./janus-evidence", "evidence segment directory")
		addr     = flag.String("addr", "127.0.0.1:8088", "address to listen on")
		keyPath  = flag.String("keys", "", "public key set (janus-keys pub ...) — without it, segment signatures are not checked")
		identity = flag.String("identity-header", "", "request header carrying the authenticated approver, set by a proxy in front of this console")
		roles    = flag.String("roles-header", "", "request header carrying the roles that layer asserts, comma separated")
		idToken  = flag.String("id-token-header", "",
			"request header carrying the approver's OIDC ID token verbatim. With it the console "+
				"verifies the token and any WebAuthn step-up instead of recording what the "+
				"proxy said, and -blobs is then required")
		rolesClaim = flag.String("roles-claim", "",
			"ID token claim the roles are read from (providers disagree; guessing means roles "+
				"that silently never verify)")
		blobs = flag.String("blobs", "",
			"directory to store approvers' assertions in, content-addressed. Required with "+
				"-id-token-header: an auth_ref pointing at nothing is worse than an approval "+
				"that admits it established nothing")
		projection = flag.String("projection", "",
			"Postgres connection string for the projections; the overview, the queue\n"+
				"and the quarantine list are read from them instead of by replaying every\n"+
				"saga -- for the two lists, the projection chooses which sagas to replay and\n"+
				"nothing more. The console never\n"+
				"folds — the daemon that owns the log does — so a page says which sequence it\n"+
				"is as of. Empty replays the log, which is slower and always current")
		orchd = flag.String("orchd", "",
			"address of the janus-orchd that owns this evidence directory; without it "+
				"the console appends approvals itself, which only works where no "+
				"coordinator is running")
		relayer = flag.String("participant", "sys_console",
			"participant this console relays people's answers as; a daemon run with "+
				"-human-relayers accepts a person's answer only from the participants named there")
		relayKey = flag.String("participant-key", "",
			"the relaying participant's key (janus-keys gen), declared in its manifest; answers "+
				"relayed to -orchd are signed with it")
		showVer = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), usage, version)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVer {
		fmt.Printf("janus-console %s\n", version)
		return
	}

	if err := run(config{
		dir: *dir, addr: *addr, keyPath: *keyPath,
		identityHeader: *identity, rolesHeader: *roles,
		idTokenHeader: *idToken, rolesClaim: *rolesClaim, blobs: *blobs,
		orchdAddr:     *orchd,
		projectionDSN: *projection,
		relayer:       *relayer, relayKey: *relayKey,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "janus-console: %v\n", err)
		os.Exit(1)
	}
}

type config struct {
	dir, addr, keyPath               string
	identityHeader, rolesHeader      string
	idTokenHeader, rolesClaim, blobs string
	orchdAddr, projectionDSN         string
	relayer, relayKey                string
}

func run(cfg config) error {
	dir, addr, keyPath := cfg.dir, cfg.addr, cfg.keyPath
	identityHeader, rolesHeader, orchdAddr := cfg.identityHeader, cfg.rolesHeader, cfg.orchdAddr
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("evidence directory %s: %w", dir, err)
	}

	c := console.Open(dir)
	if cfg.projectionDSN != "" {
		// Read-only: the console opens the store and never folds it. The writer
		// lock stays with whichever janus-orchd owns the evidence directory,
		// and this process would be refused if it tried.
		store, err := projection.Open(context.Background(), cfg.projectionDSN)
		if err != nil {
			return fmt.Errorf("opening the projection: %w", err)
		}
		defer store.Close()
		// Before anything is rendered from it: a console that never folds never
		// reaches the projector's own binding check, and one pointed at another
		// deployment's database would show that deployment's sagas under this
		// heading with nothing looking wrong.
		if err := projection.CheckLogBinding(context.Background(), store, dir); err != nil {
			return err
		}
		c = c.WithProjection(store)
	}
	if keyPath != "" {
		set, err := loadKeys(keyPath)
		if err != nil {
			return err
		}
		c = c.WithKeys(set)
	}
	// Pointed at a daemon, approvals go to whoever owns the log. The console
	// still runs every one of its own checks — only the append is delegated,
	// because the append is the one thing it is not allowed to do: one
	// process owns the log. Without this flag it appends itself, which is correct for a
	// console run against a directory nobody is writing and fails loudly
	// against one that is.
	if orchdAddr != "" {
		conn, err := grpc.NewClient(orchdAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return fmt.Errorf("connecting to janus-orchd at %s: %w", orchdAddr, err)
		}
		defer func() { _ = conn.Close() }()
		client := orchd.NewClient(conn)
		if cfg.relayKey != "" {
			signer, err := callersig.LoadSigner(cfg.relayer, cfg.relayKey)
			if err != nil {
				return fmt.Errorf("loading the relaying participant's key: %w", err)
			}
			client = client.WithSigners(signer).As(cfg.relayer)
		}
		c = c.WithRecorder(client)
	}

	// An assertion has to go somewhere. Refusing at startup rather than at the
	// first approval means a deployment that meant to require an established
	// identity finds out now, not from a person standing at a payment.
	switch {
	case cfg.idTokenHeader != "" && cfg.blobs == "":
		return errors.New("-id-token-header without -blobs: the assertion would be verified " +
			"and then thrown away, and the log would record a reference to nothing")
	case cfg.idTokenHeader != "" && identityHeader == "":
		return errors.New("-id-token-header without -identity-header: the console would have " +
			"a proof and nobody to attribute it to")
	}
	if cfg.blobs != "" {
		store, err := cas.NewFileStore(cfg.blobs)
		if err != nil {
			return fmt.Errorf("opening the assertion store at %s: %w", cfg.blobs, err)
		}
		c = c.WithBlobs(store)
	}

	if rolesHeader != "" && identityHeader == "" {
		// A roles header with nobody to attach it to would let the console
		// record roles for an approver it cannot name.
		return errors.New("-roles-header without -identity-header: there would be nobody for " +
			"those roles to belong to")
	}

	srv, err := console.NewServer(c, console.ServerOptions{
		IdentityHeader: identityHeader,
		RolesHeader:    rolesHeader,
		IDTokenHeader:  cfg.idTokenHeader,
		RolesClaim:     cfg.rolesClaim,
		Version:        version,
	})
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "janus-console %s: http://%s — %s\n", version, ln.Addr(), dir)
	if srv.ReadOnly() {
		fmt.Fprintf(os.Stderr, "  read-only: no -identity-header, so approvals cannot be attributed and will be refused\n")
	} else {
		fmt.Fprintf(os.Stderr, "  approvals attributed from header %q", identityHeader)
		if rolesHeader != "" {
			fmt.Fprintf(os.Stderr, ", roles from %q", rolesHeader)
		}
		fmt.Fprintf(os.Stderr, "\n  the console records answers; the coordinator decides the gates\n")
		if cfg.idTokenHeader != "" {
			fmt.Fprintf(os.Stderr, "  identity established from the token in %q, assertions stored in %s\n",
				cfg.idTokenHeader, cfg.blobs)
			fmt.Fprintf(os.Stderr, "  a step-up needs a secure context: serve this over https, "+
				"or reach it on localhost — navigator.credentials exists nowhere else\n")
		} else {
			fmt.Fprintf(os.Stderr, "  no -id-token-header: roles are what the proxy asserted, and a gate "+
				"requiring an established identity will refuse\n")
		}
	}
	if keyPath == "" {
		fmt.Fprintf(os.Stderr, "  no -keys: evidence search checks the chain, not the segment signatures\n")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()

	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func loadKeys(path string) (keys.PublicKeySet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key set: %w", err)
	}
	var set keys.PublicKeySet
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("parse key set %s: %w", path, err)
	}
	return set, nil
}
