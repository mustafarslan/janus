// Command janus-replicad follows a primary's evidence log into a second
// directory.
//
// It is the process a second region runs. It connects to a `janus-orchd`, asks
// for the segment bytes that directory does not have yet, verifies them, and
// reports how far it has got — on a ticker, forever, until it is stopped.
//
// # What it is not
//
// It does not promote. A follower becoming a writer is an operator act (6i) and
// nothing here can be talked into performing it, including by the primary: the
// replication surface is three read-only calls and this process holds no writer
// key. That separation is the point. An automatic failover needs a failure
// detector this repository does not have, and a wrong one produces two writers
// that both believe they are the primary.
//
// It also does not make cross-region RPO zero. To be explicit: the design's
// RPO = 0 is a property of the *synchronous* append inside one region, and what
// this process introduces is a lag. The lag is the exposure and the failover
// drill (6j) is what measures it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/replica"
	"github.com/mustafarslan/janus/pkg/orchd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// version is stamped at build time.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "janus-replicad: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// A subcommand rather than a flag: promotion is a different act from
	// following, it takes the writer lock, and it must not be reachable by
	// adding a flag to a running follower's command line.
	if len(os.Args) > 1 && os.Args[1] == "promote" {
		return promote(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "compare" {
		return compare(os.Args[2:])
	}

	var (
		primary = flag.String("primary", "127.0.0.1:7777",
			"address of the janus-orchd that owns the log being followed")
		dir = flag.String("dir", "./janus-replica",
			"directory to mirror into. It must not be one an orchd owns:\n"+
				"one process writes an evidence directory, and this is that process for its copy")
		every = flag.Duration("interval", 5*time.Second,
			"how often to ask the primary for what is new. Bounded by how stale this copy\n"+
				"may be, not by what polling costs: a caught-up pass is four round trips and\n"+
				"32 bytes whatever the log holds. The expensive pass is the first\n"+
				"one, which scales with bytes and is not throttled")
		trust = flag.String("keys", "",
			"JSON file of trusted writer public keys (key id -> hex), as janus-verify takes.\n"+
				"With none, segment signatures are not checked and the status line says so:\n"+
				"a replica that reported a verified head without checking would be the\n"+
				"hollow control this project exists to prevent")
		chunk = flag.Int("chunk", 1<<20, "bytes to ask for in one read")
	)
	flag.Parse()

	var roots keys.PublicKeySet
	if *trust != "" {
		var err error
		roots, err = loadKeys(*trust)
		if err != nil {
			return fmt.Errorf("loading the trusted writer keys: %w", err)
		}
	} else {
		log.Printf("janus-replicad: no trust root given, so segment signatures will not " +
			"be checked; pass -keys to check them")
	}

	conn, err := grpc.NewClient(*primary, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", *primary, err)
	}
	defer func() { _ = conn.Close() }()

	follower, err := replica.New(replica.Options{
		Dir:             *dir,
		Source:          orchd.NewRemoteSource(conn),
		ChunkBytes:      *chunk,
		Keys:            roots,
		VerifierVersion: version,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Printf("janus-replicad %s: following %s into %s every %s",
		version, *primary, *dir, *every)
	// Said at startup, where the operator standing this process up will read
	// it, and not only in replica.Status's doc comment, where a Go reader will.
	// The status line this prints from here on says "signatures checked through
	// segment N", and that number is about what was *copied*: a poll asks only
	// about segments at or above the cursor, so a sealed segment
	// corrupted on this host afterwards never lowers it and nothing here will
	// ever mention it again. Proved, not assumed — see
	// TestAFollowerDoesNotNoticeDamageToItsOwnHistory, and the watcher's half in
	// TestTheWatcherCatchesWhatTheFollowerPassesOver.
	log.Printf("janus-replicad: whatever this process checks, it checks as it copies — never "+
		"what is already on disk here. Run 'janus-tier watch -evidence %s -keys <roots>' on "+
		"this host as well: its sweep is the only thing that re-reads this mirror's history, "+
		"and damage below this follower's cursor is invisible to it", *dir)

	t := time.NewTicker(*every)
	defer t.Stop()
	var lastReported uint64
	for {
		if err := follower.Follow(ctx); err != nil {
			// Divergence is fatal and everything else is not, and the
			// difference matters more than it looks. A network failure means
			// try again; divergence means the two directories are not the same
			// log, and every further pass would assemble a directory that
			// verifies as neither.
			if errors.Is(err, replica.ErrDiverged) {
				return fmt.Errorf("the primary's log diverges from this copy, so "+
					"following it further would corrupt the copy: %w", err)
			}
			// Fatal for the same reason and a different situation: the bytes
			// are one log, and this copy cannot authenticate who sealed them.
			// Retrying would copy segments no auditor could check, and the
			// cause is a flag rather than a fork.
			if errors.Is(err, replica.ErrUntrustedWriter) {
				return fmt.Errorf("this copy cannot authenticate the primary's segments, so "+
					"following it further would assemble a directory nobody can verify: %w", err)
			}
			if ctx.Err() == nil {
				log.Printf("janus-replicad: %v", err)
			}
		} else if st := follower.Status(); st.Seq != lastReported {
			log.Printf("janus-replicad: %s", describe(st))
			lastReported = st.Seq
		}

		select {
		case <-ctx.Done():
			log.Printf("janus-replicad: stopping at %s", describe(follower.Status()))
			return nil
		case <-t.C:
		}
	}
}

// loadKeys reads the same trusted-writer-key file janus-verify takes, so an
// operator hands the replica the roots they already have rather than a second
// format invented for this one.
func loadKeys(path string) (keys.PublicKeySet, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var set keys.PublicKeySet
	if err := json.Unmarshal(blob, &set); err != nil {
		return nil, fmt.Errorf("parse key file %s: %w", path, err)
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("key file %s contains no keys", path)
	}
	return set, nil
}

// describe renders a status line that cannot be misread as more than it is.
//
// The signature state is on the same line as the sequence, deliberately: a
// number on its own invites the reading "verified through here", and without a
// trust root that is exactly what has not happened.
func describe(st replica.Status) string {
	var b strings.Builder
	fmt.Fprintf(&b, "acknowledged through sequence %d", st.Seq)
	fmt.Fprintf(&b, " · at segment %d offset %d", st.Segment, st.Offset)
	if st.SignaturesChecked {
		fmt.Fprintf(&b, " · signatures checked through segment %d", st.SignaturesCheckedThrough)
	} else {
		b.WriteString(" · signatures NOT checked (no trust root)")
	}
	fmt.Fprintf(&b, " · %d records framed", st.RecordsFramed)
	return b.String()
}
