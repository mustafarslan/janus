package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/continuous"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// A full sweep, run once, timed.
//
// `watch` runs sweeps on a schedule forever, which is what a deployment wants
// and not what an operator wants at the end of a restore. A restore leaves the
// signature and Merkle sweep until after the daemon starts — because verifying
// 100M events took 254.5 s against the 300 s RTO — and that decision creates
// a window in which restored bytes are trusted on their digests and their chain
// alone. The window is exactly one sweep long.
//
// A runbook that cannot state how long it lasts says "wait a while". This is how
// it gets a number, and how a restore drill measures the same thing rather than
// asserting it.

func sweep(args []string) error {
	fs := flag.NewFlagSet("sweep", flag.ContinueOnError)
	dir := fs.String("evidence", "./janus-evidence", "evidence segment directory")
	keyFile := fs.String("keys", "", "trusted writer public keys (required)")
	slice := fs.Int("slice", 0, "segments per step; zero lets the verifier choose")
	jsonOut := fs.String("json", "", "write the result to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("-keys is required: without a trusted key set this would only be " +
			"checking the log against itself, which is what a forger also passes")
	}
	set, err := loadPublicKeys(*keyFile)
	if err != nil {
		return err
	}

	var criticals []verify.Finding
	v, err := continuous.New(continuous.Config{
		Dir: *dir, Keys: set,
		OnFinding: func(f verify.Finding) {
			fmt.Printf("[%s] %s %s\n", f.Severity, f.Code, f.Message)
			if f.Severity == verify.Critical {
				criticals = append(criticals, f)
			}
		},
	})
	if err != nil {
		return err
	}

	// Driven to completion here rather than on a timer. SweepStep reports when
	// the pass it fixed at the start has been finished, and that flag is the
	// only honest end: a sweep that stopped when it ran out of new segments
	// would be an incremental check wearing a sweep's name.
	ctx := context.Background()
	start := time.Now()
	steps := 0
	for {
		_, done, err := v.SweepStep(ctx, *slice)
		if err != nil {
			return fmt.Errorf("sweeping: %w", err)
		}
		steps++
		if done {
			break
		}
	}
	took := time.Since(start)
	st := v.Status()

	fmt.Printf("swept %s in %s\n", *dir, took.Round(time.Millisecond))
	// Events and steps, not Status.SegmentsKnown: that counter is maintained by
	// the incremental pass, which this never runs, so it reads zero here — and a
	// line saying "0 segments, 20001 events verified" reads as a broken tool
	// rather than as a sweep that did its job.
	fmt.Printf("  %d events verified across %d steps\n", st.EventsVerified, steps)
	if len(criticals) > 0 {
		fmt.Printf("  %d critical finding(s)\n", len(criticals))
	}

	if *jsonOut != "" {
		if err := writeJSON(*jsonOut, map[string]any{
			"evidence": *dir, "took_ns": took, "steps": steps,
			"segments": st.SegmentsKnown, "events_verified": st.EventsVerified,
			"healthy": st.Healthy, "critical_findings": len(criticals),
		}); err != nil {
			return err
		}
	}

	// A sweep that found tampering must not exit zero. The whole point of
	// running one after a restore is to learn whether the bytes that were
	// trusted on their digests hold up against their signatures, and an
	// operator's script will read the exit status before it reads the output.
	if !st.Healthy || len(criticals) > 0 {
		return fmt.Errorf("the sweep found %d critical finding(s): the restored log's "+
			"signatures do not hold", len(criticals))
	}
	return nil
}
