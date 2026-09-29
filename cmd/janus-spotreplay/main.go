// Command janus-spotreplay re-derives completed sagas from an evidence log and
// reports how many still come out the way the log says they did.
//
// It is the other half of the replay-determinism check. CI replays the fixture corpus on every
// commit, which proves the state machine has not changed underneath histories
// somebody wrote down; this samples the sagas a deployment actually ran, which
// are the ones whose determinism a regulator would ask about.
//
// It reads. It takes no lock, appends nothing, and can run beside a live
// coordinator — a divergence is an alarm for a person, and the only correct
// automatic response to "this history no longer replays the same way" is to stop
// and look.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mustafarslan/janus/pkg/spotreplay"
	"github.com/mustafarslan/janus/pkg/telemetry"
)

var version = "dev"

const usage = `janus-spotreplay %s — continuous replay determinism sampling

  janus-spotreplay -evidence ./janus-evidence            # one pass, then report
  janus-spotreplay -evidence ./e -every 60s -state s.json  # keep sampling

Every completed saga is replayed twice and compared with itself (invariant I5),
and a committed one is also checked against the evidence root and last sequence
its own COMMIT recorded — a value written at the time by a different process and
cited afterwards as the authority for releasing an irreversible effect.

The rate this prints is over sagas that reached a terminal state. A saga still
running is checked for stability and not counted, because the gate asks about
completed sagas. With -state the count survives a restart; without it, a rate is
only ever about this run.

Exit status is 1 if anything diverged, so this can be a cron job that pages.

`

func main() {
	var (
		dir     = flag.String("evidence", "./janus-evidence", "evidence segment directory")
		every   = flag.Duration("every", 0, "keep sampling on this interval; zero does one pass and exits")
		state   = flag.String("state", "", "checkpoint file, so the rate and position survive a restart")
		asJSON  = flag.Bool("json", false, "print the tally as JSON")
		showVer = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), usage, version)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return
	}

	diverged := false
	report := func(f spotreplay.Finding) {
		if f.Deterministic() {
			return
		}
		diverged = true
		fmt.Fprintf(os.Stderr, "DIVERGED %s (%s)\n", f.SagaID, f.Status)
		for _, d := range f.Divergences() {
			fmt.Fprintf(os.Stderr, "    %s: %s\n", d.Name, d.Detail)
		}
	}

	r, err := spotreplay.New(spotreplay.Options{Dir: *dir, State: *state, Report: report})
	if err != nil {
		fmt.Fprintf(os.Stderr, "janus-spotreplay: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The counters are registered whether or not this is a daemon run: a
	// one-shot invocation under a collector that scrapes on exit is unusual but
	// not wrong, and the cost with no provider configured is nothing.
	tel := telemetry.New("janus-spotreplay")
	if reg, err := tel.SpotReplay("janus-spotreplay",
		func(context.Context) (uint64, uint64, uint64, error) {
			t := r.Tally()
			return t.Checked, t.Agreed, uint64(len(t.Diverged)), nil
		}); err != nil {
		fmt.Fprintf(os.Stderr, "janus-spotreplay: the counters will not be reported: %v\n", err)
	} else {
		defer func() { _ = reg.Unregister() }()
	}

	if *every > 0 {
		fmt.Fprintf(os.Stderr, "sampling %s every %s\n", *dir, *every)
		// A first pass immediately, so a daemon that is started and looked at
		// straight away has something to say.
		if _, err := r.Once(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "janus-spotreplay: %v\n", err)
		}
		if err := r.Run(ctx, *every); err != nil {
			fmt.Fprintf(os.Stderr, "janus-spotreplay: %v\n", err)
			os.Exit(2)
		}
	} else if _, err := r.Once(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "janus-spotreplay: %v\n", err)
		os.Exit(2)
	}

	t := r.Tally()
	if *asJSON {
		blob, err := json.MarshalIndent(t, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "janus-spotreplay: %v\n", err)
			os.Exit(2)
		}
		fmt.Println(string(blob))
	} else {
		switch t.Checked {
		case 0:
			// Not "100%". A run that checked nothing has demonstrated nothing,
			// and a gate reading 1.0 off an empty run is exactly the number that
			// ends up quoted in a report.
			fmt.Printf("no completed sagas were checked in %s — nothing has been demonstrated\n", *dir)
		default:
			fmt.Printf("%d completed sagas checked, %d agreed — %.4f%% deterministic (since %s)\n",
				t.Checked, t.Agreed, t.Rate()*100, t.Since.Format(time.RFC3339))
		}
		for _, id := range t.Diverged {
			fmt.Printf("  diverged: %s\n", id)
		}
	}
	if diverged || len(t.Diverged) > 0 {
		os.Exit(1)
	}
}
