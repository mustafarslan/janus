// Command janus-latency measures the decision path.
//
// `janus-bench` proved the *write* path: 195k events/s at p99 3.07 ms with the
// strongest durability barrier engaged. Nothing measured the path a gated
// side effect actually travels — prepare, decide, run, decide again, commit —
// and that is what the design budgets:
//
//   - p50 added latency per gated side effect ≤ 25 ms in-cluster
//   - gate decision p99 ≤ 50 ms, excluding human/validator latency
//
// Both numbers were unmeasured until this existed, which also left three
// pieces of deferred work parked on a measurement nobody had taken, and the
// Phase 6 exit gate — "load test at 10× design-partner peak
// with SLOs held" — with no baseline to hold anything against.
//
// # What varies, and why each dimension is here
//
// A latency figure with no load behind it is a figure about an idle machine, so
// every result states its concurrency (the same lesson `janus-bench` records
// about throughput: N producers and a sync costing T bound any run at N/T).
//
// Background log size is the second dimension because the two frontier-index
// implementations scale differently in it, and that difference is the whole
// argument for the projection. `gate.IndexFromLog` replays every saga in the
// directory, so its cost is O(log). `projection.Store.FrontierIndex` reads the
// sagas touching the subject's resources, so its cost is O(contending). The
// crossover is a number this prints rather than a claim to take on trust.
//
// # The frontier gate is always decided against a projection that is behind
//
// In the reference policy the FRONTIER requirement sits at PRE_RELEASE, so it is
// decided immediately after the step's own result is appended. The projection
// cannot already contain that event. This is therefore not a corner case to
// construct: every PRE_RELEASE sample in this benchmark pays for the
// synchronous catch-up `Projector.FrontierIndex` performs, which is the honest
// cost of the staleness contract and the thing the p99 decision budget is most
// at risk from.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/projection"
	"github.com/mustafarslan/janus/pkg/saga"
)

// version is stamped at build time; the default keeps local runs honest.
var version = "dev"

// Targets: the gated-effect and gate-decision latency budgets.
const (
	targetGatedEffectP50 = 25 * time.Millisecond
	targetDecisionP99    = 50 * time.Millisecond
)

// The four things measured. They are named rather than positional because the
// JSON report is meant to be diffed across runs.
const (
	mSagaStart = "saga_start"
	mPreExec   = "decide_pre_execution"
	mPreRel    = "decide_pre_release"
	mEffect    = "gated_effect"
)

type result struct {
	Measurement string `json:"measurement"`
	Index       string `json:"index"`
	Background  int    `json:"background_sagas"`
	Concurrency int    `json:"concurrency"`
	Pool        int    `json:"resource_pool"`
	Samples     int    `json:"samples"`
	// Gates is the fewest requirements any one decision judged. Zero means the
	// timing beside it is the cost of deciding nothing, which is the way this
	// benchmark would most plausibly report a false pass.
	Gates  int     `json:"gates_decided,omitempty"`
	P50MS  float64 `json:"p50_ms"`
	P99MS  float64 `json:"p99_ms"`
	P999MS float64 `json:"p999_ms"`
	MaxMS  float64 `json:"max_ms"`
	// Target is the budget this measurement is held to, and Percentile names
	// which one the budget is stated at — 25 ms is a p50 figure and 50 ms is a
	// p99 figure, and quoting either against the wrong percentile would be a
	// pass or a fail that means nothing.
	Target     float64 `json:"target_ms,omitempty"`
	Percentile string  `json:"target_percentile,omitempty"`
	Meets      bool    `json:"meets_target,omitempty"`
	Budgeted   bool    `json:"budgeted"`
	// Authoritative marks the rows the run's verdict is taken over.
	//
	// `gate.IndexFromLog` is the fallback a deployment with no projection
	// database uses, and its cost is O(log) by construction. Holding a whole run red because the documented fallback behaves
	// as documented would make this gate permanently failing and therefore
	// ignored. So when a projection was measured, the verdict is over the
	// projection — and the log rows are still printed with their budgets, next
	// to it, because the point of measuring both is the size of the gap.
	Authoritative bool `json:"authoritative"`
	// Blocked says why a configuration produced no timing at all. A row with
	// this set is a configuration that could not be measured, which is a
	// result in its own right and never a pass.
	Blocked string `json:"blocked,omitempty"`
}

type report struct {
	Version  string    `json:"version"`
	Host     string    `json:"host"`
	GOARCH   string    `json:"goarch"`
	GOOS     string    `json:"goos"`
	CPUs     int       `json:"cpus"`
	SyncMode string    `json:"sync_mode"`
	RanAt    time.Time `json:"ran_at"`
	Results  []result  `json:"results"`
}

func main() {
	var (
		dir         = flag.String("dir", "", "working directory (default: a temp dir, removed afterwards)")
		policyPath  = flag.String("policy", "docs/policy/reference.json", "gate policy to decide under")
		samples     = flag.Int("samples", 300, "gated side effects to measure per configuration")
		background  = flag.String("background", "0,2000", "comma-separated prior-saga counts to sweep")
		concurrency = flag.String("concurrency", "1,8", "comma-separated concurrent-driver counts to sweep")
		pool        = flag.Int("resources", 256, "distinct resources the sagas draw from")
		syncMode    = flag.String("sync", "full", "durability barrier: full, data or none")
		dsn         = flag.String("dsn", "", "PostgreSQL DSN; when set, the frontier index is also measured against the projection")
		segBytes    = flag.Int64("segment-bytes", 16<<20, "segment rotation threshold")
		jsonOut     = flag.String("json", "", "also write the report as JSON to this path")
	)
	flag.Parse()

	bg, err := ints(*background)
	if err != nil {
		fail("bad -background: %v", err)
	}
	conc, err := ints(*concurrency)
	if err != nil {
		fail("bad -concurrency: %v", err)
	}
	if err := run(runOpts{
		dir: *dir, policyPath: *policyPath, samples: *samples,
		background: bg, concurrency: conc, pool: *pool,
		syncMode: *syncMode, dsn: *dsn, segBytes: *segBytes, jsonOut: *jsonOut,
	}); err != nil {
		fail("%v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "janus-latency: "+format+"\n", args...)
	os.Exit(1)
}

// minSamplesPerSlot is how many samples each driver slot must get for a
// configuration's number to describe sustained load rather than one burst.
const minSamplesPerSlot = 3

// sustained refuses a configuration whose concurrency column would not describe
// what was measured.
//
// The drivers share one counter over -samples tasks, so a slot that finds the
// counter exhausted exits without ever running. With fewer samples than slots
// most slots do exactly that, and the run measures a single burst of `samples`
// drivers under a column that says `conc`: the load never becomes sustained and
// the fold count collapses to one or two. That is not a slow measurement, it is
// a measurement of a different thing, and nothing in the output distinguishes it
// from the real one — which is how a sweep at 64/256/1024 came back reading
// "16x the concurrency costs 2.4x the latency" when the last two points were the
// same burst.
//
// Three per slot is the floor: one to fill the pipeline, one under steady state,
// one after. Refused rather than warned, for the same reason the pool check is.
func sustained(conc, samples int) error {
	want := minSamplesPerSlot * conc
	if samples >= want {
		return nil
	}
	why := fmt.Sprintf("every slot runs, but only %.2f times each — too few rounds "+
		"for the load to become sustained rather than a burst",
		float64(samples)/float64(conc))
	if samples < conc {
		why = fmt.Sprintf("%d of the %d slots would find the counter exhausted and "+
			"exit without ever running, so this would measure %d drivers under a "+
			"column that says %d", conc-samples, conc, samples, conc)
	}
	return fmt.Errorf("concurrency %d with -samples %d: %s. Pass -samples %d or more "+
		"(%d per slot), or lower -concurrency", conc, samples, why, want, minSamplesPerSlot)
}

type runOpts struct {
	dir, policyPath, syncMode, dsn, jsonOut string
	samples, pool                           int
	background, concurrency                 []int
	segBytes                                int64
	judgedOn                                string
}

func run(o runOpts) error {
	if o.samples <= 0 {
		return fmt.Errorf("-samples must be positive")
	}
	mode, err := segment.ParseSyncMode(o.syncMode)
	if err != nil {
		return err
	}
	policy, err := gate.LoadPolicyFile(o.policyPath)
	if err != nil {
		return err
	}
	engine = gate.NewEngine(policy)
	// The plan is admitted once here, before anything is measured, so that a
	// policy this benchmark's saga does not fit is a clear message rather than a
	// panic from inside a driver goroutine.
	if err := engine.Admit((wire{sagaID: "sg_admit", resource: "acct:0000"}).Begin()); err != nil {
		return fmt.Errorf("the benchmark's own saga is not admissible under %s: %w", o.policyPath, err)
	}

	base := o.dir
	if base == "" {
		tmp, err := os.MkdirTemp("", "janus-latency-")
		if err != nil {
			return err
		}
		base = tmp
		defer func() { _ = os.RemoveAll(tmp) }()
	} else if err := os.MkdirAll(base, 0o750); err != nil {
		return err
	}

	// One signer for the whole run, because the background log is copied into
	// every configuration: a fresh key per configuration would leave a log
	// whose segments were sealed by two writers with no rotation recorded
	// between them, which is a shape the verifier is right to distrust.
	signer, err := keys.Generate()
	if err != nil {
		return err
	}

	indexes := []string{"log"}
	if o.dsn != "" {
		indexes = append(indexes, "projection")
	}
	judgedOn := authoritative(indexes)

	host, _ := os.Hostname()
	rep := report{
		Version: version, Host: host, GOARCH: runtime.GOARCH, GOOS: runtime.GOOS,
		CPUs: runtime.NumCPU(), SyncMode: mode.String(), RanAt: time.Now().UTC(),
	}
	o.judgedOn = judgedOn
	printHeader(rep, o)

	// The background is built once per size and copied for each configuration
	// that uses it. Two reasons, and both matter: every configuration then
	// starts from a byte-identical log, so a difference between two index
	// implementations is the index rather than the history; and the seeding
	// itself is the expensive part — a frontier gate answered from the log
	// replays everything, so building N background sagas that way costs O(N²)
	// and paying it once per size instead of once per configuration is the
	// difference between minutes and hours.
	for _, bg := range o.background {
		tmpl := filepath.Join(base, fmt.Sprintf("seed-bg%d", bg))
		if err := buildBackground(tmpl, bg, o, signer, mode); err != nil {
			return fmt.Errorf("building a %d-saga background: %w", bg, err)
		}
		for _, idx := range indexes {
			for _, conc := range o.concurrency {
				if conc > o.pool {
					return fmt.Errorf("concurrency %d exceeds the resource pool of %d: "+
						"a driver slot takes its account from the pool, so with fewer "+
						"accounts than slots two sagas in flight would share one and block "+
						"at the frontier gate, measuring a stall rather than a decision",
						conc, o.pool)
				}
				// The drivers share one counter over -samples tasks, so a slot
				// that finds the counter exhausted exits without ever running.
				// With fewer samples than slots, most slots do exactly that and
				// the run measures a single burst of `samples` drivers under a
				// column that says `conc` — the load never becomes sustained and
				// the fold count collapses to one or two. That is not a slow
				// measurement, it is a measurement of a different thing, and it
				// is indistinguishable from the real one in the output.
				//
				// Three per slot is the floor: one to fill the pipeline, one
				// measured under steady state, one after. Refused rather than
				// warned, for the same reason the pool check above is.
				if err := sustained(conc, o.samples); err != nil {
					return err
				}
				name := fmt.Sprintf("run-%s-bg%d-c%d", idx, bg, conc)
				runDir := filepath.Join(base, name)
				if err := os.CopyFS(runDir, os.DirFS(tmpl)); err != nil {
					return fmt.Errorf("%s: copying the background: %w", name, err)
				}
				res, notes, err := measure(cfg{
					authoritative: idx == judgedOn,
					dir:           runDir,
					mode:          mode,
					segBytes:      o.segBytes,
					signer:        signer,
					index:         idx,
					dsn:           o.dsn,
					schema:        name,
					bg:            bg, conc: conc, pool: o.pool, samples: o.samples,
				})
				if errors.Is(err, segment.ErrTornTail) && idx != judgedOn {
					// The fallback index cannot complete this configuration, and
					// that is the measurement: `gate.IndexFromLog` replays the
					// directory while this process is appending to it, and at
					// concurrency it reads a segment mid-record. Recorded and
					// printed rather than fatal, because a target that dies here
					// would report nothing at all about the arm that does work —
					// and this is a property of the fallback worth a line in the
					// output every time somebody runs it. It is never a pass: `blocked` carries no timing
					// and the run says so.
					blocked := result{
						Measurement: mEffect, Index: idx, Background: bg,
						Concurrency: conc, Pool: o.pool, Blocked: err.Error(),
					}
					rep.Results = append(rep.Results, blocked)
					printBlocked(blocked)
					continue
				}
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				rep.Results = append(rep.Results, res...)
				printResults(res)
				for _, n := range notes {
					fmt.Println(n)
				}
			}
		}
		// The template is only a source to copy from, and at 2000 sagas it is
		// not small. Removing it as soon as its last copy is taken keeps a
		// sweep's disk use proportional to one background rather than all of
		// them.
		_ = os.RemoveAll(tmpl)
	}

	printVerdict(rep)

	if o.jsonOut != "" {
		blob, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(o.jsonOut, append(blob, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("\nreport written to %s\n", o.jsonOut)
	}
	if !allMet(rep) {
		return fmt.Errorf("a latency budget was missed; see the table above")
	}
	return nil
}

// buildBackground writes n committed sagas into a fresh directory.
//
// It uses the projection index when a DSN is available, purely for speed: the
// index chooses how a frontier gate is *answered*, and every background saga is
// driven to commit before the next one starts, so both implementations return
// the same verdict and the log that comes out is the same log. `seed` asserts
// COMMITTED on every one of them, so a disagreement between the two would stop
// the run rather than quietly change what the benchmark measures.
func buildBackground(dir string, n int, o runOpts, signer *keys.Signer, mode segment.SyncMode) error {
	ctx := context.Background()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	app, err := evidence.Open(evidence.Options{
		Dir:                dir,
		Signer:             signer,
		SyncMode:           mode,
		SegmentTargetBytes: o.segBytes,
		QueueDepth:         1 << 16,
	})
	if err != nil {
		return err
	}

	index := gate.IndexFromLiveLog(dir, func() uint64 { return app.Stats().LastSeq })
	if o.dsn != "" {
		dsn, err := scopedDSN(ctx, o.dsn, filepath.Base(dir))
		if err != nil {
			_ = app.Close()
			return err
		}
		store, err := projection.Open(ctx, dsn)
		if err != nil {
			_ = app.Close()
			return fmt.Errorf("open the projection: %w", err)
		}
		defer store.Close()
		p := projection.NewProjector(store, dir)
		index = p.FrontierIndex(ctx, func() uint64 { return app.Stats().LastSeq })
	}

	if err := seed(ctx, app, dir, n, o.pool, gate.NewKeeper(index)); err != nil {
		_ = app.Close()
		return err
	}
	return app.Close()
}

type cfg struct {
	dir           string
	mode          segment.SyncMode
	segBytes      int64
	signer        *keys.Signer
	index         string
	authoritative bool
	dsn           string
	schema        string
	bg            int
	conc          int
	pool          int
	samples       int
}

// measure runs one configuration and returns its four rows, plus the diagnostic
// lines that explain them.
//
// The diagnostics are returned rather than printed where they are computed, so
// that they appear under the rows they describe. Printing them in place put them
// above the *next* configuration's rows, which is a caption attached to the
// wrong table — and this benchmark exists to be read.
func measure(c cfg) ([]result, []string, error) {
	ctx := context.Background()
	app, err := evidence.Open(evidence.Options{
		Dir:                c.dir,
		Signer:             c.signer,
		SyncMode:           c.mode,
		SegmentTargetBytes: c.segBytes,
		QueueDepth:         1 << 16,
	})
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = app.Close() }()

	index := gate.IndexFromLiveLog(c.dir, func() uint64 { return app.Stats().LastSeq })
	var projector *projection.Projector
	tails := &tailLengths{}
	if c.index == "projection" {
		dsn, err := scopedDSN(ctx, c.dsn, c.schema)
		if err != nil {
			return nil, nil, err
		}
		store, err := projection.Open(ctx, dsn)
		if err != nil {
			return nil, nil, fmt.Errorf("open the projection: %w", err)
		}
		defer store.Close()
		p := projection.NewProjector(store, c.dir)
		// The head is read from this process's own appender, which is the only
		// writer on this directory — the same wiring janus-orchd uses.
		index = p.FrontierIndex(ctx, func() uint64 { return app.Stats().LastSeq })
		// How far behind the log the projection is at the moment a decision
		// asks — the tail a decision would have to account for itself if it
		// stopped waiting for a fold.
		//
		// Sampled here rather than inside the projector because it is a
		// question about this measurement, not about the projection: nothing in
		// the answer depends on it, and a caller that acted on this number
		// would be reading a head without the ErrStale check that turns a stale
		// answer into a refusal.
		//
		// Read in this order — folded head first, then the log's — so the gap
		// is never understated by an append landing between the two reads. An
		// overstatement by one round of arrivals is the safe direction for a
		// number whose whole purpose is to bound work.
		base := index
		index = func(subject saga.State) (*saga.Index, error) {
			folded := p.FoldedThrough()
			if want := app.Stats().LastSeq; want > folded {
				tails.add(want - folded)
			} else {
				tails.add(0)
			}
			return base(subject)
		}
		projector = p
	}
	keeper := newTimedKeeper(gate.NewKeeper(index))
	var foldBefore projection.FoldStats
	var phaseBefore projection.FoldPhases
	var appBefore evidence.AppendPhases

	// One saga to warm first-touch page faults, lazy initialisation and, when
	// there is one, the projection's first catch-up. Measuring those once and
	// calling it a p99 would report a start-up cost as a steady-state one.
	if err := drive(ctx, app, c.dir, keeper, subject(c.bg, 0)); err != nil {
		return nil, nil, fmt.Errorf("warm-up: %w", err)
	}
	keeper.take(janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION)
	keeper.take(janusv1.GatePhase_GATE_PHASE_PRE_RELEASE)
	appBefore = app.Phases()
	if projector != nil {
		foldBefore = projector.FoldStats()
		phaseBefore = projector.FoldPhases()
	}

	var (
		mu      sync.Mutex
		starts  []time.Duration
		effects []time.Duration
		next    atomic.Int64
		wg      sync.WaitGroup
		failure error
	)
	next.Store(int64(c.bg) + 1)

	for slot := range c.conc {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			local := make([]time.Duration, 0, c.samples/c.conc+1)
			localStart := make([]time.Duration, 0, c.samples/c.conc+1)
			for {
				i := int(next.Add(1)) - 1
				if i >= int(c.bg)+1+c.samples {
					break
				}
				w := subject(i, slot)

				t0 := time.Now()
				co, err := saga.ResumeSaga(app, c.dir, w.sagaID, participant, w)
				localStart = append(localStart, time.Since(t0))
				if err != nil {
					mu.Lock()
					failure = err
					mu.Unlock()
					return
				}

				t1 := time.Now()
				s, err := co.WithGatekeeper(keeper).Drive(context.Background())
				local = append(local, time.Since(t1))
				if err != nil {
					mu.Lock()
					failure = fmt.Errorf("saga %s: %w", w.sagaID, err)
					mu.Unlock()
					return
				}
				if s.Status != saga.StatusCommitted {
					mu.Lock()
					failure = fmt.Errorf("saga %s ended %s, want COMMITTED", w.sagaID, s.Status)
					mu.Unlock()
					return
				}
			}
			mu.Lock()
			starts = append(starts, localStart...)
			effects = append(effects, local...)
			mu.Unlock()
		}(slot)
	}
	wg.Wait()
	if failure != nil {
		return nil, nil, failure
	}

	row := func(name string, obs []time.Duration, gates int, target time.Duration, pct string) result {
		slices.Sort(obs)
		r := result{
			Measurement: name, Index: c.index, Background: c.bg,
			Concurrency: c.conc, Pool: c.pool, Samples: len(obs), Gates: gates,
			Authoritative: c.authoritative,
			P50MS:         ms(percentile(obs, 0.50)), P99MS: ms(percentile(obs, 0.99)),
			P999MS: ms(percentile(obs, 0.999)), MaxMS: ms(percentile(obs, 1.0)),
		}
		if target > 0 {
			r.Budgeted, r.Target, r.Percentile = true, ms(target), pct
			switch pct {
			case "p50":
				r.Meets = percentile(obs, 0.50) <= target
			default:
				r.Meets = percentile(obs, 0.99) <= target
			}
		}
		return r
	}

	// The append half of a gated effect, split into the two things it can be:
	// queued behind another group commit, or at the durability barrier itself.
	// The two argue for opposite designs, so the split is the whole point.
	//
	// Per *sample*, not per gated effect: these cover the whole of a sample,
	// which is `saga_start` plus `gated_effect`, because the counters are the
	// appender's and every driver is writing to it at once. The two rows above
	// add up to the same window, so they are comparable to this line.
	var notes []string
	note := func(format string, args ...any) { notes = append(notes, fmt.Sprintf(format, args...)) }

	if ap := app.Phases(); ap.Appends > appBefore.Appends {
		n := ap.Appends - appBefore.Appends
		prep := ap.Prep - appBefore.Prep
		wait := ap.Wait - appBefore.Wait
		barrier := ap.Barrier - appBefore.Barrier
		note("    appends %d (%.1f per sample) · mean batch %.1f · per append: prep %.3f ms · wait %.2f ms · barrier %.2f ms",
			n, float64(n)/float64(c.samples),
			float64(ap.Batch-appBefore.Batch)/float64(n),
			ms(prep)/float64(n), ms(wait)/float64(n), ms(barrier)/float64(n))
		note("      per sample: %.2f ms in Append, of which %.0f%% waiting for the writer and %.0f%% at the barrier",
			ms(prep+wait+barrier)/float64(c.samples),
			100*safeDiv(ms(wait), ms(prep+wait+barrier)),
			100*safeDiv(ms(barrier), ms(prep+wait+barrier)))
	}

	if n, mean, p50, p99, max := tails.summary(); n > 0 {
		// What route 1 would have to do per decision, stated in records rather
		// than inferred from fold duration. p99 is the number that matters: a
		// design has to survive the decision that arrives just before a fold
		// completes, not the one that arrives just after.
		note("    tail at decision time: %d observations · mean %.0f records · "+
			"p50 %.0f · p99 %.0f · max %.0f", n, mean, p50, p99, max)
	}

	if projector != nil {
		// A diagnostic rather than a budgeted row: this separates "the fold is
		// slow" from "the fold is fine and everybody is queued behind it",
		// which is the question the concurrency sweep raises and cannot answer
		// on its own.
		st := projector.FoldStats()
		folds := st.Folds - foldBefore.Folds
		events := st.Events - foldBefore.Events
		total := st.Total - foldBefore.Total
		if folds > 0 {
			// No max: FoldStats.Max is cumulative over the projector's life and
			// there is nothing to subtract a baseline from, so printing it here
			// would report the warm-up's cold scan as this configuration's
			// worst fold. The mean over the measured window is the honest one.
			note("    folds %d · %d events (%.1f per fold) · mean fold %.2f ms · %.4f ms/event",
				folds, events, float64(events)/float64(folds),
				ms(total)/float64(folds),
				safeDiv(ms(total), float64(events)))
			ph := projector.FoldPhases()
			read := ph.Read - phaseBefore.Read
			apply := ph.Apply - phaseBefore.Apply
			commit := ph.Commit - phaseBefore.Commit
			scanned := ph.Scanned - phaseBefore.Scanned
			kept := ph.Kept - phaseBefore.Kept
			// `other` is measured against the *caller-visible* fold — the
			// coalescer's own timing, which is the number printed above — rather
			// than against the projector's internal total. The gap between the
			// two is the lock, and folding it into `other` is deliberate: a
			// decomposition that summed to 100% of a number smaller than the
			// thing a caller waits for would be arithmetically tidy and
			// operationally wrong.
			other := total - read - apply - commit
			if other < 0 {
				other = 0
			}
			note("      of that: read %.2f ms (%.0f%%) · apply %.2f ms (%.0f%%) · "+
				"commit %.2f ms (%.0f%%) · other %.2f ms (%.0f%%)",
				ms(read)/float64(folds), 100*safeDiv(ms(read), ms(total)),
				ms(apply)/float64(folds), 100*safeDiv(ms(apply), ms(total)),
				ms(commit)/float64(folds), 100*safeDiv(ms(commit), ms(total)),
				ms(other)/float64(folds), 100*safeDiv(ms(other), ms(total)))
			cw := ph.CommitWrite - phaseBefore.CommitWrite
			cs := ph.CommitSync - phaseBefore.CommitSync
			stmts := ph.Statements - phaseBefore.Statements
			note("        commit splits: statements %.2f ms (%.0f%%) · barrier %.2f ms (%.0f%%)",
				ms(cw)/float64(folds), 100*safeDiv(ms(cw), ms(commit)),
				ms(cs)/float64(folds), 100*safeDiv(ms(cs), ms(commit)))
			note("        %d statements (%.1f per fold, %.0f us each)",
				stmts, safeDiv(float64(stmts), float64(folds)),
				1000*safeDiv(ms(cw), float64(stmts)))
			fam := func(now, before uint64) float64 { return 100 * safeDiv(float64(now-before), float64(stmts)) }
			note("        by family: saga %.0f%% · clear %.0f%% · step %.0f%% · touch %.0f%%",
				fam(ph.StmtSaga, phaseBefore.StmtSaga), fam(ph.StmtClear, phaseBefore.StmtClear),
				fam(ph.StmtStep, phaseBefore.StmtStep), fam(ph.StmtTouch, phaseBefore.StmtTouch))
			note("      scanned %d records to keep %d (%.0f%% re-read)",
				scanned, kept, 100*safeDiv(float64(scanned-kept), float64(scanned)))
		}
	}

	preExec, preExecGates := keeper.take(janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION)
	preRel, preRelGates := keeper.take(janusv1.GatePhase_GATE_PHASE_PRE_RELEASE)

	// A decision that judged nothing is not a fast decision, it is an absent
	// one, and the timing beside it would be a false pass. Refusing here rather
	// than printing a zero means the failure arrives as an error at the moment
	// it happens instead of as a column somebody has to notice.
	for phase, n := range map[string]int{mPreExec: preExecGates, mPreRel: preRelGates} {
		if n == 0 {
			return nil, nil, fmt.Errorf("%s judged no requirements at all — either the policy "+
				"attaches none at this phase or the plan reached the coordinator ungated. "+
				"Either way there is no decision here to time", phase)
		}
	}

	return []result{
		row(mSagaStart, starts, 0, 0, ""),
		row(mPreExec, preExec, preExecGates, targetDecisionP99, "p99"),
		row(mPreRel, preRel, preRelGates, targetDecisionP99, "p99"),
		row(mEffect, effects, 0, targetGatedEffectP50, "p50"),
	}, notes, nil
}

// subject names the i-th saga and the resource it writes.
//
// The resource is chosen by the *driver slot*, not by the saga number, and that
// is the only thing keeping this benchmark measuring what it claims to. A slot
// drives one saga to a terminal state before it takes another, so two sagas in
// flight can never hold the same resource — no two slots share one. Deriving it
// from the saga number instead looks equivalent and is not: with more samples
// than resources the numbering wraps, a late saga lands on an early one's
// account, and the frontier gate correctly makes it wait. What gets measured
// then is a stall, and the run dies somewhere past the wrap point with a
// message about a gate holding a saga — which is the gate working, and the
// benchmark being wrong.
//
// The account is still drawn from the same pool the background uses, so a
// subject contends with committed history rather than with a resource nothing
// has ever touched. An index that matched nothing would report the cost of
// matching nothing.
func subject(i, slot int) wire {
	return wire{
		sagaID:   fmt.Sprintf("sg_lat_%06d", i),
		resource: fmt.Sprintf("acct:%04d", slot),
	}
}

func drive(ctx context.Context, app *evidence.Appender, dir string, k saga.Gatekeeper, w wire) error {
	c, err := saga.ResumeSaga(app, dir, w.sagaID, participant, w)
	if err != nil {
		return err
	}
	s, err := c.WithGatekeeper(k).Drive(ctx)
	if err != nil {
		return err
	}
	if s.Status != saga.StatusCommitted {
		return fmt.Errorf("saga %s ended %s, want COMMITTED", w.sagaID, s.Status)
	}
	return nil
}

func percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[percentileIndex(len(sorted), q)]
}

// percentileIndex is the one definition of what this harness means by a
// percentile, so that every number it prints means the same thing.
//
// It is the k-th of n by position rather than an interpolation, which is the
// honest reading for latency: every value reported is an observation that
// actually happened. The index is taken against n-1, so p100 is the worst
// observation and p0 the best.
//
// Shared rather than duplicated because the tail-length summary prints p50 and
// p99 beside these rows, and two percentiles on one page computed two ways is
// a difference nobody would look for. They diverge most at small n — over four
// observations the two conventions disagree about p99 by two positions — and
// the tail summary is the one with a small-n case, since it has one observation
// per decision rather than per sample.
func percentileIndex(n int, q float64) int {
	if n <= 0 {
		return 0
	}
	return int(float64(n-1) * q)
}

func ms(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1e6 }

func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func ints(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%q is not a non-negative integer", f)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no values")
	}
	return out, nil
}

func allMet(r report) bool {
	for _, x := range r.Results {
		if x.Budgeted && x.Authoritative && !x.Meets {
			return false
		}
	}
	return true
}

// authoritative names the index the run is judged on: the projection where one
// was measured, the log where it is all there is.
func authoritative(indexes []string) string {
	if slices.Contains(indexes, "projection") {
		return "projection"
	}
	return "log"
}

func printHeader(r report, o runOpts) {
	fmt.Printf("janus-latency %s — %s/%s, %d CPUs, sync=%s\n",
		r.Version, r.GOOS, r.GOARCH, r.CPUs, r.SyncMode)
	fmt.Printf("policy %s · %d samples per configuration · %d-resource pool\n",
		o.policyPath, o.samples, o.pool)
	fmt.Printf("targets: gated effect p50 <= %v, gate decision p99 <= %v\n",
		targetGatedEffectP50, targetDecisionP99)
	fmt.Printf("verdict taken over the %q index; a budget marked (fallback) is reported, not gated\n\n",
		o.judgedOn)
	fmt.Printf("%-22s %-11s %6s %5s %6s %8s %8s %9s %8s  %s\n",
		"measurement", "index", "bg", "conc", "gates", "p50 ms", "p99 ms", "p99.9 ms", "max ms", "budget")
}

func printBlocked(r result) {
	fmt.Printf("%-22s %-11s %6d %5d %6s %8s %8s %9s %8s  BLOCKED\n",
		r.Measurement, r.Index, r.Background, r.Concurrency, "—", "—", "—", "—", "—")
	fmt.Printf("    %s\n", r.Blocked)
}

func printResults(rs []result) {
	for _, r := range rs {
		budget := "—"
		if r.Budgeted {
			budget = fmt.Sprintf("%s <= %.0f ms  %s", r.Percentile, r.Target, passFail(r.Meets))
			if !r.Authoritative {
				budget += " (fallback)"
			}
		}
		gates := "—"
		if r.Gates > 0 {
			gates = strconv.Itoa(r.Gates)
		}
		fmt.Printf("%-22s %-11s %6d %5d %6s %8.2f %8.2f %9.2f %8.2f  %s\n",
			r.Measurement, r.Index, r.Background, r.Concurrency, gates,
			r.P50MS, r.P99MS, r.P999MS, r.MaxMS, budget)
	}
}

func printVerdict(r report) {
	fmt.Printf("\nverdict: %s\n", passFail(allMet(r)))
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}
