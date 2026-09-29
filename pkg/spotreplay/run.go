package spotreplay

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Tally is the running count a deployment reports against.
//
// It is written down rather than derived on demand because it is the number the
// Phase 6 exit gate names — "replay sampling ≥ 99.99% deterministic" — and a
// rate that resets whenever the process restarts is not a rate, it is a mood.
type Tally struct {
	// Checked is how many saga checks have completed.
	Checked uint64 `json:"checked"`
	// Agreed is how many of those had every applicable check pass.
	Agreed uint64 `json:"agreed"`
	// Diverged names the sagas that did not, and is deliberately a list rather
	// than a count: one divergence is a thing somebody has to go and look at,
	// and a counter would say how many without saying which.
	Diverged []string `json:"diverged,omitempty"`
	// Since is when counting started, so a rate can be read against a duration.
	Since time.Time `json:"since"`
	// FromSegment is where the sampler had reached, so a restart resumes rather
	// than re-checking the whole log.
	FromSegment uint64 `json:"from_segment"`
	// Seen is the dedupe state: saga id to the sequence it was last checked at.
	Seen map[string]uint64 `json:"seen,omitempty"`
}

// Rate is the fraction of checked sagas that agreed.
//
// Zero checks is reported as zero rather than as one. A run that has checked
// nothing has not demonstrated 100% determinism; it has demonstrated nothing,
// and a gate reading 1.0 off an empty run is the exact shape of a number that
// gets quoted in a report.
func (t Tally) Rate() float64 {
	if t.Checked == 0 {
		return 0
	}
	return float64(t.Agreed) / float64(t.Checked)
}

// Runner samples an evidence directory and checks what it finds.
type Runner struct {
	sampler *Sampler
	dir     string
	state   string

	mu    sync.Mutex
	tally Tally
	// report is called for every finding, agreeing or not. A divergence is an
	// integrity alarm and the caller decides what an alarm does here; this
	// package refuses to guess, and in particular refuses to append anything to
	// the log it is checking.
	report func(Finding)
}

// Options configures a Runner.
type Options struct {
	// Dir is the evidence directory to sample. It is opened read-only and no
	// lock is taken, so this can run beside a live coordinator.
	Dir string
	// State is where the tally is checkpointed. Empty keeps it in memory, which
	// is right for a one-shot run over a finished directory and wrong for a
	// daemon.
	State string
	// Report is called for every finding.
	Report func(Finding)
}

// New returns a runner, resuming from the checkpoint if there is one.
func New(opts Options) (*Runner, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("spotreplay: an evidence directory is required")
	}
	r := &Runner{
		sampler: NewSampler(opts.Dir),
		dir:     opts.Dir,
		state:   opts.State,
		report:  opts.Report,
		tally:   Tally{Since: time.Now().UTC()},
	}
	if r.report == nil {
		r.report = func(Finding) {}
	}
	if opts.State != "" {
		if err := r.load(); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Tally returns a copy of the running count.
func (r *Runner) Tally() Tally {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.tally
	out.Diverged = append([]string(nil), r.tally.Diverged...)
	return out
}

// Once samples and checks everything outstanding, and returns how many sagas it
// checked.
//
// A saga that cannot be read is left unaccepted and will be offered again. That
// is the difference between a gap in the record and a gap in the coverage: the
// first is a finding, the second is a report that quietly describes less than it
// claims to.
func (r *Runner) Once(ctx context.Context) (int, error) {
	candidates, err := r.sampler.Next()
	if err != nil {
		return 0, err
	}
	checked := 0
	for _, c := range candidates {
		if err := ctx.Err(); err != nil {
			return checked, err
		}
		f, err := CheckSaga(r.dir, c.SagaID)
		if err != nil {
			// A saga that cannot be re-derived is a finding, not a reason to
			// stop. The first version of this returned here, which meant one
			// undecodable saga blocked every candidate sorted after it on every
			// tick, forever — coverage silently ending at the broken saga, which
			// is the exact failure this daemon exists to make impossible.
			//
			// It is accepted so that it is reported once and re-reported when it
			// moves, rather than filling the log every interval. It is counted
			// as terminal-and-not-agreed, because "we could not check this" must
			// move the rate: a denominator that quietly excludes the sagas that
			// failed to read is a rate about the sagas that happened to work.
			f = Finding{
				SagaID: c.SagaID, Terminal: true,
				Checks: []Check{{Name: CheckReadable, Detail: err.Error()}},
			}
			r.sampler.Accept(c)
			r.record(f)
			r.report(f)
			checked++
			continue
		}
		r.sampler.Accept(c)
		r.record(f)
		if !f.Deterministic() || f.Terminal {
			r.report(f)
		}
		if f.Terminal {
			checked++
		}
	}
	if checked > 0 || r.state != "" {
		if err := r.save(); err != nil {
			return checked, err
		}
	}
	return checked, nil
}

// Run samples on an interval until the context is cancelled.
func (r *Runner) Run(ctx context.Context, every time.Duration) error {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if _, err := r.Once(ctx); err != nil && ctx.Err() == nil {
				// Reported and carried on. A sampler that exited on the first
				// unreadable saga would stop checking every other saga in the
				// directory, which is the wrong trade for a detector.
				r.report(Finding{SagaID: "", Checks: []Check{{
					Name: "sample", Passed: false, Detail: err.Error(),
				}}})
			}
		}
	}
}

// record folds one finding into the tally.
//
// Only terminal sagas count towards the rate, because the gate asks about
// completed sagas and a saga still running has not finished making the claims
// the checks verify. A divergence on a *running* saga is still reported —
// reporting and counting are different things, and a history that has stopped
// replaying the same way is an alarm whether or not the saga has finished.
func (r *Runner) record(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !f.Terminal {
		return
	}
	r.tally.Checked++
	if f.Deterministic() {
		r.tally.Agreed++
		return
	}
	r.tally.Diverged = append(r.tally.Diverged, f.SagaID)
}

// save checkpoints the tally and the sampler's position.
func (r *Runner) save() error {
	if r.state == "" {
		return nil
	}
	r.mu.Lock()
	out := r.tally
	r.sampler.mu.Lock()
	out.FromSegment = r.sampler.fromSegment
	out.Seen = make(map[string]uint64, len(r.sampler.seen))
	for k, v := range r.sampler.seen {
		out.Seen[k] = v
	}
	r.sampler.mu.Unlock()
	r.mu.Unlock()

	blob, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("spotreplay: encode the checkpoint: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(r.state), 0o750); err != nil {
		return fmt.Errorf("spotreplay: checkpoint directory: %w", err)
	}
	// Written to a temporary file and renamed, so a crash part way through
	// leaves the previous checkpoint rather than a truncated one. A tally that
	// cannot be parsed would reset the gate number to zero, silently.
	tmp := r.state + ".tmp"
	if err := os.WriteFile(tmp, append(blob, '\n'), 0o640); err != nil {
		return fmt.Errorf("spotreplay: write the checkpoint: %w", err)
	}
	if err := os.Rename(tmp, r.state); err != nil {
		return fmt.Errorf("spotreplay: replace the checkpoint: %w", err)
	}
	return nil
}

func (r *Runner) load() error {
	blob, err := os.ReadFile(r.state)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("spotreplay: read the checkpoint: %w", err)
	}
	var in Tally
	if err := json.Unmarshal(blob, &in); err != nil {
		return fmt.Errorf("spotreplay: the checkpoint at %s will not parse, and starting from "+
			"zero would silently reset the determinism rate: %w", r.state, err)
	}
	r.tally = in
	if r.tally.Since.IsZero() {
		r.tally.Since = time.Now().UTC()
	}
	r.sampler.fromSegment = in.FromSegment
	if in.Seen != nil {
		r.sampler.seen = in.Seen
	}
	return nil
}
