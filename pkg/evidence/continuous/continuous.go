// Package continuous re-verifies the evidence log in the background, so that
// tampering is found by Janus rather than by an auditor.
//
// A hash chain makes tampering detectable, but only to whoever runs the check.
// If the only time anything verifies the log is during an audit, then an insider
// who edits it has however long until the next audit to also fix the
// consequences — and the finding, when it comes, is at the worst possible
// moment. Janus therefore requires continuous verification with an alert on
// divergence.
//
// # Two passes, because one cannot do the job
//
// Verifying everything on every cycle is quadratic against a growing log and
// stops being possible within hours. Verifying only what is new is cheap but
// blind: an insider editing a month-old segment would never be looked at again.
//
// So there are two passes with different jobs.
//
// The incremental pass reads only the segments written since the last
// checkpoint and confirms they continue the chain. It runs often — seconds —
// and its cost does not grow with the size of the log.
//
// The rolling sweep re-reads old segments a slice at a time, so that a complete
// pass over the whole log finishes within a stated period. It is what actually
// catches tampering with history, and its detection latency is that period, not
// the incremental interval. This package reports both figures rather than
// quoting the flattering one.
package continuous

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// Checkpoint records how far the incremental pass has verified.
//
// It is an optimisation and is treated as one: an attacker who can edit the log
// can edit the checkpoint too, and moving it forward would skip verification of
// everything behind it. That is why the rolling sweep re-verifies regardless of
// what the checkpoint says. Nothing here trusts it for correctness, only for
// where to resume.
type Checkpoint struct {
	// NextSegment is the first segment the incremental pass has not verified.
	NextSegment uint64 `json:"next_segment"`
	// Chain and Seq are the position the previous segment ended on.
	Chain string    `json:"chain"`
	Seq   uint64    `json:"seq"`
	At    time.Time `json:"at"`
	// TrustedKeys is the writer-key set the last verified range ended with: the
	// configured roots plus whatever the log introduced and did not revoke.
	//
	// It is in the checkpoint because the checkpoint is what makes a restart
	// resume mid-log, and a pass that resumes mid-log cannot see the WRITER_KEY
	// declaration that introduced the key now signing. Without it a restart
	// after a rotation reports UNKNOWN_SIGNING_KEY on every segment from the
	// rotation on, and — because the pass never returns OK — stops advancing
	// the checkpoint at all, so the log quietly stops being verified while an
	// alert says it cannot be. The cost: whoever can write the checkpoint file
	// can now introduce a signer, not only hide a fork.
	TrustedKeys keys.PublicKeySet `json:"trusted_keys,omitempty"`
}

// Status is a snapshot of what the verifier knows.
type Status struct {
	// Healthy is false as soon as any pass has found a critical finding, and
	// stays false: a log that was tampered with does not become untampered.
	Healthy bool `json:"healthy"`
	// LastIncremental and LastSweepCompleted say how current each guarantee is.
	LastIncremental      time.Time        `json:"last_incremental"`
	LastSweepCompleted   time.Time        `json:"last_sweep_completed"`
	SweepProgressSegment uint64           `json:"sweep_progress_segment"`
	SegmentsKnown        int              `json:"segments_known"`
	EventsVerified       uint64           `json:"events_verified"`
	IncrementalRuns      uint64           `json:"incremental_runs"`
	SweepsCompleted      uint64           `json:"sweeps_completed"`
	Findings             []verify.Finding `json:"findings,omitempty"`
	// HistoryCheckedWithin is how stale the guarantee about *old* records can
	// be: one full sweep period. Stating it stops the incremental interval from
	// being mistaken for the detection latency.
	HistoryCheckedWithin time.Duration `json:"history_checked_within"`
}

// Config configures a Verifier.
type Config struct {
	// Dir is the evidence directory.
	Dir string
	// Keys are the trusted writer keys.
	Keys keys.PublicKeySet
	// CheckpointPath persists incremental progress across restarts. Optional;
	// without it every start re-reads from the beginning once.
	CheckpointPath string

	// IncrementalInterval is how often new segments are checked.
	// Defaults to 10 seconds.
	IncrementalInterval time.Duration
	// SweepInterval is the period within which a full pass over the log
	// completes, and therefore the detection latency for tampering with
	// history. Defaults to one hour.
	SweepInterval time.Duration
	// SweepTick is how often a slice of the sweep runs. Defaults to 30 seconds.
	SweepTick time.Duration

	// OnFinding is called for every critical or warning finding. This is the
	// alert path; divergence must be alerted within 60 seconds, and
	// this fires as soon as the finding is made.
	OnFinding func(verify.Finding)
	// OnStatus is called after each pass with the current status.
	OnStatus func(Status)
}

// Verifier re-verifies a log in the background.
type Verifier struct {
	cfg Config

	mu         sync.RWMutex
	checkpoint Checkpoint
	status     Status
	// sweepCursor is where the rolling sweep will resume.
	sweepCursor uint64
	sweepAnchor verify.Anchor
	// sweepTrust is the trust set the sweep's last slice ended with. The
	// rolling sweep re-reads the whole log, so this resets to the roots at the
	// start of every pass rather than persisting.
	sweepTrust keys.PublicKeySet
	// scan lists the log's complete segments without re-stat-ing every file.
	// This verifier lists the directory three times a round — the incremental
	// pass, the sweep's slice, and the Range inside each — and at 10,000
	// segments the stats are 17 of the 21.5 ms each listing costs.
	scan *segment.Scanner
	// sweepTarget is the last segment of the pass in progress: the end of the
	// log as it stood when that pass began. Zero means no pass is in progress.
	//
	// A pass needs a fixed end or it never has one. Without this the slice ran to
	// whatever the end of the log happened to be at each step, so on a log that
	// is still being written the cursor caught the tail and then followed it —
	// re-reading only the newest segments, which the incremental pass already
	// covers, never returning to segment 1, and never completing. Nothing
	// reported an error; the log simply stopped having its history checked while
	// Status went on quoting a sweep interval as the detection latency.
	sweepTarget uint64
}

// New builds a verifier.
func New(cfg Config) (*Verifier, error) {
	if cfg.Dir == "" {
		return nil, errors.New("continuous: Dir is required")
	}
	if len(cfg.Keys) == 0 {
		return nil, errors.New("continuous: a trusted key set is required, " +
			"or the verifier would only be checking the log against itself")
	}
	if cfg.IncrementalInterval <= 0 {
		cfg.IncrementalInterval = 10 * time.Second
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = time.Hour
	}
	if cfg.SweepTick <= 0 {
		cfg.SweepTick = 30 * time.Second
	}

	v := &Verifier{cfg: cfg, scan: segment.NewScanner(cfg.Dir)}
	v.status.Healthy = true
	v.status.HistoryCheckedWithin = cfg.SweepInterval
	v.sweepAnchor = verify.Anchor{Chain: evidence.GenesisHash, Known: true}

	if cfg.CheckpointPath != "" {
		if err := v.loadCheckpoint(); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// Status returns a snapshot.
func (v *Verifier) Status() Status {
	v.mu.RLock()
	defer v.mu.RUnlock()
	s := v.status
	s.Findings = append([]verify.Finding(nil), v.status.Findings...)
	return s
}

// Checkpoint returns the current incremental position.
func (v *Verifier) Checkpoint() Checkpoint {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.checkpoint
}

// Incremental verifies segments written since the checkpoint.
//
// It is not safe to call concurrently with Run or with itself: the checkpoint
// is read, used, and written across separate critical sections, so two
// overlapping passes can let the slower one's result overwrite the faster
// one's. The consequence is only wasted re-verification, but the contract is
// worth stating.
func (v *Verifier) Incremental(ctx context.Context) (*verify.Report, error) {
	v.mu.RLock()
	cp := v.checkpoint
	v.mu.RUnlock()

	anchor := verify.Anchor{Chain: evidence.GenesisHash, Known: true}
	if cp.Seq > 0 {
		h, err := parseChain(cp.Chain)
		if err != nil {
			return nil, fmt.Errorf("continuous: checkpoint is unreadable: %w", err)
		}
		anchor = verify.Anchor{Chain: h, Seq: cp.Seq, Known: true}
	}

	// The set the last verified range ended with, not the configured roots: a
	// pass that starts mid-log is past the declaration that introduced whatever
	// key is signing now. It *replaces* the roots rather than joining
	// them, so a revoked root stays revoked.
	rep, err := verify.Range(v.cfg.Dir, cp.NextSegment, 0, anchor, v.verifyOptions(cp.TrustedKeys))
	if err != nil {
		return nil, err
	}
	v.record(rep, false)

	// Advance only over segments that are sealed and clean. An open tail will
	// be re-read next time, which is correct: it is still growing.
	if rep.OK {
		v.advance(rep)
	}
	return rep, nil
}

// advance moves the checkpoint past every sealed segment the report covered.
func (v *Verifier) advance(rep *verify.Report) {
	v.mu.Lock()
	defer v.mu.Unlock()
	// Anchor on the last clean sealed segment's own tail hash. Using the
	// report's head would be wrong whenever an open segment follows, because
	// the head includes events that are not yet covered by the checkpoint —
	// and a mismatched (chain, seq) pair makes the next run report a chain
	// break that is not there.
	for _, s := range rep.Segments {
		if !s.Sealed || !s.ChainOK || s.LastChain == "" {
			break
		}
		v.checkpoint.NextSegment = s.SegmentID + 1
		v.checkpoint.Seq = s.LastSeq
		v.checkpoint.Chain = s.LastChain
	}
	// Carried at the same point the cursor advances, and gated by the same
	// caller check on rep.OK: a range that did not verify may hold a
	// declaration this verifier has not earned the right to trust.
	//
	// The loop above stops at the first segment that is not sealed and clean,
	// while this set is the one at the end of the whole range — which cannot
	// put trust ahead of the cursor, because a declaration is applied only from
	// a segment whose own footer and chain checked out, and an unsealed tail
	// has no footer to check.
	if rep.TrustedKeys != nil {
		v.checkpoint.TrustedKeys = rep.TrustedKeys
	}
	v.checkpoint.At = time.Now().UTC()
	if v.cfg.CheckpointPath != "" {
		_ = v.saveCheckpoint()
	}
}

// SweepStep verifies the next slice of the rolling full sweep and reports
// whether the sweep completed on this call.
//
// Like Incremental, it is not safe to call concurrently with Run or with
// itself.
func (v *Verifier) SweepStep(ctx context.Context, segments int) (*verify.Report, bool, error) {
	if segments <= 0 {
		segments = 1
	}
	ids, err := v.scan.Complete()
	if err != nil {
		return nil, false, err
	}
	if len(ids) == 0 {
		return nil, false, nil
	}

	v.mu.Lock()
	if v.sweepTarget == 0 {
		// Starting a pass: fix its end at the log as it stands now. Segments
		// written after this point belong to the next pass, and the incremental
		// check covers them in the meantime.
		v.sweepTarget = ids[len(ids)-1]
	}
	cursor, anchor, target := v.sweepCursor, v.sweepAnchor, v.sweepTarget
	sweepTrust := v.sweepTrust
	v.mu.Unlock()

	// Find where to resume, and pick the last segment of this slice.
	var slice []uint64
	for _, id := range ids {
		if id < cursor {
			continue
		}
		if id > target {
			break
		}
		slice = append(slice, id)
		if len(slice) == segments {
			break
		}
	}
	if len(slice) == 0 {
		// Past the target: the pass is done, and the next call starts a fresh one
		// whose target picks up everything written while this one ran.
		v.mu.Lock()
		v.sweepCursor = 0
		v.sweepTarget = 0
		v.sweepAnchor = verify.Anchor{Chain: evidence.GenesisHash, Known: true}
		v.sweepTrust = nil
		v.status.SweepsCompleted++
		v.status.LastSweepCompleted = time.Now().UTC()
		v.status.SweepProgressSegment = 0
		v.mu.Unlock()
		if v.cfg.OnStatus != nil {
			v.cfg.OnStatus(v.Status())
		}
		return nil, true, nil
	}

	last := slice[len(slice)-1]
	rep, err := verify.Range(v.cfg.Dir, cursor, last, anchor, v.verifyOptions(sweepTrust))
	if err != nil {
		return nil, false, err
	}
	v.record(rep, true)

	// Carry the slice's tail forward as the next slice's anchor, so the sweep
	// checks continuity across its own boundaries rather than treating each
	// slice as an island.
	newAnchor := anchor
	for _, s := range rep.Segments {
		if !s.Sealed || !s.ChainOK || s.LastChain == "" {
			continue
		}
		if h, perr := parseChain(s.LastChain); perr == nil {
			newAnchor = verify.Anchor{Chain: h, Seq: s.LastSeq, Known: true}
		}
	}

	v.mu.Lock()
	v.sweepCursor = last + 1
	v.sweepAnchor = newAnchor
	// Carried across slice boundaries for the same reason the anchor is: a
	// slice boundary that lands after a rotation would otherwise report the
	// rotated key as unknown. Reset to the roots when the pass restarts below,
	// because that pass reads the declarations again.
	if rep.OK && rep.TrustedKeys != nil {
		v.sweepTrust = rep.TrustedKeys
	}
	v.status.SweepProgressSegment = last
	v.mu.Unlock()

	return rep, false, nil
}

// record folds a report's findings into the status and fires alerts.
func (v *Verifier) record(rep *verify.Report, sweep bool) {
	v.mu.Lock()
	if !rep.OK {
		v.status.Healthy = false
	}
	for _, f := range rep.Findings {
		if f.Severity == verify.Note {
			continue
		}
		v.status.Findings = append(v.status.Findings, f)
	}
	// Keep the list bounded; the alert already fired, and an unbounded slice
	// on a long-running service is its own outage.
	if len(v.status.Findings) > 256 {
		v.status.Findings = v.status.Findings[len(v.status.Findings)-256:]
	}
	v.status.EventsVerified += uint64(rep.Events)
	if !sweep {
		// Only the incremental pass sees the whole tail, so only it can say how
		// many segments there are. A sweep slice covers a handful, and letting
		// it write this field made the reported figure oscillate between the
		// two and mean nothing.
		v.status.SegmentsKnown = len(rep.Segments)
		v.status.IncrementalRuns++
		v.status.LastIncremental = time.Now().UTC()
	}
	alerts := make([]verify.Finding, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		if f.Severity != verify.Note {
			alerts = append(alerts, f)
		}
	}
	v.mu.Unlock()

	if v.cfg.OnFinding != nil {
		for _, f := range alerts {
			v.cfg.OnFinding(f)
		}
	}
	if v.cfg.OnStatus != nil {
		v.cfg.OnStatus(v.Status())
	}
}

func (v *Verifier) verifyOptions(roots keys.PublicKeySet) verify.Options {
	origin := ""
	if len(roots) == 0 {
		roots = v.cfg.Keys
	} else {
		origin = "carried from an earlier pass"
	}
	return verify.Options{
		Keys:              roots,
		KeysOrigin:        origin,
		AllowUnsealedTail: true,
		Version:           "continuous",
		Scan:              func(string) ([]uint64, error) { return v.scan.Complete() },
	}
}

// Run verifies until the context is cancelled.
func (v *Verifier) Run(ctx context.Context) error {
	// Size each sweep slice so a full pass fits inside SweepInterval at the
	// configured tick rate. Recomputed each cycle because the log grows.
	incTicker := time.NewTicker(v.cfg.IncrementalInterval)
	defer incTicker.Stop()
	sweepTicker := time.NewTicker(v.cfg.SweepTick)
	defer sweepTicker.Stop()

	if _, err := v.Incremental(ctx); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-incTicker.C:
			if _, err := v.Incremental(ctx); err != nil {
				return err
			}
		case <-sweepTicker.C:
			if _, _, err := v.SweepStep(ctx, v.sliceSize()); err != nil {
				return err
			}
		}
	}
}

// sliceSize picks how many segments a sweep tick should cover so that a whole
// pass finishes within SweepInterval.
func (v *Verifier) sliceSize() int {
	ids, err := v.scan.Complete()
	if err != nil || len(ids) == 0 {
		return 1
	}
	ticksPerSweep := int(v.cfg.SweepInterval / v.cfg.SweepTick)
	if ticksPerSweep < 1 {
		ticksPerSweep = 1
	}
	size := len(ids) / ticksPerSweep
	if size < 1 {
		size = 1
	}
	return size
}

func (v *Verifier) loadCheckpoint() error {
	blob, err := os.ReadFile(v.cfg.CheckpointPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var cp Checkpoint
	if err := json.Unmarshal(blob, &cp); err != nil {
		// A damaged checkpoint is not fatal: re-verifying from the start is
		// slower but correct, and refusing to start would turn a corrupt cache
		// into an outage of the thing that watches for corruption.
		return nil
	}
	v.checkpoint = cp
	return nil
}

func (v *Verifier) saveCheckpoint() error {
	if err := os.MkdirAll(filepath.Dir(v.cfg.CheckpointPath), 0o750); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(v.checkpoint, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(v.cfg.CheckpointPath, append(blob, '\n'), 0o640)
}

// parseChain converts a "blake3:<hex>" head into a hash.
func parseChain(s string) (evidence.Hash, error) {
	var h evidence.Hash
	const prefix = "blake3:"
	if len(s) != len(prefix)+2*evidence.HashSize || s[:len(prefix)] != prefix {
		return h, fmt.Errorf("continuous: %q is not a chain hash", s)
	}
	for i := range evidence.HashSize {
		var b byte
		if _, err := fmt.Sscanf(s[len(prefix)+2*i:len(prefix)+2*i+2], "%02x", &b); err != nil {
			return h, err
		}
		h[i] = b
	}
	return h, nil
}
