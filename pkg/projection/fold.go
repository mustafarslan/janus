package projection

import (
	"context"
	"sync"
	"time"
)

// Sharing one fold between the readers waiting on it.
//
// `FrontierIndex` reads the log head, catches the projection up to it, then
// reads the tables. The catch-up takes the projector's lock, so concurrent gate
// decisions queued behind one another on it — and in the reference policy the
// FRONTIER requirement sits at PRE_RELEASE, decided immediately after the step's
// own result is appended, so the projection is *always* behind and every
// decision folds. There was no fast path.
//
// Measured before this: `decide_pre_release` p50 went 3.27 ms at concurrency 1
// to 22.93 ms at concurrency 8 — 7× the latency for 8× the load, which is what
// queueing on a lock looks like — and that was 23 of the 26 ms that put
// `gated_effect` over its latency budget.
//
// # What is shared, and what is not
//
// Eight readers arriving together no longer perform eight folds. One of them
// runs a fold and the rest wait on it; when it commits, everyone whose required
// sequence it reached is released together.
//
// What cannot be done is releasing a waiter the moment the fold passes *its*
// sequence. The fold is one Postgres transaction and nothing outside it can
// observe a partial one — that is the same property that makes a killed
// projector resume cleanly, and it is not worth trading. A waiter whose required
// sequence is beyond what the in-flight fold reached simply joins the next one.
//
// # Why this does not weaken the staleness contract
//
// It cannot release a waiter below the sequence it asked for: the released head
// is the sequence the fold's transaction committed, and each waiter compares
// against it individually. And it is not the last line of defence anyway —
// `Store.FrontierIndex` re-checks the head it was given inside the read and
// returns ErrStale below it, so a coalescing bug produces a refusal rather than
// a stale answer.

// FoldStats is what the folds have cost so far.
//
// A projection that is keeping up and one that is the bottleneck look the same
// from outside — both answer, both state a sequence — so the difference has to
// be counted. These are the three numbers that separate "the fold is slow" from
// "the fold is fine and everyone is queued behind it": how many folds ran, how
// many events they applied, and how long they took.
type FoldStats struct {
	Folds  uint64
	Events uint64
	Total  time.Duration
	Max    time.Duration
}

// FoldStats reports the cost of this projector's catch-ups.
func (p *Projector) FoldStats() FoldStats {
	p.fold.mu.Lock()
	defer p.fold.mu.Unlock()
	return p.fold.stats
}

// coalescer lets concurrent callers share one catch-up.
type coalescer struct {
	stats FoldStats

	mu sync.Mutex
	// inFlight is closed when the running fold finishes. Nil when none is.
	inFlight chan struct{}
	// head is the sequence the last completed fold reached.
	head uint64
}

// catchUpTo brings the projection to at least want, sharing a fold in progress
// rather than queueing behind it.
//
// It returns the sequence actually reached, which may be short of want when the
// log has not been folded that far and folding again makes no progress. The
// caller's read is what refuses in that case, and refusing is its job.
func (p *Projector) catchUpTo(ctx context.Context, want uint64) (uint64, error) {
	return p.fold.to(ctx, want, p.CatchUp)
}

// to is catchUpTo's logic with the fold passed in.
//
// Separated so it can be tested against a fold that does nothing but count and
// block. What needs testing here is the sharing and the release condition, not
// Postgres, and a test that had to stand up a database to check that eight
// callers cause fewer than eight folds would be testing the wrong thing.
func (c *coalescer) to(ctx context.Context, want uint64,
	fold func(context.Context) (uint64, error)) (uint64, error) {

	for {
		c.mu.Lock()
		if c.head >= want {
			at := c.head
			c.mu.Unlock()
			return at, nil
		}
		if wait := c.inFlight; wait != nil {
			c.mu.Unlock()
			select {
			case <-wait:
				// Re-check rather than assume: that fold may or may not have
				// reached far enough for this caller.
				continue
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		}

		// Nobody is folding, so this caller does it for everybody.
		before := c.head
		done := make(chan struct{})
		c.inFlight = done
		c.mu.Unlock()

		t0 := time.Now()
		at, err := fold(ctx)
		took := time.Since(t0)

		c.mu.Lock()
		c.stats.Folds++
		c.stats.Total += took
		if took > c.stats.Max {
			c.stats.Max = took
		}
		if err == nil && at > c.head {
			c.stats.Events += at - c.head
			c.head = at
		}
		c.inFlight = nil
		c.mu.Unlock()
		// Released after the head is recorded, so a waiter that wakes
		// immediately sees the result of the fold it was waiting for rather
		// than the state before it.
		close(done)

		if err != nil {
			// Not shared with the waiters. They loop, and whichever becomes the
			// next leader gets its own answer — an error laundered through a
			// coalescer would be reported for a fold the caller never made.
			return 0, err
		}
		if at >= want {
			return at, nil
		}
		if at <= before {
			// A fold that advanced nothing will not advance on the next
			// attempt either. Returning short lets the read refuse, which is
			// the honest answer and is what the staleness contract asks for.
			return at, nil
		}
	}
}

// NoteFolded records a catch-up performed outside catchUpTo — the daemon's
// ticker — so a decision arriving afterwards can find the projection already
// far enough along and skip folding entirely.
func (p *Projector) NoteFolded(at uint64) {
	p.fold.mu.Lock()
	defer p.fold.mu.Unlock()
	if at > p.fold.head {
		p.fold.head = at
	}
}

// FoldedThrough reports the sequence the projection has been folded to — the
// last completed fold's, or the daemon ticker's if that ran later, since
// NoteFolded advances the same head.
//
// It exists to be subtracted from the log's head, which gives the length of the
// *tail* a decision arriving now would have to account for itself if it did not
// wait for a fold. That is the quantity one proposed fix
// turns on — "the frontier decision stops waiting for a whole fold" — and it
// had never been measured, only inferred from fold duration.
//
// Read-only, and deliberately not used to decide anything: a caller that acted
// on it would be reading a projection head without the ErrStale check that
// makes a stale answer a refusal.
func (p *Projector) FoldedThrough() uint64 {
	p.fold.mu.Lock()
	defer p.fold.mu.Unlock()
	return p.fold.head
}

// FoldInFlight reports whether a catch-up is already running, so a background
// ticker can skip its tick instead of queueing behind a decision that is
// already doing the work.
func (p *Projector) FoldInFlight() bool {
	p.fold.mu.Lock()
	defer p.fold.mu.Unlock()
	return p.fold.inFlight != nil
}

// FoldPhases is where a fold's time goes, and how much of its reading was
// wasted.
//
// "The fold is slow" is not actionable; "the fold spends a third of its time
// re-decoding records it already folded" is. Scanned and Kept are the pair that
// exposed that: `Projector.read` used to resume at a whole segment, so every
// pass re-framed and re-decoded everything written to the open segment since it
// was created and discarded all but the tail. Resuming by offset fixed it, and
// the pair stayed so a regression would show.
//
// # Why the other three exist
//
// Once reading was fixed it stopped being the story. At the reference scale —
// concurrency 64 against 2,000 background sagas — reading is about a fifth of a
// fold, and the other four fifths were a single unattributed lump. That lump is
// the largest undecomposed term in the only budget Janus is marginal against
// (S4's 25 ms gated effect), so "what should be optimised next" was not a
// question anyone could answer with a number.
//
// The three are the fold's three actual stages, and they are chosen so that
// which one dominates points at a *different* kind of fix:
//
//   - Read is framing, header decode, payload hashing and chain recomputation.
//     It is CPU on bytes, and it amortises with fold size.
//   - Apply is the state machines — `saga.Apply`, `outbox.Apply`, the recovery
//     read for a saga the working set no longer holds. Go code; the fix shape
//     is Go.
//   - Commit is everything from `Begin` to `Commit`: the batched row writes,
//     the registry refold when there is one, the head update. The fix shape is
//     Postgres-side, and would be a database decision with its own cost.
//
// Commit is split again, because "the database is 64% of the fold" still does
// not choose a fix and the two halves choose opposite ones. CommitWrite is
// `Begin` through the head update — statements, round trips, the registry
// refold — and a fix there is fewer or cheaper statements, the shape that
// already won 3× when `writeSaga` stopped issuing one `Exec` per row.
// CommitSync is `tx.Commit` alone, the durability barrier, and a fix there is
// a durability decision: `synchronous_commit`, or an unlogged table for
// something that is rebuildable from the log anyway. The first is engineering; the
// second trades a guarantee, and this project does not trade one without
// writing down what it bought.
//
// Total is measured around all three together, so Total − (Read+Apply+Commit)
// is a residual: anything the fold does that nobody has attributed shows up as
// a number rather than as absence. A decomposition whose parts silently do not
// sum is how a measurement lies.
type FoldPhases struct {
	Read   time.Duration
	Apply  time.Duration
	Commit time.Duration
	// CommitWrite and CommitSync partition Commit: statements against the
	// durability barrier. They sum to Commit by construction.
	CommitWrite time.Duration
	CommitSync  time.Duration
	Total       time.Duration
	// Statements counts the SQL statements the commit half issued — every entry
	// in the batch, plus the registry writes and the head update.
	//
	// It is here because "statements are 95% of the commit" still does not
	// choose between batching harder and writing less, and the per-statement
	// cost does: a few microseconds each means the count is the problem, and a
	// millisecond each means the statements are.
	Statements uint64
	// StmtSaga, StmtClear, StmtStep and StmtTouch are the four families the
	// commit half issues, per saga a fold touched: one upsert of the saga row,
	// two DELETEs clearing its steps and touches, then one insert per step and
	// one per touch.
	//
	// They are counted separately because the earlier hot/cold experiment
	// removed exactly one family — the step rows — and moved S4 by about 3 ms
	// without closing the gap. Read as "removing a family is not enough" that is
	// a prior against the structural fix; read against these counts it may be
	// close to the linear prediction, in which case it is no prior at all. The
	// split is what tells the two readings apart.
	StmtSaga  uint64
	StmtClear uint64
	StmtStep  uint64
	StmtTouch uint64
	Scanned   uint64
	Kept      uint64
}

// Residual is the part of a fold that none of the three stages accounts for.
//
// It is reported rather than hidden because the alternative — presenting
// Read+Apply+Commit as if it were the whole fold — would make every future
// addition to the fold invisible to the measurement that is supposed to be
// deciding what to work on. A residual that starts growing is the finding.
//
// One case is expected rather than a finding: a fold that fails partway adds
// its whole elapsed time to Total and adds nothing to the stage it died in, so
// a Postgres hiccup shows up here. A residual that jumps alongside fold errors
// is that, not untimed work somebody should go looking for.
func (f FoldPhases) Residual() time.Duration {
	r := f.Total - f.Read - f.Apply - f.Commit
	if r < 0 {
		return 0
	}
	return r
}

// FoldPhases reports where this projector's fold time has gone.
func (p *Projector) FoldPhases() FoldPhases {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.phase
}
