package projection_test

import (
	"testing"

	"github.com/mustafarslan/janus/pkg/projection"
)

// TestTheFoldsPartsAreCheckedAgainstTheWhole.
//
// `FoldPhases` reported `Read` and nothing else, so four fifths of a fold were
// one unattributed lump — the largest undecomposed term in the only budget this
// project is marginal against. The split that replaced it is only worth
// anything if it stays honest, and there are exactly two ways for it to stop
// being honest: a stage that stops accumulating, and a stage added later that
// nobody times.
//
// Both show up as the same thing, which is why `Total` is measured around the
// whole fold rather than around the three stages. Parts that sum to 100% of a
// number smaller than what a caller waits for are arithmetically tidy and
// operationally wrong.
func TestTheFoldsPartsAreCheckedAgainstTheWhole(t *testing.T) {
	store, ctx := newStore(t)
	dir, _ := contendingLog(t)

	proj := projection.NewProjector(store, dir)
	at, err := proj.CatchUp(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if at == 0 {
		t.Fatal("the fold advanced nothing, so there is no time to attribute")
	}
	ph := proj.FoldPhases()

	if ph.Total == 0 {
		t.Fatal("the fold reports no total: nothing can be checked against it")
	}
	for name, d := range map[string]int64{
		"read": int64(ph.Read), "apply": int64(ph.Apply), "commit": int64(ph.Commit),
	} {
		if d == 0 {
			t.Errorf("%s is zero after a fold that advanced to %d: a stage that stops "+
				"accumulating reads as a stage that costs nothing", name, at)
		}
	}
	if sum := ph.Read + ph.Apply + ph.Commit; sum > ph.Total {
		t.Errorf("the stages sum to %s, more than the whole fold (%s): they are being "+
			"double-counted or Total is not measured around all of them", sum, ph.Total)
	}
	if ph.Residual() > ph.Total {
		t.Errorf("residual %s exceeds the fold %s", ph.Residual(), ph.Total)
	}
	// Strictly positive, and this is the assertion the whole design rests on.
	// A fold does more than the three stages — the head query, the log binding,
	// `loadRegistryEvents`, `warm` — and if `Total` were derived from the stages
	// rather than measured around the fold, the parts would sum to exactly the
	// whole and every future addition to the fold would be invisible to the
	// measurement that is supposed to decide what to work on. Zero here means
	// the decomposition has stopped being able to report its own blind spot.
	if ph.Residual() == 0 {
		t.Errorf("the residual is zero: Total (%s) is the sum of the stages rather than a "+
			"measurement of the fold, so untimed work would not show up at all", ph.Total)
	}

	// The commit halves partition the commit, so they must sum to it exactly.
	// They are what refuted trading a durability guarantee — the barrier is
	// under 3% of a fold — and a split that did not add up would have refuted it
	// on arithmetic rather than on measurement.
	if got := ph.CommitWrite + ph.CommitSync; got != ph.Commit {
		t.Errorf("statements (%s) + barrier (%s) = %s, but commit is %s: the halves do not "+
			"partition the whole", ph.CommitWrite, ph.CommitSync, got, ph.Commit)
	}
	if ph.CommitSync == 0 {
		t.Error("the durability barrier is reported as free, which is the claim this " +
			"measurement exists to check rather than to assume")
	}

	// The statement count is what said "already batched, nothing left to group".
	// A zero would make ~15 µs per statement read as free.
	if ph.Statements == 0 {
		t.Error("no statements counted for a fold that wrote rows")
	}
	if ph.Kept == 0 {
		t.Error("no events kept, so this fold folded nothing and proves nothing")
	}
}
