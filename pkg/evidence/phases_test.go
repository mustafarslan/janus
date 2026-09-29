package evidence_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// slowSync makes the durability barrier take a known, dominant amount of time.
//
// The point of AppendPhases is to say which of two things a caller's time in
// Append was: queueing behind somebody else's group commit, or the barrier
// itself. A real fsync is a few milliseconds and varies, which is enough to
// make a test of that split either flaky or vacuous. A barrier of a known size
// makes the two arms below differ by construction: one caller alone can only
// ever be paying the barrier, and callers arriving while one is in flight can
// only be waiting for it.
type slowSync struct {
	segment.File
	d time.Duration
}

func (s slowSync) Sync() error     { time.Sleep(s.d); return s.File.Sync() }
func (s slowSync) SyncData() error { time.Sleep(s.d); return s.File.SyncData() }

func slowLog(t *testing.T, d time.Duration) *evidence.Appender {
	t.Helper()
	a, err := evidence.Open(evidence.Options{
		Dir:      filepath.Join(t.TempDir(), "evidence"),
		Signer:   mustSigner(t),
		SyncMode: segment.SyncModeData,
		OpenFile: func(path string) (segment.File, error) {
			f, err := segment.OpenReal(path)
			if err != nil {
				return nil, err
			}
			return slowSync{File: f, d: d}, nil
		},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func appendOne(t *testing.T, a *evidence.Appender, i int) {
	t.Helper()
	if _, err := a.Append(context.Background(), evidence.Request{
		Kind:        evidence.KindStepResult,
		SagaID:      "sg_phases",
		StepID:      fmt.Sprintf("st_%04d", i),
		Participant: evidence.ParticipantRef{ID: "ag_phases"},
		Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
	}); err != nil {
		t.Errorf("append %d: %v", i, err)
	}
}

// TestAppendPhasesSeparateWaitingFromTheBarrier is the check that makes the
// numbers in docs/bench/README.md mean what they say.
//
// A serial caller cannot be queued behind anybody, so its time must land in
// Barrier; callers arriving while a barrier is in flight can only be queued, so
// theirs must land in Wait. Attributing either to the other would not change
// any total — which is exactly why an assertion on the totals would not catch
// it, and why this asserts on the split.
func TestAppendPhasesSeparateWaitingFromTheBarrier(t *testing.T) {
	t.Parallel()
	const barrier = 20 * time.Millisecond
	const appends = 5

	t.Run("serial", func(t *testing.T) {
		t.Parallel()
		a := slowLog(t, barrier)
		before := a.Phases()
		for i := range appends {
			appendOne(t, a, i)
		}
		got := delta(a.Phases(), before)

		if got.Appends != appends {
			t.Fatalf("counted %d appends, made %d", got.Appends, appends)
		}
		if mean := perAppend(got.Barrier, got.Appends); mean < barrier/2 {
			t.Errorf("mean barrier %v, want at least %v: a caller alone on the log "+
				"pays the durability barrier and nothing else", mean, barrier/2)
		}
		if mean := perAppend(got.Wait, got.Appends); mean > barrier/4 {
			t.Errorf("mean wait %v, want under %v: there is nobody to queue behind",
				mean, barrier/4)
		}
		if b := float64(got.Batch) / float64(got.Appends); b > 1.5 {
			t.Errorf("mean batch %.1f, want ~1: appends made one at a time cannot "+
				"share a group commit", b)
		}
	})

	t.Run("concurrent", func(t *testing.T) {
		t.Parallel()
		const producers = 8
		a := slowLog(t, barrier)
		// One append first, so the writer is inside a barrier when the rest
		// arrive. Without it the whole burst can be collected into the first
		// batch, and a batch nobody queued for is not the case being measured.
		appendOne(t, a, 0)
		before := a.Phases()

		var wg sync.WaitGroup
		for p := range producers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range appends {
					appendOne(t, a, p*appends+i+1)
				}
			}()
		}
		wg.Wait()
		// No settling loop, and that is the point: every append has returned, so
		// every append is counted. This test spent one commit polling for the
		// counters to catch up, because they trailed the acknowledgements.
		// They do not any more, and if that regresses this is one of
		// the two tests that says so.
		got := delta(a.Phases(), before)

		if got.Appends != producers*appends {
			t.Fatalf("counted %d appends, made %d", got.Appends, producers*appends)
		}
		if mean := perAppend(got.Wait, got.Appends); mean < barrier/4 {
			t.Errorf("mean wait %v, want at least %v: with %d producers against a "+
				"%v barrier, most arrivals find the writer busy", mean, barrier/4, producers, barrier)
		}
		if b := float64(got.Batch) / float64(got.Appends); b <= 1.5 {
			t.Errorf("mean batch %.1f, want above 1: producers queued behind a "+
				"barrier are collected into one group commit", b)
		}
	})
}

// TestAppendPhasesCountPrepApart guards the third term. Prep is the caller's
// own work before it queues, and it is in the split to be ruled out — which it
// can only do if it is measured rather than folded into the wait.
func TestAppendPhasesCountPrepApart(t *testing.T) {
	t.Parallel()
	a := slowLog(t, 5*time.Millisecond)
	before := a.Phases()
	for i := range 3 {
		appendOne(t, a, i)
	}
	got := delta(a.Phases(), before)
	if got.Prep < 0 {
		t.Fatalf("prep %v is negative: the caller's stamps are out of order", got.Prep)
	}
	if mean := perAppend(got.Prep, got.Appends); mean > time.Millisecond {
		t.Errorf("mean prep %v: marshalling and hashing a tiny payload should not "+
			"be milliseconds, so either the split is wrong or something expensive "+
			"has moved onto the caller's goroutine", mean)
	}
}

func delta(now, before evidence.AppendPhases) evidence.AppendPhases {
	return evidence.AppendPhases{
		Appends: now.Appends - before.Appends,
		Prep:    now.Prep - before.Prep,
		Wait:    now.Wait - before.Wait,
		Barrier: now.Barrier - before.Barrier,
		Batch:   now.Batch - before.Batch,
	}
}

func perAppend(d time.Duration, n uint64) time.Duration {
	if n == 0 {
		return 0
	}
	return d / time.Duration(n)
}
