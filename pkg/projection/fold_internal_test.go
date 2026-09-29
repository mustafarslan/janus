package projection

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Eight readers arriving together cause one fold, not eight.
//
// This is the whole of the fix: before it, `decide_pre_release` p50 went from
// 3.27 ms at concurrency 1 to 22.93 ms at concurrency 8 because each decision
// queued behind the previous one's catch-up. The number that has to change is
// the count of folds, so that is what this asserts.
func TestConcurrentReadersShareOneFold(t *testing.T) {
	var c coalescer
	var folds atomic.Int64

	// A fold that is slow enough for everybody to arrive during it, and that
	// reaches sequence 100 in one go.
	fold := func(context.Context) (uint64, error) {
		folds.Add(1)
		time.Sleep(50 * time.Millisecond)
		return 100, nil
	}

	const readers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	got := make([]uint64, readers)
	errs := make([]error, readers)
	for i := range readers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			got[i], errs[i] = c.to(context.Background(), 50, fold)
		}(i)
	}
	close(start)
	wg.Wait()

	for i := range readers {
		if errs[i] != nil {
			t.Fatalf("reader %d: %v", i, errs[i])
		}
		if got[i] < 50 {
			t.Fatalf("reader %d was released at sequence %d, below the %d it required",
				i, got[i], 50)
		}
	}
	if n := folds.Load(); n >= readers {
		t.Fatalf("%d readers caused %d folds, so nothing was shared", readers, n)
	}
	if n := folds.Load(); n != 1 {
		t.Logf("note: %d folds for %d readers (1 expected, more is still a pass)", n, readers)
	}
}

// A reader is never released below the sequence it asked for.
//
// This is the property the coalescing must not break, and it is the one that
// matters: `FrontierIndex` uses the result to decide whether a saga may commit
// over another's unsettled work, and answering from a projection that has not
// reached the caller's sequence is exactly the stale read the staleness
// contract exists to refuse.
func TestAWaiterIsNeverReleasedBelowWhatItAsked(t *testing.T) {
	var c coalescer
	var round atomic.Int64

	// Each fold advances by 10. A reader wanting 25 must wait for three of
	// them, and must not be released by the first two.
	fold := func(context.Context) (uint64, error) {
		return uint64(round.Add(1) * 10), nil
	}

	const readers = 6
	var wg sync.WaitGroup
	for i := range readers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			want := uint64(5 + i*5) // 5, 10, 15, 20, 25, 30
			at, err := c.to(context.Background(), want, fold)
			if err != nil {
				t.Errorf("reader wanting %d: %v", want, err)
				return
			}
			if at < want {
				t.Errorf("a reader wanting sequence %d was released at %d", want, at)
			}
		}(i)
	}
	wg.Wait()
}

// A fold that advances nothing returns short rather than spinning.
//
// The caller's read is what refuses in that case, which is the honest division:
// the coalescer's job is to reach a sequence if reaching it is possible, and
// `Store.FrontierIndex` decides what to do when it is not.
func TestAFoldThatMakesNoProgressReturnsRatherThanSpinning(t *testing.T) {
	var c coalescer
	var folds atomic.Int64

	fold := func(context.Context) (uint64, error) {
		folds.Add(1)
		return 7, nil // never reaches the 99 asked for
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		at, err := c.to(context.Background(), 99, fold)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if at != 7 {
			t.Errorf("returned sequence %d, want the 7 the fold actually reached", at)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("catching up to a sequence the log cannot reach did not return")
	}
	if n := folds.Load(); n > 2 {
		t.Fatalf("a fold that makes no progress ran %d times", n)
	}
}

// A fold's error is reported to the caller that ran it, and not laundered
// through the coalescer to callers that did not.
func TestAFoldErrorIsNotSharedWithWaiters(t *testing.T) {
	var c coalescer
	boom := errors.New("the database went away")
	var folds atomic.Int64

	fold := func(context.Context) (uint64, error) {
		if folds.Add(1) == 1 {
			time.Sleep(30 * time.Millisecond)
			return 0, boom
		}
		return 100, nil
	}

	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = c.to(context.Background(), 50, fold)
		}(i)
	}
	wg.Wait()

	var failed, ok int
	for _, err := range results {
		if err != nil {
			failed++
		} else {
			ok++
		}
	}
	if failed != 1 || ok != 1 {
		t.Fatalf("one caller should have seen the error and the other should have "+
			"retried and succeeded; got %d failed and %d ok", failed, ok)
	}
}
