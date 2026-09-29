package console_test

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/mustafarslan/janus/pkg/console"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// logOf writes n ordinary step results and returns the directory.
func logOf(t *testing.T, n int) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if _, err := app.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: fmt.Sprintf("sg_%d", i/4),
			StepID: fmt.Sprintf("st_%d", i), Participant: evidence.ParticipantRef{ID: "ag"},
			Payload: []byte(`{"x":1}`),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A search no longer builds a summary for every event in the log.
//
// Item 19 says the console's evidence search runs the verifier over the whole
// log and calls that "a multi-second operation" on a few hundred thousand
// events. Underneath the wall time was a shape: `IncludeEvents` built an
// `EventSummary` for every record and returned the slice, so the filter ran
// over a materialised copy of the log. Measured below, that copy is about 285
// bytes per event — 5.7 MiB at 20,000 events and 27.9 MiB at 100,000 — to
// return 200 rows.
//
// The filter runs inside the walk now. What this asserts is exactly what
// changed and no more: the summaries do not survive the walk. **The search's
// peak memory is still not flat** — the verifier reads segment files and
// accumulates a Merkle leaf per record, and that is remaining
// work rather than something this closed.
func TestASearchDoesNotBuildASummaryForEveryEvent(t *testing.T) {
	const events = 20_000
	dir := logOf(t, events)

	held := func(opts verify.Options) (uint64, int) {
		opts.AllowUnsealedTail = true
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		rep, err := verify.SegmentDir(dir, opts)
		if err != nil {
			t.Fatal(err)
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		n := len(rep.EventList)
		// Kept alive across the measurement, or what is being measured is
		// collected before it is read.
		runtime.KeepAlive(rep)
		if after.HeapAlloc < before.HeapAlloc {
			return 0, n
		}
		return after.HeapAlloc - before.HeapAlloc, n
	}

	list, listed := held(verify.Options{IncludeEvents: true})
	var seen int
	streamed, alsoListed := held(verify.Options{
		IncludeEvents: true, // ignored: the callback wins
		OnEvent:       func(verify.EventSummary) { seen++ },
	})
	t.Logf("%d events: the list holds %d KiB, the callback %d KiB", events, list/1024, streamed/1024)

	if listed != events {
		t.Fatalf("IncludeEvents returned %d summaries for %d events", listed, events)
	}
	if seen != events {
		t.Fatalf("the callback saw %d event(s) of %d: a caller that filters during the walk "+
			"must be offered every record the list would have carried", seen, events)
	}
	if alsoListed != 0 {
		t.Fatalf("the report carried %d summaries as well as calling back: a caller asking "+
			"for both gets the allocation the callback exists to avoid", alsoListed)
	}
	if streamed*4 > list {
		t.Fatalf("the callback walk holds %d KiB against the list's %d KiB — the summaries "+
			"are still surviving the walk, which is the whole change", streamed/1024, list/1024)
	}
}

// And it still answers the same thing.
//
// The filter used to run over a materialised list; it runs inside the walk now.
// A search that became cheap by reading less would be a different page — the
// point of this one is that it is a statement about the whole log.
func TestASearchStillReadsTheWholeLog(t *testing.T) {
	dir := logOf(t, 5_000)
	res, err := console.Open(dir).Search(console.Filter{Kind: "STEP_RESULT", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanned != 5_000 {
		t.Fatalf("the search scanned %d event(s) of 5,000: a cheaper search that reads less "+
			"of the log is not this search", res.Scanned)
	}
	if res.Matched != 5_000 {
		t.Fatalf("%d event(s) matched of 5,000: the filter is being applied to a different "+
			"set than it used to be", res.Matched)
	}
	if len(res.Rows) != 10 || !res.Truncated {
		t.Fatalf("got %d row(s), truncated=%v, want 10 and true", len(res.Rows), res.Truncated)
	}
	// The counts are of the whole log and the rows are the window: a search
	// that reported Scanned as the rows it kept would look identical on a small
	// log and lie on a large one.
	if res.Integrity == "" {
		t.Fatal("the integrity line is empty: a page that shows evidence without saying " +
			"whether it verified is the claim this console is not allowed to make")
	}
}
