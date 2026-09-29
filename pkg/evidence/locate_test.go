package evidence_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// The one thing the locator can get wrong is omission.
//
// Every record it points at is verified by the caller, so it cannot introduce a
// forgery. What it can do is leave an event out — and a short history replays
// into a plausible-looking saga and hashes into an evidence root that is wrong
// and passes every structural check. That is fail-open shaped, and it is why
// this comparison exists rather than a test that the locator returns "some
// events".
//
// The comparison is against the full scan, which is the implementation the
// locator is an optimisation of. Same argument as
// `TestScopedIndexAgreesUnderContention` makes for the projection against
// `IndexFromLog`: the fast path is checked against the slow one, on a history
// where the two have room to disagree.
func TestTheLocatorAgreesWithAFullScan(t *testing.T) {
	dir := t.TempDir()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// A small segment target so the log rotates and a saga's records end up
	// spread across segments, which is the case a locator that grouped badly
	// would get wrong.
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	const sagas, each = 20, 12
	ids := make([]string, sagas)
	for i := range ids {
		ids[i] = fmt.Sprintf("sg_%03d", i)
	}
	// Interleaved, so no saga's records are contiguous.
	for range each {
		for _, id := range ids {
			if _, err := app.Append(context.Background(), evidence.Request{
				Kind:        evidence.KindStepResult,
				SagaID:      id,
				Participant: evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1", Principal: "pr_1"},
				Payload:     []byte(id),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}

	for _, id := range ids {
		head := app.Stats().LastSeq
		scanned := collect(t, dir, id, evidence.AsOf(head))
		located := collect(t, dir, id, evidence.AsOf(head), evidence.WithLocator(app))

		if len(located) != each {
			t.Fatalf("saga %s: the locator returned %d events, want %d", id, len(located), each)
		}
		if len(scanned) != len(located) {
			t.Fatalf("saga %s: full scan found %d events, the locator found %d",
				id, len(scanned), len(located))
		}
		for i := range scanned {
			if scanned[i] != located[i] {
				t.Fatalf("saga %s event %d: full scan says sequence %d, the locator says %d",
					id, i, scanned[i], located[i])
			}
		}
	}
}

// The same comparison while the log is being written, because a locator built
// by the writer is exactly the thing a concurrent append can put out of step.
func TestTheLocatorAgreesWhileTheLogIsBeingWritten(t *testing.T) {
	dir := t.TempDir()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	// Noise: another saga being appended throughout, so the reads below happen
	// against a directory that is moving under them.
	//
	// It is throttled, and the reason is worth stating because the first
	// version was not. Each round below does a *full scan* for its comparison,
	// so an unthrottled writer makes this test quadratic in its own runtime —
	// it passed in seconds here and blew the package's ten-minute budget on the
	// Linux CI container. What the test needs is that appends land *between*
	// the two reads, not that there are a great many of them.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
			_, _ = app.Append(context.Background(), evidence.Request{
				Kind:        evidence.KindStepResult,
				SagaID:      "sg_noise",
				Participant: evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1", Principal: "pr_1"},
				Payload:     []byte("noise"),
			})
		}
	}()

	for round := range 15 {
		id := fmt.Sprintf("sg_live_%02d", round)
		for range 5 {
			if _, err := app.Append(context.Background(), evidence.Request{
				Kind:        evidence.KindStepResult,
				SagaID:      id,
				Participant: evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1", Principal: "pr_1"},
				Payload:     []byte(id),
			}); err != nil {
				t.Fatal(err)
			}
		}
		head := app.Stats().LastSeq
		scanned := collect(t, dir, id, evidence.AsOf(head))
		located := collect(t, dir, id, evidence.AsOf(head), evidence.WithLocator(app))
		if len(located) != 5 || len(scanned) != len(located) {
			close(stop)
			wg.Wait()
			t.Fatalf("saga %s: full scan found %d events, the locator found %d, want 5",
				id, len(scanned), len(located))
		}
	}
	close(stop)
	wg.Wait()
}

// A saga that was never written is answered without reading the log at all.
//
// This is the commonest read there is — starting a saga — and before the
// locator could answer it, every new saga paid a full directory scan to
// discover it had no history. At 2000 sagas in the log that was 23.7 ms per
// start.
func TestAnUnknownSagaIsAnsweredWithoutScanning(t *testing.T) {
	dir := t.TempDir()
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
	defer func() { _ = app.Close() }()

	for i := range 50 {
		if _, err := app.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      fmt.Sprintf("sg_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1", Principal: "pr_1"},
			Payload:     []byte("x"),
		}); err != nil {
			t.Fatal(err)
		}
	}

	locs, authoritative := app.Locate("sg_never_written")
	if !authoritative {
		t.Fatal("a saga that was never written was not answered authoritatively, " +
			"so every new saga still pays a full scan to find nothing")
	}
	if len(locs) != 0 {
		t.Fatalf("a saga that was never written has %d locations", len(locs))
	}

	// And the read agrees.
	if got := collect(t, dir, "sg_never_written",
		evidence.AsOf(app.Stats().LastSeq), evidence.WithLocator(app)); len(got) != 0 {
		t.Fatalf("a saga that was never written returned %d events", len(got))
	}
}

// A saga that *was* written is never answered as absent, whatever else the
// index has forgotten. This is the one-sided error the whole design rests on.
func TestASagaThatWasWrittenIsNeverReportedAbsent(t *testing.T) {
	dir := t.TempDir()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		// A capacity far below the number of sagas, so the generations swap
		// repeatedly and most sagas fall out of the location maps entirely.
		LocatorSagas: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	const n = 200
	for i := range n {
		if _, err := app.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      fmt.Sprintf("sg_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1", Principal: "pr_1"},
			Payload:     []byte("x"),
		}); err != nil {
			t.Fatal(err)
		}
	}

	head := app.Stats().LastSeq
	for i := range n {
		id := fmt.Sprintf("sg_%03d", i)
		locs, authoritative := app.Locate(id)
		if authoritative && len(locs) == 0 {
			t.Fatalf("saga %s was written and the locator reported it absent, which "+
				"would give it an empty history and a wrong evidence root", id)
		}
		// However the locator answered, the read must find the record.
		if got := collect(t, dir, id, evidence.AsOf(head), evidence.WithLocator(app)); len(got) != 1 {
			t.Fatalf("saga %s: read %d events through the locator, want 1", id, len(got))
		}
	}
}

func collect(t *testing.T, dir, sagaID string, opts ...evidence.ReadOption) []uint64 {
	t.Helper()
	var seqs []uint64
	if err := evidence.WalkSaga(dir, sagaID, func(h evidence.EventHeader, _ segment.Record) error {
		seqs = append(seqs, h.Seq)
		return nil
	}, opts...); err != nil {
		t.Fatalf("read saga %s: %v", sagaID, err)
	}
	return seqs
}

// A process that starts on an existing log must not mistake what it wrote for
// the whole of a saga's history.
//
// This is the failure the hosted chaos suite found: a coordinator was killed
// mid-saga, the replacement appended the next GATE_ANSWER, and its index held
// exactly that one location. Reading the saga through it produced a history
// starting at sequence 14, which replayed as "unknown step" — an index
// returning a saga's tail as if it were the saga.
//
// The rule that fixes it is that nothing in the index is authoritative until it
// has seen the whole directory, and the test is here rather than only in the
// chaos suite because 78 kills is an expensive way to notice.
func TestARestartedWriterDoesNotReturnASagasTailAsItsHistory(t *testing.T) {
	dir := t.TempDir()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	write := func(app *evidence.Appender, id string, n int) {
		t.Helper()
		for range n {
			if _, err := app.Append(context.Background(), evidence.Request{
				Kind:        evidence.KindStepResult,
				SagaID:      id,
				Participant: evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1", Principal: "pr_1"},
				Payload:     []byte(id),
			}); err != nil {
				t.Fatal(err)
			}
		}
	}

	first, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	write(first, "sg_long", 6)
	write(first, "sg_other", 3)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// The replacement. It knows nothing about what came before.
	second, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	write(second, "sg_long", 1)

	// Twice, and the second time is the one that matters. The first read falls
	// back to a scan and returns what the scan saw, so it would pass even if
	// the scan taught the index nothing. Only the second read is served from
	// the index, which is where a partial entry — this process's one record,
	// kept in preference to the scan's six — would show up.
	for attempt := range 2 {
		got := collect(t, dir, "sg_long",
			evidence.AsOf(second.Stats().LastSeq), evidence.WithLocator(second))
		if len(got) != 7 {
			t.Fatalf("read %d: a saga with 6 events before the restart and 1 after read "+
				"back as %d events (%v) — the index returned only part of its history",
				attempt+1, len(got), got)
		}
		for i := range got {
			if i > 0 && got[i] <= got[i-1] {
				t.Fatalf("read %d: events came back out of order: %v", attempt+1, got)
			}
		}
	}
}
