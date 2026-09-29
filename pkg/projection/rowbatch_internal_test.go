package projection

import (
	"context"
	"fmt"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Every statement in a batched write keeps the name of what it was for.
//
// Batching the fold's writes traded one round trip per statement for one per
// fold, and the thing it could have cost is the error message: pgx reports a
// batch failure by position, so a naive implementation says "statement 417 of
// 900 failed" — true, and useless at three in the morning.
//
// The description list has to stay in step with the queue, and nothing in the
// type system makes it. This asserts the pairing directly: one description per
// statement, in the same order, each naming the saga.
func TestEveryBatchedStatementKeepsItsName(t *testing.T) {
	s := saga.State{
		SagaID: "sg_named",
		Status: saga.StatusRunning,
		Order:  []string{"one", "two"},
		Steps: map[string]*saga.Step{
			"one": {
				ID: "one", Participant: "ag_1",
				Touches: []saga.Touch{
					{Resource: "acct:a", Mode: janusv1.ResourceTouch_MODE_WRITE, Seq: 1},
					{Resource: "acct:b", Mode: janusv1.ResourceTouch_MODE_READ, Seq: 2},
				},
			},
			"two": {ID: "two", Participant: "ag_1"},
		},
	}

	var b rowBatch
	if err := queueSaga(&b, s, "tenant", 0, 0); err != nil {
		t.Fatal(err)
	}

	// One saga upsert, two deletes, two steps, two touches.
	const want = 7
	if b.batch.Len() != want {
		t.Fatalf("queued %d statements, want %d", b.batch.Len(), want)
	}
	if len(b.what) != b.batch.Len() {
		t.Fatalf("%d statements but %d descriptions: an error would be attributed to "+
			"the wrong one, or to none", b.batch.Len(), len(b.what))
	}
	for i, what := range b.what {
		if !strings.Contains(what, "sg_named") {
			t.Fatalf("description %d (%q) does not name the saga, so a failure there "+
				"would give an operator nothing to look at", i, what)
		}
	}
	// The two that name something more specific than the saga.
	joined := strings.Join(b.what, "; ")
	for _, needle := range []string{"step one", "step two", "acct:a", "acct:b"} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("no statement is described as being about %q: %s", needle, joined)
		}
	}
}

// A saga with no id is refused before anything is queued.
func TestASagaWithNoIDIsNotQueued(t *testing.T) {
	var b rowBatch
	if err := queueSaga(&b, saga.State{}, "", 0, 0); err == nil {
		t.Fatal("a saga with no id was queued; it would become a row keyed on the " +
			"empty string in the table a frontier gate reads")
	}
	if b.batch.Len() != 0 {
		t.Fatalf("%d statements were queued for a saga that was refused", b.batch.Len())
	}
}

// A pass resumes inside the segment it stopped in, not at the top of it.
//
// `Projector.read` used to resume at a whole segment, so every fold re-framed
// and re-decoded everything written to the open segment since it was created
// and then discarded all but the tail. Measured at 90% of the records a fold
// looked at and 38% of its time — and it is a sawtooth that grows as the open
// segment fills and resets at rotation, which a benchmark starting on a fresh
// segment barely sees.
//
// The property is that a second pass over an unchanged directory reads almost
// nothing. "Almost" because the record the last pass stopped on is deliberately
// re-read: taking its own offset as the floor costs one decode per pass and
// saves working out how many bytes a record spans.
func TestASecondPassDoesNotRereadTheSegment(t *testing.T) {
	dir, app := scannedLog(t, 400)
	defer func() { _ = app.Close() }()

	// Through the constructor, because a Projector's scanner is part of what it
	// is: `read` on a zero-value one panics on a nil scanner.
	p := NewProjector(nil, dir)

	if _, _, _, err := p.read(0); err != nil {
		t.Fatal(err)
	}
	first := p.lastScanned
	if first < 400 {
		t.Fatalf("the first pass scanned %d records, want at least the 400 written", first)
	}

	// Where the first pass stopped. In the projector this is set by the fold
	// once it commits; here there is no database, so it is set directly.
	_, seg, off, err := p.read(0)
	if err != nil {
		t.Fatal(err)
	}
	p.fromSegment, p.fromOffset = seg, off

	if _, _, _, err := p.read(0); err != nil {
		t.Fatal(err)
	}
	if p.lastScanned > 2 {
		t.Fatalf("a second pass over an unchanged directory scanned %d records; it should "+
			"skip everything below the offset it stopped at and re-read only the record "+
			"it stopped on (first pass scanned %d)", p.lastScanned, first)
	}
}

// scannedLog writes n single-event sagas and leaves the appender open, which is
// the state a projector folds against in a running daemon.
func scannedLog(t *testing.T, n int) (string, *evidence.Appender) {
	t.Helper()
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
	for i := range n {
		if _, err := app.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      fmt.Sprintf("sg_%04d", i),
			Participant: evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1", Principal: "pr_1"},
			Payload:     []byte("x"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return dir, app
}
