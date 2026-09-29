package projection_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/projection"
	"github.com/mustafarslan/janus/pkg/saga"
)

// The corpus is the wrong instrument for the frontier question and it is worth
// saying why in the tree rather than only in a commit message: of its twenty
// fixtures exactly one records a resource touch, because each was written to
// exercise the state machine on its own rather than to contend with a
// neighbour. Comparing a scoped index against a whole-log index over histories
// that touch nothing compares two empty answers twenty times.
//
// So contention gets its own log, built here. Every saga below writes or reads a
// resource that another saga also uses, and they finish in the states that make
// the difference: committed and compensated are settled and clear the frontier,
// quarantine and still-running do not.

// contender describes one saga to append.
type contender struct {
	id string
	// resource is what the saga's single effectful step touches.
	resource string
	write    bool
	// end is how the saga finishes: "commit", "compensate", "quarantine", or
	// "" to leave it running with its effect in the world.
	end string
}

func appendContender(t *testing.T, app *evidence.Appender, c contender) {
	t.Helper()
	appendEvents(t, app, c.id, contenderEvents(t, c))
}

// appendEvents writes a prepared slice of a saga's events into the log.
//
// It is separate from contenderEvents so that a test can append a saga's
// history in two pieces with something else happening in between -- which is
// the only way to produce a saga that is still live across a restart, and that
// is the case the projector's recovery path exists for.
func appendEvents(t *testing.T, app *evidence.Appender, id string, events []saga.FixtureEvent) {
	t.Helper()
	f := saga.Fixture{Name: id, Events: events}
	replayable, err := f.Replayable()
	if err != nil {
		t.Fatalf("%s: %v", id, err)
	}
	for _, e := range replayable {
		if _, err := app.Append(context.Background(), evidence.Request{
			Kind: e.Kind, SagaID: id, Payload: e.Payload,
		}); err != nil {
			t.Fatalf("%s: append %s: %v", id, e.Kind, err)
		}
	}
}

// contenderEvents builds a saga's history without writing it anywhere.
func contenderEvents(t *testing.T, c contender) []saga.FixtureEvent {
	t.Helper()
	mode := "MODE_READ"
	if c.write {
		mode = "MODE_WRITE"
	}
	ev := func(kind, payload string) saga.FixtureEvent {
		return saga.FixtureEvent{Kind: kind, Payload: []byte(payload)}
	}
	q := func(format string, args ...any) string { return fmt.Sprintf(format, args...) }

	events := []saga.FixtureEvent{
		ev("SAGA_BEGIN", q(`{"saga_id":%q,"plan":[{"step_id":"pay",`+
			`"effect_class":"EFFECT_CLASS_COMPENSABLE","compensation_action":"pay.undo"}]}`, c.id)),
		ev("STEP_PREPARE", q(`{"saga_id":%q,"step_id":"pay"}`, c.id)),
		ev("STEP_RESULT", q(`{"saga_id":%q,"step_id":"pay","outcome":{"status":"STATUS_OK"},`+
			`"touches":[{"resource_id":%q,"mode":%q}]}`, c.id, c.resource, mode)),
		ev("GATE_VERDICT", q(`{"saga_id":%q,"step_id":"pay","verdict":"VERDICT_PASS"}`, c.id)),
	}

	switch c.end {
	case "commit":
		events = append(events,
			ev("SEAL_REQUEST", q(`{"saga_id":%q,"frontiers":[{"resource_id":%q,"last_sealed_seq":"0"}]}`,
				c.id, c.resource)),
			ev("COMMIT", q(`{"saga_id":%q}`, c.id)))
	case "compensate":
		events = append(events,
			ev("COMPENSATE", q(`{"saga_id":%q,"reason_ref":"withdrawn"}`, c.id)),
			ev("STEP_PREPARE", q(`{"saga_id":%q,"step_id":"pay~undo","compensates":"pay"}`, c.id)),
			ev("STEP_RESULT", q(`{"saga_id":%q,"step_id":"pay~undo","outcome":{"status":"STATUS_OK"}}`, c.id)))
	case "quarantine":
		events = append(events,
			ev("COMPENSATE", q(`{"saga_id":%q,"reason_ref":"withdrawn"}`, c.id)),
			ev("STEP_PREPARE", q(`{"saga_id":%q,"step_id":"pay~undo","compensates":"pay"}`, c.id)),
			ev("STEP_RESULT", q(`{"saga_id":%q,"step_id":"pay~undo",`+
				`"outcome":{"status":"STATUS_TERMINAL_ERROR"}}`, c.id)))
	case "":
		// Left running, with the effect in the world.
	default:
		t.Fatalf("unknown ending %q", c.end)
	}

	return events
}

// contendingLog builds a log in which sagas genuinely compete for resources.
//
// Order is the point. The evidence sequence is a total order across sagas, and
// `Blockers` only reports a touch that came *earlier* than the subject's own —
// later work waits rather than blocking. So the subjects that should see
// blockers are appended last.
func contendingLog(t *testing.T) (dir string, subjects []string) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []contender{
		// Settled: these clear the frontier and must not block anyone.
		{id: "sg-committed-a", resource: "acct:A", write: true, end: "commit"},
		{id: "sg-compensated-b", resource: "acct:B", write: true, end: "compensate"},
		// Unsettled: these must block a later writer.
		{id: "sg-running-a", resource: "acct:A", write: true},
		{id: "sg-quarantined-b", resource: "acct:B", write: true, end: "quarantine"},
		// A reader, so the "two reads do not conflict" branch is exercised
		// through the projection rather than only in the in-memory index.
		{id: "sg-reader-c", resource: "acct:C", write: false},
		// An unsettled *writer* on the resource the late reader will read.
		// Without this the only subjects that contend are writers, and a writer
		// conflicts with everything regardless of what the other party did --
		// which means the mode column could be projected wrongly and no test
		// would notice. A read blocked by an earlier write is the one case that
		// depends on the other saga's mode being recorded correctly.
		{id: "sg-running-writer-c", resource: "acct:C", write: true},

		// The subjects, appended last so everything above precedes them.
		{id: "sg-late-writer-a", resource: "acct:A", write: true},
		{id: "sg-late-writer-b", resource: "acct:B", write: true},
		{id: "sg-late-reader-c", resource: "acct:C", write: false},
		{id: "sg-late-writer-c", resource: "acct:C", write: true},
		{id: "sg-untouched", resource: "acct:Z", write: true},
	} {
		appendContender(t, app, c)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, []string{
		"sg-late-writer-a", "sg-late-writer-b", "sg-late-reader-c",
		"sg-late-writer-c", "sg-untouched", "sg-committed-a", "sg-running-a",
	}
}

// TestScopedIndexAgreesUnderContention is the equivalence that matters: on a log
// where sagas really do compete, the index built from the projection reports the
// same blockers as the index built by replaying every saga.
//
// It also asserts that blockers were found at all. An equivalence that holds
// because both sides said "nothing" is not evidence of anything, and that is
// exactly what this test looked like when it was first run against the fixture
// corpus.
func TestScopedIndexAgreesUnderContention(t *testing.T) {
	store, ctx := newStore(t)
	dir, subjects := contendingLog(t)

	proj := projection.NewProjector(store, dir)
	head, err := proj.CatchUp(ctx)
	if err != nil {
		t.Fatalf("catch up: %v", err)
	}

	states, err := saga.ReplayAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	fromLog := gate.IndexFromLog(dir)

	total := 0
	for _, id := range subjects {
		subject, ok := states[id]
		if !ok {
			t.Fatalf("saga %q is missing from the log", id)
		}
		whole, err := fromLog(subject)
		if err != nil {
			t.Fatal(err)
		}
		scoped, err := store.FrontierIndex(ctx, subject, head)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		want, got := describeBlockers(whole.Blockers(id)), describeBlockers(scoped.Blockers(id))
		if want != got {
			t.Errorf("saga %s:\n  whole log:  %s\n  projection: %s", id, want, got)
		}
		total += len(whole.Blockers(id))

		wOK, _ := whole.MayCommit(id)
		sOK, _ := scoped.MayCommit(id)
		if wOK != sOK {
			t.Errorf("saga %s: whole log says may-commit=%v, projection says %v", id, wOK, sOK)
		}
		for _, r := range resourcesOf(subject) {
			if w, g := whole.Frontier(r), scoped.Frontier(r); w != g {
				t.Errorf("saga %s frontier on %s: whole log %d, projection %d", id, r, w, g)
			}
		}
	}

	if total == 0 {
		t.Fatal("no blockers were found anywhere, so this test compared two empty answers")
	}
	t.Logf("compared %d subjects across %d blockers", len(subjects), total)
}

// TestUnprojectedSagaIsNotInvisible is the failure mode that makes the staleness
// contract load-bearing rather than tidy.
//
// `saga.Index.settled` fails closed for a saga it has heard of. It cannot fail
// closed for one nobody mentioned: a saga that began after `last_event_seq` has
// no rows, appears in no resource query, and so is not treated as unfinished —
// it is not seen at all, and the frontier check passes. Requiring the projection
// to have reached the head of the log is what closes that, and this test is the
// proof that without it the answer really does go wrong.
func TestUnprojectedSagaIsNotInvisible(t *testing.T) {
	store, ctx := newStore(t)
	dir, _ := contendingLog(t)

	proj := projection.NewProjector(store, dir)
	head, err := proj.CatchUp(ctx)
	if err != nil {
		t.Fatal(err)
	}

	states, err := saga.ReplayAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	subject := states["sg-late-writer-a"]

	caughtUp, err := store.FrontierIndex(ctx, subject, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(caughtUp.Blockers(subject.SagaID)) == 0 {
		t.Fatal("sg-late-writer-a should be blocked by sg-running-a; the rest of this test " +
			"cannot show anything if it is not")
	}

	// Now ask for an answer that requires more of the log than has been folded.
	// The projection is not merely behind; it is behind in the direction that
	// would hide a contender.
	if _, err := store.FrontierIndex(ctx, subject, head+1); err == nil {
		t.Fatal("a projection behind the log answered a frontier question anyway")
	} else if !isStale(err) {
		t.Fatalf("expected a staleness refusal, got: %v", err)
	}
}

func isStale(err error) bool { return errors.Is(err, projection.ErrStale) }
