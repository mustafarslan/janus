package projection_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/projection"
	"google.golang.org/protobuf/proto"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// TestAnEventAfterCommitDoesNotInventASaga.
//
// The outbox lifecycle events carry a saga id, so they reach `saga.Apply`, which
// counts them and moves `LastSeq` without drawing any conclusion from them. They
// also arrive *after* the saga commits — a released effect is delivered later by
// definition. And the projector evicts a saga from its working set the moment it
// reaches a terminal state, so the events that follow a commit are exactly the
// ones it no longer holds a projection for.
//
// Folding one of those onto a blank `saga.State` produced a state with no saga
// id, and writing that produced a row keyed on the empty string: a saga that does
// not exist, sitting in the table a frontier gate reads. This is that case.
func TestAnEventAfterCommitDoesNotInventASaga(t *testing.T) {
	store, ctx, dsn := newStoreDSN(t)

	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The effect is held before the saga commits and delivered after it, which
	// is the real ordering: an effect is withheld until the commit authorises
	// its release, and the delivery is recorded whenever the target answers.
	events := contenderEvents(t, contender{
		id: "sg-paid", resource: "acct:A", write: true, end: "commit"})
	appendEvents(t, app, "sg-paid", events[:3])
	appendProto(t, app, evidence.KindEffectHeld, "sg-paid", &janusv1.EffectHeld{
		EffectId: "ef-1", SagaId: "sg-paid", StepId: "pay",
		Target: "payments", IdemKey: "idem-1",
	})
	appendEvents(t, app, "sg-paid", events[3:])

	proj := projection.NewProjector(store, dir)
	if _, err := proj.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}

	// The log is closed before the second fold so that this test is about the
	// projector rather than about how promptly an unsynced appender makes its
	// last record readable.
	// Announced before attempted, which is invariant I1 and which the outbox
	// state machine enforces rather than assumes -- an earlier version of this
	// test jumped straight to delivered and was refused.
	appendProto(t, app, evidence.KindEffectReleasing, "sg-paid", &janusv1.EffectReleasing{
		EffectId: "ef-1", SagaId: "sg-paid", Attempt: 1, IdemKey: "idem-1",
		// The commit that authorises the release, named in the release itself.
		// Evidence before effect is not only about ordering: the record has to
		// say which commit it rests on.
		CommitRoot: []byte("commit-root"),
	})
	appendProto(t, app, evidence.KindEffectDelivered, "sg-paid", &janusv1.EffectDelivered{
		EffectId: "ef-1", SagaId: "sg-paid", Attempt: 1,
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	})
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	head, err := proj.CatchUp(ctx)
	if err != nil {
		t.Fatalf("folding an effect event after commit: %v", err)
	}
	if head != 9 {
		t.Fatalf("the post-commit event was not folded: head is %d, the log ends at 9", head)
	}

	rows := dumpRows(t, ctx, dsn)
	for _, line := range strings.Split(rows, "\n") {
		if strings.HasPrefix(line, "[ ") || line == "[]" {
			t.Errorf("a row keyed on the empty saga id reached the projection: %q\n%s", line, rows)
		}
	}
	// The saga must still read as committed, with its touch intact -- recovering
	// it must not have replaced its projection with one derived from the stray
	// event alone.
	if !strings.Contains(rows, "[sg-paid  COMMITTED") {
		t.Errorf("sg-paid is no longer committed in the projection:\n%s", rows)
	}
	if !strings.Contains(rows, "[acct:A sg-paid pay MODE_WRITE 3]") {
		t.Errorf("sg-paid lost its resource touch:\n%s", rows)
	}

	// A cold projector must reach the same place. This is the path that actually
	// produced the empty row, because a fresh one holds nothing at all.
	cold, _, coldDSN := newStoreDSN(t)
	if _, err := projection.NewProjector(cold, dir).CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	if want, got := dumpRows(t, ctx, coldDSN), rows; want != got {
		t.Errorf("a cold fold of the same log disagrees.\n--- cold ---\n%s\n--- warm ---\n%s", want, got)
	}
}

// TestALongLivedProjectorKeepsFolding is orchd's shape: one projector, one open
// appender, folding repeatedly as the log grows.
//
// It exists because that shape failed while every test that closed the log first
// passed. `segment.ScanComplete` reports the empty segment an open appender
// pre-creates beyond the one it is writing, so a projector that resumed from
// "the highest segment id listed" resumed from a file that was removed at the
// next rotation — and then skipped every segment below it, forever. Nothing was
// corrupted; the projector simply stopped, and because a frontier gate refuses
// when the projection is behind, the visible symptom would have been a
// coordinator that stopped committing.
func TestALongLivedProjectorKeepsFolding(t *testing.T) {
	store, ctx := newStore(t)

	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	proj := projection.NewProjector(store, dir)
	var last uint64
	for i, c := range []contender{
		{id: "lp-1", resource: "acct:A", write: true, end: "commit"},
		{id: "lp-2", resource: "acct:A", write: true},
		{id: "lp-3", resource: "acct:B", write: true, end: "quarantine"},
		{id: "lp-4", resource: "acct:A", write: true},
		{id: "lp-5", resource: "acct:B", write: true, end: "compensate"},
	} {
		appendContender(t, app, c)
		head, err := proj.CatchUp(ctx)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if head <= last {
			t.Fatalf("round %d: the projector stopped folding — head was %d and is still %d "+
				"after appending %s", i, last, head, c.id)
		}
		last = head
	}
}

// appendProto writes one protobuf event into the log under a saga id.
func appendProto(t *testing.T, app *evidence.Appender, kind evidence.Kind,
	sagaID string, msg proto.Message) {
	t.Helper()
	payload, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Append(context.Background(), evidence.Request{
		Kind: kind, SagaID: sagaID, Payload: payload,
	}); err != nil {
		t.Fatalf("append %s: %v", kind, err)
	}
}

// TestTheHeldEffectCountMatchesTheOutbox.
//
// The console's overview shows how many of a saga's effects are still held. The
// projection carries that as a count and nothing more: effect *state* is commit
// authority (invariant I1, `outbox.LogAuthority`), and a projection that offered
// it would eventually be asked to decide a release. So the count is the only
// thing to check, and it has to agree with what the outbox state machine says
// about the same log.
func TestTheHeldEffectCountMatchesTheOutbox(t *testing.T) {
	store, ctx := newStore(t)

	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Two sagas, three effects: one still held, one delivered, one held on a
	// different saga. A count that ignored delivery, or that attributed effects
	// to the wrong saga, would pass a test with only one of each.
	events := contenderEvents(t, contender{
		id: "sg-one", resource: "acct:A", write: true, end: "commit"})
	appendEvents(t, app, "sg-one", events[:3])
	appendProto(t, app, evidence.KindEffectHeld, "sg-one", &janusv1.EffectHeld{
		EffectId: "ef-held", SagaId: "sg-one", StepId: "pay",
		Target: "payments", IdemKey: "idem-held",
	})
	appendProto(t, app, evidence.KindEffectHeld, "sg-one", &janusv1.EffectHeld{
		EffectId: "ef-gone", SagaId: "sg-one", StepId: "pay",
		Target: "payments", IdemKey: "idem-gone",
	})
	appendEvents(t, app, "sg-one", events[3:])
	appendProto(t, app, evidence.KindEffectReleasing, "sg-one", &janusv1.EffectReleasing{
		EffectId: "ef-gone", SagaId: "sg-one", Attempt: 1, IdemKey: "idem-gone",
		CommitRoot: []byte("commit-root"),
	})
	appendProto(t, app, evidence.KindEffectDelivered, "sg-one", &janusv1.EffectDelivered{
		EffectId: "ef-gone", SagaId: "sg-one", Attempt: 1,
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	})

	two := contenderEvents(t, contender{
		id: "sg-two", resource: "acct:B", write: true, end: "commit"})
	appendEvents(t, app, "sg-two", two[:3])
	appendProto(t, app, evidence.KindEffectHeld, "sg-two", &janusv1.EffectHeld{
		EffectId: "ef-other", SagaId: "sg-two", StepId: "pay",
		Target: "payments", IdemKey: "idem-other",
	})
	appendEvents(t, app, "sg-two", two[3:])
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := projection.NewProjector(store, dir).CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	rows, _, err := store.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}

	outboxEvents, err := outbox.LoadEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := outbox.Replay(outboxEvents)
	if err != nil {
		t.Fatal(err)
	}

	byID := map[string]int{}
	for _, r := range rows {
		byID[r.SagaID] = r.Held
		want := len(outbox.PendingFor(state, r.SagaID))
		if r.Held != want {
			t.Errorf("saga %s: the projection counts %d outstanding effects, the outbox "+
				"counts %d", r.SagaID, r.Held, want)
		}
	}
	// One outstanding on the first saga -- the other was delivered and is
	// finished -- and one on the second. An earlier version counted
	// the delivered effect too, under a column headed "held", on a page somebody
	// reads to see what is still in the world.
	if byID["sg-one"] != 1 || byID["sg-two"] != 1 {
		t.Fatalf("outstanding effects are sg-one=%d sg-two=%d, want 1 and 1",
			byID["sg-one"], byID["sg-two"])
	}
	if got := len(outbox.EffectsFor(state, "sg-one")); got != 2 {
		t.Fatalf("sg-one owns %d effects, want 2 -- the fixture no longer has a delivered "+
			"one and would stop distinguishing owned from outstanding", got)
	}
}
