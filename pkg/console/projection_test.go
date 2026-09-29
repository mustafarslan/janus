package console_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/console"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/projection"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

// consoleStore gives a test its own projection schema and folds a directory
// into it, returning a store the console may read.
//
// The store handed to the console is a *second* one, opened separately, because
// that is what a console is: a different process from the daemon that folds. The
// projector's writer lock is held by the first, and the console never asks for
// it.
func consoleStore(t *testing.T, dir string) *projection.Store {
	t.Helper()
	store, _ := consoleStoreDSN(t, dir)
	return store
}

// consoleStoreDSN is consoleStore, and also hands back the connection string the
// store was opened on.
//
// Only one kind of test needs it: the one that writes to the projection behind
// the console's back, to prove that what a column says is not what the page
// shows. That is a deliberately unpleasant thing to be able to do, which is why
// it is a second function rather than the default.
func consoleStoreDSN(t *testing.T, dir string) (*projection.Store, string) {
	t.Helper()
	dsn := os.Getenv("JANUS_PG_DSN")
	if dsn == "" {
		if os.Getenv("JANUS_PG_REQUIRED") != "" {
			t.Fatal("JANUS_PG_REQUIRED is set but JANUS_PG_DSN is not, so the console's " +
				"projection path would have gone untested")
		}
		t.Skip("set JANUS_PG_DSN to exercise the projection-backed console")
	}
	ctx := context.Background()
	schema := "c_" + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, strings.ToLower(t.Name()))
	if len(schema) > 60 {
		schema = schema[:60]
	}
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to %s: %v", dsn, err)
	}
	for _, q := range []string{`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`, `CREATE SCHEMA ` + schema} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	_ = admin.Close(ctx)
	t.Cleanup(func() {
		a, err := pgx.Connect(ctx, dsn)
		if err != nil {
			return
		}
		_, _ = a.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		_ = a.Close(ctx)
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	scoped := dsn + sep + "options=-c%20search_path%3D" + schema

	// The daemon's store: it folds, and it keeps the writer lock for the rest of
	// the test.
	writer, err := projection.Open(ctx, scoped)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(writer.Close)
	if _, err := projection.NewProjector(writer, dir).CatchUp(ctx); err != nil {
		t.Fatalf("folding the log: %v", err)
	}

	// The console's store: a different connection, no lock, read only.
	reader, err := projection.Open(ctx, scoped)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reader.Close)
	return reader, scoped
}

// writeToProjection runs a statement against the projection directly, as a
// daemon with a wrong fold or a person with the database would.
func writeToProjection(t *testing.T, dsn, sql string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	tag, err := conn.Exec(ctx, sql)
	if err != nil {
		t.Fatal(err)
	}
	if tag.RowsAffected() == 0 {
		t.Fatalf("%q changed no rows, so this test would pass without proving anything", sql)
	}
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestTheProjectedOverviewIsTheSamePage.
//
// Item 19 asks for the console to stop replaying every saga on every request.
// The bar for that is not "faster": it is that the page a person reads does not
// change. A projection-backed overview that quietly lost the principal, or the
// reason a saga is stuck, would still look like a page — which is why this
// compares the whole rendered structure rather than a few fields.
func TestTheProjectedOverviewIsTheSamePage(t *testing.T) {
	dir := richLog(t)
	store := consoleStore(t, dir)

	fromLog, err := console.Open(dir).Overview()
	if err != nil {
		t.Fatal(err)
	}
	fromProjection, err := console.Open(dir).WithProjection(store).Overview()
	if err != nil {
		t.Fatal(err)
	}

	if !fromProjection.Projected {
		t.Error("the projection-backed overview does not say it came from the projection")
	}
	if fromProjection.AsOf == 0 {
		t.Error("the projection-backed overview does not say which sequence it is as of")
	}
	// The columns this test exists to defend have to be present in the data, or
	// it is comparing empty strings to empty strings. An earlier version ran
	// over a log with one waiting saga: no parent, no reason, no held effect,
	// and so no coverage of the three columns most likely to be got wrong.
	var sawParent, sawReason, sawHeld bool
	for _, r := range fromLog.Sagas {
		sawParent = sawParent || r.Parent != ""
		sawReason = sawReason || r.Reason != ""
		sawHeld = sawHeld || r.Held > 0
	}
	// The count is what is outstanding, not what the saga owns. sg_child holds
	// two effects and one of them was delivered; before the fix this
	// read 2, under a column headed "held", on the page somebody checks to see
	// what is still in the world.
	for _, r := range fromLog.Sagas {
		if r.SagaID != "sg_child" {
			continue
		}
		if r.Held != 1 {
			t.Errorf("sg_child shows %d outstanding effects; it owns two and one was "+
				"delivered, so the answer is 1", r.Held)
		}
	}
	if !sawParent || !sawReason || !sawHeld {
		t.Fatalf("the log does not exercise the columns under test "+
			"(parent=%v reason=%v held=%v); this comparison would pass on a bug",
			sawParent, sawReason, sawHeld)
	}

	// AsOf and Projected differ by construction — one read the log, the other
	// the tables — so they are checked above and cleared before comparing the
	// substance.
	fromLog.AsOf, fromProjection.AsOf = 0, 0
	fromLog.Projected, fromProjection.Projected = false, false
	if want, got := jsonOf(t, fromLog), jsonOf(t, fromProjection); want != got {
		t.Errorf("the projected overview is a different page.\n--- log ---\n%s\n--- projection ---\n%s",
			want, got)
	}
}

// TestTheProjectedQueueIsTheSameQueue.
//
// The queue is the page somebody acts on, so the bar is higher than for the
// overview: an approval offered against the wrong step is worse than a slow
// page. The projection is trusted for one thing here — which sagas have a step
// stopped at a gate — and every gate's standing is still decided by
// `gate.Decide` over sagas replayed from the log. This is the test that says the
// shortlist did not change any answer.
func TestTheProjectedQueueIsTheSameQueue(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	store := consoleStore(t, dir)

	fromLog, err := console.Open(dir).Queue()
	if err != nil {
		t.Fatal(err)
	}
	fromProjection, err := console.Open(dir).WithProjection(store).Queue()
	if err != nil {
		t.Fatal(err)
	}

	if len(fromLog.Items) == 0 {
		t.Fatal("nothing is waiting in this log, so this comparison is vacuous")
	}
	if !fromProjection.Projected || fromProjection.AsOf == 0 {
		t.Error("the projection-backed queue does not say where it came from or when")
	}

	if want, got := jsonOf(t, fromLog.Items), jsonOf(t, fromProjection.Items); want != got {
		t.Errorf("the projected queue is a different queue.\n--- log ---\n%s\n--- projection ---\n%s",
			want, got)
	}
}

// TestAConsoleRefusesAProjectionFromAnotherLog.
//
// The projection's log binding is written and checked by the projector, and a
// console never folds — so nothing on the console's path would have caught a projection
// belonging to a different deployment. Both halves would be internally
// consistent: real rows, a real sequence, and somebody else's sagas under this
// deployment's heading.
func TestAConsoleRefusesAProjectionFromAnotherLog(t *testing.T) {
	mine, _ := waitingLog(t, validatorAgrees)
	theirs, _ := waitingLog(t, validatorAgrees)

	// A store folded from the *other* directory.
	store := consoleStore(t, theirs)

	if err := projection.CheckLogBinding(context.Background(), store, mine); err == nil {
		t.Fatal("a console accepted a projection built from a different log")
	} else if !errors.Is(err, projection.ErrWrongLog) {
		t.Fatalf("expected a wrong-log refusal, got: %v", err)
	}

	// And the one it does belong to is fine.
	if err := projection.CheckLogBinding(context.Background(), store, theirs); err != nil {
		t.Errorf("the console refused the projection built from its own log: %v", err)
	}
}

// richLog builds a log whose sagas exercise the overview columns that
// `waitingLog` never touches.
//
// It exists because the equality test above was passing on a log with one
// waiting saga: no parent link, no quarantine, no terminal reason, no held
// effects. The columns added to keep a projected page from being a quietly
// poorer one were therefore untested by the very test whose job that is — a
// `parentOf` bug or a `TerminalReason` mismatch would have passed.
func richLog(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
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

	write := func(id string, events []saga.FixtureEvent) {
		t.Helper()
		replayable, err := saga.Fixture{Name: id, Events: events}.Replayable()
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		for _, e := range replayable {
			if _, err := app.Append(ctx, evidence.Request{
				Kind: e.Kind, SagaID: id, Payload: e.Payload,
			}); err != nil {
				t.Fatalf("%s: append %s: %v", id, e.Kind, err)
			}
		}
	}
	ev := func(kind, payload string) saga.FixtureEvent {
		return saga.FixtureEvent{Kind: kind, Payload: []byte(payload)}
	}

	// A saga that quarantines, so `reason` is not empty.
	write("sg_stuck", []saga.FixtureEvent{
		ev("SAGA_BEGIN", `{"saga_id":"sg_stuck","intent":{"intent_id":"in_stuck",`+
			`"principal":"pr_bank"},"plan":[{"step_id":"pay",`+
			`"effect_class":"EFFECT_CLASS_COMPENSABLE","compensation_action":"pay.undo"}]}`),
		ev("STEP_PREPARE", `{"saga_id":"sg_stuck","step_id":"pay"}`),
		ev("STEP_RESULT", `{"saga_id":"sg_stuck","step_id":"pay","outcome":{"status":"STATUS_OK"}}`),
		ev("GATE_VERDICT", `{"saga_id":"sg_stuck","step_id":"pay","verdict":"VERDICT_PASS"}`),
		ev("COMPENSATE", `{"saga_id":"sg_stuck","reason_ref":"the counterparty withdrew"}`),
		ev("STEP_PREPARE", `{"saga_id":"sg_stuck","step_id":"pay~undo","compensates":"pay"}`),
		ev("STEP_RESULT", `{"saga_id":"sg_stuck","step_id":"pay~undo",`+
			`"outcome":{"status":"STATUS_TERMINAL_ERROR"}}`),
	})

	// A parent and a child, so `parent` is not empty on one of them.
	write("sg_parent", []saga.FixtureEvent{
		ev("SAGA_BEGIN", `{"saga_id":"sg_parent","intent":{"intent_id":"in_parent",`+
			`"principal":"pr_bank"},"plan":[{"step_id":"delegate",`+
			`"effect_class":"EFFECT_CLASS_PURE"}]}`),
		ev("STEP_PREPARE", `{"saga_id":"sg_parent","step_id":"delegate"}`),
	})
	write("sg_child", []saga.FixtureEvent{
		ev("SAGA_BEGIN", `{"saga_id":"sg_child","intent":{"intent_id":"in_child",`+
			`"principal":"pr_bank"},"plan":[{"step_id":"charge",`+
			`"effect_class":"EFFECT_CLASS_COMPENSABLE","compensation_action":"charge.undo"}],`+
			`"parent":{"saga_id":"sg_parent","step_id":"delegate",`+
			`"commit_mode":"CHILD_COMMIT_MODE_CASCADE"}}`),
		ev("STEP_PREPARE", `{"saga_id":"sg_child","step_id":"charge"}`),
		ev("STEP_RESULT", `{"saga_id":"sg_child","step_id":"charge","outcome":{"status":"STATUS_OK"}}`),
	})

	// Two effects on one saga: one still held, one released and delivered. The
	// distinction is the whole point — the overview's column is
	// what is *outstanding*, and a delivered effect is finished.
	put := func(kind evidence.Kind, msg proto.Message) {
		t.Helper()
		payload, err := proto.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.Append(ctx, evidence.Request{
			Kind: kind, SagaID: "sg_child", Payload: payload,
		}); err != nil {
			t.Fatal(err)
		}
	}
	put(evidence.KindEffectHeld, &janusv1.EffectHeld{
		EffectId: "ef-open", SagaId: "sg_child", StepId: "charge",
		Target: "payments", IdemKey: "idem-open",
	})
	put(evidence.KindEffectHeld, &janusv1.EffectHeld{
		EffectId: "ef-done", SagaId: "sg_child", StepId: "charge",
		Target: "payments", IdemKey: "idem-done",
	})
	put(evidence.KindEffectReleasing, &janusv1.EffectReleasing{
		EffectId: "ef-done", SagaId: "sg_child", Attempt: 1, IdemKey: "idem-done",
		CommitRoot: []byte("commit-root"),
	})
	put(evidence.KindEffectDelivered, &janusv1.EffectDelivered{
		EffectId: "ef-done", SagaId: "sg_child", Attempt: 1,
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	})

	// A committed saga holding a frozen effect. This is the shape the quarantine
	// list exists for and the shape that made the front page wrong: the saga
	// reached COMMITTED and stayed there, because nothing drags a saga into
	// QUARANTINE when one of its effects cannot be delivered. Somebody reading
	// the overview saw a committed saga and no quarantine count at all, with a
	// payment sitting undelivered underneath it.
	write("sg_paid", []saga.FixtureEvent{
		ev("SAGA_BEGIN", `{"saga_id":"sg_paid","intent":{"intent_id":"in_paid",`+
			`"principal":"pr_desk"},"plan":[{"step_id":"settle",`+
			`"effect_class":"EFFECT_CLASS_COMPENSABLE","compensation_action":"settle.undo"}]}`),
		ev("STEP_PREPARE", `{"saga_id":"sg_paid","step_id":"settle"}`),
		ev("STEP_RESULT", `{"saga_id":"sg_paid","step_id":"settle","outcome":{"status":"STATUS_OK"}}`),
		ev("GATE_VERDICT", `{"saga_id":"sg_paid","step_id":"settle","verdict":"VERDICT_PASS"}`),
		ev("SEAL_REQUEST", `{"saga_id":"sg_paid"}`),
		ev("COMMIT", `{"saga_id":"sg_paid","evidence_root":"cm9vdA=="}`),
	})
	putFor := func(sagaID string, kind evidence.Kind, msg proto.Message) {
		t.Helper()
		payload, err := proto.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.Append(ctx, evidence.Request{
			Kind: kind, SagaID: sagaID, Payload: payload,
		}); err != nil {
			t.Fatal(err)
		}
	}
	putFor("sg_paid", evidence.KindEffectHeld, &janusv1.EffectHeld{
		EffectId: "ef-frozen", SagaId: "sg_paid", StepId: "settle",
		Target: "ledger", Action: "settle.post", IdemKey: "idem-frozen",
	})
	putFor("sg_paid", evidence.KindEffectReleasing, &janusv1.EffectReleasing{
		EffectId: "ef-frozen", SagaId: "sg_paid", Attempt: 1, IdemKey: "idem-frozen",
		CommitRoot: []byte("root"),
	})
	putFor("sg_paid", evidence.KindEffectDelivered, &janusv1.EffectDelivered{
		EffectId: "ef-frozen", SagaId: "sg_paid", Attempt: 1,
		Outcome: &janusv1.Outcome{
			Status: janusv1.Outcome_STATUS_TERMINAL_ERROR, Message: "ledger closed the period",
		},
	})
	putFor("sg_paid", evidence.KindEffectQuarantined, &janusv1.EffectQuarantined{
		EffectId: "ef-frozen", SagaId: "sg_paid", Attempts: 1,
		Reason: "attempts exhausted", LastError: "ledger closed the period",
	})

	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestTheQuarantineListFindsAFrozenEffectOnACommittedSaga.
//
// The finding this closes was not that quarantine was broken. It was that the
// only way to see a frozen effect was to open the page of the saga that produced
// it, and that saga is normally COMMITTED — a saga nobody has any reason to
// open, on a front page that showed no quarantine count at all because the count
// it showed was of sagas. So the bar is that the effect is reachable without
// knowing anything: not its saga id, not its effect id.
func TestTheQuarantineListFindsAFrozenEffectOnACommittedSaga(t *testing.T) {
	board, err := console.Open(richLog(t)).Quarantine()
	if err != nil {
		t.Fatal(err)
	}
	if len(board.Items) != 1 {
		t.Fatalf("the quarantine list has %d row(s); the log holds exactly one frozen "+
			"effect: %s", len(board.Items), jsonOf(t, board))
	}
	got := board.Items[0]
	if got.EffectID != "ef-frozen" {
		t.Errorf("the frozen effect is %q, want ef-frozen", got.EffectID)
	}
	// The row has to carry what somebody reconciling by hand actually needs: the
	// key the target deduplicates on, whether the effect might already be in the
	// world, and what the target said. A list that only named the effect would
	// send them back to the saga page this exists to replace.
	if got.IdemKey != "idem-frozen" {
		t.Errorf("the row has no idempotency key (%q); it is what a person searches "+
			"the target's own records for", got.IdemKey)
	}
	if got.Target != "ledger" || got.Action != "settle.post" {
		t.Errorf("the row does not say what was asked of whom: target %q action %q",
			got.Target, got.Action)
	}
	if !got.MayHaveLanded {
		t.Error("an effect with an announced attempt is reported as certainly not landed; " +
			"it may have, and reconciliation starts from that")
	}
	if got.LastError == "" || got.Reason == "" {
		t.Errorf("the row does not say why it is frozen: reason %q last error %q",
			got.Reason, got.LastError)
	}
	// The saga's standing is the part that makes the page legible. If this
	// stopped saying COMMITTED, the reader would go looking for a quarantined
	// saga that does not exist.
	if got.SagaStatus != "COMMITTED" {
		t.Errorf("the frozen effect's saga reads as %q; it is COMMITTED, and saying so is "+
			"the whole reason the row carries it", got.SagaStatus)
	}

	// And the overview has to point at it. The old page rendered its quarantine
	// count only when it was non-zero and counted sagas, so this deployment —
	// one frozen payment — rendered nothing.
	over, err := console.Open(richLog(t)).Overview()
	if err != nil {
		t.Fatal(err)
	}
	if over.QuarantinedEffects != 1 {
		t.Errorf("the overview counts %d frozen effect(s), want 1", over.QuarantinedEffects)
	}
	if over.Quarantined != 1 {
		t.Errorf("the overview counts %d quarantined saga(s), want 1 (sg_stuck); the two "+
			"numbers are independent and both belong on the page", over.Quarantined)
	}
}

// TestTheProjectedQuarantineListIsTheSameList.
//
// The projection chooses which sagas to look at and nothing else. This is the
// half of that claim that says the shortlist changed no answer.
func TestTheProjectedQuarantineListIsTheSameList(t *testing.T) {
	dir := richLog(t)
	store := consoleStore(t, dir)

	fromLog, err := console.Open(dir).Quarantine()
	if err != nil {
		t.Fatal(err)
	}
	fromProjection, err := console.Open(dir).WithProjection(store).Quarantine()
	if err != nil {
		t.Fatal(err)
	}
	if !fromProjection.Projected {
		t.Error("the projection-backed quarantine list does not say the shortlist came " +
			"from the projection")
	}
	if fromProjection.AsOf == 0 {
		t.Error("the projection-backed quarantine list does not say which sequence it is as of")
	}
	if len(fromLog.Items) == 0 {
		t.Fatal("the log holds no frozen effect, so this comparison would pass on a bug")
	}
	fromLog.AsOf, fromProjection.AsOf = 0, 0
	fromLog.Projected, fromProjection.Projected = false, false
	if want, got := jsonOf(t, fromLog), jsonOf(t, fromProjection); want != got {
		t.Errorf("the projected quarantine list is a different list.\n--- log ---\n%s\n"+
			"--- projection ---\n%s", want, got)
	}
}

// TestTheProjectionCannotPutAnEffectOnTheQuarantineList.
//
// This is the test the schema comment is written against, and it is a different
// claim from "the column is folded correctly". `quarantined_effects` says which
// sagas are worth replaying; it does not say what is frozen on them, and there
// is deliberately no effect id in those tables for it to say it with (invariant
// I1). A console that trusted the count would put a row on the
// operator's work list that no evidence supports.
//
// So: point the column at a saga with nothing frozen in its log, and require the
// list to be unmoved. Break it by having the board believe the count and this
// goes red; break the fold instead and it stays green, which is the point —
// the two failures are not the same failure.
func TestTheProjectionCannotPutAnEffectOnTheQuarantineList(t *testing.T) {
	dir := richLog(t)
	store, dsn := consoleStoreDSN(t, dir)

	before, err := console.Open(dir).WithProjection(store).Quarantine()
	if err != nil {
		t.Fatal(err)
	}

	// sg_child holds one effect and one delivered effect, and nothing frozen.
	// The column is written to as the daemon would write it if the fold were
	// wrong, or as anyone with the database would write it.
	writeToProjection(t, dsn,
		`UPDATE sagas SET quarantined_effects = 1 WHERE saga_id = 'sg_child'`)

	after, err := console.Open(dir).WithProjection(store).Quarantine()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range after.Items {
		if item.SagaID == "sg_child" {
			t.Fatalf("the projection put an effect on the work list: %s\n"+
				"sg_child has no quarantined effect in the log, and a column said it did",
				jsonOf(t, item))
		}
	}
	if want, got := jsonOf(t, before.Items), jsonOf(t, after.Items); want != got {
		t.Errorf("a column changed the work list.\n--- before ---\n%s\n--- after ---\n%s",
			want, got)
	}
}
