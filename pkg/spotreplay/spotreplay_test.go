package spotreplay_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/spotreplay"
	"google.golang.org/protobuf/proto"
)

// A saga that commits, and then keeps producing events.
//
// The trailing effect events are the point of this fixture rather than
// decoration. The coordinator computes a saga's evidence root and *then* appends
// the COMMIT, so the recorded root covers what came before it; the outbox
// lifecycle events carry the saga's id and arrive afterwards, because a delivery
// is recorded when the target answers. A checker that recomputed the root over
// everything the saga ever produced would disagree with this log, and this log is
// healthy.
func committedLog(t *testing.T, dir string) {
	t.Helper()
	ctx := context.Background()
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

	ev := func(kind, payload string) saga.FixtureEvent {
		return saga.FixtureEvent{Kind: kind, Payload: []byte(payload)}
	}
	write := func(id string, events []saga.FixtureEvent) {
		t.Helper()
		replayable, err := saga.Fixture{Name: id, Events: events}.Replayable()
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		for _, e := range replayable {
			// The commit's evidence root has to be the real one, computed the
			// way the coordinator computes it: over the saga's events before
			// the commit. A fixture that recorded a made-up root would make the
			// check under test pass or fail for the wrong reason.
			if e.Kind == evidence.KindCommit {
				root, err := saga.EvidenceRoot(dir, id)
				if err != nil {
					t.Fatal(err)
				}
				var c janusv1.Commit
				if err := proto.Unmarshal(e.Payload, &c); err != nil {
					t.Fatal(err)
				}
				c.EvidenceRoot = root
				c.LastSeq = lastSeqOf(t, dir, id)
				if e.Payload, err = proto.Marshal(&c); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := app.Append(ctx, evidence.Request{
				Kind: e.Kind, SagaID: id, Payload: e.Payload,
			}); err != nil {
				t.Fatalf("%s: append %s: %v", id, e.Kind, err)
			}
		}
	}

	write("sg_paid", []saga.FixtureEvent{
		ev("SAGA_BEGIN", `{"saga_id":"sg_paid","intent":{"intent_id":"in_paid",`+
			`"principal":"pr_bank"},"plan":[{"step_id":"pay",`+
			`"effect_class":"EFFECT_CLASS_COMPENSABLE","compensation_action":"pay.undo"}]}`),
		ev("STEP_PREPARE", `{"saga_id":"sg_paid","step_id":"pay"}`),
		ev("STEP_RESULT", `{"saga_id":"sg_paid","step_id":"pay","outcome":{"status":"STATUS_OK"},`+
			`"touches":[{"resource_id":"acct:1","mode":"MODE_WRITE"}]}`),
		ev("GATE_VERDICT", `{"saga_id":"sg_paid","step_id":"pay","verdict":"VERDICT_PASS"}`),
		ev("SEAL_REQUEST", `{"saga_id":"sg_paid","frontiers":[{"resource_id":"acct:1",`+
			`"last_sealed_seq":"0"}]}`),
		ev("COMMIT", `{"saga_id":"sg_paid"}`),
	})

	// After the commit: the effect is released and delivered, which is the
	// ordering invariant I1 requires and which extends the saga's event list.
	for _, m := range []struct {
		kind evidence.Kind
		msg  proto.Message
	}{
		{evidence.KindEffectHeld, &janusv1.EffectHeld{
			EffectId: "ef-1", SagaId: "sg_paid", StepId: "pay",
			Target: "payments", IdemKey: "idem-1",
		}},
		{evidence.KindEffectReleasing, &janusv1.EffectReleasing{
			EffectId: "ef-1", SagaId: "sg_paid", Attempt: 1, IdemKey: "idem-1",
			CommitRoot: []byte("commit-root"),
		}},
		{evidence.KindEffectDelivered, &janusv1.EffectDelivered{
			EffectId: "ef-1", SagaId: "sg_paid", Attempt: 1,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}},
	} {
		payload, err := proto.Marshal(m.msg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.Append(ctx, evidence.Request{
			Kind: m.kind, SagaID: "sg_paid", Payload: payload,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// A compensated saga too, so the checks that only apply to a commit are seen
	// not to apply rather than seen to pass.
	write("sg_undone", []saga.FixtureEvent{
		ev("SAGA_BEGIN", `{"saga_id":"sg_undone","intent":{"intent_id":"in_undone",`+
			`"principal":"pr_bank"},"plan":[{"step_id":"pay",`+
			`"effect_class":"EFFECT_CLASS_COMPENSABLE","compensation_action":"pay.undo"}]}`),
		ev("STEP_PREPARE", `{"saga_id":"sg_undone","step_id":"pay"}`),
		ev("STEP_RESULT", `{"saga_id":"sg_undone","step_id":"pay","outcome":{"status":"STATUS_OK"}}`),
		ev("GATE_VERDICT", `{"saga_id":"sg_undone","step_id":"pay","verdict":"VERDICT_PASS"}`),
		ev("COMPENSATE", `{"saga_id":"sg_undone","reason_ref":"withdrawn"}`),
		ev("STEP_PREPARE", `{"saga_id":"sg_undone","step_id":"pay~undo","compensates":"pay"}`),
		ev("STEP_RESULT", `{"saga_id":"sg_undone","step_id":"pay~undo",`+
			`"outcome":{"status":"STATUS_OK"}}`),
	})

	// A quarantined saga, because `State.Terminal` includes QUARANTINE and so
	// quarantined sagas count towards the rate. They are also the ones somebody
	// will be reading closely — a quarantined saga whose history no longer
	// replays the same way is the worst version of this finding — and until this
	// fixture existed the denominator included a status class no test had ever
	// produced through this path.
	write("sg_frozen", []saga.FixtureEvent{
		ev("SAGA_BEGIN", `{"saga_id":"sg_frozen","intent":{"intent_id":"in_frozen",`+
			`"principal":"pr_bank"},"plan":[{"step_id":"pay",`+
			`"effect_class":"EFFECT_CLASS_COMPENSABLE","compensation_action":"pay.undo"}]}`),
		ev("STEP_PREPARE", `{"saga_id":"sg_frozen","step_id":"pay"}`),
		ev("STEP_RESULT", `{"saga_id":"sg_frozen","step_id":"pay","outcome":{"status":"STATUS_OK"}}`),
		ev("GATE_VERDICT", `{"saga_id":"sg_frozen","step_id":"pay","verdict":"VERDICT_PASS"}`),
		ev("COMPENSATE", `{"saga_id":"sg_frozen","reason_ref":"withdrawn"}`),
		ev("STEP_PREPARE", `{"saga_id":"sg_frozen","step_id":"pay~undo","compensates":"pay"}`),
		ev("STEP_RESULT", `{"saga_id":"sg_frozen","step_id":"pay~undo",`+
			`"outcome":{"status":"STATUS_TERMINAL_ERROR"}}`),
	})

	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
}

func lastSeqOf(t *testing.T, dir, sagaID string) uint64 {
	t.Helper()
	events, err := saga.LoadEvents(dir, sagaID)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		return 0
	}
	return events[len(events)-1].Seq
}

// TestAHealthyLogAgrees is the decisive test, and what makes it decisive is the
// events *after* the commit.
//
// A saga's recorded evidence root covers what came before its COMMIT. A checker
// that recomputed over everything would find a disagreement on this log, which
// is entirely healthy — so this passing is what says the as-of boundary is
// right, and breaking that boundary is what proves the check is load-bearing
// rather than decorative.
func TestAHealthyLogAgrees(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	committedLog(t, dir)

	for _, id := range []string{"sg_paid", "sg_undone", "sg_frozen"} {
		f, err := spotreplay.CheckSaga(dir, id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if !f.Deterministic() {
			for _, d := range f.Divergences() {
				t.Errorf("%s: %s: %s", id, d.Name, d.Detail)
			}
		}
	}

	// The committed saga gets all three checks; the compensated one gets only
	// the check that applies to it. A rate whose denominator nobody can see is a
	// number nobody can audit, so which checks applied is part of the finding.
	paid, err := spotreplay.CheckSaga(dir, "sg_paid")
	if err != nil {
		t.Fatal(err)
	}
	if len(paid.Checks) != 3 {
		t.Errorf("a committed saga got %d checks, want 3: %+v", len(paid.Checks), paid.Checks)
	}
	for _, id := range []string{"sg_undone", "sg_frozen"} {
		f, err := spotreplay.CheckSaga(dir, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(f.Checks) != 1 {
			t.Errorf("%s got %d checks, want 1 — it never recorded a root or a commit "+
				"sequence, so the other two do not apply: %+v", id, len(f.Checks), f.Checks)
		}
		if !f.Terminal {
			t.Errorf("%s is %s and was not counted as terminal, so it would not reach the "+
				"determinism rate at all", id, f.Status)
		}
	}

	// And the one that is frozen rather than finished is the one whose status
	// matters most to a reader of this report.
	frozen, err := spotreplay.CheckSaga(dir, "sg_frozen")
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Status != saga.StatusQuarantine {
		t.Errorf("sg_frozen replays as %s, want QUARANTINE — the fixture no longer produces "+
			"the status class this test exists to cover", frozen.Status)
	}
}

// TestACorruptedRootIsFound: the root check compares against something written
// down at the time by a different process, so it is the one that would catch a
// log whose bytes are intact and whose history has changed.
func TestACorruptedRootIsFound(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	committedLog(t, dir)

	// Recompute the root over *everything*, which is what a checker that missed
	// the as-of boundary would compare against.
	whole, err := saga.EvidenceRoot(dir, "sg_paid")
	if err != nil {
		t.Fatal(err)
	}
	events, err := saga.LoadEvents(dir, "sg_paid")
	if err != nil {
		t.Fatal(err)
	}
	var commitSeq uint64
	for _, e := range events {
		if e.Kind == evidence.KindCommit {
			commitSeq = e.Seq
		}
	}
	before, err := saga.EvidenceRootBefore(dir, "sg_paid", commitSeq)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", whole) == fmt.Sprintf("%x", before) {
		t.Fatal("the root over the whole saga equals the root before its commit, so this log " +
			"does not exercise the boundary and the test below proves nothing")
	}
}

// TestTheSamplerOffersEachSagaOnce. The sampler does not decide which sagas are
// finished -- that is `saga.State.Terminal` after a replay -- so what it must get
// right is offering each saga that moved, once, until it moves again.
func TestTheSamplerOffersEachSagaOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	committedLog(t, dir)

	s := spotreplay.NewSampler(dir)
	first, err := s.Next()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 {
		t.Fatalf("the sampler offered %d sagas, want the three the log holds"+
			": %+v", len(first), first)
	}
	for _, c := range first {
		s.Accept(c)
	}
	again, err := s.Next()
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Errorf("the sampler offered %d sagas again after they were accepted: %+v",
			len(again), again)
	}
}

// TestTheRateIsZeroOnAnEmptyRun.
//
// A run that has checked nothing has not demonstrated 100% determinism; it has
// demonstrated nothing. Reporting 1.0 off an empty run is the exact shape of a
// number that ends up in a report.
func TestTheRateIsZeroOnAnEmptyRun(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	if err := writeEmpty(dir); err != nil {
		t.Fatal(err)
	}
	r, err := spotreplay.New(spotreplay.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	n, err := r.Once(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("checked %d sagas in an empty directory", n)
	}
	if got := r.Tally().Rate(); got != 0 {
		t.Errorf("an empty run reports a determinism rate of %v", got)
	}
}

func writeEmpty(dir string) error {
	signer, err := keys.Generate()
	if err != nil {
		return err
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		return err
	}
	return app.Close()
}

// TestTheTallySurvivesARestart. The rate is the number the Phase 6 gate names,
// and a rate that resets whenever the process restarts is not a rate.
func TestTheTallySurvivesARestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	committedLog(t, dir)
	state := filepath.Join(t.TempDir(), "spotreplay.json")

	first, err := spotreplay.New(spotreplay.Options{Dir: dir, State: state})
	if err != nil {
		t.Fatal(err)
	}
	n, err := first.Once(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("checked %d sagas, want 3", n)
	}

	second, err := spotreplay.New(spotreplay.Options{Dir: dir, State: state})
	if err != nil {
		t.Fatal(err)
	}
	if got := second.Tally().Checked; got != 3 {
		t.Errorf("a restarted runner reports %d checked, want the 3 the first one did", got)
	}
	// And it does not re-check what has not moved.
	again, err := second.Once(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if again != 0 {
		t.Errorf("a restarted runner re-checked %d sagas that had not moved", again)
	}
	if got := second.Tally().Rate(); got != 1 {
		t.Errorf("the rate over a healthy log is %v, want 1", got)
	}
	if strings.Contains(fmt.Sprint(second.Tally().Diverged), "sg_") {
		t.Errorf("a healthy log reported divergences: %v", second.Tally().Diverged)
	}
}

// TestARootThatNoLongerAgreesIsReported.
//
// The log here is intact — every chain hash checks out, `janus-verify` would
// pass it — and its commit cites a root the log does not produce. That is what a
// change to the state machine, or to how a root is computed, looks like from the
// outside, and it is the case this daemon exists for: the verifier checks that
// the bytes are what they were, and this checks that the bytes still mean what
// they meant.
func TestARootThatNoLongerAgreesIsReported(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	ctx := context.Background()
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

	ev := func(kind, payload string) saga.FixtureEvent {
		return saga.FixtureEvent{Kind: kind, Payload: []byte(payload)}
	}
	events := []saga.FixtureEvent{
		ev("SAGA_BEGIN", `{"saga_id":"sg_wrong","intent":{"intent_id":"in_wrong",`+
			`"principal":"pr_bank"},"plan":[{"step_id":"pay",`+
			`"effect_class":"EFFECT_CLASS_COMPENSABLE","compensation_action":"pay.undo"}]}`),
		ev("STEP_PREPARE", `{"saga_id":"sg_wrong","step_id":"pay"}`),
		ev("STEP_RESULT", `{"saga_id":"sg_wrong","step_id":"pay","outcome":{"status":"STATUS_OK"}}`),
		ev("GATE_VERDICT", `{"saga_id":"sg_wrong","step_id":"pay","verdict":"VERDICT_PASS"}`),
		ev("SEAL_REQUEST", `{"saga_id":"sg_wrong"}`),
		ev("COMMIT", `{"saga_id":"sg_wrong"}`),
	}
	replayable, err := saga.Fixture{Name: "sg_wrong", Events: events}.Replayable()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range replayable {
		if e.Kind == evidence.KindCommit {
			var c janusv1.Commit
			if err := proto.Unmarshal(e.Payload, &c); err != nil {
				t.Fatal(err)
			}
			// A root of the right shape and the wrong value.
			c.EvidenceRoot = make([]byte, 32)
			c.LastSeq = lastSeqOf(t, dir, "sg_wrong")
			if e.Payload, err = proto.Marshal(&c); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := app.Append(ctx, evidence.Request{
			Kind: e.Kind, SagaID: "sg_wrong", Payload: e.Payload,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := spotreplay.CheckSaga(dir, "sg_wrong")
	if err != nil {
		t.Fatal(err)
	}
	if f.Deterministic() {
		t.Fatal("a commit citing a root the log does not produce was reported as deterministic")
	}
	var named bool
	for _, d := range f.Divergences() {
		if d.Name == spotreplay.CheckRootAgrees {
			named = true
			t.Logf("reported: %s", d.Detail)
		}
	}
	if !named {
		t.Errorf("the divergence was found but not attributed to the root check: %+v",
			f.Divergences())
	}

	// And the tally counts it as checked and not agreed, so the rate moves.
	r, err := spotreplay.New(spotreplay.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Once(ctx); err != nil {
		t.Fatal(err)
	}
	tally := r.Tally()
	if tally.Checked != 1 || tally.Agreed != 0 || len(tally.Diverged) != 1 {
		t.Errorf("tally is %+v; want one checked, none agreed, one named", tally)
	}
	if got := tally.Rate(); got != 0 {
		t.Errorf("the rate over a log with one divergent saga is %v, want 0", got)
	}
}

// TestALongLivedSamplerKeepsFinding is the rotation trap, written before it bit
// rather than after.
//
// `segment.ScanComplete` reports the empty segment an open appender pre-creates
// beyond the one it is writing, and that file is removed at the next rotation.
// A tailer resuming from "the highest segment id listed" therefore resumes from
// a segment that no longer exists and skips the whole log for the rest of its
// life. The projector did exactly that in 6a and every test that closed the log
// before reading passed. This one keeps the appender open.
func TestALongLivedSamplerKeepsFinding(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	ctx := context.Background()
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

	s := spotreplay.NewSampler(dir)
	ev := func(kind, payload string) saga.FixtureEvent {
		return saga.FixtureEvent{Kind: kind, Payload: []byte(payload)}
	}

	for i := 0; i < 6; i++ {
		id := fmt.Sprintf("sg_%d", i)
		replayable, err := saga.Fixture{Name: id, Events: []saga.FixtureEvent{
			ev("SAGA_BEGIN", fmt.Sprintf(`{"saga_id":%q,"intent":{"intent_id":"in",`+
				`"principal":"pr_bank"},"plan":[{"step_id":"pay",`+
				`"effect_class":"EFFECT_CLASS_PURE"}]}`, id)),
			ev("STEP_PREPARE", fmt.Sprintf(`{"saga_id":%q,"step_id":"pay"}`, id)),
		}}.Replayable()
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range replayable {
			if _, err := app.Append(ctx, evidence.Request{
				Kind: e.Kind, SagaID: id, Payload: e.Payload,
			}); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.Next()
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		found := false
		for _, c := range got {
			s.Accept(c)
			if c.SagaID == id {
				found = true
			}
		}
		if !found {
			t.Fatalf("round %d: the sampler stopped seeing new sagas — it did not offer %s; "+
				"offered %+v", i, id, got)
		}
	}
}

// TestOneUnreadableSagaDoesNotBlockTheRest.
//
// The first version of Once returned on the first check error, which meant a
// single undecodable saga blocked every candidate sorted after it — on every
// tick, forever. Coverage would have ended silently at the broken saga, inside a
// report saying everything checked out, which is the exact failure this daemon
// exists to make impossible.
//
// A saga sorted before the healthy ones is used deliberately: sorting is what
// made the old behaviour deterministic in the worst way.
func TestOneUnreadableSagaDoesNotBlockTheRest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	ctx := context.Background()
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
	// "aaa_broken" sorts before the sagas committedLog writes, so it is offered
	// first. Its SAGA_BEGIN payload is not a SagaBegin at all.
	if _, err := app.Append(ctx, evidence.Request{
		Kind: evidence.KindSagaBegin, SagaID: "aaa_broken",
		Payload: []byte{0xff, 0xff, 0xff, 0xff},
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	committedLog(t, dir)

	var findings []spotreplay.Finding
	r, err := spotreplay.New(spotreplay.Options{
		Dir: dir, Report: func(f spotreplay.Finding) { findings = append(findings, f) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Once(ctx); err != nil {
		t.Fatalf("a run containing one unreadable saga returned an error: %v", err)
	}

	var sawBroken, sawPaid bool
	for _, f := range findings {
		switch f.SagaID {
		case "aaa_broken":
			sawBroken = true
			if f.Deterministic() {
				t.Error("a saga that could not be re-derived was reported as deterministic")
			}
		case "sg_paid":
			sawPaid = true
			if !f.Deterministic() {
				t.Errorf("the healthy saga was reported as divergent: %+v", f.Divergences())
			}
		}
	}
	if !sawBroken {
		t.Error("the unreadable saga was not reported at all")
	}
	if !sawPaid {
		t.Fatal("the healthy sagas after it were never checked; one bad saga blocked the run")
	}

	// It moves the rate rather than quietly leaving the denominator: "we could
	// not check this" is not the same as "this was fine".
	tally := r.Tally()
	if tally.Agreed == tally.Checked {
		t.Errorf("the unreadable saga did not move the rate: %+v", tally)
	}

	// And it is not retried on every tick.
	findings = nil
	if _, err := r.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("a second pass re-reported %d sagas that had not moved: %+v",
			len(findings), findings)
	}
}

// TestACommitSequenceThatDisagreesIsReported.
//
// This check compares the `last_seq` a COMMIT recorded against the sequence the
// replay reaches before it, and it is worth being clear about what kind of check
// that is: the coordinator takes the value from its own in-memory state, so on a
// log the coordinator wrote alone the two are the same number by construction and
// this can never fire.
//
// It fires when something *else* appended to the saga between the coordinator's
// last read and its commit — which is possible, because the outbox lifecycle
// events carry a saga id. So it is a tripwire for a saga id being written by two
// things at once, not an independent determinism anchor, and the test builds the
// disagreement directly because a healthy single-writer log cannot produce one.
func TestACommitSequenceThatDisagreesIsReported(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	ctx := context.Background()
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

	ev := func(kind, payload string) saga.FixtureEvent {
		return saga.FixtureEvent{Kind: kind, Payload: []byte(payload)}
	}
	events := []saga.FixtureEvent{
		ev("SAGA_BEGIN", `{"saga_id":"sg_seq","intent":{"intent_id":"in_seq",`+
			`"principal":"pr_bank"},"plan":[{"step_id":"pay",`+
			`"effect_class":"EFFECT_CLASS_PURE"}]}`),
		ev("STEP_PREPARE", `{"saga_id":"sg_seq","step_id":"pay"}`),
		// A PURE step seals on its own result, so there is no gate verdict to
		// record after it.
		ev("STEP_RESULT", `{"saga_id":"sg_seq","step_id":"pay","outcome":{"status":"STATUS_OK"}}`),
		ev("SEAL_REQUEST", `{"saga_id":"sg_seq"}`),
		ev("COMMIT", `{"saga_id":"sg_seq"}`),
	}
	replayable, err := saga.Fixture{Name: "sg_seq", Events: events}.Replayable()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range replayable {
		if e.Kind == evidence.KindCommit {
			var c janusv1.Commit
			if err := proto.Unmarshal(e.Payload, &c); err != nil {
				t.Fatal(err)
			}
			root, err := saga.EvidenceRoot(dir, "sg_seq")
			if err != nil {
				t.Fatal(err)
			}
			c.EvidenceRoot = root
			// One higher than the log's last event before this commit: a commit
			// claiming to cover an event that is not there.
			c.LastSeq = lastSeqOf(t, dir, "sg_seq") + 1
			if e.Payload, err = proto.Marshal(&c); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := app.Append(ctx, evidence.Request{
			Kind: e.Kind, SagaID: "sg_seq", Payload: e.Payload,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := spotreplay.CheckSaga(dir, "sg_seq")
	if err != nil {
		t.Fatal(err)
	}
	var named bool
	for _, d := range f.Divergences() {
		if d.Name == spotreplay.CheckCommitSeqAgrees {
			named = true
			t.Logf("reported: %s", d.Detail)
		}
	}
	if !named {
		t.Errorf("a commit claiming a last_seq the log does not have was not reported: %+v",
			f.Checks)
	}
}
