package saga_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

func mustMarshal(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ev(t *testing.T, seq uint64, kind evidence.Kind, m proto.Message) saga.Event {
	t.Helper()
	return saga.Event{Seq: seq, Kind: kind, Payload: mustMarshal(t, m)}
}

// ---- gate helpers -------------------------------------------------------------
//
// Every effectful step now has to say what judges it, so most tests need a gate
// plan. These build the smallest honest one: a single policy check on a flag
// the step declares. Building them here rather than resolving a policy keeps
// these tests on the state machine, which enforces the *structure* of gating
// without ever reading a policy document.

const testPolicy = "blake3:" +
	"1111111111111111111111111111111111111111111111111111111111111111"

// gateOn returns a requirement decided at the named phase, passing when the
// step declares approved=true.
func gateOn(id, phase string) *janusv1.GateRequirement {
	return &janusv1.GateRequirement{
		Id:    id,
		Gate:  janusv1.GateType_GATE_TYPE_POLICY,
		Phase: janusv1.GatePhase(janusv1.GatePhase_value["GATE_PHASE_"+phase]),
		Check: &janusv1.GateRequirement_Policy{
			Policy: &janusv1.PolicyCheck{Expr: "approved == true"},
		},
	}
}

// plannedGates attaches a requirement list to a step in a saga's plan.
func plannedGates(stepID, phase string) *janusv1.StepGates {
	return &janusv1.StepGates{
		StepId:  stepID,
		RuleId:  "test-rule",
		Require: []*janusv1.GateRequirement{gateOn(stepID+"-gate", phase)},
	}
}

// releaseRequirements lists the ids a step's release verdict has to cover.
func releaseRequirements(begin *janusv1.SagaBegin, stepID string) []string {
	var out []string
	for _, g := range begin.GetGatePlan() {
		if g.GetStepId() != stepID {
			continue
		}
		for _, r := range g.GetRequire() {
			if r.GetPhase() == janusv1.GatePhase_GATE_PHASE_PRE_RELEASE {
				out = append(out, r.GetId())
			}
		}
	}
	return out
}

// verdict builds a composite verdict covering a step's single requirement.
func verdict(sagaID, stepID string, v janusv1.Verdict, reason string) *janusv1.GateVerdict {
	return &janusv1.GateVerdict{
		SagaId: sagaID, StepId: stepID,
		Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
		Verdict: v,
		Reason:  reason,
		Decided: []string{stepID + "-gate"},
	}
}

func pureplan(sagaID string) *janusv1.SagaBegin {
	return &janusv1.SagaBegin{
		SagaId: sagaID,
		Intent: &janusv1.Intent{IntentId: "in_1", Principal: "pr_1"},
		Plan: []*janusv1.PlannedStep{{
			StepId:      "st_1",
			Participant: "ag_1",
			Action:      "docs.read",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
		}},
	}
}

// TestAdmissionRequiresCompensation is invariant I3 at admission time: a saga is
// refused before it starts if a step that touches the world cannot say how it
// would be undone. Discovering that mid-saga is discovering it too late.
func TestAdmissionRequiresCompensation(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1",
		Plan: []*janusv1.PlannedStep{{
			StepId:      "st_pay",
			Participant: "tool_payments",
			Action:      "payments.create",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			// No CompensationAction.
		}},
	}
	if _, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin)); !errors.Is(err, saga.ErrNotAdmitted) {
		t.Fatalf("got %v, want ErrNotAdmitted", err)
	}

	begin.Plan[0].CompensationAction = "payments.refund"
	if _, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin)); err != nil {
		t.Fatalf("a compensable step with a declared compensation should be admitted: %v", err)
	}
}

// An irreversible step is admitted without a compensation because none can
// exist — but only when a gate stands in for it. Both halves are invariant I3,
// and the second half is what stops the effect class from being a label a plan
// can apply to anything it does not want to have to undo.
func TestAdmissionAllowsIrreversibleWithAGateInsteadOfACompensation(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1",
		Plan: []*janusv1.PlannedStep{{
			StepId:      "st_wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	}

	// Neither a compensation nor a gate: the step would be unstoppable and
	// unrecoverable, which is the one combination admission exists to refuse.
	_, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin))
	if !errors.Is(err, saga.ErrNotAdmitted) {
		t.Fatalf("got %v, want an ungated irreversible step to be refused", err)
	}
	// The reason has to be the one that fits: no policy covers this step at
	// all. A neighbouring check refuses the same plan for a narrower reason —
	// that the gates it has are all decided too early — and sending an author
	// after that when they have written no rule at all is a wasted afternoon.
	if !strings.Contains(err.Error(), "no gate policy covers it") {
		t.Fatalf("the refusal blames the wrong thing: %v", err)
	}

	begin.GatePolicyVersion = testPolicy
	begin.GatePlan = []*janusv1.StepGates{plannedGates("st_wire", "PRE_RELEASE")}
	if _, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin)); err != nil {
		t.Fatalf("an irreversible step with a gate needs no compensation: %v", err)
	}
}

// An IRREVERSIBLE_GATED step whose only gates run after it does is not
// protected: the outbox is holding an effect nothing will ever judge.
func TestAdmissionRejectsGatedEffectJudgedOnlyBeforeItRuns(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId:            "sg_1",
		GatePolicyVersion: testPolicy,
		Plan: []*janusv1.PlannedStep{{
			StepId:      "st_wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		GatePlan: []*janusv1.StepGates{plannedGates("st_wire", "PRE_EXECUTION")},
	}
	_, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin))
	if !errors.Is(err, saga.ErrNotAdmitted) {
		t.Fatalf("got %v, want a held effect that nothing judges to be refused", err)
	}
}

// The mirror image: an immediate irreversible effect judged only afterwards is
// judged too late, because there is no outbox holding it back.
func TestAdmissionRejectsImmediateEffectJudgedOnlyAfterItRuns(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId:            "sg_1",
		GatePolicyVersion: testPolicy,
		Plan: []*janusv1.PlannedStep{{
			StepId:      "st_send",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE,
		}},
		GatePlan: []*janusv1.StepGates{plannedGates("st_send", "PRE_RELEASE")},
	}
	_, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin))
	if !errors.Is(err, saga.ErrNotAdmitted) {
		t.Fatalf("got %v, want an immediate effect gated only after the fact to be refused", err)
	}
}

func TestAdmissionRejectsUnclassifiedStep(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1",
		Plan:   []*janusv1.PlannedStep{{StepId: "st_1"}},
	}
	if _, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin)); !errors.Is(err, saga.ErrNotAdmitted) {
		t.Fatalf("got %v, want a step with no effect class to be refused", err)
	}
}

func TestAdmissionRejectsDependencyCycle(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1",
		Plan: []*janusv1.PlannedStep{
			{StepId: "a", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE, DependsOn: []string{"b"}},
			{StepId: "b", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE, DependsOn: []string{"a"}},
		},
	}
	// Compensation runs in reverse topological order, and a cycle has none.
	if _, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin)); !errors.Is(err, saga.ErrNotAdmitted) {
		t.Fatalf("got %v, want a cyclic plan to be refused", err)
	}
}

func TestAdmissionRejectsMissingDependency(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1",
		Plan: []*janusv1.PlannedStep{
			{StepId: "a", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE, DependsOn: []string{"ghost"}},
		},
	}
	if _, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin)); !errors.Is(err, saga.ErrNotAdmitted) {
		t.Fatalf("got %v, want a dangling dependency to be refused", err)
	}
}

// TestCommitRequiresSeal: a saga must complete its footprint before it commits,
// because commit is what releases held effects (invariant I4).
func TestCommitRequiresSeal(t *testing.T) {
	s, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, pureplan("sg_1")))
	if err != nil {
		t.Fatal(err)
	}
	_, err = saga.Apply(s, ev(t, 2, evidence.KindCommit, &janusv1.Commit{SagaId: "sg_1"}))
	if !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("got %v, want committing an unsealed saga to be refused", err)
	}
}

func TestSealRequiresEveryStepSealed(t *testing.T) {
	s, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, pureplan("sg_1")))
	if err != nil {
		t.Fatal(err)
	}
	_, err = saga.Apply(s, ev(t, 2, evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg_1"}))
	if !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("got %v, want sealing with an unfinished step to be refused", err)
	}
}

// TestEffectfulStepWaitsForAGate: only a PURE step may seal on its own result.
// Anything that touches the world stops and waits, which is what keeps an
// irreversible effect from escaping before the saga commits.
func TestEffectfulStepWaitsForAGate(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1",
		Plan: []*janusv1.PlannedStep{{
			StepId:             "st_pay",
			EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: "payments.refund",
		}},
	}
	s, err := saga.Replay([]saga.Event{
		ev(t, 1, evidence.KindSagaBegin, begin),
		ev(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg_1", StepId: "st_pay"}),
		ev(t, 3, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg_1", StepId: "st_pay",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	step, _ := s.Step("st_pay")
	if step.Status != saga.StepGated {
		t.Fatalf("a COMPENSABLE step settled at %s without a gate", step.Status)
	}
	if s.Status != saga.StatusGated {
		t.Fatalf("saga is %s, want GATED", s.Status)
	}

	// Sealing must still be refused while the step is gated.
	if _, err := saga.Apply(s, ev(t, 4, evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg_1"})); !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("got %v, want sealing to be refused while a step is gated", err)
	}

	// A passing gate releases it.
	s, err = saga.Apply(s, ev(t, 4, evidence.KindGateVerdict, &janusv1.GateVerdict{
		SagaId: "sg_1", StepId: "st_pay",
		Gate: janusv1.GateType_GATE_TYPE_POLICY, Verdict: janusv1.Verdict_VERDICT_PASS,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if step, _ := s.Step("st_pay"); step.Status != saga.StepSealed {
		t.Fatalf("step is %s after a passing gate, want SEALED", step.Status)
	}
}

func TestFailedGateSendsSagaToCompensating(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId:            "sg_1",
		GatePolicyVersion: testPolicy,
		Plan: []*janusv1.PlannedStep{{
			StepId:             "st_pay",
			EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: "payments.refund",
		}},
		GatePlan: []*janusv1.StepGates{plannedGates("st_pay", "PRE_RELEASE")},
	}
	s, err := saga.Replay([]saga.Event{
		ev(t, 1, evidence.KindSagaBegin, begin),
		ev(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg_1", StepId: "st_pay"}),
		ev(t, 3, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg_1", StepId: "st_pay", Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}),
		ev(t, 4, evidence.KindGateVerdict, verdict("sg_1", "st_pay",
			janusv1.Verdict_VERDICT_FAIL, "amount exceeds the manifest limit")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Status != saga.StatusCompensating {
		t.Fatalf("saga is %s after a failed gate, want COMPENSATING", s.Status)
	}
	if s.AbortReason == "" {
		t.Fatal("no reason was recorded for the compensation")
	}
}

func TestStepCannotStartBeforeItsDependency(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1",
		Plan: []*janusv1.PlannedStep{
			{StepId: "a", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
			{StepId: "b", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE, DependsOn: []string{"a"}},
		},
	}
	s, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saga.Apply(s, ev(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg_1", StepId: "b"})); !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("got %v, want a step to be blocked by its unfinished dependency", err)
	}
}

func TestUnknownStepIsRejected(t *testing.T) {
	s, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, pureplan("sg_1")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saga.Apply(s, ev(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg_1", StepId: "ghost"})); !errors.Is(err, saga.ErrUnknownStep) {
		t.Fatalf("got %v, want ErrUnknownStep", err)
	}
}

func TestApplyDoesNotMutateItsInput(t *testing.T) {
	before, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, pureplan("sg_1")))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := before.Clone()

	if _, err := saga.Apply(before, ev(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg_1", StepId: "st_1"})); err != nil {
		t.Fatal(err)
	}
	if diff := saga.Diff(snapshot, before); len(diff) > 0 {
		t.Fatalf("Apply mutated the state it was given: %v", diff)
	}
}

// TestRunnerRejectsIllegalTransitionWithoutWriting: the log must contain only
// legal history, or replay over it could fail.
func TestRunnerRejectsIllegalTransitionWithoutWriting(t *testing.T) {
	app, dir, _ := newLog(t)
	defer app.Close()

	r := saga.NewRunner(app, evidence.ParticipantRef{ID: "ag_1"})
	ctx := context.Background()
	if _, err := r.Begin(ctx, pureplan("sg_1")); err != nil {
		t.Fatal(err)
	}
	// Commit without sealing.
	if _, err := r.Commit(ctx, &janusv1.Commit{SagaId: "sg_1"}); !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("got %v, want the runner to refuse an illegal transition", err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	events, err := saga.LoadEvents(dir, "sg_1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("log holds %d events; the rejected transition should not have been written", len(events))
	}
	if _, err := saga.Replay(events); err != nil {
		t.Fatalf("the log does not replay cleanly: %v", err)
	}
}

// TestReplayMatchesLiveExecution is invariant I5 for a full saga: rebuilding the
// projection from the log has to land exactly where execution did.
func TestReplayMatchesLiveExecution(t *testing.T) {
	app, dir, _ := newLog(t)
	ctx := context.Background()

	r := saga.NewRunner(app, evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1.0.0"})
	const sagaID = "sg_replay"

	begin := &janusv1.SagaBegin{
		SagaId: sagaID,
		Intent: &janusv1.Intent{IntentId: "in_1"},
		Plan: []*janusv1.PlannedStep{
			{StepId: "a", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
			{StepId: "b", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE, DependsOn: []string{"a"}},
		},
	}
	if _, err := r.Begin(ctx, begin); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if _, err := r.PrepareStep(ctx, &janusv1.StepPrepare{SagaId: sagaID, StepId: id}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.StepResult(ctx, &janusv1.StepResult{
			SagaId: sagaID, StepId: id, Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Seal(ctx, &janusv1.SealRequest{SagaId: sagaID}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Commit(ctx, &janusv1.Commit{SagaId: sagaID}); err != nil {
		t.Fatal(err)
	}
	live := r.State()
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	if live.Status != saga.StatusCommitted {
		t.Fatalf("saga ended at %s, want COMMITTED", live.Status)
	}

	replayed, err := saga.ReplaySaga(dir, sagaID)
	if err != nil {
		t.Fatal(err)
	}
	if diff := saga.Diff(live, replayed); len(diff) > 0 {
		t.Fatalf("replay diverged from execution: %v", diff)
	}

	// Replaying again must give the same answer; determinism that holds once is
	// not determinism.
	again, err := saga.ReplaySaga(dir, sagaID)
	if err != nil {
		t.Fatal(err)
	}
	if diff := saga.Diff(replayed, again); len(diff) > 0 {
		t.Fatalf("two replays of the same log disagreed: %v", diff)
	}
}

// TestReplayRefusesTamperedLog: replaying unverified bytes would let a doctored
// log dictate the reconstructed history.
func TestReplayRefusesTamperedLog(t *testing.T) {
	app, dir, _ := newLog(t)
	ctx := context.Background()
	r := saga.NewRunner(app, evidence.ParticipantRef{ID: "ag_1"})
	if _, err := r.Begin(ctx, pureplan("sg_1")); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	path := segment.Path(dir, 1)
	raw, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit inside the record area, past the file header.
	raw[len(raw)/2] ^= 0x01
	if err := writeFile(path, raw); err != nil {
		t.Fatal(err)
	}

	if _, err := saga.ReplaySaga(dir, "sg_1"); err == nil {
		t.Fatal("replay accepted a tampered log")
	}
}

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o600) }

func newLog(t *testing.T) (*evidence.Appender, string, *keys.Signer) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	return app, dir, signer
}
