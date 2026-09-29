package saga_test

import (
	"strings"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

// A HUMAN requirement is answered by a person (semantics 4). The
// 2026-09-29 audit found a gated agent satisfying a four-eyes approval by
// answering in its own name with a role it claimed for itself, with signatures
// required and the relayers named: the check counted any answer that claimed
// the role, whoever gave it.

// humanGatedWire: a wire with a release-phase person approval, prepared and run,
// waiting at its release gate, then answered by `answer`.
func humanGatedWire(t *testing.T, version uint32, answer *janusv1.GateAnswer) []saga.Event {
	t.Helper()
	req := &janusv1.GateRequirement{
		Id: "four-eyes", Gate: janusv1.GateType_GATE_TYPE_HUMAN,
		Phase:          janusv1.GatePhase_GATE_PHASE_PRE_RELEASE,
		TimeoutSeconds: 60,
		Check: &janusv1.GateRequirement_Human{Human: &janusv1.HumanCheck{
			Roles: []string{"credit-officer"}, Quorum: 1,
		}},
	}
	return events(t, []rec{
		{evidence.KindSagaBegin, &janusv1.SagaBegin{
			SagaId: "sg", SemanticsVersion: version,
			Intent: &janusv1.Intent{IntentId: "in", Principal: "bob"},
			Plan: []*janusv1.PlannedStep{{
				StepId: "wire", Participant: "tool_payments",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
			}},
			GatePlan: []*janusv1.StepGates{{StepId: "wire", RuleId: "r",
				Require: []*janusv1.GateRequirement{req}}},
		}},
		{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED}},
		{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "wire", Attempt: 1,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK}}},
		{evidence.KindGateAnswer, answer},
	})
}

func participantAnswers(who string, v janusv1.Verdict) *janusv1.GateAnswer {
	return &janusv1.GateAnswer{
		SagaId: "sg", StepId: "wire", RequirementId: "four-eyes", Attempt: 1,
		Actor:   &janusv1.Actor{Participant: &janusv1.ParticipantRef{Id: who}},
		Verdict: v, Roles: []string{"credit-officer"}, Reason: "approved",
	}
}

// TestAPersonsApprovalIsGivenByAPerson: the agent, and the step's own tool,
// answering the four-eyes requirement in their own names are refused.
func TestAPersonsApprovalIsGivenByAPerson(t *testing.T) {
	for _, who := range []string{"ag_intake", "tool_payments"} {
		_, err := saga.Replay(humanGatedWire(t, 4, participantAnswers(who, janusv1.Verdict_VERDICT_PASS)))
		if err == nil {
			t.Fatalf("under semantics 4 participant %q answered a person's approval in its own "+
				"name, claiming the role, and it was taken", who)
		}
		if !strings.Contains(err.Error(), "is answered by a person") {
			t.Fatalf("%s: refused, but not because it is not a person: %v", who, err)
		}
	}
	person := participantAnswers("", janusv1.Verdict_VERDICT_PASS)
	person.Actor = &janusv1.Actor{HumanSubject: "person:alice@bank"}
	if _, err := saga.Replay(humanGatedWire(t, 4, person)); err != nil {
		t.Fatalf("a person's own approval was refused: %v", err)
	}
}

// TestAnExpiryIsStillRecordedByTheSystem: the daemon expires a person's gate
// with a FAIL answer of its own once the deadline has passed. That is not a
// person answering and must stay legal -- but only once the deadline is real.
func TestAnExpiryIsStillRecordedByTheSystem(t *testing.T) {
	h := humanGatedWire(t, 4, participantAnswers("ag_orchd", janusv1.Verdict_VERDICT_FAIL))
	// The gate opened at the result (event 3); the answer lands 61 s later.
	base := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	for i := range h {
		h[i].Wall = base
	}
	h[3].Wall = h[2].Wall.Add(61e9)
	if _, err := saga.Replay(h); err != nil {
		t.Fatalf("the system's expiry of a person's gate, after its deadline, was refused: %v", err)
	}
	h[3].Wall = h[2].Wall.Add(10e9)
	if _, err := saga.Replay(h); err == nil {
		t.Fatal("a participant's FAIL on a person's gate before its deadline was taken as an expiry")
	}
}

// TestAPersonsGateAnsweredByAParticipantStillFoldsUnderVersionThree: a
// version-3 log may hold it; the audit names it (NOT_A_PERSON).
func TestAPersonsGateAnsweredByAParticipantStillFoldsUnderVersionThree(t *testing.T) {
	if _, err := saga.Replay(humanGatedWire(t, 3, participantAnswers("ag_intake", janusv1.Verdict_VERDICT_PASS))); err != nil {
		t.Fatalf("legal under semantics 3 and no longer folds: %v", err)
	}
}

// ungatedRetry: a step with no gates fails retryably on one amount and is
// retried on a corrected one (the 2026-09-29 audit, m-3).
func ungatedRetry(t *testing.T, version uint32) []saga.Event {
	t.Helper()
	amount := func(n int64) []*janusv1.Fact {
		return []*janusv1.Fact{{Key: "amount_minor", Value: &janusv1.Fact_Number{Number: n}}}
	}
	return events(t, []rec{
		{evidence.KindSagaBegin, &janusv1.SagaBegin{
			SagaId: "sg", SemanticsVersion: version,
			Intent: &janusv1.Intent{IntentId: "in", Principal: "bob"},
			Plan: []*janusv1.PlannedStep{{StepId: "wire", MaxRetries: 1,
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE, CompensationAction: "refund"}},
		}},
		{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "wire", Facts: amount(100),
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE}},
		{evidence.KindStepResult, &janusv1.StepResult{SagaId: "sg", StepId: "wire", Attempt: 1,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_RETRYABLE_ERROR}}},
		{evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "wire", Facts: amount(90),
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE}},
	})
}

// TestARetryOfAnUngatedStepMayCorrectItsFacts: no gate judged the first
// attempt's facts, so nothing binds the second attempt to them. Under 3 the
// comparison fired anyway, and its message blamed gates that did not exist.
func TestARetryOfAnUngatedStepMayCorrectItsFacts(t *testing.T) {
	if _, err := saga.Replay(ungatedRetry(t, 4)); err != nil {
		t.Fatalf("under semantics 4 a retry of an ungated step with corrected facts was refused: %v", err)
	}
	if _, err := saga.Replay(ungatedRetry(t, 3)); err == nil {
		t.Fatal("semantics 3 refused this history and must go on refusing it")
	}
}

// TestAStepIdHasNoDot: `result.<step>.<key>` names one fact only if a step id
// cannot contain the separator; with step "credit.limit" publishing "ok" and
// step "credit" publishing "limit.ok", both were `result.credit.limit.ok`.
func TestAStepIdHasNoDot(t *testing.T) {
	h := events(t, []rec{{evidence.KindSagaBegin, &janusv1.SagaBegin{
		SagaId: "sg", SemanticsVersion: 4,
		Intent: &janusv1.Intent{IntentId: "in", Principal: "bob"},
		Plan:   []*janusv1.PlannedStep{{StepId: "credit.limit", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE}},
	}}})
	if _, err := saga.Replay(h); err == nil || !strings.Contains(err.Error(), "may not contain") {
		t.Fatalf("under semantics 4 a step id with a '.' was admitted: %v", err)
	}
}
