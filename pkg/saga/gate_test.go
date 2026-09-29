package saga_test

import (
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

// What the pure state machine enforces about gates.
//
// It does not decide verdicts — that needs a policy, and a state machine that
// read one would stop being a pure function of the log. What it enforces is the
// structure around the decision: that a step judged before it runs is judged
// before it runs, that the step which runs is the one that was judged, and that
// a verdict letting a step through accounts for every requirement due.
//
// These are the checks a coordinator cannot skip, because they happen before
// the event is written rather than after. Everything else about gating is
// checkable only afterwards, by re-deriving the decision (pkg/gate audit).

func factText(key, v string) *janusv1.Fact {
	return &janusv1.Fact{Key: key, Value: &janusv1.Fact_Text{Text: v}}
}

func factNumber(key string, v int64) *janusv1.Fact {
	return &janusv1.Fact{Key: key, Value: &janusv1.Fact_Number{Number: v}}
}

// preGatedBegin is a plan whose one step is judged before it runs.
func preGatedBegin() *janusv1.SagaBegin {
	return &janusv1.SagaBegin{
		SagaId:            "sg",
		GatePolicyVersion: testPolicy,
		Intent:            &janusv1.Intent{IntentId: "in"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "send", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE,
		}},
		GatePlan: []*janusv1.StepGates{plannedGates("send", "PRE_EXECUTION")},
	}
}

// A step whose policy judges it beforehand may not run until that judgement is
// on the record. This is the check that gives a pre-execution gate teeth:
// everything else about gating can be skipped by a coordinator with a bug, and
// this cannot, because the transition is refused before it is written.
func TestAStepJudgedBeforeItRunsCannotRunFirst(t *testing.T) {
	s, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, preGatedBegin()))
	if err != nil {
		t.Fatal(err)
	}

	_, err = saga.Apply(s, ev(t, 2, evidence.KindStepPrepare,
		&janusv1.StepPrepare{SagaId: "sg", StepId: "send"}))
	if err == nil {
		t.Fatal("the step ran with no gate decision in front of it")
	}
	if !strings.Contains(err.Error(), "ahead of the decision that permits it") {
		t.Fatalf("the refusal does not explain itself: %v", err)
	}

	// With the verdict recorded, the same prepare is legal.
	pass := verdict("sg", "send", janusv1.Verdict_VERDICT_PASS, "")
	pass.Facts = []*janusv1.Fact{factText("recipient", "ops@example.com")}
	s, err = saga.Apply(s, ev(t, 2, evidence.KindGateVerdict, pass))
	if err != nil {
		t.Fatal(err)
	}

	// Passing a pre-execution gate is permission to run, not a result: the step
	// is still PLANNED.
	if st, _ := s.Step("send"); st.Status != saga.StepPlanned {
		t.Fatalf("step is %s after a pre-execution pass, want PLANNED", st.Status)
	}

	if _, err := saga.Apply(s, ev(t, 3, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "send",
		Facts: []*janusv1.Fact{factText("recipient", "ops@example.com")},
	})); err != nil {
		t.Fatalf("a step whose gate passed was still refused: %v", err)
	}
}

// A gate that judged one proposal has said nothing about another. Without this,
// approval and execution could be about different payments and the log would
// show an ordinary, permitted step.
func TestAStepMayNotRunOnFactsItsGateNeverSaw(t *testing.T) {
	s, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, preGatedBegin()))
	if err != nil {
		t.Fatal(err)
	}
	pass := verdict("sg", "send", janusv1.Verdict_VERDICT_PASS, "")
	pass.Facts = []*janusv1.Fact{factNumber("amount_minor", 250000)}
	s, err = saga.Apply(s, ev(t, 2, evidence.KindGateVerdict, pass))
	if err != nil {
		t.Fatal(err)
	}

	_, err = saga.Apply(s, ev(t, 3, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "send",
		Facts: []*janusv1.Fact{factNumber("amount_minor", 9000000)},
	}))
	if err == nil {
		t.Fatal("a step ran with an amount its gate never saw")
	}
	if !strings.Contains(err.Error(), "made about something else") {
		t.Fatalf("the refusal does not explain the substitution: %v", err)
	}

	// Dropping a fact the gate saw is the same substitution from the other
	// direction, and is refused the same way.
	if _, err := saga.Apply(s, ev(t, 3, evidence.KindStepPrepare,
		&janusv1.StepPrepare{SagaId: "sg", StepId: "send"})); err == nil {
		t.Fatal("a step ran having dropped a fact its gate decided on")
	}
}

// A pass clears one attempt, not the step. A retry runs the participant again,
// possibly on different arguments, and a gate that cleared the first attempt
// has said nothing about the second.
func TestAPreExecutionPassClearsOneAttemptOnly(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId:            "sg",
		GatePolicyVersion: testPolicy,
		Plan: []*janusv1.PlannedStep{{
			StepId:      "send",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE,
			MaxRetries:  2,
		}},
		GatePlan: []*janusv1.StepGates{plannedGates("send", "PRE_EXECUTION")},
	}
	events := []saga.Event{
		ev(t, 1, evidence.KindSagaBegin, begin),
		ev(t, 2, evidence.KindGateVerdict, verdict("sg", "send", janusv1.Verdict_VERDICT_PASS, "")),
		ev(t, 3, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "send"}),
		ev(t, 4, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: "send",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_RETRYABLE_ERROR},
		}),
	}
	s, err := saga.Replay(events)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Step("send"); st.Status != saga.StepFailed {
		t.Fatalf("step is %s, want FAILED", st.Status)
	}

	// The second attempt needs its own decision.
	if _, err := saga.Apply(s, ev(t, 5, evidence.KindStepPrepare,
		&janusv1.StepPrepare{SagaId: "sg", StepId: "send"})); err == nil {
		t.Fatal("a retry reused the gate decision that cleared the first attempt")
	}

	s, err = saga.Apply(s, ev(t, 5, evidence.KindGateVerdict,
		verdict("sg", "send", janusv1.Verdict_VERDICT_PASS, "")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saga.Apply(s, ev(t, 6, evidence.KindStepPrepare,
		&janusv1.StepPrepare{SagaId: "sg", StepId: "send"})); err != nil {
		t.Fatalf("a retry with its own decision was refused: %v", err)
	}
}

// A refusal before the step ever ran leaves nothing behind, whatever the effect
// class. Compensating anyway would send a refund for a payment nobody made.
func TestARefusalBeforeExecutionLeavesNothingToUndo(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId:            "sg",
		GatePolicyVersion: testPolicy,
		Plan: []*janusv1.PlannedStep{{
			StepId:             "pay",
			EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: "pay.undo",
		}},
		GatePlan: []*janusv1.StepGates{plannedGates("pay", "PRE_EXECUTION")},
	}
	s, err := saga.Replay([]saga.Event{
		ev(t, 1, evidence.KindSagaBegin, begin),
		ev(t, 2, evidence.KindGateVerdict,
			verdict("sg", "pay", janusv1.Verdict_VERDICT_FAIL, "over the limit")),
	})
	if err != nil {
		t.Fatal(err)
	}

	if s.Status != saga.StatusCompensated {
		t.Fatalf("saga is %s, want COMPENSATED with nothing to undo", s.Status)
	}
	st, _ := s.Step("pay")
	if st.Status != saga.StepRefused {
		t.Fatalf("step is %s, want REFUSED", st.Status)
	}
	if st.Attempt != 0 {
		t.Fatalf("the step ran %d time(s) despite being refused beforehand", st.Attempt)
	}
	if st.Compensation != saga.CompNotNeeded {
		t.Fatalf("compensation is %q; a step that never ran has nothing to reverse",
			st.Compensation)
	}
}

// A step waiting on a contended resource is neither refused nor permitted, and
// the saga has to be able to sit there without the machine calling it finished.
func TestAnEscalationHoldsTheSagaWithoutDecidingIt(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId:            "sg",
		GatePolicyVersion: testPolicy,
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		GatePlan: []*janusv1.StepGates{plannedGates("wire", "PRE_RELEASE")},
	}
	s, err := saga.Replay([]saga.Event{
		ev(t, 1, evidence.KindSagaBegin, begin),
		ev(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "wire"}),
		ev(t, 3, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: "wire",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}),
		ev(t, 4, evidence.KindGateVerdict, &janusv1.GateVerdict{
			SagaId: "sg", StepId: "wire",
			Gate:    janusv1.GateType_GATE_TYPE_FRONTIER,
			Verdict: janusv1.Verdict_VERDICT_ESCALATE,
			Reason:  "sg_other holds acct:1 and has not finished",
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	if s.Status != saga.StatusGated {
		t.Fatalf("saga is %s, want GATED", s.Status)
	}
	if st, _ := s.Step("wire"); st.Status != saga.StepGated {
		t.Fatalf("step is %s, want it still waiting", st.Status)
	}
	step, reason, waiting := saga.WaitingOnGate(s)
	if !waiting || step != "wire" {
		t.Fatalf("the saga does not report what it is waiting for: %q %q %v", step, reason, waiting)
	}
	if !strings.Contains(reason, "sg_other") {
		t.Fatalf("the reason does not name the blocker: %q", reason)
	}

	// An escalation decides nothing, so it is not required to have accounted
	// for every requirement — but the saga also may not seal on one.
	if _, err := saga.Apply(s, ev(t, 5, evidence.KindSealRequest,
		&janusv1.SealRequest{SagaId: "sg"})); err == nil {
		t.Fatal("a saga sealed while a step was still waiting on a gate")
	}
}

// Facts have to be well formed to be decided on. Each of these would otherwise
// reach a gate as a value nobody stated.
func TestMalformedFactsAreRefused(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId: "sg",
		Plan: []*janusv1.PlannedStep{{
			StepId: "s1", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
		}},
	}
	s, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		facts []*janusv1.Fact
		hint  string
	}{
		{"no name", []*janusv1.Fact{{Value: &janusv1.Fact_Flag{Flag: true}}}, "no name"},
		{"no value", []*janusv1.Fact{{Key: "approved"}}, "carries no value"},
		{"declared twice", []*janusv1.Fact{
			factNumber("amount_minor", 1), factNumber("amount_minor", 2),
		}, "twice"},
		{"reserved namespace", []*janusv1.Fact{factText("saga.mode", "crystallized")}, "reserved"},
		{"another reserved namespace", []*janusv1.Fact{factText("intent.principal", "root")}, "reserved"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := saga.Apply(s, ev(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{
				SagaId: "sg", StepId: "s1", Facts: c.facts,
			}))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.hint) {
				t.Fatalf("the refusal does not explain itself: %v", err)
			}
		})
	}
}

// A gate plan is part of what a saga is admitted as, so it has to be coherent
// before anything runs.
func TestIncoherentGatePlansAreRefusedAtAdmission(t *testing.T) {
	base := func(gp []*janusv1.StepGates) *janusv1.SagaBegin {
		return &janusv1.SagaBegin{
			SagaId:            "sg",
			GatePolicyVersion: testPolicy,
			Plan: []*janusv1.PlannedStep{{
				StepId: "wire", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
			}},
			GatePlan: gp,
		}
	}

	cases := []struct {
		name string
		gp   []*janusv1.StepGates
		hint string
	}{
		{"covers a step that is not in the plan",
			[]*janusv1.StepGates{plannedGates("ghost", "PRE_RELEASE")}, "not in the plan"},
		{"covers a step twice", []*janusv1.StepGates{
			plannedGates("wire", "PRE_RELEASE"), plannedGates("wire", "PRE_RELEASE"),
		}, "twice"},
		{"lists a step with no requirements",
			[]*janusv1.StepGates{{StepId: "wire", RuleId: "r"}}, "listed as exempt"},
		{"a requirement with no id", []*janusv1.StepGates{{
			StepId: "wire", RuleId: "r",
			Require: []*janusv1.GateRequirement{{
				Gate:  janusv1.GateType_GATE_TYPE_POLICY,
				Phase: janusv1.GatePhase_GATE_PHASE_PRE_RELEASE,
			}},
		}}, "no id"},
		{"a requirement that does not say when it is decided", []*janusv1.StepGates{{
			StepId: "wire", RuleId: "r",
			Require: []*janusv1.GateRequirement{{
				Id: "x", Gate: janusv1.GateType_GATE_TYPE_POLICY,
			}},
		}}, "does not say when it is decided"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, base(c.gp)))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.hint) {
				t.Fatalf("the refusal does not explain itself: %v", err)
			}
		})
	}
}
