package gate_test

import (
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

// Gates whose answer comes from somebody who is not the agent being gated.
//
// The four checks in decide_test.go are pure functions of what the step itself
// declared, which makes them proof against an agent that lies about its
// arguments and useless against one that lies about the world. These are the
// other half: a validator's opinion, a human's approval, and a fact published
// by a different step — three things the gated agent cannot author.
//
// The load-bearing test in this file is the last one. A human gate that checked
// only "an approval exists" would re-derive to the same answer under audit and
// prove nothing, which is exactly the failure mode worth guarding against.

const (
	// initiator is the principal every fixture saga below is initiated for, so
	// separation of duty has something concrete to be about.
	initiator = "bob"
)

// externalState builds a projection whose one step is gated by the given
// requirements and has already produced a result, so a release gate is due.
func externalState(t *testing.T, gates ...*janusv1.GateRequirement) saga.State {
	t.Helper()
	begin := &janusv1.SagaBegin{
		SagaId: "sg", Mode: "supervised", GatePolicyVersion: "blake3:test",
		Intent: &janusv1.Intent{IntentId: "in", Principal: initiator, MandateRef: "m-1"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Participant: "ag_1", Action: "payments.wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		GatePlan: []*janusv1.StepGates{{StepId: "wire", RuleId: "r", Require: gates}},
	}
	events := []saga.Event{
		event(t, 1, evidence.KindSagaBegin, begin),
		event(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "wire"}),
		event(t, 3, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: "wire",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}),
	}
	s, err := saga.Replay(events)
	if err != nil {
		t.Fatalf("the fixture saga does not replay: %v", err)
	}
	return s
}

func event(t *testing.T, seq uint64, kind evidence.Kind, m proto.Message) saga.Event {
	t.Helper()
	payload, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return saga.Event{Seq: seq, Kind: kind, Payload: payload}
}

// withAnswer folds one answer into a projection, through the real transition so
// the state machine's own rules apply.
func withAnswer(t *testing.T, s saga.State, seq uint64, a *janusv1.GateAnswer) saga.State {
	t.Helper()
	next, err := saga.Apply(s, event(t, seq, evidence.KindGateAnswer, a))
	if err != nil {
		t.Fatalf("recording the answer: %v", err)
	}
	return next
}

func approval(person, reqID string, v janusv1.Verdict, roles ...string) *janusv1.GateAnswer {
	return &janusv1.GateAnswer{
		SagaId: "sg", StepId: "wire", RequirementId: reqID, Attempt: 1,
		Actor:   &janusv1.Actor{HumanSubject: person},
		Verdict: v, Roles: roles,
	}
}

func opinion(who, reqID string, v janusv1.Verdict, reason string) *janusv1.GateAnswer {
	return &janusv1.GateAnswer{
		SagaId: "sg", StepId: "wire", RequirementId: reqID, Attempt: 1,
		Actor:   &janusv1.Actor{Participant: &janusv1.ParticipantRef{Id: who}},
		Verdict: v, Reason: reason,
	}
}

func human(id string, quorum uint32, sod bool, roles ...string) *janusv1.GateRequirement {
	return &janusv1.GateRequirement{
		Id: id, Gate: janusv1.GateType_GATE_TYPE_HUMAN,
		Phase: janusv1.GatePhase_GATE_PHASE_PRE_RELEASE,
		Check: &janusv1.GateRequirement_Human{
			Human: &janusv1.HumanCheck{Roles: roles, Quorum: quorum, SeparationOfDuty: sod},
		},
	}
}

func validators(id string, quorum uint32, escalate bool, who ...string) *janusv1.GateRequirement {
	return &janusv1.GateRequirement{
		Id: id, Gate: janusv1.GateType_GATE_TYPE_VALIDATOR,
		Phase: janusv1.GatePhase_GATE_PHASE_PRE_RELEASE,
		Check: &janusv1.GateRequirement_Validator{
			Validator: &janusv1.ValidatorCheck{
				Validators: who, Quorum: quorum, EscalateOnDisagreement: escalate,
			},
		},
	}
}

func decideRelease(t *testing.T, s saga.State) gate.Decision {
	t.Helper()
	st, ok := s.Step("wire")
	if !ok {
		t.Fatal("no step")
	}
	return gate.Decide(preRelease, gate.Input{Saga: s, Step: st, Declared: st.Facts})
}

// ---- the human gate -----------------------------------------------------------

func TestHumanGateWaitsUntilSomebodyAnswers(t *testing.T) {
	s := externalState(t, human("approval", 1, true, "credit-officer"))

	d := decideRelease(t, s)
	if d.Verdict != janusv1.Verdict_VERDICT_ESCALATE {
		t.Fatalf("verdict is %s, want the step held until somebody answers", d.Verdict)
	}
	if !strings.Contains(d.Reason, "credit-officer") {
		t.Fatalf("the reason does not say who is being waited for: %s", d.Reason)
	}

	s = withAnswer(t, s, 4, approval("alice", "approval",
		janusv1.Verdict_VERDICT_PASS, "credit-officer"))
	if d := decideRelease(t, s); !d.Passed() {
		t.Fatalf("an approval from an entitled person was refused: %s", d.Reason)
	}
}

// Four eyes. The approver holds the right role and is refused anyway, because
// the objection is not to their competence.
func TestSelfApprovalIsRefusedRatherThanIgnored(t *testing.T) {
	s := externalState(t, human("approval", 1, true, "credit-officer"))
	s = withAnswer(t, s, 4, approval(initiator, "approval",
		janusv1.Verdict_VERDICT_PASS, "credit-officer"))

	d := decideRelease(t, s)
	if d.Verdict != janusv1.Verdict_VERDICT_FAIL {
		t.Fatalf("verdict is %s, want FAIL: the initiator approved their own payment", d.Verdict)
	}
	// Refusing rather than waiting matters. A gate that ignored the answer and
	// went on escalating would leave an attempted control violation looking
	// exactly like nobody having got round to it.
	if !strings.Contains(d.Reason, "own authority") {
		t.Fatalf("the reason does not name the problem: %s", d.Reason)
	}
}

func TestAnApproverWithoutTheRoleIsRefused(t *testing.T) {
	s := externalState(t, human("approval", 1, true, "credit-officer"))
	s = withAnswer(t, s, 4, approval("alice", "approval",
		janusv1.Verdict_VERDICT_PASS, "intern"))

	d := decideRelease(t, s)
	if d.Verdict != janusv1.Verdict_VERDICT_FAIL {
		t.Fatalf("verdict is %s, want FAIL", d.Verdict)
	}
	if !strings.Contains(d.Reason, "intern") || !strings.Contains(d.Reason, "credit-officer") {
		t.Fatalf("the reason states neither what was held nor what was needed: %s", d.Reason)
	}
}

func TestAQuorumNeedsDistinctPeople(t *testing.T) {
	s := externalState(t, human("approval", 2, true, "credit-officer"))

	s = withAnswer(t, s, 4, approval("alice", "approval",
		janusv1.Verdict_VERDICT_PASS, "credit-officer"))
	d := decideRelease(t, s)
	if d.Verdict != janusv1.Verdict_VERDICT_ESCALATE {
		t.Fatalf("one of two approvals settled the gate: %s", d.Reason)
	}

	// The same person again is refused by the state machine, before the check
	// ever sees it: a quorum of one wearing two hats is not a quorum.
	_, err := saga.Apply(s, event(t, 5, evidence.KindGateAnswer,
		approval("alice", "approval", janusv1.Verdict_VERDICT_PASS, "credit-officer")))
	if err == nil {
		t.Fatal("the same approver was counted twice")
	}
	if !strings.Contains(err.Error(), "two hats") {
		t.Fatalf("the refusal does not explain itself: %v", err)
	}

	s = withAnswer(t, s, 5, approval("carol", "approval",
		janusv1.Verdict_VERDICT_PASS, "credit-officer"))
	if d := decideRelease(t, s); !d.Passed() {
		t.Fatalf("two distinct approvals did not satisfy a quorum of two: %s", d.Reason)
	}
}

func TestAHumanRejectionRefusesImmediately(t *testing.T) {
	s := externalState(t, human("approval", 2, true, "credit-officer"))
	s = withAnswer(t, s, 4, approval("alice", "approval",
		janusv1.Verdict_VERDICT_FAIL, "credit-officer"))

	d := decideRelease(t, s)
	if d.Verdict != janusv1.Verdict_VERDICT_FAIL {
		t.Fatalf("verdict is %s; one person declining should not be outvoted", d.Verdict)
	}
}

// ---- the validator gate -------------------------------------------------------

func TestValidatorDisagreementEscalatesRatherThanBeingOutvoted(t *testing.T) {
	s := externalState(t, validators("second-opinion", 2, true, "val_a", "val_b", "val_c"))
	s = withAnswer(t, s, 4, opinion("val_a", "second-opinion", janusv1.Verdict_VERDICT_PASS, ""))
	s = withAnswer(t, s, 5, opinion("val_b", "second-opinion", janusv1.Verdict_VERDICT_PASS, ""))
	s = withAnswer(t, s, 6, opinion("val_c", "second-opinion",
		janusv1.Verdict_VERDICT_FAIL, "the counterparty is not on the mandate"))

	d := decideRelease(t, s)
	if d.Verdict != janusv1.Verdict_VERDICT_ESCALATE {
		t.Fatalf("verdict is %s; two-to-one is disagreement, not a decision", d.Verdict)
	}
	if !strings.Contains(d.Reason, "not on the mandate") {
		t.Fatalf("the reason drops the dissenting objection: %s", d.Reason)
	}
}

func TestValidatorDisagreementCanBeConfiguredToRefuse(t *testing.T) {
	s := externalState(t, validators("second-opinion", 2, false, "val_a", "val_b"))
	s = withAnswer(t, s, 4, opinion("val_a", "second-opinion", janusv1.Verdict_VERDICT_PASS, ""))
	s = withAnswer(t, s, 5, opinion("val_b", "second-opinion",
		janusv1.Verdict_VERDICT_FAIL, "schema drift"))

	if d := decideRelease(t, s); d.Verdict != janusv1.Verdict_VERDICT_FAIL {
		t.Fatalf("verdict is %s, want FAIL when disagreement does not escalate", d.Verdict)
	}
}

// Independence is the point of the gate, so an opinion from somebody nobody
// asked is a finding rather than a contribution.
func TestAnOpinionFromAnUnaskedValidatorRefuses(t *testing.T) {
	s := externalState(t, validators("second-opinion", 1, true, "val_a"))
	s = withAnswer(t, s, 4, opinion("val_rogue", "second-opinion", janusv1.Verdict_VERDICT_PASS, ""))

	d := decideRelease(t, s)
	if d.Verdict != janusv1.Verdict_VERDICT_FAIL {
		t.Fatalf("verdict is %s; an unasked participant answered", d.Verdict)
	}
	if !strings.Contains(d.Reason, "val_rogue") {
		t.Fatalf("the reason does not name who answered: %s", d.Reason)
	}
}

// ---- what the state machine refuses about answers -----------------------------

func TestAnswersMustBeAboutAQuestionThatWasAsked(t *testing.T) {
	s := externalState(t, human("approval", 1, true, "credit-officer"),
		req("shape", "SCHEMA", "PRE_RELEASE", &janusv1.SchemaCheck{
			SchemaId: "s", Fields: []*janusv1.FieldSpec{
				{Name: "amount_minor", Type: janusv1.FactType_FACT_TYPE_NUMBER},
			}}))

	cases := []struct {
		name   string
		answer *janusv1.GateAnswer
		hint   string
	}{
		{"a requirement the saga was not admitted under",
			approval("alice", "invented", janusv1.Verdict_VERDICT_PASS), "not admitted under"},
		{"a gate Janus decides itself",
			approval("alice", "shape", janusv1.Verdict_VERDICT_PASS), "voting on a computation"},
		{"an answer that is neither a yes nor a no",
			approval("alice", "approval", janusv1.Verdict_VERDICT_ESCALATE), "neither a yes nor a no"},
		{"an answer from nobody", &janusv1.GateAnswer{
			SagaId: "sg", StepId: "wire", RequirementId: "approval", Attempt: 1,
			Verdict: janusv1.Verdict_VERDICT_PASS,
		}, "names nobody"},
		{"an answer for a different attempt", &janusv1.GateAnswer{
			SagaId: "sg", StepId: "wire", RequirementId: "approval", Attempt: 2,
			Actor:   &janusv1.Actor{HumanSubject: "alice"},
			Verdict: janusv1.Verdict_VERDICT_PASS,
		}, "the one being decided"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := saga.Apply(s, event(t, 4, evidence.KindGateAnswer, c.answer))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.hint) {
				t.Fatalf("the refusal does not explain itself: %v", err)
			}
		})
	}
}

// An approval that arrives after the step has sealed is answering a question
// that has already been decided.
func TestAnAnswerArrivingTooLateIsRefused(t *testing.T) {
	s := externalState(t, human("approval", 1, true))
	s = withAnswer(t, s, 4, approval("alice", "approval", janusv1.Verdict_VERDICT_PASS))

	sealed, err := saga.Apply(s, event(t, 5, evidence.KindGateVerdict, &janusv1.GateVerdict{
		SagaId: "sg", StepId: "wire",
		Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
		Verdict: janusv1.Verdict_VERDICT_PASS,
		Decided: []string{"approval"},
	}))
	if err != nil {
		t.Fatal(err)
	}

	_, err = saga.Apply(sealed, event(t, 6, evidence.KindGateAnswer,
		approval("carol", "approval", janusv1.Verdict_VERDICT_FAIL)))
	if err == nil {
		t.Fatal("an answer was accepted for a step that had already sealed")
	}
	if !strings.Contains(err.Error(), "no longer waiting") {
		t.Fatalf("the refusal does not explain itself: %v", err)
	}
}

// ---- facts a step publishes, and thresholds relative to them ------------------

// balanceSaga is a plan whose first step reads a balance and publishes it, and
// whose second step is a payment judged against a fraction of it.
//
// dependent says whether the payment waits for the balance. It normally does,
// and the case where it does not is worth constructing because it is the only
// way to reach a gate whose published fact has not settled yet.
func balanceSaga(dependent bool) *janusv1.SagaBegin {
	wire := &janusv1.PlannedStep{
		StepId: "wire", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
	}
	if dependent {
		wire.DependsOn = []string{"balance"}
	}
	return &janusv1.SagaBegin{
		SagaId: "sg", Mode: "supervised", GatePolicyVersion: "blake3:test",
		Intent: &janusv1.Intent{IntentId: "in", Principal: initiator},
		Plan: []*janusv1.PlannedStep{
			{StepId: "balance", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
			wire,
		},
		GatePlan: []*janusv1.StepGates{{StepId: "wire", RuleId: "r",
			Require: []*janusv1.GateRequirement{
				req("share", "POLICY", "PRE_RELEASE", &janusv1.PolicyCheck{
					Expr:        shareExpr,
					Description: "a payment may not exceed a tenth of the balance",
				}),
			}}},
	}
}

func numFact(key string, n int64) *janusv1.Fact {
	return &janusv1.Fact{Key: key, Value: &janusv1.Fact_Number{Number: n}}
}

// balanceRead runs the balance step to SEALED, publishing what it found.
func balanceRead(t *testing.T, balance int64) saga.State {
	t.Helper()
	s, err := saga.Replay([]saga.Event{
		event(t, 1, evidence.KindSagaBegin, balanceSaga(true)),
		event(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "balance"}),
		// A PURE step seals on its result, so the finding is settled before
		// anything is judged against it.
		event(t, 3, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: "balance",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			Facts:   []*janusv1.Fact{numFact("available_minor", balance)},
		}),
	})
	if err != nil {
		t.Fatalf("the fixture saga does not replay: %v", err)
	}
	return s
}

// balanceState runs both steps, leaving the payment waiting on its gate.
func balanceState(t *testing.T, balance, amount int64) saga.State {
	t.Helper()
	s, err := saga.Replay(append(sagaEventsSoFar(t, balance),
		event(t, 4, evidence.KindStepPrepare, &janusv1.StepPrepare{
			SagaId: "sg", StepId: "wire", Facts: []*janusv1.Fact{numFact("amount_minor", amount)},
		}),
		event(t, 5, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: "wire",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		})))
	if err != nil {
		t.Fatalf("the fixture saga does not replay: %v", err)
	}
	return s
}

func sagaEventsSoFar(t *testing.T, balance int64) []saga.Event {
	t.Helper()
	return []saga.Event{
		event(t, 1, evidence.KindSagaBegin, balanceSaga(true)),
		event(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "balance"}),
		event(t, 3, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: "balance",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			Facts:   []*janusv1.Fact{numFact("available_minor", balance)},
		}),
	}
}

const shareExpr = "amount_minor <= 10 percent of result.balance.available_minor"

func TestARelativeThresholdReadsAFactThePayingStepCannotState(t *testing.T) {
	t.Run("within the share", func(t *testing.T) {
		s := balanceState(t, 10_000_000, 250_000)
		if d := decideRelease(t, s); !d.Passed() {
			t.Fatalf("250,000 is under a tenth of 10,000,000: %s", d.Reason)
		}
	})

	t.Run("exactly the share", func(t *testing.T) {
		s := balanceState(t, 10_000_000, 1_000_000)
		if d := decideRelease(t, s); !d.Passed() {
			t.Fatalf("the threshold is inclusive: %s", d.Reason)
		}
	})

	t.Run("over the share", func(t *testing.T) {
		s := balanceState(t, 10_000_000, 1_000_001)
		d := decideRelease(t, s)
		if d.Passed() {
			t.Fatal("a payment over a tenth of the balance was permitted")
		}
		if !strings.Contains(d.Reason, "a tenth of the balance") {
			t.Fatalf("the reason is not the one a human wrote: %s", d.Reason)
		}
	})

	// The comparison is exact rather than rounded, so a payment one minor unit
	// over a threshold that does not divide evenly is still over it.
	t.Run("one unit over an uneven share", func(t *testing.T) {
		if d := decideRelease(t, balanceState(t, 1_000_005, 100_001)); d.Passed() {
			t.Fatal("100,001 is more than a tenth of 1,000,005 and was permitted")
		}
		if d := decideRelease(t, balanceState(t, 1_000_005, 100_000)); !d.Passed() {
			t.Fatal("100,000 is under a tenth of 1,000,005 and was refused")
		}
	})
}

// The whole point of publishing the balance from a separate step is that the
// step being gated never gets to say what it was. If the paying step could
// declare it, an injected agent would simply claim a larger balance.
func TestThePayingStepCannotDeclareTheBalanceItIsJudgedAgainst(t *testing.T) {
	// The balance is on the record and the payment has not run yet, which is
	// exactly the moment an injected agent would want to state a larger one.
	s := balanceRead(t, 10_000_000)

	_, err := saga.Apply(s, event(t, 4, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "wire",
		Facts: []*janusv1.Fact{
			numFact("amount_minor", 9_000_000),
			numFact("result.balance.available_minor", 999_999_999),
		},
	}))
	if err == nil {
		t.Fatal("a step declared a fact in the namespace reserved for other steps' findings")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("the refusal does not explain itself: %v", err)
	}

	// Without the forged balance the same payment is judged against the real
	// one, and refused — which is what the namespace rule is protecting.
	honest, err := saga.Replay(append(sagaEventsSoFar(t, 10_000_000),
		event(t, 4, evidence.KindStepPrepare, &janusv1.StepPrepare{
			SagaId: "sg", StepId: "wire",
			Facts: []*janusv1.Fact{numFact("amount_minor", 9_000_000)},
		}),
		event(t, 5, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: "wire",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		})))
	if err != nil {
		t.Fatal(err)
	}
	if d := decideRelease(t, honest); d.Passed() {
		t.Fatal("9,000,000 is far more than a tenth of 10,000,000 and was permitted")
	}
}

// A finding from a step that has not sealed can still be withdrawn, so a gate
// does not get to rest on it.
func TestAFindingFromAnUnsealedStepIsNotVisibleToGates(t *testing.T) {
	// The balance step here has *reported* its finding and not sealed: it is a
	// compensable step waiting on its own gate, so the number is in the log and
	// the saga could still disown it. That is the only interesting version of
	// this — a step with no result has published nothing, and hiding nothing is
	// not a control.
	//
	// The payment does not wait for the balance, because a dependent step could
	// not have got this far: the scheduler requires its dependencies SEALED,
	// which is the same rule from the other side.
	begin := balanceSaga(false)
	begin.Plan[0] = &janusv1.PlannedStep{
		StepId:             "balance",
		EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
		CompensationAction: "balance.undo",
	}
	// Both steps start before either reports, because a saga already waiting on
	// one gate will not begin new work — so this is the only ordering that puts
	// an unsealed finding in front of another step's gate.
	s, err := saga.Replay([]saga.Event{
		event(t, 1, evidence.KindSagaBegin, begin),
		event(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "balance"}),
		event(t, 3, evidence.KindStepPrepare, &janusv1.StepPrepare{
			SagaId: "sg", StepId: "wire", Facts: []*janusv1.Fact{numFact("amount_minor", 1)},
		}),
		event(t, 4, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: "balance",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			Facts:   []*janusv1.Fact{numFact("available_minor", 10_000_000)},
		}),
		event(t, 5, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: "wire",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	balance, _ := s.Step("balance")
	if balance.Status != saga.StepGated {
		t.Fatalf("the balance step is %s, want it still waiting on its own gate", balance.Status)
	}
	if len(balance.Published) == 0 {
		t.Fatal("the balance step published nothing, so this test hides nothing")
	}

	d := decideRelease(t, s)
	if d.Passed() {
		t.Fatal("a gate decided on a balance no step has settled")
	}
	if !strings.Contains(d.Reason, "result.balance.available_minor") {
		t.Fatalf("the reason does not name the fact that was missing: %s", d.Reason)
	}
}

// A comparison whose operands do not fit is not a comparison that came out
// false. Wrapping silently would turn an enormous payment into a small one.
func TestARelativeThresholdRefusesRatherThanOverflowing(t *testing.T) {
	const huge = int64(1) << 62
	s := balanceState(t, huge, huge)

	d := decideRelease(t, s)
	if d.Passed() {
		t.Fatal("a comparison that overflows was treated as passing")
	}
	if !strings.Contains(d.Reason, "overflows") {
		t.Fatalf("the reason does not name the problem: %s", d.Reason)
	}
}

func TestAPercentageOfANegativeQuantityIsRefused(t *testing.T) {
	s := balanceState(t, -400_000, 1)
	d := decideRelease(t, s)
	if d.Passed() {
		t.Fatal("a threshold relative to an overdrawn balance was treated as satisfied")
	}
	if !strings.Contains(d.Reason, "no meaning as a threshold") {
		t.Fatalf("the reason does not name the problem: %s", d.Reason)
	}
}
