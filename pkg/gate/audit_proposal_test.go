package gate_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/saga"
)

const preApprovalPolicy = `{
  "id": "test.pre-approval",
  "rules": [{
    "id": "wires",
    "match": {"effect_classes": ["IRREVERSIBLE_GATED"]},
    "require": [
      {"id": "pre-approval", "gate": "HUMAN", "phase": "PRE_EXECUTION",
       "human": {"roles": ["credit-officer"], "separation_of_duty": true}},
      {"id": "limit", "gate": "RISK_LIMIT", "phase": "PRE_RELEASE",
       "risk_limit": {"thresholds": [{"fact": "amount_minor", "max": 10000000}]}}
    ]
  }]
}`

// writePreApprovedSaga records, under a given semantics version, a wire that
// was escalated for a person's approval on 100 and then passed on `passedOn`.
// Every verdict is the engine's own, so the only thing that can be wrong with
// the log is the one thing this audit is for.
func writePreApprovedSaga(t *testing.T, version uint32, passedOn int64) (string, error) {
	t.Helper()
	app, dir := newAuditLog(t)
	ctx := context.Background()

	e := gate.NewEngine(mustPolicy(t, preApprovalPolicy))
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1", Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in", Principal: "bob", MandateRef: "m-1"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Participant: "ag_audit", Action: "payments.wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	}
	if err := e.Admit(begin); err != nil {
		t.Fatal(err)
	}
	r := saga.NewRunner(app, auditParticipant)
	if _, err := r.BeginUnder(ctx, begin, version); err != nil {
		t.Fatal(err)
	}
	amount := func(n int64) map[string]saga.FactValue {
		return map[string]saga.FactValue{
			"amount_minor": {Type: janusv1.FactType_FACT_TYPE_NUMBER, Number: n},
		}
	}
	decide := func(n int64) *janusv1.GateVerdict {
		st, _ := r.State().Step("wire")
		return gate.Decide(janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION, gate.Input{
			Saga: r.State(), Step: st, Declared: amount(n),
		}).GateVerdict("")
	}

	if _, err := r.Gate(ctx, decide(100)); err != nil {
		t.Fatalf("escalating: %v", err)
	}
	if _, err := r.Answer(ctx, &janusv1.GateAnswer{
		SagaId: "sg_1", StepId: "wire", RequirementId: "pre-approval", Attempt: 1,
		Actor:   &janusv1.Actor{HumanSubject: "alice"},
		Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"},
		AuthRef: "auth:alice", Reason: "approved for 100",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := r.Gate(ctx, decide(passedOn))
	if cerr := app.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	return dir, err
}

// TestAuditNamesAnApprovalCountedForAnotherProposal: the version-1 log that
// records this legally. Every verdict in it re-derives — the approval
// is there and it is for attempt 1 — so the ordinary re-derivation says PASS
// and agrees. Only the proposal changed, and only this check looks.
func TestAuditNamesAnApprovalCountedForAnotherProposal(t *testing.T) {
	dir, err := writePreApprovedSaga(t, 1, 1_000_000)
	if err != nil {
		t.Fatalf("version 1 recorded this history legally, and that is the premise: %v", err)
	}
	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found *gate.Finding
	for i, f := range rep.Findings {
		if f.Kind == gate.FindingProposalChanged {
			found = &rep.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("an approval given on 100 was counted for a pass on 1,000,000 and the audit "+
			"said nothing:\n%s", rep)
	}
	if !strings.Contains(found.Detail, "escalated on amount_minor=100") ||
		!strings.Contains(found.Detail, "decides it on amount_minor=1000000") {
		t.Errorf("the finding does not say what was asked and what was decided: %s", found)
	}
}

// TestAuditAcceptsAnApprovalForTheProposalItWasGivenFor is the other half: the
// same log with the pass on 100 is clean, under either version.
func TestAuditAcceptsAnApprovalForTheProposalItWasGivenFor(t *testing.T) {
	for _, version := range []uint32{1, 2} {
		dir, err := writePreApprovedSaga(t, version, 100)
		if err != nil {
			t.Fatalf("v%d: %v", version, err)
		}
		rep, err := gate.Audit(dir)
		if err != nil {
			t.Fatal(err)
		}
		if !rep.OK() {
			t.Errorf("v%d: an honest pre-approval audited with findings:\n%s", version, rep)
		}
	}
}

// TestVersionTwoRefusesToRecordTheSwapAtAll: under semantics 2 the runner
// cannot append the pass, because the fold refuses it before it is written.
func TestVersionTwoRefusesToRecordTheSwapAtAll(t *testing.T) {
	if _, err := writePreApprovedSaga(t, 2, 1_000_000); err == nil {
		t.Fatal("a version-2 runner recorded a pass on 1,000,000 for an attempt escalated on 100")
	}
}

// forgetfulProgram proposes 100 until it is restarted, and then proposes
// nothing: the shape of a daemon whose declarations lived in memory. A
// Program is meant to be pure; this one is not, and the point is that the
// coordinator no longer needs it to be for a question already asked.
type forgetfulProgram struct {
	begin  *janusv1.SagaBegin
	forgot bool
}

func (p forgetfulProgram) Begin() *janusv1.SagaBegin { return p.begin }
func (p forgetfulProgram) Run(string, uint32) saga.StepOutcome {
	return saga.StepOutcome{Status: janusv1.Outcome_STATUS_OK}
}
func (p forgetfulProgram) Undo(string) janusv1.Outcome_Status { return janusv1.Outcome_STATUS_OK }
func (p forgetfulProgram) Facts(string, uint32) map[string]saga.FactValue {
	if p.forgot {
		return nil
	}
	return map[string]saga.FactValue{"amount_minor": gate.Number(100)}
}
func (p forgetfulProgram) Answer(_ string, attempt uint32, req string) *janusv1.GateAnswer {
	if !p.forgot || req != "pre-approval" {
		return nil
	}
	return &janusv1.GateAnswer{
		SagaId: "sg_1", StepId: "wire", RequirementId: req, Attempt: attempt,
		Actor:   &janusv1.Actor{HumanSubject: "alice"},
		Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"},
		AuthRef: "auth:alice", Reason: "approved for 100",
	}
}

// TestAResumedCoordinatorDecidesTheQuestionThatWasAsked: after a restart the
// answer arrives and the Program no longer remembers what it proposed. The
// decision is made on the proposal the log pinned, not on whatever the
// Program says now — which here is nothing, and under semantics 2 a pass on
// nothing would not fold.
func TestAResumedCoordinatorDecidesTheQuestionThatWasAsked(t *testing.T) {
	app, _ := newAuditLog(t)
	ctx := context.Background()
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1", Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in", Principal: "bob", MandateRef: "m-1"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Participant: "ag_audit", Action: "payments.wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	}
	if err := gate.NewEngine(mustPolicy(t, preApprovalPolicy)).Admit(begin); err != nil {
		t.Fatal(err)
	}

	first := saga.NewRunner(app, auditParticipant)
	_, err := saga.NewCoordinator(first, forgetfulProgram{begin: begin}).
		WithGatekeeper(gate.NewKeeper(nil)).Drive(ctx)
	if !errors.Is(err, saga.ErrWaiting) {
		t.Fatalf("the wire did not stop for its approval: %v", err)
	}

	resumed := saga.NewRunner(app, auditParticipant)
	resumed.Adopt(first.State())
	final, err := saga.NewCoordinator(resumed, forgetfulProgram{begin: begin, forgot: true}).
		WithGatekeeper(gate.NewKeeper(nil)).Drive(ctx)
	if err != nil {
		t.Fatalf("the resumed coordinator could not act on the approval: %v", err)
	}
	if final.Status != saga.StatusCommitted {
		t.Fatalf("the saga is %s, want COMMITTED", final.Status)
	}
	if got := saga.DescribeFacts(final.Steps["wire"].Facts); len(got) != 1 || got[0] != "amount_minor=100" {
		t.Fatalf("the wire ran on %v; the approval was for amount_minor=100", got)
	}
}
