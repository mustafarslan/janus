package gate_test

import (
	"context"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/saga"
)

// The audit's half of the routes around the approval binding. Semantics 3
// refuses these histories; a version-2 log may hold them legally, and every verdict in them
// re-derives, so these checks are the only place they are named.

func wireBegin(t *testing.T, policy string) *janusv1.SagaBegin {
	t.Helper()
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1", Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in", Principal: "bob", MandateRef: "m-1"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Participant: "ag_audit", Action: "payments.wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	}
	if err := gate.NewEngine(mustPolicy(t, policy)).Admit(begin); err != nil {
		t.Fatal(err)
	}
	return begin
}

// writeApprovedNothing records, under `version`, a wire escalated on no facts,
// approved, passed on no facts, and prepared on 250,000.
func writeApprovedNothing(t *testing.T, version uint32) (string, error) {
	t.Helper()
	app, dir := newAuditLog(t)
	ctx := context.Background()
	r := saga.NewRunner(app, auditParticipant)
	if _, err := r.BeginUnder(ctx, wireBegin(t, preApprovalPolicy), version); err != nil {
		t.Fatal(err)
	}
	decide := func() *janusv1.GateVerdict {
		st, _ := r.State().Step("wire")
		return gate.Decide(janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION, gate.Input{
			Saga: r.State(), Step: st,
		}).GateVerdict("")
	}
	if _, err := r.Gate(ctx, decide()); err != nil {
		t.Fatalf("escalating: %v", err)
	}
	if _, err := r.Answer(ctx, &janusv1.GateAnswer{
		SagaId: "sg_1", StepId: "wire", RequirementId: "pre-approval", Attempt: 1,
		Actor:   &janusv1.Actor{HumanSubject: "alice"},
		Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"},
		AuthRef: "auth:alice", Reason: "approved",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Gate(ctx, decide()); err != nil {
		t.Fatalf("passing: %v", err)
	}
	_, err := r.PrepareStep(ctx, &janusv1.StepPrepare{
		SagaId: "sg_1", StepId: "wire",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		Facts:       []*janusv1.Fact{{Key: "amount_minor", Value: &janusv1.Fact_Number{Number: 250000}}},
	})
	if cerr := app.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	return dir, err
}

func findingOf(rep gate.Report, kind gate.FindingKind) *gate.Finding {
	for i, f := range rep.Findings {
		if f.Kind == kind {
			return &rep.Findings[i]
		}
	}
	return nil
}

// TestAuditNamesAnApprovalOfNothingThatRanOnAnAmount is route (b) in a
// version-2 log, and its refusal under version 3.
func TestAuditNamesAnApprovalOfNothingThatRanOnAnAmount(t *testing.T) {
	dir, err := writeApprovedNothing(t, 2)
	if err != nil {
		t.Fatalf("version 2 recorded this history legally, and that is the premise: %v", err)
	}
	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := findingOf(rep, gate.FindingProposalChanged)
	if f == nil {
		t.Fatalf("a wire approved while it stated no amount ran on 250,000 and the audit "+
			"said nothing:\n%s", rep)
	}
	if !strings.Contains(f.Detail, "shown no facts and runs on amount_minor=250000") {
		t.Errorf("the finding does not say what was shown and what ran: %s", f)
	}
	if _, err := writeApprovedNothing(t, 3); err == nil {
		t.Fatal("a version-3 runner recorded a prepare on 250,000 after a pass on nothing")
	}
}

const releaseApprovalPolicy = `{
  "id": "test.release-approval",
  "rules": [{
    "id": "wires",
    "match": {"effect_classes": ["IRREVERSIBLE_GATED"]},
    "require": [
      {"id": "release-approval", "gate": "HUMAN", "phase": "PRE_RELEASE",
       "human": {"roles": ["credit-officer"]}}
    ]
  }]
}`

func writeEarlyReleaseAnswer(t *testing.T, version uint32) (string, error) {
	t.Helper()
	app, dir := newAuditLog(t)
	ctx := context.Background()
	r := saga.NewRunner(app, auditParticipant)
	if _, err := r.BeginUnder(ctx, wireBegin(t, releaseApprovalPolicy), version); err != nil {
		t.Fatal(err)
	}
	_, err := r.Answer(ctx, &janusv1.GateAnswer{
		SagaId: "sg_1", StepId: "wire", RequirementId: "release-approval", Attempt: 1,
		Actor:   &janusv1.Actor{HumanSubject: "alice"},
		Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"},
		AuthRef: "auth:alice", Reason: "release it",
	})
	if cerr := app.Close(); cerr != nil {
		t.Fatal(cerr)
	}
	return dir, err
}

// TestAuditNamesAReleaseApprovalGivenBeforeTheStepRan is route (d).
func TestAuditNamesAReleaseApprovalGivenBeforeTheStepRan(t *testing.T) {
	dir, err := writeEarlyReleaseAnswer(t, 2)
	if err != nil {
		t.Fatalf("version 2 recorded this answer legally, and that is the premise: %v", err)
	}
	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := findingOf(rep, gate.FindingAnswerBeforeDue)
	if f == nil {
		t.Fatalf("an approval of a step's release was recorded before the step ran and the "+
			"audit said nothing:\n%s", rep)
	}
	if !strings.Contains(f.Detail, `"release-approval"`) {
		t.Errorf("the finding does not name the requirement: %s", f)
	}
	if _, err := writeEarlyReleaseAnswer(t, 3); err == nil {
		t.Fatal("a version-3 runner recorded a release approval before the step ran")
	}
}

// TestAuditNamesAnApprovalGivenBeforeTheQuestion: a version-2 log in which a
// pre-execution answer was recorded before the gate escalated anything.
func TestAuditNamesAnApprovalGivenBeforeTheQuestion(t *testing.T) {
	app, dir := newAuditLog(t)
	ctx := context.Background()
	r := saga.NewRunner(app, auditParticipant)
	if _, err := r.BeginUnder(ctx, wireBegin(t, preApprovalPolicy), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Answer(ctx, &janusv1.GateAnswer{
		SagaId: "sg_1", StepId: "wire", RequirementId: "pre-approval", Attempt: 1,
		Actor:   &janusv1.Actor{HumanSubject: "alice"},
		Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"},
		AuthRef: "auth:alice", Reason: "approved in advance",
	}); err != nil {
		t.Fatalf("version 2 recorded this answer legally, and that is the premise: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := findingOf(rep, gate.FindingAnswerBeforeDue)
	if f == nil || !strings.Contains(f.Detail, "before the gate put any proposal to it") {
		t.Fatalf("an approval recorded before any question was asked went unnamed:\n%s", rep)
	}
}

// eagerProgram answers the pre-approval from the start, before anything has
// been asked: the shape of a scripted approver, or of a queue drained early.
type eagerProgram struct{ forgetfulProgram }

func (p eagerProgram) Answer(_ string, attempt uint32, req string) *janusv1.GateAnswer {
	if req != "pre-approval" {
		return nil
	}
	return &janusv1.GateAnswer{
		RequirementId: req, Attempt: attempt,
		Actor:   &janusv1.Actor{HumanSubject: "alice"},
		Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"},
		AuthRef: "auth:alice", Reason: "approved for 100",
	}
}

// TestACoordinatorWaitsForTheQuestionBeforeTakingTheAnswer: under semantics 3
// the fold refuses an answer recorded before the escalation, so a coordinator
// whose Program offers one early must hold it until the gate has put the
// proposal -- otherwise it wedges on a transition it can never make.
func TestACoordinatorWaitsForTheQuestionBeforeTakingTheAnswer(t *testing.T) {
	app, _ := newAuditLog(t)
	begin := wireBegin(t, preApprovalPolicy)
	final, err := saga.NewCoordinator(saga.NewRunner(app, auditParticipant),
		eagerProgram{forgetfulProgram{begin: begin}}).
		WithGatekeeper(gate.NewKeeper(nil)).Drive(context.Background())
	if err != nil {
		t.Fatalf("a coordinator with an eager approver could not drive the saga: %v", err)
	}
	if final.Status != saga.StatusCommitted {
		t.Fatalf("the saga is %s, want COMMITTED", final.Status)
	}
	if st := final.Steps["wire"]; st.ProposalAttempt != 1 {
		t.Fatalf("the approval was recorded without the gate having escalated (proposal attempt %d)",
			st.ProposalAttempt)
	}
}

// TestAuditNamesAPersonsApprovalAParticipantGave: a version-3 log in which the
// release approval of a person's gate was answered by the agent in its own
// name, claiming the role. Every verdict re-derives; only this check names it.
func TestAuditNamesAPersonsApprovalAParticipantGave(t *testing.T) {
	app, dir := newAuditLog(t)
	ctx := context.Background()
	r := saga.NewRunner(app, auditParticipant)
	if _, err := r.BeginUnder(ctx, wireBegin(t, releaseApprovalPolicy), 3); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PrepareStep(ctx, &janusv1.StepPrepare{SagaId: "sg_1", StepId: "wire",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.StepResult(ctx, &janusv1.StepResult{SagaId: "sg_1", StepId: "wire", Attempt: 1,
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Answer(ctx, &janusv1.GateAnswer{
		SagaId: "sg_1", StepId: "wire", RequirementId: "release-approval", Attempt: 1,
		Actor:   &janusv1.Actor{Participant: &janusv1.ParticipantRef{Id: "ag_intake"}},
		Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"}, Reason: "ok",
	}); err != nil {
		t.Fatalf("version 3 recorded this answer legally, and that is the premise: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := findingOf(rep, gate.FindingNotAPerson)
	if f == nil || !strings.Contains(f.Detail, `participant "ag_intake"`) {
		t.Fatalf("a person's approval given by the agent in its own name went unnamed:\n%s", rep)
	}
}

// decideOriginatorApproval records, under `version`, a wire begun by
// originator "person:carol@bank" for principal "bob", approved by carol at its
// separation-of-duty person gate, and returns what the gate decides.
func decideOriginatorApproval(t *testing.T, version uint32) janusv1.Verdict {
	t.Helper()
	app, _ := newAuditLog(t)
	ctx := context.Background()
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1", Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in", Principal: "bob", MandateRef: "m-1",
			Originator: "person:carol@bank"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Participant: "ag_audit", Action: "payments.wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	}
	if err := gate.NewEngine(mustPolicy(t, approvalPolicy)).Admit(begin); err != nil {
		t.Fatal(err)
	}
	r := saga.NewRunner(app, auditParticipant)
	if _, err := r.BeginUnder(ctx, begin, version); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PrepareStep(ctx, &janusv1.StepPrepare{SagaId: "sg_1", StepId: "wire"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.StepResult(ctx, &janusv1.StepResult{SagaId: "sg_1", StepId: "wire", Attempt: 1,
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Answer(ctx, &janusv1.GateAnswer{
		SagaId: "sg_1", StepId: "wire", RequirementId: "approval", Attempt: 1,
		Actor:   &janusv1.Actor{HumanSubject: "person:carol@bank"},
		Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"}, AuthRef: "auth:carol",
	}); err != nil {
		t.Fatal(err)
	}
	st, _ := r.State().Step("wire")
	_ = app.Close()
	return gate.Decide(janusv1.GatePhase_GATE_PHASE_PRE_RELEASE, gate.Input{
		Saga: r.State(), Step: st, Declared: st.Facts,
	}).GateVerdict("").GetVerdict()
}

// TestTheInitiatorDoesNotApproveTheirOwnSaga is the audit's M-2: separation of
// duty compared the approver with the principal -- the organisation, which a
// signed begin now forces to be the signer's -- and never with the person who
// began the saga. Under semantics 4 it compares with the declared originator
// too; under 3 the same history re-derives as it always did.
func TestTheInitiatorDoesNotApproveTheirOwnSaga(t *testing.T) {
	if got := decideOriginatorApproval(t, 4); got != janusv1.Verdict_VERDICT_FAIL {
		t.Fatalf("under semantics 4 the saga's originator approved it and the gate decided %s", got)
	}
	if got := decideOriginatorApproval(t, 3); got != janusv1.Verdict_VERDICT_PASS {
		t.Fatalf("under semantics 3 this history re-derived as %s; it must keep its meaning", got)
	}
}
