package orchd_test

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/console"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// preApprovalPolicy puts a person in front of an irreversible step *before* it
// runs. That is the phase the proposal pin is about: at release the facts are already
// pinned by the prepare, and before it nothing pinned them.
func preApprovalPolicy(t *testing.T) *gate.Policy {
	t.Helper()
	p := &gate.Policy{ID: "orchd.pre-approval", Rules: []gate.Rule{{
		ID: "wires-need-a-person-first", Match: gate.Match{EffectClasses: []string{"IRREVERSIBLE_GATED"}},
		Require: []gate.Requirement{{
			ID: "pre-approval", Gate: gate.GateHuman, Phase: gate.PhasePreExecution,
			Human: &gate.HumanSpec{Roles: []string{"credit-officer"}, Quorum: 1},
		}, {
			// Admission refuses an irreversible step nothing judges at
			// release. This one bounds nothing the test turns on, so the
			// pre-execution approval is the only thing standing in the way.
			ID: "release-sanity", Gate: gate.GatePolicy, Phase: gate.PhasePreRelease,
			Policy: &gate.PolicySpec{Expr: "amount_minor >= 0"},
		}},
	}}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func openPreApproval(t *testing.T, dir string, signer *keys.Signer) *orchd.Server {
	t.Helper()
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: preApprovalPolicy(t),
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func proposeAmount(s *orchd.Server, n int64) (*janusv1.PrepareStepResponse, error) {
	return s.PrepareStep(context.Background(), &janusv1.PrepareStepRequest{
		SagaId: notifySaga, StepId: "st_notify",
		Facts: []*janusv1.Fact{{Key: "amount_minor", Value: &janusv1.Fact_Number{Number: n}}},
	})
}

func approveAt100(t *testing.T, s *orchd.Server, dir string) {
	t.Helper()
	if _, err := console.Open(dir).WithRecorder(orchd.NewClient(clientConn(t, s))).Answer(
		context.Background(), console.AnswerRequest{
			SagaID: notifySaga, StepID: "st_notify", RequirementID: "pre-approval",
			Approve: true, Reason: "approved for 100",
			By: console.Approver{
				Subject: "person:alice@bank", Roles: []string{"credit-officer"},
				AuthRef: "oidc:session-1",
			},
		}); err != nil {
		t.Fatalf("approving: %v", err)
	}
}

func escalateOn100(t *testing.T) (*orchd.Server, string, *keys.Signer) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	s := openPreApproval(t, dir, signer)
	beginGatedPlan(t, s, context.Background())
	resp, err := proposeAmount(s, 100)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != janusv1.PrepareStatus_PREPARE_STATUS_GATED {
		t.Fatalf("a wire proposed under a pre-execution approval was %s, not held; the rest "+
			"of this test has nothing to swap", resp.GetStatus())
	}
	return s, dir, signer
}

// pinnedAmount reads what the step will run on, from the log.
func pinnedAmount(t *testing.T, dir string) string {
	t.Helper()
	st, err := saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(saga.DescribeFacts(st.Steps["st_notify"].Facts), " ")
}

// TestAParticipantCannotChangeAProposalWhileItIsBeingDecided is the swap
// that motivated the pin: a participant held on 100 declared 1,000,000, the person
// approved "100", and the approval was pinned against 1,000,000.
func TestAParticipantCannotChangeAProposalWhileItIsBeingDecided(t *testing.T) {
	s, dir, _ := escalateOn100(t)
	defer func() { _ = s.Close() }()

	_, err := proposeAmount(s, 1_000_000)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a participant held on 100 proposed 1,000,000 while the question was open "+
			"and was told %v; the approval being collected is about 100", err)
	}
	if !strings.Contains(err.Error(), "waiting on a decision about amount_minor=100") {
		t.Errorf("refused, but the participant is not told what it is held on: %v", err)
	}

	approveAt100(t, s, dir)
	if got := pinnedAmount(t, dir); got != "amount_minor=100" {
		t.Fatalf("the approval was given for 100 and the step is pinned to %q", got)
	}
}

// TestARestartDoesNotHandTheApprovalToTheNextProposal: the same hole by a
// second route. The daemon held the proposal in memory, so after a restart the
// approval was decided on whatever the participant's next prepare carried —
// the participant did not even have to re-declare during the window.
func TestARestartDoesNotHandTheApprovalToTheNextProposal(t *testing.T) {
	s, dir, signer := escalateOn100(t)
	_ = s.Close()
	s = openPreApproval(t, dir, signer)
	defer func() { _ = s.Close() }()

	approveAt100(t, s, dir)
	if _, err := proposeAmount(s, 1_000_000); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("after a restart, the approval for 100 went to the next proposal, "+
			"1,000,000: %v", err)
	}
	resp, err := proposeAmount(s, 100)
	if err != nil || resp.GetStatus() != janusv1.PrepareStatus_PREPARE_STATUS_PREPARED {
		t.Fatalf("the approved proposal itself would not prepare: %v %s", err, resp.GetStatus())
	}
	if got := pinnedAmount(t, dir); got != "amount_minor=100" {
		t.Fatalf("the approval was given for 100 and the step runs on %q", got)
	}
}

// versionOneParent writes a parent saga as a build that implemented only
// semantics 1 would have, and, if spawned is set, the prepare in which its step
// recorded delegating to that child.
func versionOneParent(t *testing.T, dir string, signer *keys.Signer, spawned string) {
	t.Helper()
	app, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	runner := saga.NewRunner(app, evidence.ParticipantRef{
		ID: "ag_old", Principal: testPrincipal, Kind: "AGENT",
	})
	parent := &janusv1.SagaBegin{
		SagaId: "sg_parent", Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in_parent", Principal: testPrincipal,
			Originator: "human:desk@bank", MandateRef: "mandate:payments", Scope: "delegate"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "st_delegate", Participant: "tool_payments", Action: "notify.email",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE, CompensationAction: "notify.retract",
		}},
	}
	if _, err := runner.BeginUnder(context.Background(), parent, 1); err != nil {
		t.Fatal(err)
	}
	if spawned == "" {
		return
	}
	if _, err := runner.PrepareStep(context.Background(), &janusv1.StepPrepare{
		SagaId: "sg_parent", StepId: "st_delegate",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
		Spawns: &janusv1.ChildSaga{
			SagaId: spawned, CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_AUTONOMOUS,
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func childBegin(id string) *janusv1.SagaBegin {
	return &janusv1.SagaBegin{
		SagaId: id, Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in_" + id, Principal: testPrincipal,
			Originator: "human:desk@bank", MandateRef: "mandate:payments", Scope: "delegated"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "st_notify", Participant: "tool_payments", Action: "notify.email",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
		Parent: &janusv1.ParentSaga{
			SagaId: "sg_parent", StepId: "st_delegate",
			CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_AUTONOMOUS,
		},
	}
}

func beginChild(t *testing.T, s *orchd.Server, dir, id string) uint32 {
	t.Helper()
	if _, err := s.BeginSaga(context.Background(), &janusv1.BeginSagaRequest{Begin: childBegin(id)}); err != nil {
		t.Fatalf("beginning %s: %v", id, err)
	}
	got, err := saga.ReplaySaga(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	return got.Semantics
}

// TestASubSagaFoldsUnderItsParentsRules is the family check that had to
// ship with version 2. A parent admitted before an upgrade delegates after it;
// the child its step recorded spawning is admitted under the parent's rules,
// not the new build's.
func TestASubSagaFoldsUnderItsParentsRules(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	versionOneParent(t, dir, signer, "sg_child")

	s := openPreApproval(t, dir, signer)
	defer func() { _ = s.Close() }()
	if got := beginChild(t, s, dir, "sg_child"); got != 1 {
		t.Fatalf("a child of a version-1 parent was admitted under %d; the family now "+
			"disagrees about what the same history means", got)
	}
}

// TestNamingAnOldParentDoesNotBuyItsRules closes one route to an old parent's rules.
// Naming a parent is the caller's claim, and a new saga that could claim any
// version-1 saga as its parent was admitted under version 1 -- where the
// proposal swap is legal again. Only a child the parent's step recorded spawning
// inherits; a child of an older parent that has not recorded it is refused,
// rather than admitted under rules its family does not share.
func TestNamingAnOldParentDoesNotBuyItsRules(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	versionOneParent(t, dir, signer, "sg_real_child")

	s := openPreApproval(t, dir, signer)
	defer func() { _ = s.Close() }()
	_, err = s.BeginSaga(context.Background(), &janusv1.BeginSagaRequest{Begin: childBegin("sg_impostor")})
	if status.Code(err) != codes.FailedPrecondition {
		got, _ := saga.ReplaySaga(dir, "sg_impostor")
		t.Fatalf("a saga its named version-1 parent never spawned was admitted (semantics %d, "+
			"err %v); claiming an old parent would buy the old rules", got.Semantics, err)
	}
	if !strings.Contains(err.Error(), "has not recorded spawning it") {
		t.Errorf("refused, but the caller is not told why: %v", err)
	}
}

// TestAParticipantCannotChangeItsDelegationWhileItIsBeingDecided is route (c):
// the person was asked about a wire that delegates nothing; the participant
// re-declares the same amount delegating to a sub-saga that commits on its own.
func TestAParticipantCannotChangeItsDelegationWhileItIsBeingDecided(t *testing.T) {
	for _, restart := range []bool{false, true} {
		s, dir, signer := escalateOn100(t)
		if restart {
			// The pin is on the log, so a daemon that forgot everything in
			// memory still refuses.
			_ = s.Close()
			s = openPreApproval(t, dir, signer)
		}
		_, err := s.PrepareStep(context.Background(), &janusv1.PrepareStepRequest{
			SagaId: notifySaga, StepId: "st_notify",
			Facts: []*janusv1.Fact{{Key: "amount_minor", Value: &janusv1.Fact_Number{Number: 100}}},
			Spawns: &janusv1.ChildSaga{
				SagaId: "sg_rogue", CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_AUTONOMOUS,
			},
		})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("restart=%v: a participant asked about a wire that delegates nothing "+
				"re-declared it delegating to an autonomous sub-saga and was told %v", restart, err)
		}
		if !strings.Contains(err.Error(), "a proposal that delegates nothing") {
			t.Errorf("restart=%v: refused, but not told what it is held on: %v", restart, err)
		}
		approveAt100(t, s, dir)
		if _, err := proposeAmount(s, 100); err != nil {
			t.Fatalf("restart=%v: the approved proposal would not prepare: %v", restart, err)
		}
		st, err := saga.ReplaySaga(dir, notifySaga)
		if err != nil {
			t.Fatal(err)
		}
		if c := st.Steps["st_notify"].Child; c != nil {
			t.Fatalf("restart=%v: the approval was for a wire that delegates nothing, and "+
				"the step runs delegating to %+v", restart, c)
		}
		_ = s.Close()
	}
}

// factsOf renders a pending gate's facts as "key=value" for assertions.
func factsOf(g *janusv1.PendingGate) map[string]string {
	out := map[string]string{}
	for _, f := range g.GetFacts() {
		switch v := f.GetValue().(type) {
		case *janusv1.Fact_Number:
			out[f.GetKey()] = strconv.FormatInt(v.Number, 10)
		case *janusv1.Fact_Text:
			out[f.GetKey()] = v.Text
		case *janusv1.Fact_Flag:
			out[f.GetKey()] = strconv.FormatBool(v.Flag)
		}
	}
	return out
}

// TestAQuestionCarriesTheProposalItIsAbout: a validator or a person
// asked to approve a step before it runs is shown the proposal the escalation
// pinned — the thing their answer is now bound to — and the facts Janus derives
// from the record, which is what an expression gate would have decided on.
func TestAQuestionCarriesTheProposalItIsAbout(t *testing.T) {
	s, dir, _ := escalateOn100(t)
	defer func() { _ = s.Close() }()

	pending := stepOf(t, getSaga(t, s, notifySaga), "st_notify").GetPendingGates()
	if len(pending) != 1 {
		t.Fatalf("want one pending gate, got %d", len(pending))
	}
	got := factsOf(pending[0])
	if got["amount_minor"] != "100" {
		t.Fatalf("the question about a wire of 100 shows amount_minor=%q; the answerer is "+
			"approving with the number blanked out (all facts: %v)", got["amount_minor"], got)
	}
	if got["step.action"] != "notify.email" || got["intent.principal"] != testPrincipal {
		t.Errorf("the derived facts a gate decides on are missing: %v", got)
	}

	// The console's queue is the human answerer's view of the same question.
	board, err := console.Open(dir).Queue()
	if err != nil {
		t.Fatal(err)
	}
	if len(board.Items) != 1 || board.Items[0].Facts["amount_minor"] != "100" {
		t.Fatalf("the approver's queue does not show what they are approving: %+v", board.Items)
	}
}

// TestAReleaseQuestionCarriesWhatTheStepPreparedOn: at release the question is
// about what the step ran on, which is on the record from its prepare.
func TestAReleaseQuestionCarriesWhatTheStepPreparedOn(t *testing.T) {
	s, _ := newGatedServer(t)
	ctx := context.Background()
	beginGatedPlan(t, s, ctx)
	resp, err := s.PrepareStep(ctx, &janusv1.PrepareStepRequest{
		SagaId: notifySaga, StepId: "st_notify",
		Facts: []*janusv1.Fact{{Key: "recipient", Value: &janusv1.Fact_Text{Text: "ops@bank"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteStep(ctx, &janusv1.CompleteStepRequest{Result: &janusv1.StepResult{
		SagaId: notifySaga, StepId: "st_notify", Attempt: resp.GetAttempt(),
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	}}); err != nil {
		t.Fatal(err)
	}
	pending := stepOf(t, getSaga(t, s, notifySaga), "st_notify").GetPendingGates()
	if len(pending) != 1 {
		t.Fatalf("want one pending release gate, got %d", len(pending))
	}
	if got := factsOf(pending[0]); got["recipient"] != "ops@bank" {
		t.Fatalf("the release question does not show what the step ran on: %v", got)
	}
}

// TestAnEscalatedDelegationIsTheOneThatRuns: the pin carries a delegation when
// there is one, written by the escalation, so the step runs with the sub-saga
// the person was asked about -- including after a restart emptied the daemon's
// memory of what was declared -- and dropping it is refused like changing it.
func TestAnEscalatedDelegationIsTheOneThatRuns(t *testing.T) {
	kid := &janusv1.ChildSaga{
		SagaId: "sg_kid", CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE,
	}
	withKid := func(s *orchd.Server, spawn *janusv1.ChildSaga) (*janusv1.PrepareStepResponse, error) {
		return s.PrepareStep(context.Background(), &janusv1.PrepareStepRequest{
			SagaId: notifySaga, StepId: "st_notify", Spawns: spawn,
			Facts: []*janusv1.Fact{{Key: "amount_minor", Value: &janusv1.Fact_Number{Number: 100}}},
		})
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	s := openPreApproval(t, dir, signer)
	beginGatedPlan(t, s, context.Background())
	if resp, err := withKid(s, kid); err != nil ||
		resp.GetStatus() != janusv1.PrepareStatus_PREPARE_STATUS_GATED {
		t.Fatalf("a delegating wire was not held for its approval: %v %s", err, resp.GetStatus())
	}
	_ = s.Close()
	s = openPreApproval(t, dir, signer)
	defer func() { _ = s.Close() }()

	if _, err := withKid(s, nil); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("the person was asked about a wire delegating to sg_kid, and a re-declaration "+
			"that delegates nothing was accepted: %v", err)
	}
	approveAt100(t, s, dir)
	if _, err := withKid(s, kid); err != nil {
		t.Fatalf("the approved proposal would not prepare: %v", err)
	}
	st, err := saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	if c := st.Steps["st_notify"].Child; c == nil || c.SagaID != "sg_kid" {
		t.Fatalf("the approval was for a wire delegating to cascade sub-saga sg_kid and the "+
			"step runs delegating to %+v", c)
	}
}
