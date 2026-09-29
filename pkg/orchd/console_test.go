package orchd_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/console"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/orchd"
)

const notifySaga = "sg_notify"

// TestAConsoleRecordsAnApprovalWhileTheCoordinatorIsRunning is the first
// half of the Phase 4a exit gate.
//
// Until now this was impossible by construction: one process writes an evidence
// directory, so a console beside a live coordinator could only tell
// the approver to come back later. The answer is not composed differently now —
// the console still runs every check and still produces the same GATE_ANSWER —
// it is simply appended by the process that owns the log.
//
// The test asserts both halves, because only the pair is evidence: the direct
// path must still be refused, or the delegated path is not solving anything.
func TestAConsoleRecordsAnApprovalWhileTheCoordinatorIsRunning(t *testing.T) {
	s, dir := newGatedServer(t)
	client, stop := dial(t, s)
	defer stop()
	ctx := context.Background()

	beginGated(t, s, ctx)

	req := console.AnswerRequest{
		SagaID: notifySaga, StepID: "st_notify", RequirementID: "notify-four-eyes",
		Approve: true, Reason: "counterparty verified",
		By: console.Approver{
			Subject: "person:alice@bank", Roles: []string{"credit-officer"},
			AuthRef: "oidc:session-1",
		},
	}

	// Half one: the coordinator is running, so the console cannot write.
	_, err := console.Open(dir).Answer(ctx, req)
	if !errors.Is(err, evidence.ErrLocked) {
		t.Fatalf("a console appending directly beside a live daemon should be refused "+
			"by the writer lock; got %v — if this stops being true the test below "+
			"proves nothing", err)
	}

	// Half two: pointed at the daemon, the same approval goes through.
	ref, err := console.Open(dir).WithRecorder(orchd.NewClient(clientConn(t, s))).
		Answer(ctx, req)
	if err != nil {
		t.Fatalf("recording an approval through the orchestrator: %v", err)
	}
	if ref.Seq == 0 {
		t.Fatal("the approver was given no record of their own approval")
	}

	got := getSaga(t, s, notifySaga)
	if step := stepOf(t, got, "st_notify"); step.GetWaitingOnGate() != "" {
		t.Fatalf("the step is still waiting on %q after the gate was answered; "+
			"the answer was recorded but nothing acted on it",
			step.GetWaitingOnGate())
	}
	_ = client
}

// TestAConsoleStillRefusesAnAnswerItsOwnChecksReject proves the delegation did
// not become a way around the console's refusals.
//
// The console keeps every check and delegates only the append. A console that
// forwarded first and let the server decide would be a console that can be
// talked out of separation of duty by the thing it is supposed to be
// independent of.
func TestAConsoleStillRefusesAnAnswerItsOwnChecksReject(t *testing.T) {
	s, dir := newGatedServer(t)
	ctx := context.Background()
	beginGated(t, s, ctx)

	c := console.Open(dir).WithRecorder(orchd.NewClient(clientConn(t, s)))
	_, err := c.Answer(ctx, console.AnswerRequest{
		SagaID: notifySaga, StepID: "st_notify", RequirementID: "no-such-requirement",
		Approve: true,
		By:      console.Approver{Subject: "person:alice@bank", AuthRef: "oidc:session-1"},
	})
	if !errors.Is(err, console.ErrNotAnswerable) {
		t.Fatalf("an answer to a requirement the saga was never admitted under must be "+
			"refused by the console itself, not forwarded; got %v", err)
	}
}

func beginGated(t *testing.T, s *orchd.Server, ctx context.Context) {
	t.Helper()
	beginGatedPlan(t, s, ctx)
	attempt := prepareStep(t, s, notifySaga, "st_notify")
	if _, err := s.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: notifySaga, StepId: "st_notify", Attempt: attempt,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		},
	}); err != nil {
		t.Fatalf("reporting the step: %v", err)
	}
	if step := stepOf(t, getSaga(t, s, notifySaga), "st_notify"); step.GetWaitingOnGate() == "" {
		t.Fatal("the step should now be waiting for a person; the rest of this test " +
			"has nothing to approve")
	}
}

// beginGatedPlan records the plan and stops. It is separate because the
// delivery tests have to hold an effect between the prepare and the result,
// which is the order the outbox insists on.
func beginGatedPlan(t *testing.T, s *orchd.Server, ctx context.Context) {
	t.Helper()
	begin := &janusv1.SagaBegin{
		SagaId: notifySaga,
		Mode:   "supervised",
		Intent: &janusv1.Intent{
			IntentId: "in_notify", Principal: testPrincipal,
			Originator: "human:desk@bank", MandateRef: "mandate:payments",
			Scope: "notify a counterparty",
		},
		Plan: []*janusv1.PlannedStep{{
			StepId: "st_notify", Participant: "tool_payments", Action: "notify.email",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
	}
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{Begin: begin}); err != nil {
		t.Fatalf("beginning the gated saga: %v", err)
	}
}

// newGatedServer is newServer with a policy that puts one human in front of any
// irreversible effect — the smallest thing that produces something to approve.
func newGatedServer(t *testing.T) (*orchd.Server, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)

	p := &gate.Policy{
		ID: "orchd.test",
		Rules: []gate.Rule{{
			ID:    "irreversible-needs-a-person",
			Match: gate.Match{EffectClasses: []string{"IRREVERSIBLE_GATED"}},
			Require: []gate.Requirement{{
				ID: "notify-four-eyes", Gate: gate.GateHuman, Phase: gate.PhasePreRelease,
				Human: &gate.HumanSpec{Roles: []string{"credit-officer"}, Quorum: 1},
			}},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: p,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

// TestTheProjectionSaysWhichGateIsWaitingAndWhoMayAnswerIt is what makes a
// connected answerer possible at all.
//
// Before this, a client was told that a step was waiting and given a sentence
// of prose. A validator could not act on that: it did not know which
// requirement was outstanding, which attempt an answer would belong to, or
// whether it was one of the parties named to answer. The only way to find out
// was to read the log — which is the one thing a client of this service does
// not do.
func TestTheProjectionSaysWhichGateIsWaitingAndWhoMayAnswerIt(t *testing.T) {
	s, _ := newGatedServer(t)
	beginGated(t, s, context.Background())

	step := stepOf(t, getSaga(t, s, notifySaga), "st_notify")
	pending := step.GetPendingGates()
	if len(pending) != 1 {
		t.Fatalf("the step is held by a gate but the projection lists %d pending gates; "+
			"an answerer has nothing to answer", len(pending))
	}
	g := pending[0]
	if g.GetRequirementId() != "notify-four-eyes" {
		t.Fatalf("pending gate is %q, want the requirement the saga was admitted under; "+
			"an answer to a requirement that was never resolved is meaningless",
			g.GetRequirementId())
	}
	if g.GetGate() != janusv1.GateType_GATE_TYPE_HUMAN {
		t.Fatalf("pending gate type is %s, want HUMAN — a validator and a person are "+
			"answered by different parties", g.GetGate())
	}
	if g.GetAttempt() != 1 {
		t.Fatalf("pending gate names attempt %d, want 1; an answer for the wrong attempt "+
			"is an opinion about a decision already made", g.GetAttempt())
	}
	if len(g.GetAnswerableBy()) != 1 || g.GetAnswerableBy()[0] != "credit-officer" {
		t.Fatalf("answerable_by is %v, want [credit-officer] — without it a connected "+
			"party cannot tell whether the question is for it", g.GetAnswerableBy())
	}
	if g.GetQuorum() != 1 {
		t.Fatalf("quorum is %d, want 1; a caller that cannot tell one answer short from "+
			"a refusal either gives up or answers twice", g.GetQuorum())
	}
}

// TestAnAnsweredGateLeavesTheQueue guards the other direction: a requirement
// that has been satisfied must stop being listed, or every answerer that
// connects would try to answer it again.
func TestAnAnsweredGateLeavesTheQueue(t *testing.T) {
	s, dir := newGatedServer(t)
	ctx := context.Background()
	beginGated(t, s, ctx)

	if _, err := console.Open(dir).WithRecorder(orchd.NewClient(clientConn(t, s))).
		Answer(ctx, console.AnswerRequest{
			SagaID: notifySaga, StepID: "st_notify", RequirementID: "notify-four-eyes",
			Approve: true, Reason: "verified",
			By: console.Approver{
				Subject: "person:alice@bank", Roles: []string{"credit-officer"},
				AuthRef: "oidc:session-1",
			},
		}); err != nil {
		t.Fatalf("approving: %v", err)
	}

	step := stepOf(t, getSaga(t, s, notifySaga), "st_notify")
	if got := len(step.GetPendingGates()); got != 0 {
		t.Fatalf("the gate was answered and %d pending gates remain; an answerer that "+
			"reconnected would answer it a second time", got)
	}
}
