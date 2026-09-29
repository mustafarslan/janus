package console_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/console"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/saga"
)

// What an approval through the console is, and what it is not.
//
// It is one GATE_ANSWER, identical in shape and consequence to one arriving
// from anywhere else. It is not a decision: the coordinator composes the
// verdict afterwards, from the log, and applies the same rules it applies to
// every other answer. These tests hold that line, because a console with a
// shorter path to a released effect than the ordinary one is the thing an
// attacker would go for.

func approve(t *testing.T, dir, subject string, roles []string) error {
	t.Helper()
	_, err := console.Open(dir).Answer(context.Background(), console.AnswerRequest{
		SagaID:        testSaga,
		StepID:        testStep,
		RequirementID: fourEyesReq,
		Approve:       true,
		Reason:        "checked against the invoice",
		By:            console.Approver{Subject: subject, Roles: roles, AuthRef: "proxy-header:X-User"},
	})
	return err
}

func TestAnApprovalIsRecordedAsAnOrdinaryAnswer(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)

	if err := approve(t, dir, "alice", []string{"credit-officer"}); err != nil {
		t.Fatalf("recording an approval failed: %v", err)
	}

	// It is in the log, against the requirement and the attempt it answers.
	state, err := saga.ReplaySaga(dir, testSaga)
	if err != nil {
		t.Fatal(err)
	}
	st := state.Steps[testStep]
	answers := saga.AnswersFor(st, fourEyesReq, saga.AttemptUnderDecision(st,
		saga.PhaseUnderDecision(st)))
	if len(answers) != 1 {
		t.Fatalf("%d answers recorded against the four-eyes gate", len(answers))
	}
	a := answers[0]
	switch {
	case a.ActorID != "alice":
		t.Fatalf("recorded actor %q", a.ActorID)
	case !a.Human:
		t.Fatal("the answer is not recorded as a person's")
	case a.Verdict != janusv1.Verdict_VERDICT_PASS:
		t.Fatalf("recorded verdict %v", a.Verdict)
	case a.AuthRef != "proxy-header:X-User":
		t.Fatalf("the answer does not say where the identity claim came from: %q", a.AuthRef)
	case len(a.Roles) != 1 || a.Roles[0] != "credit-officer":
		t.Fatalf("roles recorded as %v", a.Roles)
	}

	// And the console did not decide anything: one approval of the two the gate
	// asks for still leaves the step waiting.
	if st.Gate.Verdict == janusv1.Verdict_VERDICT_PASS {
		t.Fatal("recording an approval moved the step's verdict; the console decided a gate")
	}
	q, err := console.Open(dir).Queue()
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Items) != 1 {
		t.Fatalf("the step left the queue after one of two approvals")
	}
	if !strings.Contains(q.Items[0].Outstanding[0].Reason, "1 of 2") {
		t.Fatalf("the queue does not show the approval that arrived: %q",
			q.Items[0].Outstanding[0].Reason)
	}
}

// TestTheGateStillDecides. Two approvals from two people with the right roles
// satisfy the requirement — and it is the gate composition that says so, run
// afterwards over the log, not the console.
func TestTheGateStillDecides(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)

	if err := approve(t, dir, "alice", []string{"credit-officer"}); err != nil {
		t.Fatal(err)
	}
	if err := approve(t, dir, "carol", []string{"treasury-approver"}); err != nil {
		t.Fatal(err)
	}

	state, err := saga.ReplaySaga(dir, testSaga)
	if err != nil {
		t.Fatal(err)
	}
	st := state.Steps[testStep]
	d := gate.Decide(saga.PhaseUnderDecision(st), gate.Input{
		Saga: state, Step: st, Index: saga.NewIndex(state),
	})
	if !d.Passed() {
		t.Fatalf("two valid approvals did not satisfy the gate: %s", d.Reason)
	}
}

// TestASelfApprovalIsRefusedByTheGateNotHiddenByTheConsole.
//
// The console records it. The gate refuses it, and records a finding rather
// than waiting past it. That division is the point: if the console silently
// dropped the attempt, the log would show a payment that nobody ever tried to
// self-approve.
func TestASelfApprovalIsRefusedByTheGateNotHiddenByTheConsole(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)

	if err := approve(t, dir, testPrincipal, []string{"credit-officer"}); err != nil {
		t.Fatalf("the console refused to record a self-approval; it has to be on the record: %v", err)
	}

	state, err := saga.ReplaySaga(dir, testSaga)
	if err != nil {
		t.Fatal(err)
	}
	st := state.Steps[testStep]
	d := gate.Decide(saga.PhaseUnderDecision(st), gate.Input{
		Saga: state, Step: st, Index: saga.NewIndex(state),
	})
	if d.Verdict != janusv1.Verdict_VERDICT_FAIL {
		t.Fatalf("a self-approval produced %v: %s", d.Verdict, d.Reason)
	}
	if !strings.Contains(d.Reason, "initiator") {
		t.Fatalf("the refusal does not say why: %q", d.Reason)
	}
}

// TestAnAnonymousApprovalIsRefused. There is no such thing as an approval by
// nobody, and inventing an identity for one is how separation of duty becomes
// a formality.
func TestAnAnonymousApprovalIsRefused(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)

	err := approve(t, dir, "", nil)
	if !errors.Is(err, console.ErrAnonymous) {
		t.Fatalf("an approval with no approver was accepted: %v", err)
	}
}

// TestAnAnswerToSomethingThatIsNotWaitingIsRefused, in each of the ways it can
// be wrong. Every one of these would otherwise put a meaningless event in a log
// that is supposed to be the record of what happened.
func TestAnAnswerToSomethingThatIsNotWaitingIsRefused(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)

	cases := []struct {
		name string
		req  console.AnswerRequest
		want string
	}{
		{
			name: "a requirement the saga was not admitted under",
			req:  console.AnswerRequest{StepID: testStep, RequirementID: "wire-invented"},
			want: "not admitted under a requirement",
		},
		{
			name: "a step that does not exist",
			req:  console.AnswerRequest{StepID: "st_nowhere", RequirementID: fourEyesReq},
			want: "no step",
		},
		{
			name: "a validator gate, which is not a person's to answer",
			req:  console.AnswerRequest{StepID: testStep, RequirementID: secondOpinion},
			want: "answered by the participants it names",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			req.SagaID = testSaga
			req.Approve = true
			req.By = console.Approver{Subject: "alice", Roles: []string{"credit-officer"}}

			_, err := console.Open(dir).Answer(context.Background(), req)
			if err == nil {
				t.Fatal("the answer was recorded")
			}
			if !errors.Is(err, console.ErrNotAnswerable) {
				t.Fatalf("want ErrNotAnswerable, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// TestAnAnswerToADecidedStepIsRefused. Once the gate has resolved, an answer is
// an opinion about a decision already made.
func TestAnAnswerToADecidedStepIsRefused(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)

	if err := approve(t, dir, "alice", []string{"credit-officer"}); err != nil {
		t.Fatal(err)
	}
	if err := approve(t, dir, "carol", []string{"treasury-approver"}); err != nil {
		t.Fatal(err)
	}
	// Drive the saga to the end, so the gate has actually decided.
	finish(t, dir)

	err := approve(t, dir, "dave", []string{"credit-officer"})
	if !errors.Is(err, console.ErrNotAnswerable) {
		t.Fatalf("an answer to a settled step was accepted: %v", err)
	}
}
