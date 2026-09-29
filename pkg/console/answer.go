package console

import (
	"context"
	"errors"
	"fmt"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/identity"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Recording an approval, and everything this deliberately does not do.
//
// It appends one GATE_ANSWER — the same event a validator produces and the same
// one the chaos suite feeds in — and stops. It does not compose the verdict, it
// does not advance the saga, and it does not check whether the approval is
// sufficient. All three belong to the coordinator, which will read this answer
// off the log along with every other input and decide.
//
// That division is what keeps an approval from the console indistinguishable
// from an approval from anywhere else, which is the property that matters: if
// the console had a shorter path to a released effect than the ordinary one,
// the console would be the thing to attack.
//
// Three refusals happen here rather than downstream, because all three would
// otherwise put a meaningless event in the log:
//
//   - an answer to a requirement the saga was not admitted under, which is how
//     a quorum gets satisfied with answers to a question nobody asked;
//   - an answer to a step that is not waiting, which records an opinion about
//     a decision already made;
//   - an answer from nobody — an unauthenticated approval — which is the whole
//     subject of the identity note below.

// Approver is who is answering, as established by the layer in front of the
// console.
//
// Janus does not authenticate anybody. The roles here are what an
// authenticating proxy asserted, recorded as an assertion; the gate checks the
// claim against what the requirement demands and cannot check that the claim
// was true. AuthRef says where the claim
// came from, so a reader can weigh it rather than assume it.
type Approver struct {
	// Subject is the person's identifier. Never taken from a form: the whole
	// point of separation of duty is that the approver cannot choose who they
	// are.
	Subject string
	Roles   []string
	AuthRef string
	// Assertion is the proof the approver presented: an OIDC ID token, and for
	// a step-up a WebAuthn assertion bound to this approval.
	//
	// When it is present the console verifies it, stores it content-addressed,
	// and records the reference in AuthRef — so a gate that requires an
	// established identity has something to verify rather than a claim to read.
	// When it is absent the console records
	// what the authenticating layer asserted, which is what it has always done
	// and is exactly as trustworthy as that layer.
	Assertion *identity.Assertion
}

// AnswerRequest is one approval or refusal.
type AnswerRequest struct {
	SagaID        string
	StepID        string
	RequirementID string
	Approve       bool
	Reason        string
	By            Approver
}

// ErrNotAnswerable means the answer does not belong to anything that is waiting.
var ErrNotAnswerable = errors.New("console: nothing here is waiting for that answer")

// ErrAnonymous means no authenticated identity was supplied.
var ErrAnonymous = errors.New("console: an approval needs an authenticated approver")

// Answer records an approval or refusal against a gate.
//
// It opens the evidence log as a writer, which means it can only run where no
// coordinator is writing: one process owns a directory at a time (see
// evidence.ErrLocked). A deployment that wants the console live beside a
// running coordinator hands the answer to that coordinator instead — which is
// the Phase 4 service boundary.
func (c *Console) Answer(ctx context.Context, req AnswerRequest) (evidence.Ref, error) {
	if strings.TrimSpace(req.By.Subject) == "" {
		return evidence.Ref{}, ErrAnonymous
	}

	state, err := saga.ReplaySaga(c.dir, req.SagaID)
	if err != nil {
		return evidence.Ref{}, fmt.Errorf("console: read saga %s: %w", req.SagaID, err)
	}
	st, ok := state.Steps[req.StepID]
	if !ok {
		return evidence.Ref{}, fmt.Errorf("%w: saga %s has no step %s", ErrNotAnswerable,
			req.SagaID, req.StepID)
	}
	if !saga.HeldByGate(st) {
		return evidence.Ref{}, fmt.Errorf("%w: step %s/%s is %s and its last gate decision was "+
			"%q; an answer now would be an opinion about a decision already made",
			ErrNotAnswerable, req.SagaID, req.StepID, st.Status, shortVerdict(st.Gate.Verdict))
	}

	phase := saga.PhaseUnderDecision(st)
	var requirement *janusv1.GateRequirement
	for _, r := range st.Gates {
		if r.GetId() == req.RequirementID {
			requirement = r
			break
		}
	}
	switch {
	case requirement == nil:
		return evidence.Ref{}, fmt.Errorf("%w: step %s/%s was not admitted under a requirement "+
			"called %q", ErrNotAnswerable, req.SagaID, req.StepID, req.RequirementID)
	case requirement.GetGate() != janusv1.GateType_GATE_TYPE_HUMAN:
		// A validator's opinion comes from the validator, under its own
		// participant identity. Letting a person record one from here would put
		// an independent opinion in the log that no independent party gave.
		return evidence.Ref{}, fmt.Errorf("%w: %q is a %s gate, which is answered by the "+
			"participants it names, not by a person", ErrNotAnswerable, req.RequirementID,
			shortGate(requirement.GetGate()))
	case requirement.GetPhase() != phase:
		return evidence.Ref{}, fmt.Errorf("%w: %q is decided %s and the step is at %s",
			ErrNotAnswerable, req.RequirementID, shortPhase(requirement.GetPhase()),
			shortPhase(phase))
	}

	verdict := janusv1.Verdict_VERDICT_PASS
	if !req.Approve {
		verdict = janusv1.Verdict_VERDICT_FAIL
	}
	answer := &janusv1.GateAnswer{
		SagaId:        req.SagaID,
		StepId:        req.StepID,
		RequirementId: req.RequirementID,
		Attempt:       saga.AttemptUnderDecision(st, phase),
		Actor:         &janusv1.Actor{HumanSubject: req.By.Subject},
		Verdict:       verdict,
		Reason:        req.Reason,
		Roles:         req.By.Roles,
		AuthRef:       req.By.AuthRef,
	}

	// The assertion is verified and stored before the answer goes anywhere. The
	// console keeps its own refusals rather than forwarding them: an approval
	// attributed to somebody the proof does not name is not an approval by
	// them, and finding that out at the gate would mean the answer is already
	// in the log.
	//
	// This runs above the delegation below, and the ordering is the whole
	// point. It was the other way round until step-up was built, which meant a console
	// pointed at a daemon — the only shape that works beside a running
	// coordinator, and therefore the one a deployment actually uses — dropped
	// the proof on the floor and recorded the proxy header instead. Silently:
	// the approval succeeded, and the gate that required an established
	// identity refused it later for a reason that named nothing about the
	// console. Storing the assertion is a blob-store write, not a log append,
	// so there is nothing about delegation that prevents it.
	if req.By.Assertion != nil {
		ref, verr := c.captureAssertion(ctx, req, answer)
		if verr != nil {
			return evidence.Ref{}, verr
		}
		answer.AuthRef = ref
	}

	// A console pointed at a daemon hands the answer over. Everything above
	// this line still happened here: the checks are the console's, and the only
	// thing delegated is the append it is not allowed to do.
	if c.recorder != nil {
		ref, err := c.recorder.RecordAnswer(ctx, answer)
		if err != nil {
			return evidence.Ref{}, fmt.Errorf("console: the orchestrator refused to record "+
				"the answer: %w", err)
		}
		return ref, nil
	}

	app, err := evidence.Open(evidence.Options{Dir: c.dir, SyncMode: segment.SyncModeFull})
	if err != nil {
		if errors.Is(err, evidence.ErrLocked) {
			// The honest version of this limitation. One process writes an
			// evidence directory at a time, so a console cannot append while a
			// coordinator holds it. The answer is not lost and nothing is
			// half-written — the person is told to try again, and the fix is
			// the service boundary Phase 4 introduces, where the coordinator
			// takes the answer rather than the console writing it.
			return evidence.Ref{}, fmt.Errorf("%w — a coordinator is writing this log, so the "+
				"console cannot append the answer right now; it will go through once that "+
				"process finishes", err)
		}
		return evidence.Ref{}, fmt.Errorf("console: open the log to record the answer: %w", err)
	}
	defer func() { _ = app.Close() }()

	// The runner is given the identity of the console itself, not of the
	// approver. The console is what wrote the event; who approved is inside it,
	// and conflating the two would make the log say a person appended to the
	// evidence chain.
	runner := saga.NewRunner(app, evidence.ParticipantRef{
		ID: "sys_console", Kind: "SYSTEM", Principal: state.Intent.Principal,
	})
	runner.Adopt(state)

	ref, err := runner.Answer(ctx, answer)
	if err != nil {
		return evidence.Ref{}, fmt.Errorf("console: record answer: %w", err)
	}
	return ref, nil
}

// captureAssertion verifies the proof an approver presented and stores it.
//
// The trust store is folded out of this log, not configured here. That is the
// property that makes the whole thing worth having: a third party replaying the
// bundle folds the same store and reaches the same answer, rather than
// verifying against keys they chose.
func (c *Console) captureAssertion(ctx context.Context, req AnswerRequest,
	answer *janusv1.GateAnswer) (string, error) {

	if c.blobs == nil {
		return "", fmt.Errorf("console: an assertion was presented and this console has no " +
			"blob store to put it in; without one the proof would be summarised into the " +
			"log rather than kept, and a summary of a signature verifies nothing")
	}
	trust, err := identity.LoadTrust(c.dir)
	if err != nil {
		return "", fmt.Errorf("console: reading the identity trust store: %w", err)
	}
	binding := identity.Binding{
		SagaID: req.SagaID, StepID: req.StepID,
		RequirementID: req.RequirementID, Attempt: answer.GetAttempt(),
	}
	established, err := identity.Verify(req.By.Assertion, trust, binding, time.Now())
	if err != nil {
		return "", fmt.Errorf("console: the assertion does not establish this approval: %w", err)
	}
	if established.Subject != req.By.Subject {
		return "", fmt.Errorf("%w: the approver is recorded as %q and the assertion "+
			"establishes %q", ErrNotAnswerable, req.By.Subject, established.Subject)
	}
	return identity.PutAssertion(ctx, c.blobs, req.By.Assertion)
}
