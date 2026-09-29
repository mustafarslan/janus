package gate_test

import (
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/identity"
	"github.com/mustafarslan/janus/pkg/saga"
)

// TestAGateThatRequiresAnEstablishedIdentityChecksTheProvenRolesNotTheClaimed
// is what makes role claims established rather than asserted, for a policy
// that asks for it.
//
// The answer records "credit-officer". The assertion establishes "intern". Left
// to the recorded claim the gate passes, which is the problem with an asserted
// role: the role check is exactly as trustworthy as whatever wrote the
// answer. Verifying, it fails.
func TestAGateThatRequiresAnEstablishedIdentityChecksTheProvenRolesNotTheClaimed(t *testing.T) {
	state := humanGate(t, &janusv1.HumanCheck{
		Roles: []string{"credit-officer"}, RequireEstablishedIdentity: true,
	})
	answer(t, &state, saga.GateAnswerRecord{
		RequirementID: "four-eyes", Attempt: 1, ActorID: "person:alice", Human: true,
		Verdict: janusv1.Verdict_VERDICT_PASS,
		Roles:   []string{"credit-officer"}, // what the answer says
		AuthRef: "blake3:assertion",
	})

	decision := decideWithIdentity(t, state, func(string) (*identity.Established, error) {
		// what the identity provider actually signed for
		return &identity.Established{Subject: "person:alice", Roles: []string{"intern"}}, nil
	})
	if decision.Passed() {
		t.Fatal("the gate accepted a role the answer claimed and no assertion established")
	}
	if !strings.Contains(decision.Reason, "intern") {
		t.Fatalf("the refusal does not name the roles that were actually established: %s",
			decision.Reason)
	}
}

// TestAnEstablishedIdentityWithTheRightRolePasses, so the check above is not
// simply always refusing.
func TestAnEstablishedIdentityWithTheRightRolePasses(t *testing.T) {
	state := humanGate(t, &janusv1.HumanCheck{
		Roles: []string{"credit-officer"}, RequireEstablishedIdentity: true,
	})
	answer(t, &state, saga.GateAnswerRecord{
		RequirementID: "four-eyes", Attempt: 1, ActorID: "person:alice", Human: true,
		Verdict: janusv1.Verdict_VERDICT_PASS, AuthRef: "blake3:assertion",
	})

	decision := decideWithIdentity(t, state, func(string) (*identity.Established, error) {
		return &identity.Established{
			Subject: "person:alice", Roles: []string{"credit-officer"}, SteppedUp: true,
		}, nil
	})
	if !decision.Passed() {
		t.Fatalf("an approval whose role was established was refused: %s", decision.Reason)
	}
}

// TestAnApprovalAttributedToSomebodyTheProofDoesNotNameIsRefused.
//
// The answer says Alice approved; the assertion proves Bob was present. That is
// not a stronger proof, it is an unanswered question.
func TestAnApprovalAttributedToSomebodyTheProofDoesNotNameIsRefused(t *testing.T) {
	state := humanGate(t, &janusv1.HumanCheck{RequireEstablishedIdentity: true})
	answer(t, &state, saga.GateAnswerRecord{
		RequirementID: "four-eyes", Attempt: 1, ActorID: "person:alice", Human: true,
		Verdict: janusv1.Verdict_VERDICT_PASS, AuthRef: "blake3:assertion",
	})

	decision := decideWithIdentity(t, state, func(string) (*identity.Established, error) {
		return &identity.Established{Subject: "person:bob", Roles: []string{"credit-officer"}}, nil
	})
	if decision.Passed() {
		t.Fatal("an approval recorded as Alice's was accepted on a proof that names Bob")
	}
}

// TestAStepUpRequirementRefusesAnApprovalWithoutOne closes the step-up gap for a
// policy that asks for it: an approval is exactly the moment where a stolen session
// should not be enough.
func TestAStepUpRequirementRefusesAnApprovalWithoutOne(t *testing.T) {
	state := humanGate(t, &janusv1.HumanCheck{RequireStepUp: true})
	answer(t, &state, saga.GateAnswerRecord{
		RequirementID: "four-eyes", Attempt: 1, ActorID: "person:alice", Human: true,
		Verdict: janusv1.Verdict_VERDICT_PASS, AuthRef: "blake3:assertion",
	})

	decision := decideWithIdentity(t, state, func(string) (*identity.Established, error) {
		// A valid session, and no proof of presence at this approval.
		return &identity.Established{Subject: "person:alice", SteppedUp: false}, nil
	})
	if decision.Passed() {
		t.Fatal("a gate requiring a step-up accepted an approval that had none")
	}
	if !strings.Contains(decision.Reason, "step-up") {
		t.Fatalf("the refusal does not say what was missing: %s", decision.Reason)
	}
}

// TestADeploymentThatCannotVerifyRefusesRatherThanAssuming.
//
// A gate configured to require an established identity, in a deployment with no
// way to establish one, must refuse. Passing would be the control switching
// itself off in exactly the conditions it exists for.
func TestADeploymentThatCannotVerifyRefusesRatherThanAssuming(t *testing.T) {
	state := humanGate(t, &janusv1.HumanCheck{RequireEstablishedIdentity: true})
	answer(t, &state, saga.GateAnswerRecord{
		RequirementID: "four-eyes", Attempt: 1, ActorID: "person:alice", Human: true,
		Verdict: janusv1.Verdict_VERDICT_PASS, AuthRef: "blake3:assertion",
	})

	decision := decideWithIdentity(t, state, nil)
	if decision.Passed() {
		t.Fatal("a deployment with no verifier passed a gate that requires one")
	}
	if !strings.Contains(decision.Reason, "rather than relaxing the gate") {
		t.Fatalf("the refusal does not tell an operator what to do: %s", decision.Reason)
	}
}

// TestAPolicyThatDoesNotAskForItIsUnchanged. The hardening is opt-in: a control
// that has to be switched off to get work done is a control that gets switched
// off, so an existing policy behaves exactly as before.
func TestAPolicyThatDoesNotAskForItIsUnchanged(t *testing.T) {
	state := humanGate(t, &janusv1.HumanCheck{Roles: []string{"credit-officer"}})
	answer(t, &state, saga.GateAnswerRecord{
		RequirementID: "four-eyes", Attempt: 1, ActorID: "person:alice", Human: true,
		Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"},
	})

	decision := decideWithIdentity(t, state, nil)
	if !decision.Passed() {
		t.Fatalf("a policy that never asked for an established identity was refused: %s",
			decision.Reason)
	}
}

// ---- fixtures --------------------------------------------------------------

func humanGate(t *testing.T, check *janusv1.HumanCheck) saga.State {
	t.Helper()
	requirement := &janusv1.GateRequirement{
		Id:    "four-eyes",
		Gate:  janusv1.GateType_GATE_TYPE_HUMAN,
		Phase: janusv1.GatePhase_GATE_PHASE_PRE_RELEASE,
		Check: &janusv1.GateRequirement_Human{Human: check},
	}
	return stateWith(t, janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED, requirement)
}

// answer puts one recorded answer on the step, at the attempt under decision.
func answer(t *testing.T, s *saga.State, record saga.GateAnswerRecord) {
	t.Helper()
	step, ok := s.Step("wire")
	if !ok {
		t.Fatal("the fixture has no step")
	}
	step.Attempt = 1
	step.Status = saga.StepGated
	step.Answers = append(step.Answers, record)
	s.Steps["wire"] = step
}

func decideWithIdentity(t *testing.T, s saga.State,
	resolve func(string) (*identity.Established, error)) gate.Decision {
	t.Helper()
	step, ok := s.Step("wire")
	if !ok {
		t.Fatal("the fixture has no step")
	}
	return gate.Decide(janusv1.GatePhase_GATE_PHASE_PRE_RELEASE, gate.Input{
		Saga: s, Step: step, Identity: resolve,
	})
}
