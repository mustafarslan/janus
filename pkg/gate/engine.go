package gate

import (
	"fmt"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Composing a step's requirements into one decision.
//
// The rule is unanimity: every requirement due in the phase must pass, the
// first refusal decides, and any check that wants to wait makes the whole
// decision wait. There is no weighting, no quorum, and no majority — a payment
// that fails the sanctions check is not made acceptable by passing the schema
// check, and a design where it could be is a design where somebody will
// eventually be asked to explain the arithmetic to a regulator.
//
// Refusal short-circuits. That is a statement about what gets recorded rather
// than about cost: whichever check refuses first is the reason in the log, so
// the order requirements are evaluated in is chosen to make that reason the
// most useful one available (see orderRequirements).
//
// An escalation does not short-circuit the checks before it, but it does stop
// the ones after: a step waiting on a contended resource has not been refused
// and has not been permitted, and running further checks against facts that may
// change before the wait clears would record answers to questions nobody asked.

// Decision is the composed outcome for one step at one phase.
type Decision struct {
	SagaID  string
	StepID  string
	Phase   janusv1.GatePhase
	Verdict janusv1.Verdict
	// Results holds every check that was evaluated, in the order it ran.
	Results []Result
	// Decided lists the requirement ids the decision accounts for, which is
	// what the state machine checks the verdict against.
	Decided []string
	// Reason is the sentence that explains the verdict.
	Reason string
	// Gate names the check that determined the outcome, or COMPOSITE when
	// every check agreed.
	Gate janusv1.GateType
	// Facts are the values the decision was rendered on.
	Facts map[string]saga.FactValue
	// PolicyVersion pins the policy the requirements came from.
	PolicyVersion string
	// IntentRef is the saga's intent, so the DPR joins the "why" chain
	// rather than dangling as an isolated justification.
	IntentRef string
}

// Passed reports whether the step may proceed.
func (d Decision) Passed() bool { return d.Verdict == janusv1.Verdict_VERDICT_PASS }

// Engine decides gate verdicts from a policy.
//
// It holds the policy for resolving *new* sagas at admission. It does not
// consult it when deciding a running saga's gates: those requirements were
// resolved when the saga began and are recorded in its own log, so a policy
// edited mid-saga governs the next saga rather than reaching into this one.
type Engine struct {
	policy  *Policy
	version string
}

// NewEngine returns an engine backed by a policy.
func NewEngine(p *Policy) *Engine {
	return &Engine{policy: p, version: p.Version()}
}

// Policy returns the policy new sagas are admitted under.
func (e *Engine) Policy() *Policy { return e.policy }

// Version is the content address of that policy.
func (e *Engine) Version() string { return e.version }

// Decide composes a step's requirements for one phase.
//
// It reads the requirements off the step, which came from the saga's own
// SAGA_BEGIN — not from e.policy. The engine's policy decides what future sagas
// owe; this decides what this one owes, and those are different questions
// whenever somebody has deployed a change since the saga started.
func Decide(phase janusv1.GatePhase, in Input) Decision {
	st := in.Step
	in.Phase = phase
	d := Decision{
		SagaID:        in.Saga.SagaID,
		StepID:        st.ID,
		Phase:         phase,
		Facts:         in.Declared,
		PolicyVersion: in.Saga.GatePolicyVersion,
		IntentRef:     in.Saga.IntentID,
		Gate:          janusv1.GateType_GATE_TYPE_COMPOSITE,
	}

	due := orderRequirements(saga.GatesFor(st, phase))
	if len(due) == 0 {
		// Nothing is due, so nothing was decided. Callers check this before
		// recording anything: a verdict covering no requirements would be a
		// gate decision that gated nothing.
		d.Verdict = janusv1.Verdict_VERDICT_PASS
		d.Reason = "no gates are due at this phase"
		return d
	}

	f := Environment(in.Saga, st, in.Declared)
	for _, req := range due {
		res := evaluate(req, f, in)
		d.Results = append(d.Results, res)
		d.Decided = append(d.Decided, res.RequirementID)

		switch res.Verdict {
		case janusv1.Verdict_VERDICT_FAIL:
			d.Verdict = janusv1.Verdict_VERDICT_FAIL
			d.Gate = res.Gate
			d.Reason = res.Reason
			return d
		case janusv1.Verdict_VERDICT_ESCALATE:
			d.Verdict = janusv1.Verdict_VERDICT_ESCALATE
			d.Gate = res.Gate
			d.Reason = res.Reason
			return d
		}
	}

	d.Verdict = janusv1.Verdict_VERDICT_PASS
	d.Reason = fmt.Sprintf("%s passed under policy %s",
		quantity(len(due), "gate"), shortVersion(in.Saga.GatePolicyVersion))
	return d
}

// GateVerdict renders the decision as the composite event, citing the DPR that
// holds the individual checks.
func (d Decision) GateVerdict(dprRef string) *janusv1.GateVerdict {
	return &janusv1.GateVerdict{
		SagaId:        d.SagaID,
		StepId:        d.StepID,
		Gate:          d.Gate,
		Verdict:       d.Verdict,
		DprRef:        dprRef,
		PolicyVersion: d.PolicyVersion,
		Reason:        d.Reason,
		Decided:       d.Decided,
		Facts:         FactsToProto(d.Facts),
	}
}

// DPR renders the individual check results as a decision provenance record.
//
// This is the "why" a gate decision has to carry. The
// composite verdict says a step was let through or stopped; this says which
// checks ran, what each one found, and on what facts — which is what an
// adverse-action explanation is generated from, and what an auditor re-derives
// the composite from.
func (d Decision) DPR(dprID string) *janusv1.DecisionProvenanceRecord {
	validations := make([]*janusv1.GateVerdict, 0, len(d.Results))
	grounds := make([]*janusv1.DecisionProvenanceRecord_Ground, 0, len(d.Results))
	for _, r := range d.Results {
		validations = append(validations, &janusv1.GateVerdict{
			SagaId:        d.SagaID,
			StepId:        d.StepID,
			Gate:          r.Gate,
			Verdict:       r.Verdict,
			RequirementId: r.RequirementID,
			PolicyVersion: d.PolicyVersion,
			Reason:        r.Reason,
		})
		grounds = append(grounds, &janusv1.DecisionProvenanceRecord_Ground{
			Claim:  fmt.Sprintf("%s gate %q: %s", shortGate(r.Gate), r.RequirementID, r.Reason),
			Source: "policy",
		})
	}
	return &janusv1.DecisionProvenanceRecord{
		DprId:        dprID,
		SagaId:       d.SagaID,
		StepId:       d.StepID,
		DecisionKind: janusv1.DecisionProvenanceRecord_DECISION_KIND_VALIDATE,
		Grounds:      grounds,
		Validations:  validations,
		IntentRef:    d.IntentRef,
	}
}

func shortVersion(v string) string {
	const keep = 12
	hex, ok := strings.CutPrefix(v, "blake3:")
	if !ok {
		if v == "" {
			return "(none)"
		}
		return v
	}
	if len(hex) <= keep {
		return v
	}
	return "blake3:" + hex[:keep] + "…"
}
