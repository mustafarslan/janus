package gate

import (
	"errors"
	"fmt"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Admission: turning a plan and a policy into the gates a saga owes.
//
// This runs once, before SAGA_BEGIN is written, and its output goes into that
// event. From then on the saga carries its own rules. Two things follow, and
// both are the point rather than side effects.
//
// A saga is judged by the policy in force when it started. Somebody widening a
// limit this afternoon cannot make this morning's refused payment look
// permitted, and somebody tightening one cannot strand a saga halfway through
// against rules it was never admitted under. Either would make the log a record
// of the current configuration rather than of what happened.
//
// And a plan that cannot be protected is refused before anything runs. A step
// whose effect cannot be taken back and which no rule covers does not get to
// begin and fail later at the gate — there would be nothing to fail at. This is
// the completion of invariant I3: every non-PURE step has a compensation or a
// gate policy, proven at admission rather than hoped for at failure time.

// ErrNotAdmissible means the plan cannot be run under this policy.
var ErrNotAdmissible = errors.New("gate: plan not admissible")

// Admit resolves the gate plan for a saga and refuses one that cannot be
// protected.
//
// It fills in gate_policy_version and gate_plan on the message, so the caller
// records a SAGA_BEGIN that already carries what the saga owes.
func (e *Engine) Admit(begin *janusv1.SagaBegin) error {
	mode := begin.GetMode()

	// The mode is checked before anything is resolved against it, because it is
	// what the resolution is scoped by. A mode outside the vocabulary is not a
	// mode nobody wrote a rule for; it is a plan that would silently miss every
	// rule scoped to a mode, and the direction of that failure is fewer gates.
	if err := saga.ValidateMode(mode); err != nil {
		return fmt.Errorf("%w: %w", ErrNotAdmissible, err)
	}
	// A crystallized saga must name the template it is confined to. Whether that
	// template exists, is active, and matches the plan is decided by
	// `registry.AdmitFor`, which is what can resolve it — this is only the part
	// the plan alone can answer, and it is here so that a plan with no pin is
	// refused before any gate is resolved for it.
	if saga.Mode(mode) == saga.ModeCrystallized && begin.GetTemplatePin() == nil {
		return fmt.Errorf("%w: mode %q confines a plan to a template and this saga pins none",
			ErrNotAdmissible, saga.ModeCrystallized)
	}

	plan := make([]*janusv1.StepGates, 0, len(begin.GetPlan()))

	for _, step := range begin.GetPlan() {
		rule := e.policy.Resolve(Subject{
			StepID:      step.GetStepId(),
			Participant: step.GetParticipant(),
			Action:      step.GetAction(),
			EffectClass: step.GetEffectClass(),
			Mode:        mode,
		})

		if rule == nil {
			if err := admissibleWithoutGates(step, e.policy.ID); err != nil {
				return err
			}
			continue
		}
		if err := coversEffectClass(step, rule); err != nil {
			return err
		}
		plan = append(plan, &janusv1.StepGates{
			StepId:  step.GetStepId(),
			RuleId:  rule.ID,
			Require: rule.Requirements(),
		})
	}

	begin.GatePolicyVersion = e.version
	begin.GatePlan = plan
	return nil
}

// admissibleWithoutGates decides whether a step no rule matched may run.
//
// A PURE step may: it changes nothing outside Janus, so there is nothing to
// gate. A step with a registered compensation may: the plan already says how to
// take it back, which is the other half of I3. An irreversible step may not,
// and the refusal names the gap rather than the rule, because the author has to
// either write a policy rule or reclassify the step and only they can say which
// is true.
func admissibleWithoutGates(step *janusv1.PlannedStep, policyID string) error {
	switch step.GetEffectClass() {
	case janusv1.EffectClass_EFFECT_CLASS_PURE:
		return nil
	case janusv1.EffectClass_EFFECT_CLASS_REVERSIBLE,
		janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE:
		if step.GetCompensationAction() != "" {
			return nil
		}
		return fmt.Errorf("%w: step %q is %s, declares no compensation, and no rule in policy %q "+
			"covers it, so nothing would decide whether its effect may happen and nothing could "+
			"undo it afterwards", ErrNotAdmissible, step.GetStepId(),
			shortClass(step.GetEffectClass()), policyID)
	default:
		return fmt.Errorf("%w: step %q is %s and no rule in policy %q covers it; an effect that "+
			"cannot be taken back needs a gate standing in for the compensation it cannot have",
			ErrNotAdmissible, step.GetStepId(), shortClass(step.GetEffectClass()), policyID)
	}
}

// coversEffectClass checks the matched rule protects the step at a moment that
// can still stop it.
//
// The state machine enforces the same thing when it admits the SAGA_BEGIN. It
// is checked here as well so the failure lands on whoever wrote the policy,
// with the rule id in hand, rather than surfacing later as a rejected event.
func coversEffectClass(step *janusv1.PlannedStep, rule *Rule) error {
	var pre, release int
	for _, r := range rule.Require {
		switch r.Phase {
		case PhasePreExecution:
			pre++
		case PhasePreRelease:
			release++
		}
	}

	switch step.GetEffectClass() {
	case janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE:
		if pre == 0 {
			return fmt.Errorf("%w: rule %q covers step %q, which is IRREVERSIBLE_IMMEDIATE, but "+
				"every requirement is decided %s; that effect is in the world as soon as the "+
				"participant returns, so a gate judging the result would be judging something "+
				"already done", ErrNotAdmissible, rule.ID, step.GetStepId(), PhasePreRelease)
		}
	case janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED:
		if release == 0 {
			return fmt.Errorf("%w: rule %q covers step %q, which is IRREVERSIBLE_GATED, but every "+
				"requirement is decided %s; the effect the outbox holds is the one the step "+
				"produced, and nothing would judge it", ErrNotAdmissible, rule.ID,
				step.GetStepId(), PhasePreExecution)
		}
	}
	return nil
}

// Explain describes what a plan would owe under this policy, without admitting
// anything.
//
// It exists because "which gates will this saga have to pass" is a question
// asked far more often than it is answered — by a developer before deploying,
// by a compliance officer reviewing a workflow, by an operator working out why
// a saga is waiting. Answering it from the same resolution code that admission
// uses is what keeps the answer true.
func (e *Engine) Explain(begin *janusv1.SagaBegin) string {
	var b strings.Builder
	fmt.Fprintf(&b, "policy %s (%s)\n", e.policy.ID, shortVersion(e.version))
	for _, step := range begin.GetPlan() {
		rule := e.policy.Resolve(Subject{
			StepID:      step.GetStepId(),
			Participant: step.GetParticipant(),
			Action:      step.GetAction(),
			EffectClass: step.GetEffectClass(),
			Mode:        begin.GetMode(),
		})
		fmt.Fprintf(&b, "  %s (%s)\n", step.GetStepId(), shortClass(step.GetEffectClass()))
		if rule == nil {
			reason := "no rule matches"
			if err := admissibleWithoutGates(step, e.policy.ID); err != nil {
				reason = "no rule matches, and the step is not admissible without one"
			}
			fmt.Fprintf(&b, "    %s\n", reason)
			continue
		}
		fmt.Fprintf(&b, "    rule %s\n", rule.ID)
		for _, r := range rule.Require {
			// The id comes first because it is what a recorded verdict cites.
			// An operator holding a log entry that says a step was stopped by
			// "wire-limit" needs to find "wire-limit" here.
			fmt.Fprintf(&b, "      %-18s %-12s %-14s %s\n",
				r.ID, r.Gate, r.Phase, describeRequirement(r))
		}
	}
	return b.String()
}

func describeRequirement(r Requirement) string {
	switch {
	case r.Schema != nil:
		names := make([]string, 0, len(r.Schema.Fields))
		for _, f := range r.Schema.Fields {
			names = append(names, f.Name)
		}
		return r.Schema.SchemaID + ": " + strings.Join(names, ", ")
	case r.Policy != nil:
		if r.Policy.Description != "" {
			return r.Policy.Description
		}
		return r.Policy.Expr
	case r.RiskLimit != nil:
		parts := make([]string, 0, len(r.RiskLimit.Thresholds)+2)
		for _, t := range r.RiskLimit.Thresholds {
			parts = append(parts, fmt.Sprintf("%s ≤ %d", t.Fact, t.Max))
		}
		if r.RiskLimit.MaxGatedEffects > 0 {
			parts = append(parts, fmt.Sprintf("≤ %d irreversible steps", r.RiskLimit.MaxGatedEffects))
		}
		if r.RiskLimit.MaxResources > 0 {
			parts = append(parts, fmt.Sprintf("≤ %d resources", r.RiskLimit.MaxResources))
		}
		return strings.Join(parts, ", ")
	case r.Human != nil:
		parts := []string{fmt.Sprintf("%s from", quantity(max(int(r.Human.Quorum), 1), "approval"))}
		if len(r.Human.Roles) > 0 {
			parts = append(parts, strings.Join(r.Human.Roles, " or "))
		} else {
			parts = append(parts, "any authenticated human")
		}
		if r.Human.SeparationOfDuty {
			parts = append(parts, "(not the initiator)")
		}
		return strings.Join(parts, " ")
	case r.Validator != nil:
		s := fmt.Sprintf("%s from %s",
			quantity(max(int(r.Validator.Quorum), 1), "opinion"),
			strings.Join(r.Validator.Validators, ", "))
		if r.Validator.EscalateOnDisagreement {
			s += "; disagreement escalates"
		}
		return s
	default:
		return "wait for contending sagas to finish"
	}
}
