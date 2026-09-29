package registry

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/template"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// Admission: the registry's answer to a plan.
//
// A saga's SAGA_BEGIN carries a plan and a set of manifest pins. Before it runs,
// the registry is asked whether the plan is consistent with what the pinned
// manifests declare. Three questions, and the third is the one with teeth.
//
// Is every pin resolvable and active? This is invariant I8 at the moment it
// still matters — a step whose manifest cannot be resolved is a step nobody can
// audit later, and a step pinning a suspended participant is one running under
// a declaration somebody withdrew.
//
// Does the participant declare the action at all? An agent invoking something
// its manifest never mentioned is outside the capability envelope the registry
// exists to describe.
//
// And does the plan's effect class match the manifest's? This is the one that
// stops an attack rather than a mistake. Janus gates by effect class: the
// outbox holds IRREVERSIBLE_GATED until commit, a policy rule matches on the
// class, a human gate is attached to it. A planner that writes its own plan can
// write any class it likes — and a planner following an injected instruction
// has every reason to write PURE next to a wire transfer. The manifest is a
// signed, evaluated, separately-recorded declaration of what the action really
// is, so admission believes it and refuses the plan.
//
// The direction is not symmetrical in consequence but it is refused both ways.
// Understating the class evades a gate. Overstating it is harmless to safety
// and still means the log records two contradictory accounts of what an action
// does, which is exactly what makes a later audit unanswerable.

// ErrNotAdmissible means the plan contradicts the registry.
//
// It is deliberately a different error from gate.ErrNotAdmissible: the two
// admission checks answer different questions — "may this plan be protected"
// and "is this plan what the participants say they do" — and an operator
// reading a refusal needs to know which one refused.
var ErrNotAdmissible = errors.New("registry: plan not admissible")

// Admit checks a saga plan against the registry, for an unpinned deployment.
//
// It is a check rather than a mutation: it fills nothing in, so a caller can
// run it before gate admission, after it, or from a test, and get the same
// answer.
func Admit(r *Registry, begin *janusv1.SagaBegin) error {
	return AdmitFor(r, begin, tenancy.Tenant{})
}

// AdmitFor checks a saga plan against the registry on behalf of one tenant.
//
// When that tenant has pinned a jurisdiction, every step is additionally
// checked against where its participant declared it may run. See
// jurisdictionAllows for what that means and why the absence of a declaration
// is a refusal rather than a permission.
func AdmitFor(r *Registry, begin *janusv1.SagaBegin, tenant tenancy.Tenant) error {
	if err := admitTemplate(r, begin); err != nil {
		return err
	}
	pins := begin.GetManifestPins()

	for _, step := range begin.GetPlan() {
		participant := step.GetParticipant()
		if participant == "" {
			return fmt.Errorf("%w: step %q names no participant", ErrNotAdmissible, step.GetStepId())
		}

		version, pinned := pins[participant]
		if !pinned {
			return fmt.Errorf("%w: step %q runs on %q, which the saga does not pin; a step whose "+
				"manifest version is not recorded cannot be resolved at replay time (I8)",
				ErrNotAdmissible, step.GetStepId(), participant)
		}

		e, ok := r.Resolve(participant, version)
		if !ok {
			return fmt.Errorf("%w: step %q pins %s@%s, which is not registered",
				ErrNotAdmissible, step.GetStepId(), participant, version)
		}
		if e.State != StateActive {
			return fmt.Errorf("%w: step %q pins %s@%s, which is %s%s; only an active version may "+
				"be pinned by a new saga", ErrNotAdmissible, step.GetStepId(), participant,
				version, e.State, reasonSuffix(e))
		}

		action := step.GetAction()
		declared := e.Manifest.Action(action)
		if declared == nil {
			return fmt.Errorf("%w: step %q invokes %q on %s@%s, which declares %s; a participant "+
				"may only be asked for what it registered", ErrNotAdmissible, step.GetStepId(),
				action, participant, version, actionList(e.Manifest))
		}

		want, _ := e.Manifest.EffectClassOf(action)
		got := step.GetEffectClass()
		if got != want {
			return fmt.Errorf("%w: step %q declares %q as %s, but %s@%s registers it as %s. %s",
				ErrNotAdmissible, step.GetStepId(), action, ShortClass(got), participant, version,
				ShortClass(want), mismatchNote(got, want))
		}

		if err := jurisdictionAllows(step, e, tenant); err != nil {
			return err
		}

		if comp := step.GetCompensationAction(); comp != "" {
			if declared.Compensation == nil {
				return fmt.Errorf("%w: step %q plans to compensate %q with %q, but %s@%s "+
					"registers no compensation for it", ErrNotAdmissible, step.GetStepId(),
					action, comp, participant, version)
			}
			if declared.Compensation.Action != comp {
				return fmt.Errorf("%w: step %q plans to compensate %q with %q, but %s@%s "+
					"registers %q as the inverse; the compensation that was evaluated is the "+
					"registered one", ErrNotAdmissible, step.GetStepId(), action, comp,
					participant, version, declared.Compensation.Action)
			}
		}
	}

	// A pin nothing uses is not an error worth refusing a saga over, but it is
	// worth not silently accepting either: it usually means a step was removed
	// from a plan and the pin left behind, and a stale pin in the record reads
	// later as though that participant took part.
	for participant := range pins {
		if !planUses(begin, participant) {
			return fmt.Errorf("%w: the saga pins %q, which no step uses; a pin in the record "+
				"reads as a participant that took part", ErrNotAdmissible, participant)
		}
	}
	return nil
}

// AdmitAt checks a plan against the registry as it stood at a sequence.
//
// This is what an audit needs and a live coordinator does not: whether the pins
// a saga recorded were resolvable and active when the saga began, rather than
// whether they are now. A participant suspended after a payment went out does
// not make that payment retrospectively inadmissible.
func AdmitAt(events []Event, until uint64, begin *janusv1.SagaBegin) error {
	r, err := FoldUntil(events, until)
	if err != nil {
		return err
	}
	return Admit(r, begin)
}

// jurisdictionAllows refuses a step whose participant may not run where this
// tenant's work has to stay.
//
// The declaration has been in the manifest since Phase 3 and until now nothing
// read it. A compliance check confirmed participants *declared* a jurisdiction,
// which is a different property entirely: a participant could declare
// deployable_in ["US"], get registered, and run every step of a saga belonging
// to a tenant pinned to DE, and no part of Janus would object. Declaring is not
// pinning.
//
// The refusal on an *empty* declaration is the part worth defending. It is
// tempting to read "says nothing" as "no restriction", and that reading would
// make the pin useless on exactly the population it exists for: every
// participant registered before anybody thought about jurisdiction. A
// participant that has not said where it may run has not been assessed for
// anywhere, and the manifest is where it would have said so.
//
// Data residency is checked as well as deployability. Where a participant may
// run and where it may keep what it produces are different questions, and a
// tool that runs in Frankfurt and writes its results to a bucket in Ohio has
// satisfied one of them.
func jurisdictionAllows(step *janusv1.PlannedStep, e *Entry, tenant tenancy.Tenant) error {
	if !tenant.Pinned() {
		return nil
	}
	j := e.Manifest.Jurisdiction
	if !tenant.Permits(j.DeployableIn) {
		where := "declares no jurisdiction it may be deployed in"
		if len(j.DeployableIn) > 0 {
			where = fmt.Sprintf("may be deployed in %s", strings.Join(j.DeployableIn, ", "))
		}
		return fmt.Errorf("%w: step %q runs on %s@%s, which %s; this tenant's work is pinned to %s",
			ErrNotAdmissible, step.GetStepId(), step.GetParticipant(),
			e.Manifest.Version, where, tenant.Jurisdiction)
	}
	if j.DataResidency != "" && j.DataResidency != tenant.Jurisdiction {
		return fmt.Errorf("%w: step %q runs on %s@%s, which keeps its data in %s; this tenant's "+
			"work is pinned to %s, and where a participant runs is not where it stores",
			ErrNotAdmissible, step.GetStepId(), step.GetParticipant(), e.Manifest.Version,
			j.DataResidency, tenant.Jurisdiction)
	}
	return nil
}

func planUses(begin *janusv1.SagaBegin, participant string) bool {
	for _, step := range begin.GetPlan() {
		if step.GetParticipant() == participant {
			return true
		}
	}
	return false
}

func reasonSuffix(e *Entry) string {
	if e.Reason == "" {
		return ""
	}
	return fmt.Sprintf(" (%s)", e.Reason)
}

func actionList(m *Manifest) string {
	names := make([]string, 0, len(m.Actions))
	for i := range m.Actions {
		names = append(names, m.Actions[i].Name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "no actions"
	}
	out := names[0]
	for _, n := range names[1:] {
		out += ", " + n
	}
	return out
}

// mismatchNote says which way the disagreement runs, because the two
// directions mean very different things about what is going on.
func mismatchNote(planned, registered janusv1.EffectClass) string {
	if weight(planned) < weight(registered) {
		return "The plan claims a weaker effect than the participant registered, which is how a " +
			"gated effect gets past a gate: the class is what decides whether the outbox holds it."
	}
	return "The plan claims a stronger effect than the participant registered. That is safe, and " +
		"it still leaves the log carrying two accounts of what the action does, so it is refused " +
		"rather than quietly resolved in either direction."
}

// weight orders effect classes by how much they constrain execution.
func weight(c janusv1.EffectClass) int {
	switch c {
	case janusv1.EffectClass_EFFECT_CLASS_PURE:
		return 1
	case janusv1.EffectClass_EFFECT_CLASS_REVERSIBLE:
		return 2
	case janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE:
		return 3
	case janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED:
		return 4
	case janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE:
		return 5
	default:
		return 0
	}
}

// admitTemplate enforces crystallized mode against the template it pins.
//
// It lives here rather than in the gate engine because it is the same question
// the manifest pins ask — is this version registered, is it active, does the
// plan agree with what it declares — and the registry is what can answer it.
//
// The checks are in the order somebody debugging would want them: is there a
// pin, does it resolve, is it in good standing, and only then does the plan
// match. A deviation reported before the version was even resolvable would send
// a reader to the wrong place.
func admitTemplate(r *Registry, begin *janusv1.SagaBegin) error {
	pin := begin.GetTemplatePin()
	crystallized := saga.Mode(begin.GetMode()) == saga.ModeCrystallized

	if !crystallized {
		// A pin outside crystallized mode is refused rather than ignored. A
		// saga carrying a template it is not confined to is a record that reads
		// as a confinement and is not one, which is the failure mode enforcement
		// exists to prevent.
		if pin != nil {
			return fmt.Errorf("%w: the saga pins template %s@%s but runs in mode %q; a "+
				"template confines a plan only in crystallized mode, and a pin that confines "+
				"nothing would read on the record as though it did",
				ErrNotAdmissible, pin.GetTemplateId(), pin.GetVersion(), begin.GetMode())
		}
		return nil
	}

	switch {
	case pin == nil:
		return fmt.Errorf("%w: mode %q confines a plan to a template and this saga pins none",
			ErrNotAdmissible, saga.ModeCrystallized)
	case pin.GetTemplateId() == "" || pin.GetVersion() == "":
		return fmt.Errorf("%w: the template pin names %q@%q; both halves are required, because "+
			"a pin with no version would confine the saga to whatever happened to be active "+
			"when it began", ErrNotAdmissible, pin.GetTemplateId(), pin.GetVersion())
	}

	e, ok := r.ResolveTemplate(pin.GetTemplateId(), pin.GetVersion())
	if !ok {
		return fmt.Errorf("%w: the saga pins template %s@%s, which is not registered",
			ErrNotAdmissible, pin.GetTemplateId(), pin.GetVersion())
	}
	if e.State != StateActive {
		return fmt.Errorf("%w: the saga pins template %s@%s, which is %s%s; only an active "+
			"template may confine a new saga -- an unvalidated or withdrawn shape is not "+
			"something to hold a plan to", ErrNotAdmissible, pin.GetTemplateId(),
			pin.GetVersion(), e.State, reasonSuffix(e))
	}
	if err := template.Match(e.Template, begin.GetPlan()); err != nil {
		return fmt.Errorf("%w: %w", ErrNotAdmissible, err)
	}

	// A crystallized saga's children are not confined *here*, and the reason is
	// structural rather than a gap: the obvious check -- refuse a plan containing
	// a spawning step -- cannot be made at this point. `spawns` is declared on
	// STEP_PREPARE, not on the plan, so a parent's admission cannot see whether
	// any of its steps will delegate. It needs the CHILD's admission to know its
	// parent's mode, which means reading the parent out of the log, which is a
	// different shape from everything else this function does.
	//
	// So it is done there instead: `orchd.Server.confineChildToItsParent` refuses
	// a child of a crystallized parent that is not itself crystallized, which
	// removes the escape hatch. What is still open here is *which*
	// template the child pins -- it chooses its own, so the parent has confined
	// its own shape and not its delegates'.
	//
	// This is written down rather than approximated because a check that catches
	// the cases it can see, and says nothing about the ones it cannot, is the
	// kind of control that reads as complete.
	return nil
}
