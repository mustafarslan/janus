package registry

import (
	"context"
	"fmt"
	"sort"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// Manifest conformance testing.
//
// "Registration is not paperwork: declared compensations execute against
// sandbox doubles; idempotency recipes are stress-tested (duplicate delivery);
// limits enforced-by-test."
//
// The reason this exists rather than a review checklist is that the effect
// class is not a description — it is a control input. IRREVERSIBLE_GATED means
// the outbox holds the effect until the saga commits; REVERSIBLE means Janus
// may run the action optimistically and undo it later. A participant that
// declares REVERSIBLE and has no working undo has not mislabelled a document,
// it has disabled a gate. The evil-auditor suite includes exactly this:
// "registering a participant with a false REVERSIBLE claim".
//
// So each claim is turned into something that can fail:
//
//	purity                 a PURE action must leave the sandbox world unchanged
//	compensation_restores  a REVERSIBLE action's inverse must restore it exactly
//	compensation_runs      a COMPENSABLE action's inverse must at least succeed
//	idempotency            two deliveries under one key must land as one effect
//	limits                 an argument over the declared cap must be refused
//
// What the harness cannot do is stated as plainly as what it can. An
// irreversible action has no inverse to demonstrate, so its class is recorded
// as skipped rather than passed — a report that says "checked" about something
// it did not check is worse than no report. And a sandbox is a double: it
// proves the claim is coherent against the operator's model of the
// participant, not that the production participant behaves the same way. The
// report names the sandbox it ran against so a reader can weigh it.

// HarnessVersion identifies the conformance code that produced a verdict. A
// conformance result is only as meaningful as the harness that reached it, so
// the report carries this and audit can tell an old verdict from a new one.
const HarnessVersion = "janus-conformance/1"

// Check names, as they appear in a report.
const (
	CheckPurity              = "purity"
	CheckCompensationRestore = "compensation_restores"
	CheckCompensationRuns    = "compensation_runs"
	CheckIdempotency         = "idempotency"
	CheckLimits              = "limits"
)

// Call is one invocation of a participant action against a sandbox.
type Call struct {
	Action string
	// Args carries the arguments the check needs the double to see. The harness
	// only ever sets the amount field a manifest's limits name, because that is
	// the only argument whose meaning the manifest declares.
	Args map[string]int64
	// IdemKey is the idempotency key. Two calls carrying the same key are the
	// same effect delivered twice, which is what the outbox does on a retry.
	IdemKey string
}

// Result is what a sandbox reports back.
type Result struct {
	// Refused means the participant declined the call — what a limit check
	// requires to happen.
	Refused bool
	// Duplicate means the double recognised the idempotency key and did not
	// apply the effect again.
	Duplicate bool
	Detail    string
}

// Sandbox is a stand-in for the participant under evaluation.
//
// World returns a comparable snapshot of everything the doubles hold. The
// harness compares snapshots rather than asking the sandbox whether it was
// restored, because a participant that could report on its own restoration
// would be the one making the claim under test.
type Sandbox interface {
	Invoke(ctx context.Context, call Call) (Result, error)
	World() map[string]int64
	// Name identifies the doubles, and goes into the report.
	Name() string
}

// Evaluate runs a manifest's claims against a sandbox and returns the report
// that attaches to the manifest at EVALUATED.
//
// It is deterministic: no clock, no randomness, no ordering that depends on map
// iteration. The report goes into the evidence log and has to replay to the
// same bytes.
func Evaluate(ctx context.Context, m *Manifest, sb Sandbox) (*janusv1.EvaluationReport, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	report := &janusv1.EvaluationReport{
		HarnessVersion: HarnessVersion,
		Sandbox:        sb.Name(),
		// A full run exercises every claim the manifest makes, so it answers
		// every change-driven trigger as well as a periodic review. Covering
		// less would mean a fresh evaluation could not clear a change it had
		// just re-tested.
		TriggersCovered: knownTriggers(),
	}

	actions := append([]Action(nil), m.Actions...)
	sort.Slice(actions, func(i, j int) bool { return actions[i].Name < actions[j].Name })

	for i := range actions {
		checks, err := evaluateAction(ctx, &actions[i], sb)
		if err != nil {
			return nil, err
		}
		report.Checks = append(report.Checks, checks...)
	}

	report.Passed = true
	for _, c := range report.GetChecks() {
		if !c.GetSkipped() && !c.GetPassed() {
			report.Passed = false
		}
	}
	return report, nil
}

func evaluateAction(ctx context.Context, a *Action, sb Sandbox) ([]*janusv1.EvaluationReport_Check, error) {
	class, err := EffectClassFor(a.EffectClass)
	if err != nil {
		return nil, err
	}
	var out []*janusv1.EvaluationReport_Check

	switch class {
	case janusv1.EffectClass_EFFECT_CLASS_PURE:
		c, err := checkPurity(ctx, a, sb)
		if err != nil {
			return nil, err
		}
		return []*janusv1.EvaluationReport_Check{c}, nil

	case janusv1.EffectClass_EFFECT_CLASS_REVERSIBLE,
		janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE:
		c, err := checkCompensation(ctx, a, class, sb)
		if err != nil {
			return nil, err
		}
		out = append(out, c)

	default:
		out = append(out, &janusv1.EvaluationReport_Check{
			Action:  a.Name,
			Name:    CheckCompensationRestore,
			Skipped: true,
			Detail: fmt.Sprintf("%s declares no inverse, so the sandbox has nothing to "+
				"demonstrate; the class is a claim this harness cannot falsify, which is why "+
				"Janus holds the effect until the saga commits instead of trusting it",
				a.EffectClass),
		})
	}

	if a.Idempotency != nil {
		c, err := checkIdempotency(ctx, a, sb)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if a.Limits != nil && a.Limits.MaxAmount > 0 {
		c, err := checkLimits(ctx, a, sb)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// checkPurity requires a PURE action to change nothing.
//
// A PURE step is gated by nothing at all, which makes "this only reads" the
// single most valuable claim to check and the easiest one to get wrong by
// accident — a retrieval action that writes an audit row somewhere is not pure,
// and nothing downstream would ever notice.
func checkPurity(ctx context.Context, a *Action, sb Sandbox) (*janusv1.EvaluationReport_Check, error) {
	before := sb.World()
	if _, err := sb.Invoke(ctx, Call{Action: a.Name, IdemKey: a.Name + "/purity"}); err != nil {
		return nil, fmt.Errorf("sandbox: invoke %s: %w", a.Name, err)
	}
	after := sb.World()
	if diff, changed := worldDiff(before, after); changed {
		return &janusv1.EvaluationReport_Check{
			Action: a.Name, Name: CheckPurity, Passed: false,
			Detail: fmt.Sprintf("declared PURE but the call changed %s; a PURE action passes "+
				"every gate by definition", diff),
		}, nil
	}
	return &janusv1.EvaluationReport_Check{
		Action: a.Name, Name: CheckPurity, Passed: true,
		Detail: "the call left the sandbox world unchanged",
	}, nil
}

// checkCompensation runs the action and then its declared inverse.
func checkCompensation(ctx context.Context, a *Action, class janusv1.EffectClass,
	sb Sandbox) (*janusv1.EvaluationReport_Check, error) {

	name := CheckCompensationRestore
	if class == janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE {
		name = CheckCompensationRuns
	}

	before := sb.World()
	res, err := sb.Invoke(ctx, Call{Action: a.Name, IdemKey: a.Name + "/compensate"})
	if err != nil {
		return nil, fmt.Errorf("sandbox: invoke %s: %w", a.Name, err)
	}
	if res.Refused {
		return &janusv1.EvaluationReport_Check{
			Action: a.Name, Name: name, Passed: false,
			Detail: fmt.Sprintf("the sandbox refused the action itself (%s), so its compensation "+
				"was never exercised", res.Detail),
		}, nil
	}

	comp, err := sb.Invoke(ctx, Call{
		Action:  a.Compensation.Action,
		IdemKey: a.Name + "/compensate/undo",
	})
	if err != nil {
		return nil, fmt.Errorf("sandbox: invoke compensation %s: %w", a.Compensation.Action, err)
	}
	if comp.Refused {
		return &janusv1.EvaluationReport_Check{
			Action: a.Name, Name: name, Passed: false,
			Detail: fmt.Sprintf("the declared compensation %s was refused (%s); an undo that does "+
				"not run is not an undo", a.Compensation.Action, comp.Detail),
		}, nil
	}

	after := sb.World()
	diff, changed := worldDiff(before, after)

	if class == janusv1.EffectClass_EFFECT_CLASS_REVERSIBLE {
		if changed {
			// This is the evil-auditor case: a false REVERSIBLE claim. Janus
			// runs REVERSIBLE actions optimistically because it believes it can
			// take them back, so the cost of believing this claim wrongly is an
			// effect that stays in the world after the saga unwinds.
			return &janusv1.EvaluationReport_Check{
				Action: a.Name, Name: name, Passed: false,
				Detail: fmt.Sprintf("declared REVERSIBLE, but after %s the world still differs "+
					"by %s; the class permits optimistic execution on the strength of an undo "+
					"that does not undo", a.Compensation.Action, diff),
			}, nil
		}
		return &janusv1.EvaluationReport_Check{
			Action: a.Name, Name: name, Passed: true,
			Detail: fmt.Sprintf("%s restored the sandbox world exactly", a.Compensation.Action),
		}, nil
	}

	detail := fmt.Sprintf("%s ran; the world still differs by %s, which is what the manifest "+
		"declares as residual: %s", a.Compensation.Action, diff, a.Compensation.ResidualEffects)
	if !changed {
		// Not a failure. Declaring the weaker class is the safe direction, and
		// a sandbox is too coarse to prove a real residual does not exist.
		detail = fmt.Sprintf("%s restored the sandbox world exactly; the manifest declares "+
			"residual effects (%s) that this sandbox does not model, so the weaker class stands",
			a.Compensation.Action, a.Compensation.ResidualEffects)
	}
	return &janusv1.EvaluationReport_Check{
		Action: a.Name, Name: name, Passed: true, Detail: detail,
	}, nil
}

// checkIdempotency delivers the same effect twice under one key.
//
// This is the claim the outbox stakes an irreversible effect on. Delivery is
// at-least-once and the receiver's idempotency is the other half of what makes
// it effectively exactly-once; if the receiver does not hold up its
// half, a retried wire is a second wire.
func checkIdempotency(ctx context.Context, a *Action, sb Sandbox) (*janusv1.EvaluationReport_Check, error) {
	key := a.Name + "/idem"

	before := sb.World()
	if _, err := sb.Invoke(ctx, Call{Action: a.Name, IdemKey: key}); err != nil {
		return nil, fmt.Errorf("sandbox: invoke %s: %w", a.Name, err)
	}
	once := sb.World()
	res, err := sb.Invoke(ctx, Call{Action: a.Name, IdemKey: key})
	if err != nil {
		return nil, fmt.Errorf("sandbox: redeliver %s: %w", a.Name, err)
	}
	twice := sb.World()

	if diff, changed := worldDiff(once, twice); changed {
		return &janusv1.EvaluationReport_Check{
			Action: a.Name, Name: CheckIdempotency, Passed: false,
			Detail: fmt.Sprintf("redelivering key %q applied the effect again (%s); recipe %q "+
				"does not make a retry recognisable", key, diff, a.Idempotency.KeyRecipe),
		}, nil
	}
	_, moved := worldDiff(before, once)
	if !moved && !res.Duplicate {
		// The double did nothing either time, so the check proved nothing. Say
		// so rather than reporting a pass: a check that cannot fail is not
		// evidence.
		return &janusv1.EvaluationReport_Check{
			Action: a.Name, Name: CheckIdempotency, Skipped: true,
			Detail: "the sandbox models no effect for this action, so a duplicate delivery " +
				"could not have been observed either way",
		}, nil
	}
	return &janusv1.EvaluationReport_Check{
		Action: a.Name, Name: CheckIdempotency, Passed: true,
		Detail: fmt.Sprintf("a second delivery under key %q was absorbed", key),
	}, nil
}

// checkLimits asks the participant to exceed its own declared cap.
func checkLimits(ctx context.Context, a *Action, sb Sandbox) (*janusv1.EvaluationReport_Check, error) {
	over := a.Limits.MaxAmount + 1
	before := sb.World()
	res, err := sb.Invoke(ctx, Call{
		Action:  a.Name,
		Args:    map[string]int64{a.Limits.AmountField: over},
		IdemKey: fmt.Sprintf("%s/limit/%d", a.Name, over),
	})
	if err != nil {
		return nil, fmt.Errorf("sandbox: invoke %s over its limit: %w", a.Name, err)
	}
	after := sb.World()
	diff, changed := worldDiff(before, after)

	switch {
	case !res.Refused:
		return &janusv1.EvaluationReport_Check{
			Action: a.Name, Name: CheckLimits, Passed: false,
			Detail: fmt.Sprintf("%s=%d exceeds the declared maximum of %d and the participant "+
				"accepted it; a limit the participant does not enforce is one only the gate "+
				"enforces, and the manifest claims both", a.Limits.AmountField, over,
				a.Limits.MaxAmount),
		}, nil
	case changed:
		return &janusv1.EvaluationReport_Check{
			Action: a.Name, Name: CheckLimits, Passed: false,
			Detail: fmt.Sprintf("the call was refused but the world still changed by %s; a "+
				"refusal with a side effect is the worst of both", diff),
		}, nil
	default:
		return &janusv1.EvaluationReport_Check{
			Action: a.Name, Name: CheckLimits, Passed: true,
			Detail: fmt.Sprintf("%s=%d over the declared maximum of %d was refused",
				a.Limits.AmountField, over, a.Limits.MaxAmount),
		}, nil
	}
}

// worldDiff renders what moved between two snapshots, in a stable order.
func worldDiff(before, after map[string]int64) (string, bool) {
	keys := map[string]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)

	var parts []string
	for _, k := range names {
		if before[k] != after[k] {
			parts = append(parts, fmt.Sprintf("%s %d→%d", k, before[k], after[k]))
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += ", " + p
	}
	return out, true
}

// ReportText renders an evaluation report for a person.
func ReportText(r *janusv1.EvaluationReport) string {
	verdict := "FAILED"
	if r.GetPassed() {
		verdict = "passed"
	}
	out := fmt.Sprintf("conformance %s (%s against %s)\n", verdict, r.GetHarnessVersion(), r.GetSandbox())
	if from := r.GetInheritedFrom(); from != "" {
		out += fmt.Sprintf("  inherited from version %s; this version was not separately evaluated\n", from)
	}
	for _, c := range r.GetChecks() {
		mark := "FAIL"
		switch {
		case c.GetSkipped():
			mark = "skip"
		case c.GetPassed():
			mark = "ok"
		}
		out += fmt.Sprintf("  %-4s %-22s %-24s %s\n", mark, c.GetName(), c.GetAction(), c.GetDetail())
	}
	return out
}
