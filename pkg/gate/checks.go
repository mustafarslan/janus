package gate

import (
	"fmt"
	"slices"
	"strings"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/identity"
	"github.com/mustafarslan/janus/pkg/saga"
)

// The four checks this build implements.
//
// Each one answers with a verdict and a sentence. The sentence is not
// decoration: it is what an operator reads at three in the morning and what an
// adverse-action export quotes back to a customer, so "policy P-12 refused" is
// not an acceptable answer where "the amount is 2,400,000 minor units and the
// limit is 1,000,000" is available.
//
// Every check is a pure function of (requirement, facts, saga state). Nothing
// here reads a clock, a network, or a file. That is what lets audit re-run them
// over a recorded log and get the same answers, which is the only way to tell a
// decision that was made correctly from one that was merely recorded.

// Result is one check's outcome.
type Result struct {
	RequirementID string
	Gate          janusv1.GateType
	Verdict       janusv1.Verdict
	Reason        string
}

// Passed reports whether the check permitted the step to continue.
func (r Result) Passed() bool { return r.Verdict == janusv1.Verdict_VERDICT_PASS }

// Input is everything a gate decides on.
type Input struct {
	// Saga is the projection the step belongs to.
	Saga saga.State
	// Step is the step being judged.
	Step *saga.Step
	// Declared is what the step put forward: the proposal at a pre-execution
	// gate, and what it recorded at a release gate.
	Declared map[string]saga.FactValue
	// Identity establishes what an answer's assertion actually proves, given
	// the reference the answer recorded. Nil means nothing can be established,
	// which is not the same as nothing being required: a requirement that asks
	// for an established identity refuses rather than assuming one.
	//
	// It is a function rather than a store because resolving an assertion means
	// reading it out of the content-addressed blob store, and a gate should not
	// know where that is.
	Identity func(authRef string) (*identity.Established, error)
	// Index answers frontier questions across sagas. It is nil when the caller
	// has not built one, and a frontier check then refuses rather than assuming
	// the resource is clear — an index nobody supplied is not an index that
	// found nothing.
	Index *saga.Index
	// Phase is the moment being decided. Decide sets it; the checks that read
	// recorded answers need it to know which attempt those answers are about.
	Phase janusv1.GatePhase
}

// evaluate runs one requirement.
//
// Every path that is not an unambiguous pass returns FAIL — including a
// requirement of a kind this build does not implement. A gate the code cannot
// evaluate is not a gate that abstains; it is a gate whose answer is unknown,
// and acting on an unknown answer is exactly what gates exist to prevent.
func evaluate(req *janusv1.GateRequirement, f Facts, in Input) Result {
	res := Result{RequirementID: req.GetId(), Gate: req.GetGate()}
	switch c := req.GetCheck().(type) {
	case *janusv1.GateRequirement_Schema:
		res.Verdict, res.Reason = checkSchema(c.Schema, f)
	case *janusv1.GateRequirement_Policy:
		res.Verdict, res.Reason = checkPolicy(c.Policy, f)
	case *janusv1.GateRequirement_RiskLimit:
		res.Verdict, res.Reason = checkRiskLimit(c.RiskLimit, f, in.Saga)
	case *janusv1.GateRequirement_Frontier:
		res.Verdict, res.Reason = checkFrontier(in)
	case *janusv1.GateRequirement_Human:
		res.Verdict, res.Reason = checkHuman(c.Human, req.GetId(), in)
	case *janusv1.GateRequirement_Validator:
		res.Verdict, res.Reason = checkValidator(c.Validator, req.GetId(), in)
	default:
		res.Verdict = janusv1.Verdict_VERDICT_FAIL
		res.Reason = fmt.Sprintf("requirement %q is a %s gate, which this build cannot evaluate; "+
			"a gate whose answer is unknown refuses", req.GetId(), shortGate(req.GetGate()))
	}
	return res
}

// checkSchema validates the shape of the facts before anything reasons about
// their values.
//
// It runs first among a step's requirements for a reason that is about
// diagnosis rather than cost: a policy expression over a missing fact refuses
// with "unknown fact", which is true and unhelpful. Stating that the step never
// declared an amount is the finding somebody can act on.
func checkSchema(c *janusv1.SchemaCheck, f Facts) (janusv1.Verdict, string) {
	var missing, wrong []string
	for _, field := range c.GetFields() {
		v, ok := f[field.GetName()]
		if !ok {
			if !field.GetOptional() {
				missing = append(missing, field.GetName())
			}
			continue
		}
		if v.Type != field.GetType() {
			wrong = append(wrong, fmt.Sprintf("%s is %s, expected %s",
				field.GetName(), typeName(v.Type), typeName(field.GetType())))
		}
	}

	switch {
	case len(missing) > 0 && len(wrong) > 0:
		return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
			"schema %s: %s not declared; %s", c.GetSchemaId(),
			strings.Join(missing, ", "), strings.Join(wrong, "; "))
	case len(missing) > 0:
		return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
			"schema %s: the step declares no %s, so there is nothing to decide on",
			c.GetSchemaId(), strings.Join(missing, " and no "))
	case len(wrong) > 0:
		return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
			"schema %s: %s", c.GetSchemaId(), strings.Join(wrong, "; "))
	default:
		return janusv1.Verdict_VERDICT_PASS, fmt.Sprintf(
			"schema %s: %s declared", c.GetSchemaId(), quantity(len(c.GetFields()), "field"))
	}
}

// checkPolicy evaluates a boolean expression that must hold.
func checkPolicy(c *janusv1.PolicyCheck, f Facts) (janusv1.Verdict, string) {
	expr, err := Compile(c.GetExpr())
	if err != nil {
		// The policy was validated when it was loaded, so reaching this means
		// the requirement in the log was not produced by a policy this build
		// would accept — a tampered plan, or a version skew. Either way the
		// honest answer is that nothing here can be evaluated.
		return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
			"the recorded expression does not compile, so nothing decided this step: %v", err)
	}
	ok, err := expr.Eval(f)
	if err != nil {
		return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf("%v (facts: %s)", err, describeFacts(f))
	}
	if ok {
		return janusv1.Verdict_VERDICT_PASS, describeExpr(c, "holds")
	}
	return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf("%s (facts: %s)",
		describeExpr(c, "does not hold"), describeFacts(f))
}

func describeExpr(c *janusv1.PolicyCheck, verb string) string {
	if d := c.GetDescription(); d != "" {
		return fmt.Sprintf("%s — %q %s", d, c.GetExpr(), verb)
	}
	return fmt.Sprintf("%q %s", c.GetExpr(), verb)
}

// checkRiskLimit caps magnitude and blast radius.
//
// The thresholds are about one payment. The two caps below them are about the
// saga, and they are the ones that hold against an agent doing something
// systematically wrong rather than once: forty payments each under the limit
// are not forty acceptable payments.
func checkRiskLimit(c *janusv1.RiskLimitCheck, f Facts, s saga.State) (janusv1.Verdict, string) {
	for _, t := range c.GetThresholds() {
		v, ok := f[t.GetFact()]
		if !ok {
			return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
				"the limit is on %q and the step does not declare it, so the limit cannot be "+
					"applied", t.GetFact())
		}
		if v.Type != janusv1.FactType_FACT_TYPE_NUMBER {
			return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
				"the limit is on %q, which the step declares as %s rather than a number",
				t.GetFact(), typeName(v.Type))
		}
		if v.Num > t.GetMax() {
			return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
				"%s is %d, over the limit of %d", t.GetFact(), v.Num, t.GetMax())
		}
	}

	if limit := c.GetMaxGatedEffects(); limit > 0 {
		if n := countIrreversible(s); n > int(limit) {
			return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
				"the saga plans %s that cannot be taken back, over the cap of %d",
				quantity(n, "step"), limit)
		}
	}
	if limit := c.GetMaxResources(); limit > 0 {
		if n := len(saga.TouchedResources(s)); n > int(limit) {
			return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
				"the saga has touched %s, over the blast-radius cap of %d",
				quantity(n, "resource"), limit)
		}
	}
	return janusv1.Verdict_VERDICT_PASS, "within every limit"
}

// checkFrontier makes the step wait for contending sagas to finish.
//
// It escalates rather than refusing. A blocking saga will commit or compensate
// and either resolves the conflict, so refusing here would turn ordinary
// contention into a failed transaction and, for an irreversible step, into an
// unwind nobody needed.
//
// The index is built from the sagas the caller supplied. An index that does not
// know about a contending saga cannot see the conflict, which is why the
// coordinator passes every saga touching the same resources rather than only
// this one — and why saga.Index treats an unknown saga as unfinished rather
// than assuming the best.
func checkFrontier(in Input) (janusv1.Verdict, string) {
	if in.Index == nil {
		return janusv1.Verdict_VERDICT_FAIL, "no cross-saga index was supplied, so whether another " +
			"saga holds a resource this step touched is unknown; an unanswered frontier check " +
			"refuses rather than assuming the resource is clear"
	}
	var mine []saga.Blocker
	for _, b := range in.Index.Blockers(in.Saga.SagaID) {
		if b.BlockedStep == in.Step.ID {
			mine = append(mine, b)
		}
	}
	if len(mine) == 0 {
		return janusv1.Verdict_VERDICT_PASS, "no unfinished saga holds a resource this step touched"
	}
	reasons := make([]string, 0, len(mine))
	for _, b := range mine {
		reasons = append(reasons, b.Reason)
	}
	return janusv1.Verdict_VERDICT_ESCALATE, strings.Join(reasons, "; ")
}

// checkHuman decides on the approvals recorded against this requirement.
//
// It reads answers rather than asking for one, which is what keeps a human in
// the loop and replay determinism in the same system: the approval is an event
// like any other, and re-deriving this decision years later reaches the same
// answer without anybody being consulted again.
//
// The check is not "an approval exists". That version would be a tautology —
// it would agree with itself under audit and prove nothing about the control.
// What it checks is that the recorded approval satisfies the recorded rule:
// that the approver was not the initiator, that they held a role the policy
// names, and that enough distinct people said yes.
func checkHuman(c *janusv1.HumanCheck, reqID string, in Input) (janusv1.Verdict, string) {
	answers := saga.AnswersFor(in.Step, reqID, saga.AttemptUnderDecision(in.Step, in.Phase))
	quorum := max(int(c.GetQuorum()), 1)

	if len(answers) == 0 {
		return janusv1.Verdict_VERDICT_ESCALATE, waitingFor(c, quorum)
	}

	approvals := 0
	for _, a := range answers {
		// What this gate checks about the approver: either what the answer
		// claimed, or what an assertion established. The two are different
		// kinds of thing and the requirement says which it wants.
		roles := a.Roles
		if c.GetRequireEstablishedIdentity() || c.GetRequireStepUp() {
			established, err := establish(in, a)
			if err != nil {
				return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
					"%q answered and this gate requires an established identity: %v",
					a.ActorID, err)
			}
			if established.Subject != a.ActorID {
				return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
					"the answer is recorded as %q and the assertion establishes %q; an "+
						"approval attributed to somebody the proof does not name is not an "+
						"approval by them", a.ActorID, established.Subject)
			}
			if c.GetRequireStepUp() && !established.SteppedUp {
				return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
					"%q answered without a step-up bound to this approval, and this gate "+
						"requires one", a.ActorID)
			}
			roles = established.Roles
		}
		// The system expiring the gate is read before anything about roles,
		// because it holds none and never could. Ordering this after the role
		// check would make every timeout read as "answered holding no roles",
		// which is a true statement about the wrong thing.
		//
		// `saga.IsExpiry` insists the deadline had genuinely elapsed by the
		// answer's own recorded time, so an answer forged to look like a timeout
		// falls through to the checks below and is refused there for what it
		// actually is.
		if saga.IsExpiry(a, requirementOf(in.Step, reqID), saga.GateOpenedAt(in.Step, in.Phase)) {
			return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
				"nobody answered within %s of the gate opening, so the system refused it on "+
					"the deadline's behalf: %s",
				deadlineOf(in.Step, reqID), a.Reason)
		}
		// An answer from somebody who should not be giving one fails the gate
		// rather than being skipped over. An initiator approving their own
		// payment is an incident; silently ignoring it and waiting for somebody
		// else would file that incident nowhere.
		if c.GetSeparationOfDuty() && a.ActorID == in.Saga.Intent.Principal {
			return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
				"%q approved a saga initiated on their own authority, and this gate requires the "+
					"approver not be the initiator", a.ActorID)
		}
		// Semantics 4: the initiator is also the person the saga says began it.
		// Comparing with the principal alone could only ever catch an approver
		// named after the organisation -- which a signed begin forces the
		// principal to be -- so the person at the desk could approve their own
		// saga (the 2026-09-29 audit, M-2). The originator is declared
		// by the participant that signed the begin, not authenticated, so this
		// stops an honest mistake, not a caller that lies about who began it.
		if c.GetSeparationOfDuty() && in.Saga.Semantics >= 4 &&
			in.Saga.Intent.Originator != "" && a.ActorID == in.Saga.Intent.Originator {
			return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
				"%q approved a saga they began, and this gate requires the approver not be the "+
					"initiator", a.ActorID)
		}
		if !saga.HoldsAnyRole(roles, c.GetRoles()) {
			return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
				"%q answered holding %s, and this gate requires one of %s",
				a.ActorID, orNone(roles), strings.Join(c.GetRoles(), ", "))
		}
		if a.Verdict == janusv1.Verdict_VERDICT_FAIL {
			return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf("%q declined: %s",
				a.ActorID, orUnstated(a.Reason))
		}
		approvals++
	}

	if approvals >= quorum {
		return janusv1.Verdict_VERDICT_PASS, fmt.Sprintf("approved by %s",
			strings.Join(actorNames(answers), ", "))
	}
	return janusv1.Verdict_VERDICT_ESCALATE, fmt.Sprintf(
		"%d of %d approvals; waiting for %d more", approvals, quorum, quorum-approvals)
}

func waitingFor(c *janusv1.HumanCheck, quorum int) string {
	who := "an authorised approver"
	if len(c.GetRoles()) > 0 {
		who = "an approver holding one of " + strings.Join(c.GetRoles(), ", ")
	}
	if quorum > 1 {
		return fmt.Sprintf("waiting for %d approvals, each from %s", quorum, who)
	}
	return "waiting for approval from " + who
}

// checkValidator decides on the opinions recorded by independent participants.
func checkValidator(c *janusv1.ValidatorCheck, reqID string, in Input) (janusv1.Verdict, string) {
	answers := saga.AnswersFor(in.Step, reqID, saga.AttemptUnderDecision(in.Step, in.Phase))
	quorum := max(int(c.GetQuorum()), 1)

	if len(answers) == 0 {
		return janusv1.Verdict_VERDICT_ESCALATE, fmt.Sprintf(
			"waiting for %s from %s", quantity(quorum, "opinion"),
			strings.Join(c.GetValidators(), ", "))
	}

	var agree, dissent []string
	for _, a := range answers {
		// Independence is the whole point, so the validators are named in the
		// policy. Somebody answering a question nobody put to them is the shape
		// of a compromised path rather than a helpful volunteer.
		if len(c.GetValidators()) > 0 && !slices.Contains(c.GetValidators(), a.ActorID) {
			return janusv1.Verdict_VERDICT_FAIL, fmt.Sprintf(
				"%q rendered an opinion and is not one of the validators this gate asks (%s)",
				a.ActorID, strings.Join(c.GetValidators(), ", "))
		}
		if a.Verdict == janusv1.Verdict_VERDICT_PASS {
			agree = append(agree, a.ActorID)
		} else {
			dissent = append(dissent, fmt.Sprintf("%s (%s)", a.ActorID, orUnstated(a.Reason)))
		}
	}

	// Disagreement between independent checkers is information. Letting a
	// majority carry it is how a system with two opinions ends up acting as
	// though it had one.
	if len(agree) > 0 && len(dissent) > 0 && c.GetEscalateOnDisagreement() {
		return janusv1.Verdict_VERDICT_ESCALATE, fmt.Sprintf(
			"the validators disagree — %s accepted, %s objected — so this needs a human",
			strings.Join(agree, ", "), strings.Join(dissent, "; "))
	}
	if len(dissent) > 0 {
		return janusv1.Verdict_VERDICT_FAIL, "rejected by " + strings.Join(dissent, "; ")
	}
	if len(agree) >= quorum {
		return janusv1.Verdict_VERDICT_PASS, "accepted by " + strings.Join(agree, ", ")
	}
	return janusv1.Verdict_VERDICT_ESCALATE, fmt.Sprintf(
		"%d of %d opinions; waiting for %d more", len(agree), quorum, quorum-len(agree))
}

func actorNames(answers []saga.GateAnswerRecord) []string {
	out := make([]string, 0, len(answers))
	for _, a := range answers {
		out = append(out, a.ActorID)
	}
	return out
}

func orNone(roles []string) string {
	if len(roles) == 0 {
		return "no roles"
	}
	return strings.Join(roles, ", ")
}

func orUnstated(reason string) string {
	if reason == "" {
		return "no reason given"
	}
	return reason
}

func shortGate(g janusv1.GateType) string {
	return strings.TrimPrefix(g.String(), "GATE_TYPE_")
}

// orderRequirements puts a step's requirements into the order they are decided.
//
// Schema first, then the value checks, then frontier. It is a diagnosis order,
// not an optimisation: composition short-circuits on the first refusal, so
// whichever check refuses first is the reason the log records, and "the step
// declared no amount" is a better reason than "the amount comparison could not
// be evaluated". Within a rank, policy order is preserved, so an author who
// cares about the order of two policy checks can express it.
func orderRequirements(in []*janusv1.GateRequirement) []*janusv1.GateRequirement {
	out := slices.Clone(in)
	slices.SortStableFunc(out, func(a, b *janusv1.GateRequirement) int {
		return gateRank(a.GetGate()) - gateRank(b.GetGate())
	})
	return out
}

func gateRank(g janusv1.GateType) int {
	switch g {
	case janusv1.GateType_GATE_TYPE_SCHEMA:
		return 0
	case janusv1.GateType_GATE_TYPE_FRONTIER:
		return 2
	default:
		return 1
	}
}

// establish resolves and verifies the assertion an answer recorded.
//
// The failure modes are kept distinct because they mean different things to
// whoever reads the refusal: no resolver configured is a deployment that turned
// on a control it cannot enforce, no reference is an approval captured without
// one, and a verification failure is a proof that did not hold.
func establish(in Input, a saga.GateAnswerRecord) (*identity.Established, error) {
	if in.Identity == nil {
		return nil, fmt.Errorf("this deployment has no way to verify an assertion, so the " +
			"requirement cannot be met — configure one rather than relaxing the gate")
	}
	if a.AuthRef == "" {
		return nil, fmt.Errorf("the answer carries no assertion reference")
	}
	established, err := in.Identity(a.AuthRef)
	if err != nil {
		return nil, err
	}
	if established == nil {
		return nil, fmt.Errorf("the assertion at %q established nothing", a.AuthRef)
	}
	return established, nil
}

// requirementOf finds a step's requirement by id.
//
// The requirement recorded on the saga, not the one in the policy file: a
// deadline is pinned at admission (GateRequirement.timeout_seconds), which is
// what lets a decision be re-derived years later against the rule it was
// actually made under rather than against whatever the policy says now.
func requirementOf(st *saga.Step, reqID string) *janusv1.GateRequirement {
	if st == nil {
		return nil
	}
	for _, r := range st.Gates {
		if r.GetId() == reqID {
			return r
		}
	}
	return nil
}

// deadlineOf renders a requirement's deadline for a human reading a refusal.
func deadlineOf(st *saga.Step, reqID string) time.Duration {
	r := requirementOf(st, reqID)
	return time.Duration(r.GetTimeoutSeconds()) * time.Second
}
