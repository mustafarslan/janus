// Package compliance maps what Janus records onto what a regulator asks for.
//
// # Packs are data, not code
//
// A compliance pack is a JSON document: a framework, its articles, and for each
// article the checks that have to hold. Legal review updates a pack; it does not
// update a build. That is the whole design, and it is why the article text,
// the citation and the mapping all live in the pack rather than in a Go file
// somebody has to be a lawyer to review.
//
// # The honest limit
//
// A pack chooses from a fixed vocabulary of checks, and cannot invent a new kind
// of check without code. Adding "Article 22 requires X" where X is a property
// nothing here can evaluate needs a new checker, which needs a build.
//
// That limit is stated rather than hidden because the alternative — an
// expression language in the pack — would make packs into code with none of the
// review a build gets, and the failure would be a pack that quietly evaluates to
// true. What the vocabulary does cover is the properties Janus can actually
// establish from what it holds: what participants declared, and what the policy
// requires of them.
//
// # What the linter is for
//
// It runs before an audit, not during one. It reads the registry and the gate
// policy — declarations and rules, not a log of things that happened — and says
// which articles are satisfiable and which are already exposed. "Three actions
// declare no way to be undone and no gate stands in for one" is a finding
// somebody can act on in a sprint; the same finding from an inspector is a
// finding in a report.
package compliance

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// Subject is what the linter reads: what participants declared, and what the
// policy requires of them.
//
// Deliberately not a log. A log says what happened; these say what is allowed to
// happen, and an article about controls is a question about the second.
type Subject struct {
	Registry *registry.Registry
	Policy   *gate.Policy
	// Tenant is the binding the deployment writes under. The zero value is a
	// deployment that has not made the declaration, which is a distinct answer
	// from having made it and being wrong — see
	// jurisdictionIsPinnedAndEnforced.
	Tenant tenancy.Tenant
	// Clock is what the log demonstrates about the clock its events were
	// stamped by, read from the evidence directory the way Tenant is. Nil means
	// it was not derived, which is a distinct answer from a deployment that
	// attests nothing: the first makes the check Unknown, the second exposes it.
	//
	// It does not make this a log-reading Subject in the sense the type's
	// comment rules out. RTS 25 Art. 4 asks a firm to *demonstrate* traceability
	// to UTC, and a demonstration is the one kind of compliance question that
	// can only be answered from what was recorded — there is no declaration a
	// deployment could make that would answer it.
	Clock *ClockTraceability
}

// Result is how one check came out.
type Result struct {
	// Satisfied is false when the check found something. Unknown is separate:
	// a check that could not run is not a check that passed.
	Satisfied bool
	Unknown   bool
	Detail    string
}

// checker evaluates one named property of a Subject.
type checker func(Subject) Result

// checks is the vocabulary a pack may draw on. A pack naming anything else is
// refused at load time rather than silently skipped — an article mapped to a
// check that does not exist would otherwise report as satisfied.
var checks = map[string]checker{
	"every_effectful_action_can_be_undone_or_is_gated": everyEffectfulActionIsRecoverable,
	"every_irreversible_class_is_covered_by_policy":    everyIrreversibleClassCovered,
	"irreversible_effects_require_a_human":             irreversibleRequiresHuman,
	"human_gates_enforce_separation_of_duty":           humanGatesEnforceSoD,
	"every_participant_declares_jurisdiction":          everyParticipantDeclaresJurisdiction,
	"jurisdiction_is_pinned_and_enforced":              jurisdictionIsPinnedAndEnforced,
	"every_participant_declares_a_risk_tier":           everyParticipantDeclaresRiskTier,
	"every_active_manifest_is_signed":                  everyActiveManifestIsSigned,
	"irreversible_actions_declare_limits":              irreversibleActionsDeclareLimits,
	"every_agent_identifies_its_model":                 everyAgentIdentifiesItsModel,
	"business_clocks_are_traceable_to_utc":             businessClocksAreTraceableToUTC,
}

// Run evaluates one check by name, for a caller that wants a single property
// rather than a whole pack's worth. An unknown name is Unknown rather than a
// panic: the pack loader already refuses names outside the vocabulary, so
// reaching here with one means a caller typed it, and answering "could not run"
// is the same answer this package gives every other check it cannot run.
func Run(name string, s Subject) Result {
	c, ok := checks[name]
	if !ok {
		return Result{Unknown: true, Detail: "no check named " + name}
	}
	return c(s)
}

// CheckNames lists the vocabulary, for documentation and for the error a pack
// gets when it names something else.
func CheckNames() []string {
	out := make([]string, 0, len(checks))
	for name := range checks {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ---- the checks ------------------------------------------------------------

// everyEffectfulActionIsRecoverable is the Art. 14 shape: an action that changes
// the world either declares how to take it back, or is declared irreversible —
// in which case a gate has to stand in for the undo that does not exist.
//
// The two are not the same answer and the finding says which: an action that
// declares itself COMPENSABLE and names no inverse is a broken declaration,
// while an action declared IRREVERSIBLE_GATED is an honest one that has moved
// the obligation to the policy.
func everyEffectfulActionIsRecoverable(s Subject) Result {
	if s.Registry == nil {
		return Result{Unknown: true, Detail: "no registry was supplied"}
	}
	var broken []string
	var gated []string
	for _, entry := range activeEntries(s.Registry) {
		for _, action := range entry.Manifest.Actions {
			switch action.EffectClass {
			case "PURE":
			case "REVERSIBLE", "COMPENSABLE":
				if action.Compensation == nil || action.Compensation.Action == "" {
					broken = append(broken, entry.ParticipantID+"/"+action.Name)
				}
			default:
				gated = append(gated, entry.ParticipantID+"/"+action.Name)
			}
		}
	}
	if len(broken) > 0 {
		sort.Strings(broken)
		return Result{Detail: fmt.Sprintf(
			"%d action(s) claim to be reversible and name no inverse: %s",
			len(broken), strings.Join(broken, ", "))}
	}
	detail := "every reversible action names its inverse"
	if len(gated) > 0 {
		sort.Strings(gated)
		detail += fmt.Sprintf("; %d irreversible action(s) rely on a gate instead: %s",
			len(gated), strings.Join(gated, ", "))
	}
	return Result{Satisfied: true, Detail: detail}
}

// everyIrreversibleClassCovered: an irreversible action with no policy rule
// matching its class is an action nothing decides on.
func everyIrreversibleClassCovered(s Subject) Result {
	if s.Registry == nil || s.Policy == nil {
		return Result{Unknown: true, Detail: "a registry and a policy are both needed"}
	}
	covered := map[string]bool{}
	for _, rule := range s.Policy.Rules {
		for _, class := range rule.Match.EffectClasses {
			covered[class] = true
		}
	}
	var exposed []string
	for _, entry := range activeEntries(s.Registry) {
		for _, action := range entry.Manifest.Actions {
			if strings.HasPrefix(action.EffectClass, "IRREVERSIBLE") && !covered[action.EffectClass] {
				exposed = append(exposed, entry.ParticipantID+"/"+action.Name)
			}
		}
	}
	if len(exposed) > 0 {
		sort.Strings(exposed)
		return Result{Detail: fmt.Sprintf(
			"%d irreversible action(s) match no policy rule, so nothing decides on them: %s",
			len(exposed), strings.Join(exposed, ", "))}
	}
	return Result{Satisfied: true, Detail: "every irreversible class a participant declares is matched by a rule"}
}

// irreversibleRequiresHuman is Art. 14 human oversight read strictly: an
// irreversible effect needs a person, not merely a rule.
func irreversibleRequiresHuman(s Subject) Result {
	if s.Policy == nil {
		return Result{Unknown: true, Detail: "no policy was supplied"}
	}
	var without []string
	for _, rule := range s.Policy.Rules {
		if !matchesIrreversible(rule) {
			continue
		}
		if !hasGate(rule, gate.GateHuman) {
			without = append(without, rule.ID)
		}
	}
	if len(without) > 0 {
		sort.Strings(without)
		return Result{Detail: fmt.Sprintf(
			"%d rule(s) cover an irreversible effect without requiring a person: %s",
			len(without), strings.Join(without, ", "))}
	}
	return Result{Satisfied: true, Detail: "every rule over an irreversible effect requires a human approval"}
}

// humanGatesEnforceSoD: an approval by the person who raised the request is not
// a second pair of eyes.
func humanGatesEnforceSoD(s Subject) Result {
	if s.Policy == nil {
		return Result{Unknown: true, Detail: "no policy was supplied"}
	}
	var lax []string
	var found int
	for _, rule := range s.Policy.Rules {
		for _, requirement := range rule.Require {
			if requirement.Gate != gate.GateHuman || requirement.Human == nil {
				continue
			}
			found++
			if !requirement.Human.SeparationOfDuty {
				lax = append(lax, rule.ID+"/"+requirement.ID)
			}
		}
	}
	if found == 0 {
		return Result{Unknown: true, Detail: "the policy has no human gate to check"}
	}
	if len(lax) > 0 {
		sort.Strings(lax)
		return Result{Detail: fmt.Sprintf(
			"%d human gate(s) accept an approval from the saga's own initiator: %s",
			len(lax), strings.Join(lax, ", "))}
	}
	return Result{Satisfied: true, Detail: fmt.Sprintf("%d human gate(s), all refusing self-approval", found)}
}

func everyParticipantDeclaresJurisdiction(s Subject) Result {
	if s.Registry == nil {
		return Result{Unknown: true, Detail: "no registry was supplied"}
	}
	var missing []string
	for _, entry := range activeEntries(s.Registry) {
		j := entry.Manifest.Jurisdiction
		if len(j.DeployableIn) == 0 || j.DataResidency == "" {
			missing = append(missing, entry.ParticipantID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return Result{Detail: fmt.Sprintf(
			"%d participant(s) declare no jurisdiction or data residency: %s",
			len(missing), strings.Join(missing, ", "))}
	}
	return Result{Satisfied: true, Detail: "every active participant declares where it may run and where its data rests"}
}

// jurisdictionIsPinnedAndEnforced is a strictly stronger property than
// every_participant_declares_jurisdiction, and the two are separate checks
// rather than one check made stricter.
//
// They answer different questions and a pack that mapped an article to the
// weaker one should keep getting the weaker answer. "Every participant declares
// a jurisdiction" is about the completeness of the register: somebody wrote
// down where each thing may run. It says nothing about whether that writing
// down has any consequence, and until Phase 5c it had none — a participant
// could declare deployable_in ["US"], be registered, and run every step of a
// German tenant's saga with nothing objecting.
//
// This check asks the question that follows: does this deployment name a
// jurisdiction, and would the participants it has actually pass admission
// there? A deployment that is not pinned answers Unknown rather than false. It
// has not failed to enforce a pin; it has not made the declaration, and a check
// that reported that as a violation would push deployments into declaring a
// jurisdiction to clear a report.
func jurisdictionIsPinnedAndEnforced(s Subject) Result {
	if s.Registry == nil {
		return Result{Unknown: true, Detail: "no registry was supplied"}
	}
	if !s.Tenant.Pinned() {
		return Result{Unknown: true, Detail: "this deployment declares no jurisdiction to pin " +
			"work to, so there is nothing to enforce"}
	}
	var barred []string
	for _, entry := range activeEntries(s.Registry) {
		j := entry.Manifest.Jurisdiction
		switch {
		case !s.Tenant.Permits(j.DeployableIn):
			barred = append(barred, entry.ParticipantID+" (deployable in "+
				list(j.DeployableIn)+")")
		case j.DataResidency != "" && j.DataResidency != s.Tenant.Jurisdiction:
			barred = append(barred, entry.ParticipantID+" (data rests in "+j.DataResidency+")")
		}
	}
	if len(barred) > 0 {
		sort.Strings(barred)
		return Result{Detail: fmt.Sprintf(
			"work is pinned to %s, and %d active participant(s) may not be used there: %s",
			s.Tenant.Jurisdiction, len(barred), strings.Join(barred, ", "))}
	}
	return Result{Satisfied: true, Detail: fmt.Sprintf(
		"work is pinned to %s and every active participant may be used there; admission refuses "+
			"any step that would leave it", s.Tenant.Jurisdiction)}
}

// list renders a declaration, naming the empty one rather than printing
// nothing — "declares none" is the case a reader most needs to see.
func list(v []string) string {
	if len(v) == 0 {
		return "nowhere it has declared"
	}
	return strings.Join(v, ", ")
}

func everyParticipantDeclaresRiskTier(s Subject) Result {
	if s.Registry == nil {
		return Result{Unknown: true, Detail: "no registry was supplied"}
	}
	var missing []string
	for _, entry := range activeEntries(s.Registry) {
		if entry.Manifest.Risk.Tier == 0 {
			missing = append(missing, entry.ParticipantID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return Result{Detail: fmt.Sprintf("%d participant(s) declare no risk tier: %s",
			len(missing), strings.Join(missing, ", "))}
	}
	return Result{Satisfied: true, Detail: "every active participant declares a risk tier"}
}

// everyActiveManifestIsSigned reports what the registry could check, which is
// not the same as what is true: with no trusted key for a principal, a manifest
// is unchecked rather than unsigned, and saying otherwise would be the report
// claiming more than the evidence.
func everyActiveManifestIsSigned(s Subject) Result {
	if s.Registry == nil {
		return Result{Unknown: true, Detail: "no registry was supplied"}
	}
	var unsigned []string
	for _, entry := range activeEntries(s.Registry) {
		if entry.Signature == nil || len(entry.Signature.GetSignature()) == 0 {
			unsigned = append(unsigned, entry.ParticipantID)
		}
	}
	if len(unsigned) > 0 {
		sort.Strings(unsigned)
		return Result{Detail: fmt.Sprintf("%d active manifest(s) carry no signature: %s",
			len(unsigned), strings.Join(unsigned, ", "))}
	}
	return Result{Satisfied: true,
		Detail: "every active manifest carries a signature; whether each key is trusted is the registry audit's question"}
}

// ---- helpers ---------------------------------------------------------------

func activeEntries(reg *registry.Registry) []*registry.Entry {
	var out []*registry.Entry
	for _, participant := range reg.Participants() {
		if entry, ok := reg.Active(participant); ok && entry.Manifest != nil {
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ParticipantID < out[j].ParticipantID })
	return out
}

func matchesIrreversible(rule gate.Rule) bool {
	for _, class := range rule.Match.EffectClasses {
		if strings.HasPrefix(class, "IRREVERSIBLE") {
			return true
		}
	}
	return false
}

func hasGate(rule gate.Rule, kind string) bool {
	for _, requirement := range rule.Require {
		if requirement.Gate == kind {
			return true
		}
	}
	return false
}

// irreversibleActionsDeclareLimits finds irreversible actions with no cap on
// their magnitude or rate.
//
// # Why this is a check and not a validation rule
//
// Most of what a manifest must carry is refused at admission: an effectful
// action with no idempotency recipe, an IRREVERSIBLE_IMMEDIATE with no mandate,
// a compensable class with no compensation. A check restating one of those could
// never find anything on a registry that loaded, which is a check that cannot
// fail — the same hollowness as a test that never goes red.
//
// `Limits` is different. `Manifest.validate` checks a Limits block *if one is
// present* and requires none, so an irreversible action with no ceiling is a
// manifest this system accepts. That is the gap worth reporting: a payment
// action with no maximum amount and no rate is one where a single mistaken step
// is unbounded and cannot be taken back.
//
// # Irreversible only, and why not every effectful action
//
// A reversible action with no cap is a mess somebody can undo. Requiring limits
// everywhere would report on actions whose worst case is recoverable, and a
// linter that flags what does not matter teaches its reader to skip it. The line
// is drawn where the undo stops existing.
func irreversibleActionsDeclareLimits(s Subject) Result {
	if s.Registry == nil {
		return Result{Unknown: true, Detail: "no registry was supplied"}
	}
	var unbounded []string
	for _, entry := range activeEntries(s.Registry) {
		for _, action := range entry.Manifest.Actions {
			if !strings.HasPrefix(action.EffectClass, "IRREVERSIBLE") {
				continue
			}
			if action.Limits == nil {
				unbounded = append(unbounded, entry.ParticipantID+"/"+action.Name)
			}
		}
	}
	if len(unbounded) > 0 {
		sort.Strings(unbounded)
		return Result{Detail: fmt.Sprintf(
			"%d irreversible action(s) declare no limit on magnitude or rate, so a single "+
				"mistaken step is unbounded and cannot be taken back: %s",
			len(unbounded), strings.Join(unbounded, ", "))}
	}
	return Result{Satisfied: true,
		Detail: "every irreversible action declares a limit on its magnitude or rate"}
}

// everyAgentIdentifiesItsModel finds agents whose manifest does not say which
// model they run.
//
// A model inventory that cannot name the model is a list of participants. What
// makes it an inventory is `Runtime.ModelID` — and, where a deployment serves
// the same model id from more than one build, `ServingFingerprint`, which is
// what distinguishes two things a vendor calls by one name.
//
// # Agents only
//
// `Identity.Kind` is AGENT, TOOL, SYSTEM, HUMAN or VALIDATOR, and only an agent
// runs a model. Requiring a model id of a database connector would report a
// finding nobody can act on, and a finding nobody can act on is how a report
// stops being read. A tool that happens to declare one is not penalised; it is
// simply not asked.
func everyAgentIdentifiesItsModel(s Subject) Result {
	if s.Registry == nil {
		return Result{Unknown: true, Detail: "no registry was supplied"}
	}
	var unnamed []string
	var agents int
	for _, entry := range activeEntries(s.Registry) {
		if entry.Manifest.Identity.Kind != "AGENT" {
			continue
		}
		agents++
		if entry.Manifest.Runtime.ModelID == "" {
			unnamed = append(unnamed, entry.ParticipantID)
		}
	}
	if agents == 0 {
		// Unknown rather than satisfied, and the reason is that two very
		// different deployments look identical from here: one that runs no
		// models at all, for which this article is out of scope, and one whose
		// models were never registered, which is the gap the article exists to
		// close. Nothing in the registry distinguishes them, so the honest
		// answer is the one the linter already prints at the bottom of every
		// report — a question nobody has answered, not a mild pass.
		return Result{Unknown: true,
			Detail: "no active participant is registered as an AGENT: either this deployment " +
				"runs no models, in which case this article does not apply to it, or its " +
				"models were never registered, which is exactly what the article is about. " +
				"The registry cannot tell those apart"}
	}
	if len(unnamed) > 0 {
		sort.Strings(unnamed)
		return Result{Detail: fmt.Sprintf(
			"%d of %d agent(s) name no model, so the inventory cannot say what is running: %s",
			len(unnamed), agents, strings.Join(unnamed, ", "))}
	}
	return Result{Satisfied: true,
		Detail: fmt.Sprintf("all %d active agent(s) name the model they run", agents)}
}

// businessClocksAreTraceableToUTC is RTS 25 Art. 4's shape: a firm must be able
// to *demonstrate* traceability to UTC, not merely assert it.
//
// This is the first check whose evidence arrived before it. `clockatt` was
// wired into the daemon, so every event's wall reading points at a recorded
// attestation of what the clock was checked against and how far off it was —
// and nothing in `pkg/compliance` asked about it, so the packs could not map the
// article the feature exists to serve.
//
// Three ways it fails, and they are different findings because the remedies
// differ. Events carrying no reference at all is a deployment that configured no
// clock source: nothing lied, the events simply demonstrate nothing.
// Unsynchronised attestations are a source that was unreachable, which is a gap
// in the window they cover. Out-of-tolerance attestations are a clock that was
// checked and found wrong, which is the only one of the three where the log
// establishes an actual divergence.
func businessClocksAreTraceableToUTC(s Subject) Result {
	if s.Clock == nil {
		return Result{Unknown: true, Detail: "no evidence directory was read, so the log's " +
			"clock attestations could not be examined"}
	}
	c := s.Clock
	if c.Events == 0 {
		return Result{Unknown: true, Detail: "the log holds no events to attest"}
	}

	graded := fmt.Sprintf("%s. Worst demonstrated divergence %s over %d attestation(s) from %s",
		gradedAgainst(c), c.WorstOffset, c.Attestations, sources(c.Sources))

	switch {
	case c.Attested == 0 && c.Attestations == 0:
		return Result{Detail: fmt.Sprintf("none of %d event(s) points at a clock attestation "+
			"and the log holds none, so it demonstrates no traceability to UTC at all — this "+
			"deployment runs with no clock source configured (janus-orchd -clock-sources)",
			c.Events)}
	case c.Attested == 0:
		// Attestations exist and nothing points at them. A clock source *is*
		// configured; the events were written by something that did not record
		// the reference. Saying "no clock source configured" here would be
		// false, and this case was found by reading the real command's output on
		// a log that had both.
		//
		// Every binary that writes a log can attest now, so the
		// realistic cause is no longer a binary that cannot but an invocation
		// that was not given -clock-sources — the flag is per process, and an
		// operator who set it on the daemon can still forget it on a one-shot
		// command.
		//
		// That invocation is now warned at the moment it happens: a writer
		// records what it attests against in the directory's node-local marker,
		// and a later process given no sources names it rather than printing
		// the sentence an air-gapped deployment gets. This check is
		// still what finds a log already written that way — the warning is at
		// the keyboard and this is in the evidence, and they are answering the
		// same question at two different times.
		return Result{Detail: fmt.Sprintf("the log holds %d clock attestation(s) from %s, and "+
			"none of its %d event(s) points at one: a clock source is configured, but the "+
			"process that appended these events was not given one — -clock-sources is per "+
			"process, and every operational writer takes it",
			c.Attestations, sources(c.Sources), c.Events)}
	case c.Attested < c.Events:
		return Result{Detail: fmt.Sprintf("%d of %d event(s) point at a clock attestation; "+
			"%d do not, so traceability cannot be demonstrated for those. %s",
			c.Attested, c.Events, c.Events-c.Attested, graded)}
	case c.OutOfTolerance > 0:
		return Result{Detail: fmt.Sprintf("every event is attested, but %d of %d attestation(s) "+
			"found the clock outside tolerance. %s", c.OutOfTolerance, c.Attestations, graded)}
	case c.Unsynchronised > 0:
		return Result{Detail: fmt.Sprintf("every event is attested, but %d of %d attestation(s) "+
			"could not reach a time source, so the windows they cover demonstrate nothing. %s",
			c.Unsynchronised, c.Attestations, graded)}
	case c.OutOfDeclared > 0:
		// Inside the article's second and outside the deployment's own figure.
		// Art. 2(2) is satisfied and Art. 4 is not: what a firm has to be able to
		// demonstrate is the tolerance it stated, and this log demonstrates the
		// opposite of it.
		return Result{Detail: fmt.Sprintf("every event is attested and every attestation is "+
			"within RTS 25 Art. 2(2)'s one second, but %d of %d found the clock outside the "+
			"tolerance its own record declares (%s): the deployment holds the article's bound "+
			"and not the one it claims. %s",
			c.OutOfDeclared, c.Attestations, declaredList(c.Declared), graded)}
	case c.LooserThanArticle > 0:
		// The declaration, not the measurement. Art. 2(2)'s second is a maximum,
		// so an operator running -clock-tolerance=5s has a daemon that will not
		// raise a breach until the clock is four seconds past the point the
		// regulation stops permitting, and the clock being fine today does not
		// make that configuration compliant.
		return Result{Detail: fmt.Sprintf("every event is attested and the clock was measured "+
			"within one second throughout, but %d of %d attestation(s) declare a tolerance "+
			"wider than RTS 25 Art. 2(2) permits (%s against a one-second maximum), so nothing "+
			"in this deployment would report a divergence the article forbids. %s",
			c.LooserThanArticle, c.Attestations, declaredList(c.Declared), graded)}
	}
	return Result{Satisfied: true, Detail: fmt.Sprintf(
		"all %d event(s) point at a clock attestation, and all %d attestation(s) found the "+
			"clock synchronised and within tolerance. %s", c.Events, c.Attestations, graded)}
}

// gradedAgainst says which bounds the verdict was actually reached against, so
// a reader is never left to assume the stricter of two figures was checked.
//
// The three cases are different claims. A log whose attestations all declare a
// tolerance was graded against that and the article; one whose attestations
// declare none — every log written before the tolerance was recorded — was
// graded against the article alone and can say nothing about a stricter figure
// its operator may well have configured; a mixed log has both and says how many
// of each.
func gradedAgainst(c *ClockTraceability) string {
	const article = "RTS 25 Art. 2(2)'s one second"
	switch {
	case len(c.Declared) == 0:
		return "graded against " + article + " alone: no attestation here records the " +
			"tolerance its deployment declared, so a stricter figure cannot be checked from " +
			"this log"
	case c.Undeclared == 0:
		return "graded against " + article + " and the tolerance each attestation declares (" +
			declaredList(c.Declared) + ")"
	default:
		return fmt.Sprintf("graded against %s and the tolerance each attestation declares (%s); "+
			"%d of %d record none and were graded against the article alone",
			article, declaredList(c.Declared), c.Undeclared, c.Attestations)
	}
}

// declaredList renders the distinct tolerances a log declares.
func declaredList(v []time.Duration) string {
	if len(v) == 0 {
		return "none declared"
	}
	out := make([]string, len(v))
	for i, d := range v {
		out[i] = d.String()
	}
	return strings.Join(out, ", ")
}

// sources renders the time sources a log's attestations name.
//
// Not `list`, whose empty case reads "nowhere it has declared" — right for a
// jurisdiction and wrong here, where the absence is of a server rather than of a
// declaration.
func sources(v []string) string {
	if len(v) == 0 {
		return "no named time source"
	}
	return strings.Join(v, ", ")
}
