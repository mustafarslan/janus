package registry

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/template"
)

// What changed between two manifest versions, and what that costs.
//
// A manifest change — a new model version, a new prompt — is a
// registered change event that triggers policy-defined revalidation. The part
// that makes it more than bookkeeping is the *policy-defined* half: the
// predecessor declares which changes invalidate the evidence that cleared it,
// and a successor that fires one of those triggers cannot inherit that
// evidence. It has to be evaluated again before it can be activated.
//
// The diff is computed here, from the two manifests, rather than taken from
// whoever registered the new version. That is the same discipline the gate
// audit applies to verdicts: a registrant that could describe its own change
// could describe a new model as a typo fix and skip the revalidation its
// predecessor demanded. Audit recomputes this diff from the recorded manifests
// and reports a change record that understates what happened (audit.go).

// Diff describes one manifest version against its predecessor.
func Diff(prev, next *Manifest) *janusv1.ChangeRecord {
	changed := changedFields(prev, next)
	return &janusv1.ChangeRecord{
		FromVersion:   prev.Version,
		Changed:       changed,
		TriggersFired: triggersFor(prev, changed),
	}
}

// changedFields names every field that differs, in a stable order.
//
// The names are paths into the document — "runtime.model_id",
// "actions.payments.wire.effect_class" — because a change record is read by
// somebody deciding whether to revalidate, and "3 fields changed" does not
// support that decision.
func changedFields(prev, next *Manifest) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	for _, f := range []struct{ name, was, now string }{
		{"runtime.model_id", prev.Runtime.ModelID, next.Runtime.ModelID},
		{"runtime.model_serving_fingerprint", prev.Runtime.ServingFingerprint, next.Runtime.ServingFingerprint},
		{"runtime.prompt_bundle_hash", prev.Runtime.PromptBundleHash, next.Runtime.PromptBundleHash},
		{"runtime.policy_bundle_version", prev.Runtime.PolicyBundleVersion, next.Runtime.PolicyBundleVersion},
		{"runtime.framework", prev.Runtime.Framework, next.Runtime.Framework},
		{"runtime.sbom_ref", prev.Runtime.SBOMRef, next.Runtime.SBOMRef},
		{"identity.kind", prev.Identity.Kind, next.Identity.Kind},
		{"identity.principal", prev.Identity.Principal, next.Identity.Principal},
		{"jurisdiction.data_residency", prev.Jurisdiction.DataResidency, next.Jurisdiction.DataResidency},
	} {
		if f.was != f.now {
			add("%s", f.name)
		}
	}
	if prev.Risk.Tier != next.Risk.Tier {
		add("risk.tier")
	}
	if !slices.Equal(prev.Risk.RevalidationTriggers, next.Risk.RevalidationTriggers) {
		add("risk.revalidation_triggers")
	}
	if !slices.Equal(prev.Jurisdiction.DeployableIn, next.Jurisdiction.DeployableIn) {
		add("jurisdiction.deployable_in")
	}
	if !slices.Equal(prev.Identity.PublicKeys, next.Identity.PublicKeys) {
		add("identity.public_keys")
	}

	prevActions := actionMap(prev)
	nextActions := actionMap(next)
	for _, name := range sortedKeys(prevActions) {
		before := prevActions[name]
		after, still := nextActions[name]
		if !still {
			add("actions.%s.removed", name)
			continue
		}
		if before.EffectClass != after.EffectClass {
			add("actions.%s.effect_class", name)
		}
		if compensationOf(before) != compensationOf(after) {
			add("actions.%s.compensation", name)
		}
		if idempotencyOf(before) != idempotencyOf(after) {
			add("actions.%s.idempotency", name)
		}
		if limitsOf(before) != limitsOf(after) {
			add("actions.%s.limits", name)
		}
		if before.PreauthorizedMandate != after.PreauthorizedMandate {
			add("actions.%s.preauthorized_mandate", name)
		}
	}
	for _, name := range sortedKeys(nextActions) {
		if _, had := prevActions[name]; !had {
			add("actions.%s.added", name)
		}
	}

	sort.Strings(out)
	return out
}

// triggersFor maps changed fields onto the triggers the *predecessor* declared.
//
// The predecessor's list is what counts, not the successor's. The question
// being asked is whether the evidence that cleared the old version still covers
// the new one, and only the old version's terms can answer that. Reading the
// successor's list instead would let a new manifest excuse itself by declaring
// fewer triggers than the one it replaces.
func triggersFor(prev *Manifest, changed []string) []string {
	declared := prev.Risk.RevalidationTriggers
	fired := map[string]bool{}
	for _, field := range changed {
		for _, t := range triggersForField(field) {
			if slices.Contains(declared, t) {
				fired[t] = true
			}
		}
	}
	out := make([]string, 0, len(fired))
	for t := range fired {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func triggersForField(field string) []string {
	switch {
	case field == "runtime.model_id" || field == "runtime.model_serving_fingerprint":
		return []string{TriggerModelChange}
	case field == "runtime.prompt_bundle_hash":
		return []string{TriggerPromptChange}
	case field == "runtime.policy_bundle_version":
		return []string{TriggerPolicyChange}
	case strings.HasSuffix(field, ".effect_class"), strings.HasSuffix(field, ".compensation"),
		strings.HasSuffix(field, ".added"), strings.HasSuffix(field, ".removed"),
		strings.HasSuffix(field, ".idempotency"), strings.HasSuffix(field, ".preauthorized_mandate"):
		return []string{TriggerActionChange}
	case strings.HasSuffix(field, ".limits"):
		return []string{TriggerLimitChange}
	default:
		// A change to a field no trigger names does not fire one. That is a
		// deliberate hole with a floor under it: the change is still recorded,
		// audit still recomputes it, and a deployment that wants tighter cover
		// declares more triggers. Inventing a trigger for every field would
		// make every edit require a re-evaluation and teach people to declare
		// none.
		return nil
	}
}

func actionMap(m *Manifest) map[string]*Action {
	out := make(map[string]*Action, len(m.Actions))
	for i := range m.Actions {
		out[m.Actions[i].Name] = &m.Actions[i]
	}
	return out
}

func sortedKeys(m map[string]*Action) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The three comparisons below render a sub-document to a string rather than
// comparing pointers, so that "the same compensation written differently" is
// not reported as a change and a real edit inside it is.
func compensationOf(a *Action) string {
	if a.Compensation == nil {
		return ""
	}
	c := a.Compensation
	params := make([]string, 0, len(c.ParamMap))
	for k, v := range c.ParamMap {
		params = append(params, k+"="+v)
	}
	sort.Strings(params)
	return fmt.Sprintf("%s|%v|%d|%s", c.Action, params, c.MaxDelaySeconds, c.ResidualEffects)
}

func idempotencyOf(a *Action) string {
	if a.Idempotency == nil {
		return ""
	}
	return fmt.Sprintf("%s|%d", a.Idempotency.KeyRecipe, a.Idempotency.WindowSeconds)
}

func limitsOf(a *Action) string {
	if a.Limits == nil {
		return ""
	}
	l := a.Limits
	return fmt.Sprintf("%d|%s|%s|%d", l.MaxAmount, l.AmountField, l.Currency, l.RatePerHour)
}

// DiffTemplate describes one template version against its predecessor.
//
// It is a separate function from `Diff` rather than a branch inside it, because
// the two documents share a change *record* and nothing else: the fields are
// different, the paths are different, and the question of
// who decides which changes matter is answered differently.
func DiffTemplate(prev, next *template.Template) *janusv1.ChangeRecord {
	changed := template.Changed(prev, next)
	return &janusv1.ChangeRecord{
		FromVersion:   prev.Version,
		Changed:       changed,
		TriggersFired: templateTriggersFor(changed),
	}
}

// templateTriggersFor maps changed paths onto triggers, with no declared list to
// intersect against.
//
// This is where a template parts company with a manifest. A manifest's predecessor declares which changes invalidate its
// evidence because deployments genuinely disagree — a model version bump matters
// to one and not another. A template's shape is not like that: an evaluation
// that cleared a five-step DAG says nothing about a six-step one, in every
// deployment, and a declared list here would be a field every extractor set
// identically. The cost is that nothing can opt out, which is the point.
func templateTriggersFor(changed []string) []string {
	fired := map[string]bool{}
	for _, field := range changed {
		switch {
		case strings.HasPrefix(field, "steps."):
			fired[TriggerShapeChange] = true
		case strings.HasSuffix(field, ".observed"):
			// No edit to a slot's observed values fires anything. They are what
			// extraction saw, not an allowed-value list (`template.Slot`), and
			// `ConfinesFacts` reads slot *names* — so nothing that happens to
			// this list changes which facts a saga is confined to, and a change
			// that confines nothing differently cannot invalidate the evidence
			// that cleared the confinement. It stays in the record, because
			// "this slot varied more than we thought" is what a reader judging
			// the risk tier wants to see.
		case strings.HasPrefix(field, "slots."):
			fired[TriggerSlotChange] = true
		}
		// Everything else — principal, risk.tier, provenance — is recorded and
		// fires nothing, which is the same hole `triggersForField` leaves for a
		// manifest's identity and tier, with the same floor under it: the change
		// is in the record and the audit recomputes it.
	}
	out := make([]string, 0, len(fired))
	for t := range fired {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
