package registry

import (
	"fmt"
	"sort"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/template"
)

// Templates in the registry.
//
// A saga template is meant to be "registered as its own manifest (versioned,
// risk-tiered) → template change = change event". Read literally that would mean
// a template *is* a `Manifest`, and it is not: a Manifest describes a
// participant — its identity kind, its runtime, its actions, its jurisdiction —
// and a template describes a saga's shape. Forcing one into the other would give
// every template a participant kind it does not have.
//
// What that asks for is the *lifecycle*, and that is shared exactly. A
// template travels in the same `RegistryEvent` stream, through the same state
// machine, with the same transitions: registered as DRAFT, evaluated, activated,
// suspended, retired. Everything Phase 6b built follows for free — templates are
// in the projection's `registry_events` table without a line of new code, and
// `FoldUntil` answers "which template version governed this saga" the way it
// answers the same question about a manifest, which is what invariant I8 is
// actually about.
//
// # Why templates are a separate map and not a kind flag on the same one
//
// `Participants()` has seven callers — the compliance packs, the audit report,
// the projection's inventory, the console's count, the registry CLI. Every one
// of them would have to learn to skip templates, and a missed skip is a template
// counted as a participant in a compliance report. Nothing in the type system
// would catch it.
//
// Keeping templates in their own map means no read site can see one by accident:
// the ones that want templates ask for templates. The cost is two maps to keep
// in step, which is visible in one file rather than spread across seven.

// Templates lists the template ids the registry holds, sorted.
func (r *Registry) Templates() []string {
	out := make([]string, 0, len(r.templates))
	for id := range r.templates {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ResolveTemplate returns one template version's standing.
func (r *Registry) ResolveTemplate(templateID, version string) (*Entry, bool) {
	byVersion, ok := r.templates[templateID]
	if !ok {
		return nil, false
	}
	e, ok := byVersion[version]
	return e, ok
}

// ActiveTemplate returns the template version currently active, if any.
func (r *Registry) ActiveTemplate(templateID string) (*Entry, bool) {
	for _, v := range r.templateOrder[templateID] {
		if e := r.templates[templateID][v]; e != nil && e.State == StateActive {
			return e, true
		}
	}
	return nil, false
}

// TemplateVersions lists a template's versions in registration order.
func (r *Registry) TemplateVersions(templateID string) []*Entry {
	out := make([]*Entry, 0, len(r.templateOrder[templateID]))
	for _, v := range r.templateOrder[templateID] {
		if e := r.templates[templateID][v]; e != nil {
			out = append(out, e)
		}
	}
	return out
}

// applyTemplateRegistered enters a template version as DRAFT.
//
// It enforces the same three things registering a manifest does, for the same
// reasons: the document must agree with the event about its own id and version,
// the recorded content address must match the bytes, and a version may never be
// registered twice with different content — because every saga that pinned the
// string recorded a claim about what it would do, and a version that can be
// edited is not a pin.
func (r *Registry) applyTemplateRegistered(seq uint64, ev *janusv1.RegistryEvent) error {
	t, err := template.Decode(ev.GetTemplate())
	if err != nil {
		return fmt.Errorf("registry: event at seq %d: %w", seq, err)
	}
	if t.Version != ev.GetVersion() {
		return fmt.Errorf("registry: event at seq %d registers template %q but the document "+
			"it carries declares version %q", seq, ev.GetVersion(), t.Version)
	}
	if t.TemplateID != ev.GetParticipantId() {
		return fmt.Errorf("registry: event at seq %d registers template %q but the document "+
			"it carries belongs to %q", seq, ev.GetParticipantId(), t.TemplateID)
	}
	addr := ContentAddressOf(ev.GetTemplate())
	if ev.GetContentAddress() != "" && ev.GetContentAddress() != addr {
		return fmt.Errorf("registry: event at seq %d records content address %s for template "+
			"bytes that hash to %s", seq, shortAddress(ev.GetContentAddress()), shortAddress(addr))
	}

	// One namespace, two maps. Nothing stopped a template taking an id a
	// participant already held, and the consequence was not a duplicate: the
	// lifecycle events after registration carry no document, so `resolveEither`
	// decides which map they act on by looking — participants first. A template
	// sharing an id would have had its activation land on the participant.
	//
	// Refused in both directions, at registration, where there is still a
	// document to say which kind was meant.
	if _, taken := r.entries[t.TemplateID]; taken {
		return fmt.Errorf("registry: event at seq %d registers template %q, which is already "+
			"a participant id; the two share a namespace because a version's later events say "+
			"only the id, and one of them would act on the wrong document", seq, t.TemplateID)
	}

	byVersion, ok := r.templates[t.TemplateID]
	if !ok {
		byVersion = map[string]*Entry{}
		r.templates[t.TemplateID] = byVersion
	}
	if prior, exists := byVersion[t.Version]; exists {
		if prior.ContentAddress != addr {
			return fmt.Errorf("registry: event at seq %d registers template %s@%s again with "+
				"different content (%s, was %s); a version that can be edited is not a pin",
				seq, t.TemplateID, t.Version, shortAddress(addr), shortAddress(prior.ContentAddress))
		}
		return fmt.Errorf("registry: event at seq %d registers template %s@%s a second time",
			seq, t.TemplateID, t.Version)
	}

	e := &Entry{
		ParticipantID:  t.TemplateID,
		Version:        t.Version,
		ContentAddress: addr,
		Template:       t,
		Signature:      ev.GetSignature(),
		State:          StateDraft,
		Change:         ev.GetChange(),
		RegisteredSeq:  seq,
		LastSeq:        seq,
	}
	// The same debt a manifest version carries from birth (`applyRegistered`).
	// This fold once dropped both fields, which cost nothing while
	// `RegisterTemplate` wrote no change record and would have cost everything
	// the moment it did: the record would have been in the log, the audit would
	// have recomputed it, and the lifecycle would have activated the new shape
	// on the old shape's evidence anyway.
	e.PendingTriggers = append([]string(nil), ev.GetChange().GetTriggersFired()...)
	byVersion[t.Version] = e
	r.templateOrder[t.TemplateID] = append(r.templateOrder[t.TemplateID], t.Version)
	return nil
}

// ResolveEither finds a version in whichever map holds it, for callers that have
// an id and a version and do not know which kind it names.
//
// A command line is the case: `janus-registry evaluate <id> <version>` is handed
// a string, and that string may name either document. Every caller
// that reached for `Resolve` alone told an operator a registered template was
// "not registered" -- or, in one place, dereferenced the nil it got back.
func (r *Registry) ResolveEither(id, version string) (*Entry, bool) {
	return r.resolveEither(id, version)
}

// VersionsEither is `Versions` for whichever map holds the id.
func (r *Registry) VersionsEither(id string) []*Entry {
	if v := r.Versions(id); len(v) > 0 {
		return v
	}
	return r.TemplateVersions(id)
}

// resolveEither finds a version in whichever map holds it.
//
// The lifecycle events after registration — evaluated, activated, suspended,
// retired — carry no document, so the only way to know whether a version is a
// participant or a template is to look. The recorder's pre-checks use this so
// that they agree with what `mutable` will decide when the event is folded; two
// lookups with different reach would let the recorder refuse an event the state
// machine would have accepted, or the other way round.
func (r *Registry) resolveEither(id, version string) (*Entry, bool) {
	if e, ok := r.Resolve(id, version); ok {
		return e, true
	}
	return r.ResolveTemplate(id, version)
}
