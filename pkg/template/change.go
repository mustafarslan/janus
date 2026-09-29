package template

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// What changed between two versions of a shape.
//
// This is the template half of revalidation, and deliberately only half. The
// paths are computed here, in the package that owns the document; which of them
// invalidate a prior evaluation is a registry question, because the answer is
// expressed in the registry's revalidation-trigger vocabulary and the registry
// is what refuses an activation (`registry.DiffTemplate`). The manifest side is
// split the same way for the same reason, and the split is what keeps
// `pkg/template` free of an import back into `pkg/registry`.
//
// Nothing here reads the successor's opinion of its own change. A registrant
// that could describe its own edit could call a step swapped for another
// participant a rename.

// Changed names every field that differs between two versions of a shape, in a
// stable order.
//
// The names are paths into the document — "steps.wire.participant",
// "slots.wire.amount.kind" — because a change record is read by somebody
// deciding whether the evidence that cleared the old shape still covers the new
// one, and "4 fields changed" does not support that decision.
//
// Steps are compared by id rather than by position, because that is how `Match`
// compares them: a plan is admitted on its step ids and their declared
// dependencies, not on the order the steps happen to sit in the document. Two
// templates that differ only in step order confine exactly the same plans, so
// reporting that as a change would fire a revalidation for a reordered file.
func Changed(prev, next *Template) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	if prev.Principal != next.Principal {
		add("principal")
	}
	if prev.Risk != next.Risk {
		add("risk.tier")
	}

	prevSteps := stepMap(prev)
	nextSteps := stepMap(next)
	for _, id := range sortedStepIDs(prevSteps) {
		before := prevSteps[id]
		after, still := nextSteps[id]
		if !still {
			add("steps.%s.removed", id)
			continue
		}
		for _, f := range []struct{ name, was, now string }{
			{"participant", before.Participant, after.Participant},
			{"action", before.Action, after.Action},
			{"effect_class", before.EffectClass, after.EffectClass},
			{"compensation_action", before.CompensationAction, after.CompensationAction},
			{"child_template", before.ChildTemplate, after.ChildTemplate},
		} {
			if f.was != f.now {
				add("steps.%s.%s", id, f.name)
			}
		}
		if !slices.Equal(before.DependsOn, after.DependsOn) {
			add("steps.%s.depends_on", id)
		}
	}
	for _, id := range sortedStepIDs(nextSteps) {
		if _, had := prevSteps[id]; !had {
			add("steps.%s.added", id)
		}
	}

	prevSlots := slotMap(prev)
	nextSlots := slotMap(next)
	for _, key := range sortedSlotKeys(prevSlots) {
		before := prevSlots[key]
		after, still := nextSlots[key]
		if !still {
			add("slots.%s.removed", key)
			continue
		}
		if before.Kind != after.Kind {
			add("slots.%s.kind", key)
		}
		if !slices.Equal(before.Observed, after.Observed) {
			add("slots.%s.observed", key)
		}
	}
	for _, key := range sortedSlotKeys(nextSlots) {
		if _, had := prevSlots[key]; !had {
			add("slots.%s.added", key)
		}
	}

	if provenanceOf(prev) != provenanceOf(next) {
		add("provenance")
	}

	sort.Strings(out)
	return out
}

func stepMap(t *Template) map[string]*Step {
	out := make(map[string]*Step, len(t.Steps))
	for i := range t.Steps {
		out[t.Steps[i].StepID] = &t.Steps[i]
	}
	return out
}

// slotMap keys on step and name together, because `Slot`'s own documentation
// says a slot is scoped to its step: the same key on two steps is two slots,
// because they are two decisions.
func slotMap(t *Template) map[string]*Slot {
	out := make(map[string]*Slot, len(t.Slots))
	for i := range t.Slots {
		out[t.Slots[i].StepID+"."+t.Slots[i].Name] = &t.Slots[i]
	}
	return out
}

func sortedStepIDs(m map[string]*Step) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSlotKeys(m map[string]*Slot) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// provenanceOf renders the sub-document to a string, so that a re-extraction
// from the same runs written in a different order is not reported as a change
// and a genuinely different source set is.
func provenanceOf(t *Template) string {
	p := t.Provenance
	sagas := append([]string(nil), p.SagaIDs...)
	roots := append([]string(nil), p.EvidenceRoots...)
	sort.Strings(sagas)
	sort.Strings(roots)
	return fmt.Sprintf("%d|%s|%s|%s", p.Runs, strings.Join(sagas, ","),
		strings.Join(roots, ","), p.ExtractedFrom)
}
