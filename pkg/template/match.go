package template

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// ErrDeviates means a plan is not the shape its template declares.
var ErrDeviates = errors.New("template: the plan deviates from the template it pins")

// Match refuses a plan that is not exactly the template's shape.
//
// Exactly, and in both directions: a plan missing a step the template declares
// is as much a deviation as one that adds a step. A template is a claim about
// what a saga *will* do, and a claim that permits omissions is a claim about
// nothing.
//
// What is compared is the plan — the steps, their participants, their actions,
// their effect classes, their compensations and their dependencies — because the
// plan is what admission has in front of it. The facts are not compared here;
// they are not known until a step runs, and confining them is what the slots are
// for (ConfinesFacts).
//
// Every deviation found is reported, not just the first. Somebody handed a plan
// that does not match is going to fix it, and returning one difference at a time
// makes that a conversation.
func Match(t *Template, plan []*janusv1.PlannedStep) error {
	if t == nil {
		return fmt.Errorf("%w: there is no template to compare against", ErrDeviates)
	}
	got := StepsOfPlan(plan)

	declared := make(map[string]Step, len(t.Steps))
	for _, s := range t.Steps {
		declared[s.StepID] = s
	}
	present := make(map[string]Step, len(got))
	for _, s := range got {
		present[s.StepID] = s
	}

	var problems []string
	for _, s := range got {
		want, ok := declared[s.StepID]
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"step %q is not in the template", s.StepID))
			continue
		}
		problems = append(problems, stepDiff(want, s)...)
	}
	for _, s := range t.Steps {
		if _, ok := present[s.StepID]; !ok {
			problems = append(problems, fmt.Sprintf(
				"step %q is in the template and not in the plan", s.StepID))
		}
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("%w %s@%s: %s", ErrDeviates, t.TemplateID, t.Version,
		strings.Join(problems, "; "))
}

func stepDiff(want, got Step) []string {
	var out []string
	add := func(what, w, g string) {
		if w != g {
			out = append(out, fmt.Sprintf("step %q %s is %q, the template declares %q",
				got.StepID, what, g, w))
		}
	}
	add("participant", want.Participant, got.Participant)
	add("action", want.Action, got.Action)
	add("effect class", want.EffectClass, got.EffectClass)
	add("compensation", want.CompensationAction, got.CompensationAction)
	add("dependencies", strings.Join(want.DependsOn, ","), strings.Join(got.DependsOn, ","))
	return out
}

// ConfinesFacts refuses declared facts a template has no slot for.
//
// This is the "LLM confined to declared slots" half of crystallized mode, and it
// is a separate function from Match because it answers a question at a different
// time: Match runs at admission, over a plan; this runs when a step *declares*
// what it will act on, before the declaration is bound.
//
// # Declared facts only, and why that is the whole scope
//
// A saga has two kinds of fact and they are different vocabularies. Declared
// facts arrive with the request to prepare, are what a pre-execution gate decides
// against, and are what a template's slots are extracted from — those are these.
// Published facts are what a step reported from what it found, and a later gate
// can decide on one through `saga.PublishedFactPrefix`.
//
// A template says nothing about published facts, and could not: its slots were
// extracted from the declared vocabulary, so checking published names against
// them would be comparing two lists that were never meant to line up. What
// constrains a published fact is the gate policy that chose to read it — a rule
// naming `published.<step>.<key>` is a policy author deciding that value is worth
// deciding on, and that exposure is the same for a crystallized saga as for any
// other. Crystallization does not widen it and does not close it.
//
// It checks that every declared fact has a slot, and not that every slot has a
// fact. A step that omits an optional one has not escaped confinement — the gate
// policy is what decides whether a missing fact is acceptable, and it already
// does.
func ConfinesFacts(t *Template, stepID string, facts []string) error {
	if t == nil {
		return fmt.Errorf("%w: there is no template to confine to", ErrDeviates)
	}
	allowed := map[string]struct{}{}
	for _, s := range t.Slots {
		if s.StepID == stepID {
			allowed[s.Name] = struct{}{}
		}
	}
	var undeclared []string
	for _, f := range facts {
		if _, ok := allowed[f]; !ok {
			undeclared = append(undeclared, f)
		}
	}
	if len(undeclared) == 0 {
		return nil
	}
	sort.Strings(undeclared)
	return fmt.Errorf("%w %s@%s: step %q carries fact(s) %s, which the template declares no "+
		"slot for; a template whose free part is not enumerated confines nothing",
		ErrDeviates, t.TemplateID, t.Version, stepID, strings.Join(undeclared, ", "))
}
