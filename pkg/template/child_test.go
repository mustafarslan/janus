package template_test

import (
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/template"
)

// childPlan is the shape the sub-saga in these tests ran.
func childPlan() []*janusv1.PlannedStep {
	return []*janusv1.PlannedStep{{
		StepId: "st_settle", Participant: "tool_ledger", Action: "ledger.post",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
	}}
}

func childTemplate() *template.Template {
	return &template.Template{
		TemplateID: "tpl_settle", Version: "1.0.0", Principal: "pr_bank", Risk: 2,
		Steps: template.StepsOfPlan(childPlan()),
		Provenance: template.Provenance{
			Runs: 3, ExtractedFrom: "supervised",
			SagaIDs: []string{"c1", "c2", "c3"}, EvidenceRoots: []string{"aa", "bb", "cc"},
		},
	}
}

// spawning is `run` with st_pay delegating to a sub-saga of the given plan.
func spawning(id string, plan []*janusv1.PlannedStep) template.Run {
	r := run(id, nil)
	childID := "sg_child_" + id
	r.State.Steps["st_pay"].Child = &saga.ChildLink{
		SagaID: childID, Mode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE,
	}
	r.Children = map[string]*janusv1.SagaBegin{
		"st_pay": {SagaId: childID, Mode: "supervised", Plan: plan},
	}
	return r
}

func extractWith(children map[string]*template.Template, runs ...template.Run) (*template.Template, error) {
	return template.Extract("tpl_loan", "1.0.0", "pr_bank", 2, runs, children)
}

// A step that delegates and names no child template stops confining there.
//
// This is child confinement stated as a refusal at extraction rather than
// discovered at admission: a template built from runs whose steps spawned, saying nothing
// about what they spawned, is a confinement that ends at the first branch.
func TestATemplateMayNotBeExtractedFromASpawnItDoesNotDeclare(t *testing.T) {
	_, err := extractWith(nil,
		spawning("sg1", childPlan()), spawning("sg2", childPlan()), spawning("sg3", childPlan()))
	if err == nil {
		t.Fatal("a template was extracted from runs that delegated, declaring nothing about " +
			"the sub-sagas; the confinement stops at the first step that spawns")
	}
	if !strings.Contains(err.Error(), "no child template was named") {
		t.Fatalf("the refusal does not say what is missing: %v", err)
	}
}

// The declared child template is checked against what the runs actually spawned.
//
// Templates are extracted from *supervised* runs, whose children are supervised sagas
// pinning no template — so the operator has to assert which template the child
// must pin, and there is nothing in the evidence to read it from. An assertion
// nobody checks is the shape of every defect this repository keeps finding, so
// the assertion is matched against every run's child plan.
func TestADeclaredChildTemplateIsCheckedAgainstTheRunsThatSpawned(t *testing.T) {
	children := map[string]*template.Template{"st_pay": childTemplate()}

	tpl, err := extractWith(children,
		spawning("sg1", childPlan()), spawning("sg2", childPlan()), spawning("sg3", childPlan()))
	if err != nil {
		t.Fatalf("runs whose children matched the declared template were refused: %v", err)
	}
	var found bool
	for _, st := range tpl.Steps {
		if st.StepID == "st_pay" && st.ChildTemplate == "tpl_settle" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the extracted template does not carry the child reference: %+v", tpl.Steps)
	}

	// One run whose sub-saga did something else. The claim is refused, not
	// recorded: a template asserting a child shape three runs do not have is a
	// constraint nobody has evidence for.
	deviant := childPlan()
	deviant[0].Action = "ledger.reverse"
	_, err = extractWith(children,
		spawning("sg1", childPlan()), spawning("sg2", childPlan()), spawning("sg3", deviant))
	if err == nil {
		t.Fatal("a child template was declared for runs whose sub-sagas do not have its shape")
	}
	if !strings.Contains(err.Error(), "does not have that shape") {
		t.Fatalf("the refusal does not say the claim failed its check: %v", err)
	}
}

// A child template declared for a step that never delegated is refused.
//
// The mirror of the first test, and it matters for the same reason `Match`
// compares in both directions: a constraint in the template that no run is
// evidence for reads as a control while resting on nothing.
func TestAChildTemplateIsRefusedForAStepThatNeverSpawned(t *testing.T) {
	children := map[string]*template.Template{"st_pay": childTemplate()}
	_, err := extractWith(children, run("sg1", nil), run("sg2", nil), run("sg3", nil))
	if err == nil {
		t.Fatal("a child template was declared for a step that does not delegate")
	}
	if !strings.Contains(err.Error(), "does not delegate") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// Which steps delegate is part of the shape, and `Shape` cannot see it.
//
// Spawns are declared on STEP_PREPARE rather than on the plan, so two runs whose
// plans are identical can disagree about whether a step branches. Merging them
// would produce a template whose child constraint applied to some sagas and not
// others — the "roughly these steps" argument arriving by a different door.
//
// Refused from both sides by the two directional checks rather than by a third
// comparison of its own, so this asserts both directions and the exact message
// each produces. A test that accepted either message would be a test that did
// not know which control it was exercising — and the comparison it would have
// been covering for was unreachable.
func TestRunsThatDisagreeAboutSpawningAreTwoShapes(t *testing.T) {
	children := map[string]*template.Template{"st_pay": childTemplate()}

	// The odd run does not delegate, and the declaration has nothing to rest on
	// in it.
	_, err := extractWith(children,
		spawning("sg1", childPlan()), spawning("sg2", childPlan()), run("sg3", nil))
	if err == nil {
		t.Fatal("runs that disagree about which steps delegate were merged into one template")
	}
	if !strings.Contains(err.Error(), "does not delegate in saga") {
		t.Fatalf("the refusal does not name the disagreement: %v", err)
	}

	// The other side: nothing declared, and one run branches anyway.
	_, err = extractWith(nil,
		run("sg1", nil), run("sg2", nil), spawning("sg3", childPlan()))
	if err == nil {
		t.Fatal("a run that delegated was merged with two that did not")
	}
	if !strings.Contains(err.Error(), "no child template was named") {
		t.Fatalf("the refusal does not name the disagreement from the other side: %v", err)
	}
}
