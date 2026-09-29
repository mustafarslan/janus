package template_test

import (
	"slices"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/template"
)

func shape() *template.Template {
	return &template.Template{
		TemplateID: "tpl_loan", Version: "1.0.0", Principal: "pr_bank", Risk: 2,
		Steps: []template.Step{
			{
				StepID: "st_check", Participant: "tool_credit", Action: "credit.score",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE.String(),
			},
			{
				StepID: "st_pay", Participant: "tool_payments", Action: "payments.wire",
				EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE.String(),
				CompensationAction: "payments.refund",
				DependsOn:          []string{"st_check"},
			},
		},
		Slots: []template.Slot{
			{Name: "amount", StepID: "st_pay", Kind: "NUMBER", Observed: []string{"100", "250"}},
		},
		Provenance: template.Provenance{
			Runs: 3, ExtractedFrom: "supervised",
			SagaIDs: []string{"sg1", "sg2", "sg3"}, EvidenceRoots: []string{"aa", "bb", "cc"},
		},
	}
}

// Every kind of change is named, and named as a path a reader can act on.
//
// The paths are the product, not the count. Somebody deciding whether the
// evidence that cleared the old shape still covers the new one needs to know
// that st_pay now goes to a different participant; "6 fields changed" leaves
// them opening both documents.
func TestChangedNamesEveryKindOfDifference(t *testing.T) {
	next := shape()
	next.Version = "2.0.0"
	next.Principal = "pr_other"
	next.Risk = 1
	next.Steps[1].Participant = "tool_other"
	next.Steps[1].Action = "payments.ach"
	next.Steps[1].EffectClass = janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED.String()
	next.Steps[1].CompensationAction = ""
	next.Steps[1].DependsOn = nil
	next.Steps[1].ChildTemplate = "tpl_settle"
	next.Steps = append(next.Steps, template.Step{
		StepID: "st_notify", Participant: "tool_email", Action: "email.send",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE.String(),
	})
	next.Steps = slices.Delete(next.Steps, 0, 1) // st_check removed
	next.Slots[0].Kind = "TEXT"
	next.Slots[0].Observed = []string{"100", "250", "400"}
	next.Slots = append(next.Slots, template.Slot{
		Name: "memo", StepID: "st_pay", Kind: "TEXT",
	})
	next.Provenance.Runs = 4

	want := []string{
		"principal",
		"provenance",
		"risk.tier",
		"slots.st_pay.amount.kind",
		"slots.st_pay.amount.observed",
		"slots.st_pay.memo.added",
		"steps.st_check.removed",
		"steps.st_notify.added",
		"steps.st_pay.action",
		"steps.st_pay.child_template",
		"steps.st_pay.compensation_action",
		"steps.st_pay.depends_on",
		"steps.st_pay.effect_class",
		"steps.st_pay.participant",
	}
	got := template.Changed(shape(), next)
	if !slices.Equal(got, want) {
		t.Fatalf("Changed reported\n  %v\nwant\n  %v", got, want)
	}
}

// A template compared against itself changed nothing.
//
// This is what lets a version bump that edits no shape inherit its
// predecessor's evaluation, and it is the assertion that catches a comparison
// written against a slice's order rather than its contents.
func TestChangedReportsNothingForTheSameShape(t *testing.T) {
	if got := template.Changed(shape(), shape()); len(got) != 0 {
		t.Fatalf("a template compared against itself reported %v", got)
	}
}

// Steps and slots are compared by identity, not by position.
//
// `Match` admits a plan on its step ids, so two documents that list the same
// steps in a different order confine exactly the same plans. Reporting that as
// a change would make reformatting a file owe a revalidation, and a revalidation
// nobody believes is one people learn to skip. Slots are keyed on step *and*
// name, because `Slot`'s own documentation says the same key on two steps is two
// decisions.
func TestReorderingIsNotAChangeAndTheSameNameOnTwoStepsIsTwoSlots(t *testing.T) {
	reordered := shape()
	reordered.Steps[0], reordered.Steps[1] = reordered.Steps[1], reordered.Steps[0]
	if got := template.Changed(shape(), reordered); len(got) != 0 {
		t.Fatalf("reordering the steps of a template reported %v", got)
	}

	moved := shape()
	moved.Slots[0].StepID = "st_check"
	got := template.Changed(shape(), moved)
	want := []string{"slots.st_check.amount.added", "slots.st_pay.amount.removed"}
	if !slices.Equal(got, want) {
		t.Fatalf("a slot moved to another step reported\n  %v\nwant\n  %v", got, want)
	}
}
