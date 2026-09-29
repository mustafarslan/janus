package registry_test

import (
	"context"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/template"
)

// putTemplate registers one version through the recorder and returns its entry.
func putTemplate(t *testing.T, rec *registry.Recorder, signer *keys.Signer,
	tpl *template.Template) *registry.Entry {

	t.Helper()
	sig, err := registry.SignTemplate(tpl, signer)
	if err != nil {
		t.Fatal(err)
	}
	e, err := rec.RegisterTemplate(context.Background(), tpl, sig)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// templateBase registers the participant a template's step pins and puts the
// template's first version through register/evaluate/activate, so that a test
// about the *second* version starts from a shape that is actually in service.
func templateBase(t *testing.T) (*registry.Recorder, *keys.Signer) {
	t.Helper()
	rec, signer, _ := newRecorder(t)
	ctx := context.Background()
	register(t, rec, signer, wireManifest())
	evaluate(t, rec, wireManifest())
	if err := rec.Activate(ctx, "tool_payments", wireManifest().Version); err != nil {
		t.Fatal(err)
	}

	putTemplate(t, rec, signer, testTemplate())
	if err := rec.Evaluate(ctx, "tpl_wire", "1.0.0", &janusv1.EvaluationReport{
		Passed: true, HarnessVersion: "test", Sandbox: "ok",
		TriggersCovered: []string{registry.TriggerShapeChange, registry.TriggerSlotChange},
	}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, "tpl_wire", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	return rec, signer
}

// A step added to the shape owes fresh evidence, and the registry refuses to
// activate the new version until an evaluation says it covered that.
//
// This is the whole of the gap in one assertion. Until change records,
// `RegisterTemplate` wrote no change record at all, so a template could grow a
// step that sent money to a new participant and be activated on the evidence
// that cleared the shape without it — the registry's own `canActivate` check
// was reached with an empty PendingTriggers list and had nothing to refuse.
func TestAStepAddedToATemplateOwesAFreshEvaluation(t *testing.T) {
	rec, signer := templateBase(t)
	ctx := context.Background()

	v2 := testTemplate()
	v2.Version = "2.0.0"
	v2.Steps = append(v2.Steps, template.Step{
		StepID: "st_notify", Participant: "tool_payments", Action: "payments.wire",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED.String(),
		DependsOn:   []string{"st_wire"},
	})
	e := putTemplate(t, rec, signer, v2)

	if got := e.Change.GetChanged(); len(got) != 1 || got[0] != "steps.st_notify.added" {
		t.Fatalf("the change record names %v, want the added step", got)
	}
	if got := e.PendingTriggers; len(got) != 1 || got[0] != registry.TriggerShapeChange {
		t.Fatalf("adding a step left pending triggers %v, want %v",
			got, []string{registry.TriggerShapeChange})
	}

	// An evaluation that passes but covers nothing does not clear it: the
	// question is not whether the new shape passed a harness, it is whether the
	// harness answered the change.
	if err := rec.Evaluate(ctx, "tpl_wire", "2.0.0", &janusv1.EvaluationReport{
		Passed: true, HarnessVersion: "test", Sandbox: "ok",
	}); err != nil {
		t.Fatal(err)
	}
	err := rec.Activate(ctx, "tpl_wire", "2.0.0")
	if err == nil {
		t.Fatal("a template that grew a step was activated on an evaluation that " +
			"covered no trigger")
	}
	if !strings.Contains(err.Error(), registry.TriggerShapeChange) {
		t.Fatalf("the refusal does not name the trigger that is owed: %v", err)
	}

	// And an evaluation that says it covered the shape change does clear it.
	if err := rec.Evaluate(ctx, "tpl_wire", "2.0.0", &janusv1.EvaluationReport{
		Passed: true, HarnessVersion: "test", Sandbox: "ok",
		TriggersCovered: []string{registry.TriggerShapeChange},
	}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, "tpl_wire", "2.0.0"); err != nil {
		t.Fatalf("a re-evaluated template could not be activated: %v", err)
	}
}

// A slot's observed-value list growing fires nothing, and the new version
// inherits the evidence that cleared the old one.
//
// This is the other half of the entry's own vocabulary — "a step added or
// removed almost certainly does; a slot's observed-value list growing almost
// certainly does not" — and it is the half that says why the diff had to be
// written rather than approximated with `Diff`. A manifest diff run over these
// two documents would have compared nine scalar fields — six runtime, two
// identity, one jurisdiction — that a template does not have, found every one of
// them equal because both are empty, and fired nothing for the added step
// either.
func TestASlotSeenVaryingMoreDoesNotInvalidateATemplate(t *testing.T) {
	rec, signer := templateBase(t)
	ctx := context.Background()

	v2 := testTemplate()
	v2.Version = "2.0.0"
	v2.Slots[0].Observed = []string{"100", "250", "400"}
	v2.Provenance.Runs = 4
	v2.Provenance.SagaIDs = append(v2.Provenance.SagaIDs, "sg4")
	v2.Provenance.EvidenceRoots = append(v2.Provenance.EvidenceRoots, "dd")
	e := putTemplate(t, rec, signer, v2)

	if len(e.Change.GetChanged()) == 0 {
		t.Fatal("a wider observed set and a fourth source run were recorded as no change " +
			"at all; the record is what a reader checks the inheritance against")
	}
	if got := e.Change.GetTriggersFired(); len(got) != 0 {
		t.Fatalf("a slot's observed values growing fired %v; observed values are what "+
			"extraction saw, not what the template permits", got)
	}

	if err := rec.InheritEvaluation(ctx, "tpl_wire", "2.0.0"); err != nil {
		t.Fatalf("a template change that fired no trigger could not inherit its "+
			"predecessor's evaluation: %v", err)
	}
	if err := rec.Activate(ctx, "tpl_wire", "2.0.0"); err != nil {
		t.Fatalf("a template with an inherited evaluation could not be activated: %v", err)
	}
}

// A slot *added* is a new degree of freedom, and that does fire.
//
// The boundary is what gives the rule above its meaning: if nothing about slots
// ever fired, "observed values do not fire" would be a sentence about a code
// path that does not exist.
func TestASlotAddedToATemplateOwesAFreshEvaluation(t *testing.T) {
	rec, signer := templateBase(t)

	v2 := testTemplate()
	v2.Version = "2.0.0"
	v2.Slots = append(v2.Slots, template.Slot{
		Name: "memo", StepID: "st_wire", Kind: "TEXT",
	})
	e := putTemplate(t, rec, signer, v2)

	if got := e.PendingTriggers; len(got) != 1 || got[0] != registry.TriggerSlotChange {
		t.Fatalf("adding a slot left pending triggers %v, want %v",
			got, []string{registry.TriggerSlotChange})
	}
}
