package registry_test

import (
	"context"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/template"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

func testTemplate() *template.Template {
	return &template.Template{
		TemplateID: "tpl_wire", Version: "1.0.0", Principal: "pr_bank", Risk: 2,
		Steps: []template.Step{{
			StepID: "st_wire", Participant: "tool_payments", Action: "payments.wire",
			EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE.String(),
			CompensationAction: "payments.refund",
		}},
		Slots: []template.Slot{{Name: "amount", StepID: "st_wire", Kind: "NUMBER"}},
		Provenance: template.Provenance{
			Runs: 3, ExtractedFrom: "supervised",
			SagaIDs:       []string{"sg1", "sg2", "sg3"},
			EvidenceRoots: []string{"aa", "bb", "cc"},
		},
	}
}

func crystallizedBegin() *janusv1.SagaBegin {
	return &janusv1.SagaBegin{
		SagaId: "sg_crystal",
		Mode:   string(saga.ModeCrystallized),
		Intent: &janusv1.Intent{IntentId: "in_crystal", Principal: "pr_bank"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "st_wire", Participant: "tool_payments", Action: "payments.wire",
			EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: "payments.refund",
		}},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
		TemplatePin:  &janusv1.TemplatePin{TemplateId: "tpl_wire", Version: "1.0.0"},
	}
}

// registerTemplate puts a template through the registry's own lifecycle.
func registerTemplate(t *testing.T, rec *registry.Recorder, signer *keys.Signer, activate bool) {
	t.Helper()
	ctx := context.Background()
	tpl := testTemplate()
	sig, err := registry.SignTemplate(tpl, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RegisterTemplate(ctx, tpl, sig); err != nil {
		t.Fatalf("registering the template: %v", err)
	}
	if !activate {
		return
	}
	if err := rec.Evaluate(ctx, "tpl_wire", "1.0.0", &janusv1.EvaluationReport{
		Passed: true, HarnessVersion: "test", Sandbox: "re-matched its own source runs",
	}); err != nil {
		t.Fatalf("evaluating the template: %v", err)
	}
	if err := rec.Activate(ctx, "tpl_wire", "1.0.0"); err != nil {
		t.Fatalf("activating the template: %v", err)
	}
}

// TestATemplateRidesTheRegistryLifecycle is the claim that a
// template is "registered as its own manifest".
//
// It is not a Manifest — a Manifest describes a participant — but it goes
// through the same event stream and the same state machine, and this is what
// says so: the same DRAFT → EVALUATED → ACTIVE transitions, the same recorder,
// the same trust store, re-derived from the same log.
func TestATemplateRidesTheRegistryLifecycle(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	registerTemplate(t, rec, signer, false)

	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := reg.ResolveTemplate("tpl_wire", "1.0.0")
	if !ok {
		t.Fatal("the template is not in a registry folded from the log")
	}
	if e.State != registry.StateDraft {
		t.Errorf("a freshly registered template is %s, want DRAFT", e.State)
	}
	if e.Template == nil || e.Manifest != nil {
		t.Errorf("the entry carries manifest=%v template=%v; exactly one is expected",
			e.Manifest != nil, e.Template != nil)
	}

	// And it is invisible to every participant reader, which is why templates
	// live in their own map: `Participants()` has seven callers and a template
	// counted as a participant is a template in a compliance report.
	for _, id := range reg.Participants() {
		if id == "tpl_wire" {
			t.Error("the template appears in Participants(); a compliance pack walking " +
				"participants would count a saga shape as one")
		}
	}
	if got := reg.Templates(); len(got) != 1 || got[0] != "tpl_wire" {
		t.Errorf("Templates() reports %v", got)
	}
}

// TestACrystallizedSagaIsConfinedToItsTemplate.
func TestACrystallizedSagaIsConfinedToItsTemplate(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	register(t, rec, signer, wireManifest())
	evaluate(t, rec, wireManifest())
	if err := rec.Activate(context.Background(), "tool_payments", wireManifest().Version); err != nil {
		t.Fatal(err)
	}
	registerTemplate(t, rec, signer, true)

	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.AdmitFor(reg, crystallizedBegin(), tenancy.Tenant{}); err != nil {
		t.Fatalf("a plan that is exactly its template was refused: %v", err)
	}

	// One field different, and the plan is not the shape any more.
	deviant := crystallizedBegin()
	deviant.Plan[0].Action = "payments.wire.large"
	err = registry.AdmitFor(reg, deviant, tenancy.Tenant{})
	if err == nil {
		t.Fatal("a plan that deviates from its template was admitted")
	}
	if !strings.Contains(err.Error(), "action") {
		t.Errorf("the refusal does not name the deviation: %v", err)
	}
}

// TestAPinToANonActiveTemplateIsRefused is what makes the lifecycle reuse worth
// having rather than decorative.
//
// Crystallized mode requires "a *validated* template". If any registered template were pinnable,
// the validation would be a word — so a DRAFT template is refused, and so is one
// suspended between one saga and the next, which is the same reason
// `admitAgainstRegistry` re-reads the registry at all.
func TestAPinToANonActiveTemplateIsRefused(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	register(t, rec, signer, wireManifest())
	evaluate(t, rec, wireManifest())
	if err := rec.Activate(context.Background(), "tool_payments", wireManifest().Version); err != nil {
		t.Fatal(err)
	}
	registerTemplate(t, rec, signer, false) // registered, never activated

	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = registry.AdmitFor(reg, crystallizedBegin(), tenancy.Tenant{})
	if err == nil {
		t.Fatal("a saga was confined to a template nobody had validated")
	}
	if !strings.Contains(err.Error(), "DRAFT") {
		t.Errorf("the refusal does not say what state the template is in: %v", err)
	}

	// Now activate it, then suspend it, and admission must change its mind both
	// times.
	ctx := context.Background()
	if err := rec.Evaluate(ctx, "tpl_wire", "1.0.0", &janusv1.EvaluationReport{
		Passed: true, HarnessVersion: "test", Sandbox: "double",
	}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, "tpl_wire", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if reg, err = registry.Replay(dir); err != nil {
		t.Fatal(err)
	}
	if err := registry.AdmitFor(reg, crystallizedBegin(), tenancy.Tenant{}); err != nil {
		t.Fatalf("an active template was refused: %v", err)
	}

	if err := rec.Suspend(ctx, "tpl_wire", "1.0.0", "the shape was wrong"); err != nil {
		t.Fatal(err)
	}
	if reg, err = registry.Replay(dir); err != nil {
		t.Fatal(err)
	}
	err = registry.AdmitFor(reg, crystallizedBegin(), tenancy.Tenant{})
	if err == nil {
		t.Fatal("a saga was confined to a template that had been withdrawn")
	}
	if !strings.Contains(err.Error(), "SUSPENDED") {
		t.Errorf("the refusal does not say the template was withdrawn: %v", err)
	}
}

// TestATemplatePinOutsideCrystallizedModeIsRefused.
//
// A saga carrying a template it is not confined to is a record that reads as a
// confinement and is not one.
func TestATemplatePinOutsideCrystallizedModeIsRefused(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	register(t, rec, signer, wireManifest())
	evaluate(t, rec, wireManifest())
	if err := rec.Activate(context.Background(), "tool_payments", wireManifest().Version); err != nil {
		t.Fatal(err)
	}
	registerTemplate(t, rec, signer, true)

	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	begin := crystallizedBegin()
	begin.Mode = string(saga.ModeSupervised)
	err = registry.AdmitFor(reg, begin, tenancy.Tenant{})
	if err == nil {
		t.Fatal("a supervised saga carried a template pin and was admitted")
	}
	if !strings.Contains(err.Error(), "confines nothing") &&
		!strings.Contains(err.Error(), "confines a plan only in crystallized mode") {
		t.Errorf("the refusal does not say why the pin is meaningless here: %v", err)
	}
}

// TestATemplateMayNotTakeAParticipantsID.
//
// The two maps share one namespace, and that is not a tidiness point. The
// lifecycle events after registration carry no document — an ACTIVATED says only
// an id and a version — so `resolveEither` decides which map they act on by
// looking, participants first. A template sharing an id with a participant would
// have had its activation land on the participant, activating a manifest nobody
// asked to activate.
//
// It is the unaudited cost of keeping templates in their own map, found by
// asking what the decision made possible rather than what it made safe.
func TestATemplateMayNotTakeAParticipantsID(t *testing.T) {
	rec, signer, _ := newRecorder(t)
	m := wireManifest()
	register(t, rec, signer, m)

	tpl := testTemplate()
	tpl.TemplateID = m.Identity.ParticipantID
	sig, err := registry.SignTemplate(tpl, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RegisterTemplate(context.Background(), tpl, sig); err == nil {
		t.Fatal("a template took an id a participant already holds; its activation would " +
			"have landed on the manifest")
	} else if !strings.Contains(err.Error(), "already a participant id") {
		t.Errorf("the refusal does not say what the clash is: %v", err)
	}
}

// TestAParticipantMayNotTakeATemplatesID is the same refusal from the other
// side, because whichever is registered first must exclude the other.
func TestAParticipantMayNotTakeATemplatesID(t *testing.T) {
	rec, signer, _ := newRecorder(t)
	registerTemplate(t, rec, signer, false)

	m := wireManifest()
	m.Identity.ParticipantID = "tpl_wire"
	sig, err := registry.Sign(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Register(context.Background(), m, sig); err == nil {
		t.Fatal("a participant took an id a template already holds")
	} else if !strings.Contains(err.Error(), "already a template id") {
		t.Errorf("the refusal does not say what the clash is: %v", err)
	}
}
