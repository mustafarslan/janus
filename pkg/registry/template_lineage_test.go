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

// lineageTemplate builds a standalone template with the given id and an optional
// extra step, so a second version can differ in shape.
func lineageTemplate(id, version string, extraStep bool) *template.Template {
	t := testTemplate()
	t.TemplateID = id
	t.Version = version
	if extraStep {
		t.Steps = append(t.Steps, template.Step{
			StepID: "st_notify", Participant: "tool_payments", Action: "payments.wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE.String(),
			DependsOn:   []string{"st_wire"},
		})
	}
	return t
}

// lineage registers, evaluates and activates one template version.
func lineage(t *testing.T, rec *registry.Recorder, signer *keys.Signer,
	tpl *template.Template, covers ...string) {

	t.Helper()
	ctx := context.Background()
	sig, err := registry.SignTemplate(tpl, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RegisterTemplate(ctx, tpl, sig); err != nil {
		t.Fatalf("registering %s@%s: %v", tpl.TemplateID, tpl.Version, err)
	}
	if err := rec.Evaluate(ctx, tpl.TemplateID, tpl.Version, &janusv1.EvaluationReport{
		Passed: true, HarnessVersion: template.HarnessVersion,
		Sandbox: "re-matched its source runs", TriggersCovered: covers,
	}); err != nil {
		t.Fatalf("evaluating %s@%s: %v", tpl.TemplateID, tpl.Version, err)
	}
	if err := rec.Activate(ctx, tpl.TemplateID, tpl.Version); err != nil {
		t.Fatalf("activating %s@%s: %v", tpl.TemplateID, tpl.Version, err)
	}
}

// parentOver registers a parent whose step confines its children to childID,
// then evaluates and activates it.
func parentOver(t *testing.T, rec *registry.Recorder, signer *keys.Signer,
	version, childID string, covers ...string) {

	t.Helper()
	p := lineageTemplate("tpl_parent", version, false)
	p.Steps[0].ChildTemplate = childID
	lineage(t, rec, signer, p, covers...)
}

func lineageAudit(t *testing.T, dir string, signer *keys.Signer) registry.Report {
	t.Helper()
	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	rep, err := registry.Audit(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func lineageFindings(rep registry.Report) []registry.Finding {
	var out []registry.Finding
	for _, f := range rep.Findings {
		if f.Kind == registry.FindingParentEvidencePredatesChild {
			out = append(out, f)
		}
	}
	return out
}

// A child reshaped and activated under a parent is named by the audit.
//
// A parent's step names the template its children
// must pin; a change record makes the child owe fresh evidence for its own shape change.
// Nothing connected the two, so the parent stayed ACTIVE — admitting sagas whose
// branches are confined to a shape its own evaluation never saw.
func TestTheAuditNamesAParentWhoseChildWasReshapedUnderIt(t *testing.T) {
	rec, signer, dir := newRecorder(t)

	lineage(t, rec, signer, lineageTemplate("tpl_child", "1.0.0", false))
	parentOver(t, rec, signer, "1.0.0", "tpl_child")

	if got := lineageFindings(lineageAudit(t, dir, signer)); len(got) != 0 {
		t.Fatalf("a parent evaluated after its child was activated is not stale: %+v", got)
	}

	// The child grows a step: shape_change, fresh evidence, activated. The
	// parent has not moved.
	lineage(t, rec, signer, lineageTemplate("tpl_child", "2.0.0", true),
		registry.TriggerShapeChange)

	got := lineageFindings(lineageAudit(t, dir, signer))
	if len(got) != 1 {
		t.Fatalf("a child reshaped under an active parent produced %d finding(s), want 1",
			len(got))
	}
	if got[0].ParticipantID != "tpl_parent" || got[0].Version != "1.0.0" {
		t.Fatalf("the finding names %s@%s, want tpl_parent@1.0.0",
			got[0].ParticipantID, got[0].Version)
	}
	// The remedy is not obvious and the finding has to say it: re-evaluating
	// the parent fails, because the harness matches its source runs' children
	// against the active child template, which is exactly what changed.
	for _, want := range []string{"Re-evaluating", "inheriting", "new version"} {
		if !strings.Contains(got[0].Detail, want) {
			t.Errorf("the finding does not say %q, so it names a problem and no way out: %s",
				want, got[0].Detail)
		}
	}
}

// A child change that fires no shape trigger is not a finding.
//
// This is the boundary that makes the number mean something. The
// recommended path for a slot-only change is: register, inherit, activate — and
// the parent's evidence is *not* stale, because the branch still has the same
// shape. A comparison on sequence alone would report it, and a finding that
// fires on the recommended path is one people learn to ignore.
func TestASlotOnlyChildChangeDoesNotStaleItsParent(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	ctx := context.Background()

	lineage(t, rec, signer, lineageTemplate("tpl_child", "1.0.0", false))
	parentOver(t, rec, signer, "1.0.0", "tpl_child")

	second := lineageTemplate("tpl_child", "2.0.0", false)
	second.Slots[0].Observed = []string{"100", "250", "400"}
	sig, err := registry.SignTemplate(second, signer)
	if err != nil {
		t.Fatal(err)
	}
	e, err := rec.RegisterTemplate(ctx, second, sig)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.PendingTriggers) != 0 {
		t.Fatalf("the fixture no longer exercises the no-trigger path: %v", e.PendingTriggers)
	}
	if err := rec.InheritEvaluation(ctx, "tpl_child", "2.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, "tpl_child", "2.0.0"); err != nil {
		t.Fatal(err)
	}

	if got := lineageFindings(lineageAudit(t, dir, signer)); len(got) != 0 {
		t.Fatalf("a child change that fired no shape trigger was reported as staling its "+
			"parent: %+v", got)
	}
}

// A parent re-evaluated after the child moved is no longer named.
//
// The finding is about evidence, not about order of registration, so the way out
// has to be to establish fresh evidence. Without this leg the check above would
// pass for a rule that named a parent forever once its child ever changed.
func TestAParentEvaluatedAfterTheChildMovedIsNotNamed(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	ctx := context.Background()

	lineage(t, rec, signer, lineageTemplate("tpl_child", "1.0.0", false))
	parentOver(t, rec, signer, "1.0.0", "tpl_child")
	lineage(t, rec, signer, lineageTemplate("tpl_child", "2.0.0", true),
		registry.TriggerShapeChange)

	if got := lineageFindings(lineageAudit(t, dir, signer)); len(got) != 1 {
		t.Fatalf("the fixture did not produce the finding this test clears: %+v", got)
	}

	// A fresh passing evaluation of the *same* parent version. In a real
	// deployment this is the harness re-run, and the harness would refuse it here
	// because the child's shape moved -- that refusal is why the finding says a
	// new version is needed. Recorded directly, so that what this test asserts
	// is the audit's rule and not the harness's.
	if err := rec.Evaluate(ctx, "tpl_parent", "1.0.0", &janusv1.EvaluationReport{
		Passed: true, HarnessVersion: template.HarnessVersion,
		Sandbox: "re-matched its source runs",
	}); err != nil {
		t.Fatal(err)
	}
	if got := lineageFindings(lineageAudit(t, dir, signer)); len(got) != 0 {
		t.Fatalf("a parent whose evidence was re-established after the child moved is still "+
			"named: %+v", got)
	}
}

// A failing re-run does not refresh the parent's evidence.
//
// Otherwise the way out of the finding would be to fail a check, which is the
// worst possible incentive to put in an audit.
func TestAFailingReEvaluationDoesNotClearTheFinding(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	ctx := context.Background()

	lineage(t, rec, signer, lineageTemplate("tpl_child", "1.0.0", false))
	parentOver(t, rec, signer, "1.0.0", "tpl_child")
	lineage(t, rec, signer, lineageTemplate("tpl_child", "2.0.0", true),
		registry.TriggerShapeChange)

	if err := rec.Evaluate(ctx, "tpl_parent", "1.0.0", &janusv1.EvaluationReport{
		Passed: false, HarnessVersion: template.HarnessVersion,
		Sandbox: "re-matched its source runs",
	}); err != nil {
		t.Fatal(err)
	}
	if got := lineageFindings(lineageAudit(t, dir, signer)); len(got) != 1 {
		t.Fatalf("a failing re-run changed the finding: %+v", got)
	}
}

// A parent version that inherits carries the evidence it inherited, seq and all.
//
// A provenance-only bump of the parent fires no trigger and may inherit. If that
// reset the parent's place in the log, an operator could clear this finding by
// registering a version that changed nothing and inheriting the very evidence
// the finding is about.
func TestAParentThatInheritsDoesNotInheritFreshness(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	ctx := context.Background()

	lineage(t, rec, signer, lineageTemplate("tpl_child", "1.0.0", false))
	parentOver(t, rec, signer, "1.0.0", "tpl_child")
	lineage(t, rec, signer, lineageTemplate("tpl_child", "2.0.0", true),
		registry.TriggerShapeChange)

	// A parent v2 that changes nothing but its provenance.
	second := lineageTemplate("tpl_parent", "2.0.0", false)
	second.Steps[0].ChildTemplate = "tpl_child"
	second.Provenance.Runs = 4
	second.Provenance.SagaIDs = append(second.Provenance.SagaIDs, "sg4")
	second.Provenance.EvidenceRoots = append(second.Provenance.EvidenceRoots, "dd")
	sig, err := registry.SignTemplate(second, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RegisterTemplate(ctx, second, sig); err != nil {
		t.Fatal(err)
	}
	if err := rec.InheritEvaluation(ctx, "tpl_parent", "2.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, "tpl_parent", "2.0.0"); err != nil {
		t.Fatal(err)
	}

	got := lineageFindings(lineageAudit(t, dir, signer))
	if len(got) != 1 {
		t.Fatalf("inheriting the stale evidence cleared the finding it is about: %+v", got)
	}
	if got[0].Version != "2.0.0" {
		t.Fatalf("the finding names version %s; the active parent is 2.0.0 and it is the one "+
			"admitting sagas", got[0].Version)
	}
}
