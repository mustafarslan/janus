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

// The audit is what the adversarial suite points at, and it skipped every template
// registration in silence.
//
// `auditRegistration` began with `DecodeManifest(ev.GetManifest())`, which fails
// on a template event because that field is empty, and returned — under a
// comment reading "the fold reports this too; returning here avoids saying it
// twice." That is true of a malformed manifest. It is false of a well-formed
// template: the fold takes the template path and succeeds, so nothing reported
// anything. Three checks were skipped that way, and the report's own totals said
// the log held no template versions.
func TestTheAuditSeesTemplates(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	ctx := context.Background()
	register(t, rec, signer, wireManifest())
	evaluate(t, rec, wireManifest())
	if err := rec.Activate(ctx, "tool_payments", wireManifest().Version); err != nil {
		t.Fatal(err)
	}
	registerTemplate(t, rec, signer, true)

	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	rep, err := registry.Audit(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("a well-formed log did not audit clean:\n%s", rep)
	}

	// The totals are how a reader judges what the audit looked at, and they
	// reported a log holding one template as holding none.
	if rep.Templates != 1 {
		t.Fatalf("the audit counted %d template version(s), want 1", rep.Templates)
	}
	if !strings.Contains(rep.String(), "1 template version(s)") {
		t.Fatalf("the report does not say it saw a template:\n%s", rep)
	}
	// And it checked the signature rather than passing over it.
	if rep.Unchecked != 0 {
		t.Fatalf("%d signature(s) went unchecked with a trust store that knows the "+
			"principal:\n%s", rep.Unchecked, rep)
	}
}

// A template signed by a key nobody trusts is a finding, the same as a manifest
// signed by one. Before this it was nothing at all.
func TestTheAuditChecksATemplateSignature(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	ctx := context.Background()
	register(t, rec, signer, wireManifest())
	evaluate(t, rec, wireManifest())
	if err := rec.Activate(ctx, "tool_payments", wireManifest().Version); err != nil {
		t.Fatal(err)
	}
	registerTemplate(t, rec, signer, true)

	// A trust store that knows the principal and a different key for it: the
	// signature is checkable and does not check out, which is the case that has
	// to be a finding rather than an Unchecked.
	stranger, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust("pr_bank", stranger.Public())
	rep, aerr := registry.Audit(dir, trust)
	if aerr != nil {
		t.Fatal(aerr)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Kind == registry.FindingSignatureUnverified && f.ParticipantID == "tpl_wire" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a template signed by an untrusted key produced no finding:\n%s", rep)
	}
}

// And a template activated without evaluation is named, which it was not:
// the check resolved the version in the participant map only, so it never ran.
//
// The fold refuses the transition, so this is the audit saying *why* a log is
// broken rather than the only thing standing between a template and activation.
func TestTheAuditNamesATemplateActivatedWithoutEvaluation(t *testing.T) {
	app, dir := newLog(t)
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	rec := registry.NewRecorder(app, operator, registry.New(), trust)

	ctx := context.Background()
	register(t, rec, signer, wireManifest())
	evaluate(t, rec, wireManifest())
	if err := rec.Activate(ctx, "tool_payments", wireManifest().Version); err != nil {
		t.Fatal(err)
	}
	registerTemplate(t, rec, signer, false) // DRAFT: never evaluated

	// Appended directly, because the recorder refuses to write it — which is
	// the point: an audit exists for a log somebody else produced, not for the
	// events this process would have emitted.
	rawAppend(t, app, &janusv1.RegistryEvent{
		Kind: janusv1.RegistryEvent_KIND_ACTIVATED, ParticipantId: "tpl_wire", Version: "1.0.0",
	})

	rep, err := registry.Audit(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Kind == registry.FindingActivatedWithoutEvaluation && f.ParticipantID == "tpl_wire" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a template activated straight out of DRAFT produced no such finding:\n%s", rep)
	}
}

// The audit recomputes a template's change record from the two templates, the
// way it recomputes a manifest's from the two manifests.
//
// This is the check that makes the diff worth having. A registrant that could
// describe its own change could call a step swapped for a different participant
// a rename, fire no trigger, and inherit an evaluation that never saw the new
// shape. The recorder computes the record, so the only way to write a dishonest
// one is to append the event directly — which is exactly what an adversary with
// write access to the log has, and what the adversarial suite points the audit at.
func TestTheAuditRecomputesATemplateChangeRecord(t *testing.T) {
	app, dir, signer, trust := honestLog(t)
	rec := registry.NewRecorder(app, operator, registry.New(), trust)
	ctx := context.Background()

	v1 := testTemplate()
	sig1, err := registry.SignTemplate(v1, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RegisterTemplate(ctx, v1, sig1); err != nil {
		t.Fatal(err)
	}

	// A second version that moves the step to a different participant, carrying
	// a change record that says a slot's observed values grew.
	v2 := testTemplate()
	v2.Version = "2.0.0"
	v2.Steps[0].Participant = "tool_other"
	canonical, err := template.Encode(v2)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := registry.SignTemplate(v2, signer)
	if err != nil {
		t.Fatal(err)
	}
	rawAppend(t, app, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_REGISTERED,
		ParticipantId:  v2.TemplateID,
		Version:        v2.Version,
		ContentAddress: registry.ContentAddressOf(canonical),
		Template:       canonical,
		Signature:      sig2,
		Change: &janusv1.ChangeRecord{
			FromVersion: "1.0.0",
			Changed:     []string{"slots.st_wire.amount.observed"},
		},
	})

	rep, err := registry.Audit(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range rep.Findings {
		if f.Kind == registry.FindingChangeUnderstated && f.ParticipantID == "tpl_wire" &&
			strings.Contains(f.Detail, "steps.st_wire.participant") &&
			strings.Contains(f.Detail, registry.TriggerShapeChange) {
			found = true
		}
	}
	if !found {
		t.Fatalf("a template change record that hid a step moving to another "+
			"participant produced no finding naming what really changed:\n%s", rep)
	}
}

// A log written before template change records has template versions and no change records at
// all, and the audit says so rather than passing over them.
//
// This is the migration, and it is a cost: a deployment that upgrades sees
// findings today that it did not see yesterday, on a log nobody touched. That
// is the right answer — the record is genuinely missing, and the successor was
// activated without the revalidation its shape change should have required —
// but it is a surprise, so it is asserted here rather than met in a terminal.
//
// The fold is deliberately not part of this. Replaying an old log still produces
// ACTIVE, because `PendingTriggers` comes from the recorded record and there is
// none; an upgrade does not retroactively withdraw a running deployment's
// template. The audit names it, the fold leaves it alone.
func TestALogWrittenBeforeTheTemplateDiffAuditsAsUnderstated(t *testing.T) {
	app, dir, signer, trust := honestLog(t)
	for _, mutate := range []func(*template.Template){
		func(*template.Template) {},
		func(tpl *template.Template) {
			tpl.Version = "2.0.0"
			tpl.Steps = append(tpl.Steps, template.Step{
				StepID: "st_notify", Participant: "tool_email", Action: "email.send",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED.String(),
				DependsOn:   []string{"st_wire"},
			})
		},
	} {
		tpl := testTemplate()
		mutate(tpl)
		canonical, err := template.Encode(tpl)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := registry.SignTemplate(tpl, signer)
		if err != nil {
			t.Fatal(err)
		}
		// No Change field: this is what RegisterTemplate wrote before change records.
		rawAppend(t, app, &janusv1.RegistryEvent{
			Kind:           janusv1.RegistryEvent_KIND_REGISTERED,
			ParticipantId:  tpl.TemplateID,
			Version:        tpl.Version,
			ContentAddress: registry.ContentAddressOf(canonical),
			Template:       canonical,
			Signature:      sig,
		})
	}

	rep, err := registry.Audit(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range rep.Findings {
		if f.Kind == registry.FindingChangeUnderstated && f.Version == "2.0.0" &&
			strings.Contains(f.Detail, "records no change record") &&
			strings.Contains(f.Detail, registry.TriggerShapeChange) {
			found = true
		}
	}
	if !found {
		t.Fatalf("a template log from before change records with a changed shape and no change record "+
			"audits clean:\n%s", rep)
	}

	// And the fold is untouched. The same log, evaluated and activated the way
	// it was before change records -- a report covering no trigger -- still replays to
	// ACTIVE, because PendingTriggers comes from the recorded record and there
	// is none. The audit names the gap; an upgrade does not reach back and
	// withdraw a template somebody is running.
	for _, kind := range []janusv1.RegistryEvent_Kind{
		janusv1.RegistryEvent_KIND_EVALUATED, janusv1.RegistryEvent_KIND_ACTIVATED,
	} {
		ev := &janusv1.RegistryEvent{
			Kind: kind, ParticipantId: "tpl_wire", Version: "2.0.0",
		}
		if kind == janusv1.RegistryEvent_KIND_EVALUATED {
			ev.Evaluation = &janusv1.EvaluationReport{
				Passed: true, HarnessVersion: "test", Sandbox: "ok",
			}
		}
		rawAppend(t, app, ev)
	}
	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := reg.ResolveTemplate("tpl_wire", "2.0.0")
	if !ok || e.State != registry.StateActive {
		t.Fatalf("replaying a log from before change records withdrew a template that was active in it "+
			"(resolved %t, state %q)", ok, e.State)
	}
}

// And the same log, with the shape unchanged between the two versions, does not.
//
// A version bump that changes nothing owes no record, so a log from before
// change records must not light up merely for holding two versions. Without this the
// migration finding above would be "two template versions exist", which is not
// a defect and would teach a reader to ignore the whole class.
func TestAnUnchangedShapeWithNoRecordIsNotAFinding(t *testing.T) {
	app, dir, signer, trust := honestLog(t)

	for _, version := range []string{"1.0.0", "2.0.0"} {
		tpl := testTemplate()
		tpl.Version = version
		canonical, err := template.Encode(tpl)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := registry.SignTemplate(tpl, signer)
		if err != nil {
			t.Fatal(err)
		}
		rawAppend(t, app, &janusv1.RegistryEvent{
			Kind:           janusv1.RegistryEvent_KIND_REGISTERED,
			ParticipantId:  tpl.TemplateID,
			Version:        tpl.Version,
			ContentAddress: registry.ContentAddressOf(canonical),
			Template:       canonical,
			Signature:      sig,
		})
	}

	rep, err := registry.Audit(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f.Kind == registry.FindingChangeUnderstated {
			t.Fatalf("two identical shapes under different version numbers produced a "+
				"change finding:\n%s", rep)
		}
	}
}

// The audit counts template evaluations no harness produced.
//
// Item 55's own "what to do if it goes wrong" named this symptom: a registry
// whose templates all carry identical reports with a typed `HarnessVersion` and
// `TriggersCovered` naming every trigger there is — "not coverage, a constant,
// and registry.Audit cannot tell the difference". It can now, for the half that
// is mechanical.
//
// A count rather than findings, because `Recorder.Evaluate` accepts a
// hand-assembled report for a manifest too and a deployment may hold templates
// evaluated before the harness existed. What must not happen is silence.
func TestTheAuditCountsTemplateEvaluationsNobodyRan(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	ctx := context.Background()
	register(t, rec, signer, wireManifest())
	evaluate(t, rec, wireManifest())
	if err := rec.Activate(ctx, "tool_payments", wireManifest().Version); err != nil {
		t.Fatal(err)
	}
	registerTemplate(t, rec, signer, false)
	if err := rec.Evaluate(ctx, "tpl_wire", "1.0.0", &janusv1.EvaluationReport{
		Passed: true, HarnessVersion: "test", Sandbox: "ok",
	}); err != nil {
		t.Fatal(err)
	}

	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	rep, err := registry.Audit(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TemplateEvaluationsHandAssembled != 1 {
		t.Fatalf("the audit counts %d hand-assembled template evaluation(s), want 1",
			rep.TemplateEvaluationsHandAssembled)
	}
	if !strings.Contains(rep.String(), template.HarnessVersion) {
		t.Fatalf("the report does not name the harness the evaluation lacks:\n%s", rep)
	}
	// The manifest's own evaluation is hand-assembled in this fixture too and
	// is not counted: the counter is about the document the harness exists for.
	if rep.TemplateEvaluationsHandAssembled > 1 {
		t.Fatalf("a manifest evaluation was counted as a template one:\n%s", rep)
	}

	// A report carrying the harness version is not counted. Without this leg
	// the check above passes for a counter that counts every evaluation.
	if err := rec.Evaluate(ctx, "tpl_wire", "1.0.0", &janusv1.EvaluationReport{
		Passed: true, HarnessVersion: template.HarnessVersion,
		Sandbox: "re-matched its source runs", TriggersCovered: []string{"shape_change"},
	}); err != nil {
		t.Fatal(err)
	}
	if rep, err = registry.Audit(dir, trust); err != nil {
		t.Fatal(err)
	}
	if rep.TemplateEvaluationsHandAssembled != 1 {
		t.Fatalf("a report carrying %s was counted as hand-assembled: %d",
			template.HarnessVersion, rep.TemplateEvaluationsHandAssembled)
	}

	// And an *inherited* evaluation, which is the path for a change that
	// fired no trigger, is counted by what it inherited rather than by having
	// run nothing itself. This is the boundary that gives the number meaning: a
	// deployment following the recommended path for a slot-only change must not
	// watch this count climb under a line saying nothing re-read the runs.
	second := testTemplate()
	second.Version = "2.0.0"
	second.Slots[0].Observed = []string{"100", "250"}
	sig, err := registry.SignTemplate(second, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RegisterTemplate(ctx, second, sig); err != nil {
		t.Fatal(err)
	}
	if err := rec.InheritEvaluation(ctx, "tpl_wire", "2.0.0"); err != nil {
		t.Fatal(err)
	}
	if rep, err = registry.Audit(dir, trust); err != nil {
		t.Fatal(err)
	}
	if rep.TemplateEvaluationsHandAssembled != 1 {
		t.Fatalf("inheriting a harness-produced verdict was counted as hand-assembled: %d",
			rep.TemplateEvaluationsHandAssembled)
	}
}
