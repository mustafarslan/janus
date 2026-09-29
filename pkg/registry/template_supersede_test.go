package registry_test

import (
	"context"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// TestActivatingATemplateSupersedesTheOneItReplaces is the rule the fold's own
// comment states — "activating a successor is the decision to stop using the
// predecessor" — applied to the documents it was not applied to.
//
// A template and a participant live in different maps. `applyActivated` looked
// the predecessor up with `Active`, which reads only the participant map, so a
// template successor superseded nobody: **both versions stayed ACTIVE**. That is
// not a cosmetic state error. Admission requires the pinned version to be ACTIVE
// (admit.go), so activating a corrected template did not stop the shape it
// corrected from confining new sagas — an operator who had done everything right
// had changed nothing. And `ActiveTemplate` returns the first ACTIVE version in
// registration order, which is the *old* one.
func TestActivatingATemplateSupersedesTheOneItReplaces(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	ctx := context.Background()

	put := func(version string) {
		tpl := testTemplate()
		tpl.Version = version
		sig, err := registry.SignTemplate(tpl, signer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rec.RegisterTemplate(ctx, tpl, sig); err != nil {
			t.Fatalf("registering %s: %v", version, err)
		}
		if err := rec.Evaluate(ctx, "tpl_wire", version, &janusv1.EvaluationReport{
			Passed: true, HarnessVersion: "test", Sandbox: "re-matched its own source runs",
		}); err != nil {
			t.Fatalf("evaluating %s: %v", version, err)
		}
		if err := rec.Activate(ctx, "tpl_wire", version); err != nil {
			t.Fatalf("activating %s: %v", version, err)
		}
	}
	put("1.0.0")
	put("2.0.0")

	// Re-derived from the log rather than read out of the recorder's memory:
	// the fold is what an auditor runs, and it is the thing under test.
	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}

	states := map[string]registry.State{}
	active := 0
	for _, e := range reg.TemplateVersions("tpl_wire") {
		states[e.Version] = e.State
		if e.State == registry.StateActive {
			active++
		}
	}
	if active != 1 {
		t.Fatalf("%d template versions are ACTIVE at once (%v); activating a successor is the "+
			"decision to stop using the predecessor", active, states)
	}
	if states["2.0.0"] != registry.StateActive {
		t.Fatalf("2.0.0 is %s, want ACTIVE", states["2.0.0"])
	}
	if states["1.0.0"] != registry.StateSuperseded {
		t.Fatalf("1.0.0 is %s, want SUPERSEDED", states["1.0.0"])
	}

	// The query an operator asks, and the one that read the old shape back.
	e, ok := reg.ActiveTemplate("tpl_wire")
	if !ok {
		t.Fatal("no active template after activating 2.0.0")
	}
	if e.Version != "2.0.0" {
		t.Fatalf("ActiveTemplate returns %s, want 2.0.0 — the version an operator activated",
			e.Version)
	}
}

// And the consequence that made it more than a state error: a saga may no
// longer pin the superseded shape.
//
// Admission refuses a pin to anything but ACTIVE. Before the fix 1.0.0 stayed
// ACTIVE after 2.0.0 was activated, so both were admissible and activating the
// correction withdrew nothing.
func TestASupersededTemplateNoLongerAdmitsASaga(t *testing.T) {
	rec, signer, dir := newRecorder(t)
	ctx := context.Background()

	// The participant the template's one step pins, so that admission gets past
	// the manifest check and reaches the template check this test is about.
	register(t, rec, signer, wireManifest())
	evaluate(t, rec, wireManifest())
	if err := rec.Activate(ctx, "tool_payments", wireManifest().Version); err != nil {
		t.Fatal(err)
	}

	for _, version := range []string{"1.0.0", "2.0.0"} {
		tpl := testTemplate()
		tpl.Version = version
		sig, err := registry.SignTemplate(tpl, signer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rec.RegisterTemplate(ctx, tpl, sig); err != nil {
			t.Fatal(err)
		}
		if err := rec.Evaluate(ctx, "tpl_wire", version, &janusv1.EvaluationReport{
			Passed: true, HarnessVersion: "test", Sandbox: "ok",
		}); err != nil {
			t.Fatal(err)
		}
		if err := rec.Activate(ctx, "tpl_wire", version); err != nil {
			t.Fatal(err)
		}
	}

	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}

	begin := crystallizedBegin()
	begin.TemplatePin = &janusv1.TemplatePin{TemplateId: "tpl_wire", Version: "1.0.0"}
	err = registry.AdmitFor(reg, begin, tenancy.Tenant{})
	if err == nil {
		t.Fatal("a saga was admitted against the template version that was replaced; " +
			"activating the successor withdrew nothing")
	}
	// Refused *for the right reason*: a change that broke template admission
	// outright would keep an err != nil assertion green while removing the
	// thing this test exists to protect.
	if !strings.Contains(err.Error(), string(registry.StateSuperseded)) {
		t.Fatalf("the refusal does not say the pinned version was superseded: %v", err)
	}

	// And the successor still admits, so the fix withdrew the old shape rather
	// than breaking crystallized admission.
	begin.TemplatePin = &janusv1.TemplatePin{TemplateId: "tpl_wire", Version: "2.0.0"}
	if err := registry.AdmitFor(reg, begin, tenancy.Tenant{}); err != nil {
		t.Fatalf("the active template no longer admits a saga pinned to it: %v", err)
	}
}
