package registry_test

import (
	"context"
	"path/filepath"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/bundle"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
)

// TestTheRegistryRoundTrip is the registry half of the Phase 3 exit gate:
// "register → evaluate → activate → pin in saga → change
// manifest → revalidation triggered".
//
// It is one test rather than six because the value is in the joins. Each step
// is checked elsewhere; what this asserts is that a manifest registered by one
// component is what a saga pins, what a step runs under, and what an auditor
// re-derives from the log afterwards — with nobody passing anything to anybody
// except through the evidence log.
func TestTheRegistryRoundTrip(t *testing.T) {
	ctx := context.Background()
	app, dir := newLog(t)

	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	rec := registry.NewRecorder(app, operator, registry.New(), trust)

	// ---- 1. register -----------------------------------------------------
	v1 := wireManifest()
	sig, err := registry.Sign(v1, signer)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := rec.Register(ctx, v1, sig)
	if err != nil {
		t.Fatal(err)
	}
	if entry.State != registry.StateDraft {
		t.Fatalf("a fresh registration is %s, want DRAFT", entry.State)
	}

	// ---- 2. evaluate -----------------------------------------------------
	report, err := registry.Evaluate(ctx, v1, honestDoubles())
	if err != nil {
		t.Fatal(err)
	}
	if !report.GetPassed() {
		t.Fatalf("conformance failed:\n%s", registry.ReportText(report))
	}
	if err := rec.Evaluate(ctx, v1.Identity.ParticipantID, v1.Version, report); err != nil {
		t.Fatal(err)
	}

	// ---- 3. activate -----------------------------------------------------
	if err := rec.Activate(ctx, v1.Identity.ParticipantID, v1.Version); err != nil {
		t.Fatal(err)
	}

	// ---- 4. pin in a saga ------------------------------------------------
	begin := &janusv1.SagaBegin{
		SagaId: "sg_roundtrip_0001",
		Mode:   "supervised",
		Intent: &janusv1.Intent{
			IntentId:   "in_roundtrip",
			Principal:  "pr_bank",
			Originator: "human:treasury@bank",
			MandateRef: "policy:P-12",
		},
		Plan: []*janusv1.PlannedStep{{
			StepId:             "st_wire",
			Participant:        "tool_payments",
			Action:             "payments.wire",
			EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: "payments.refund",
		}},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
	}
	if err := registry.Admit(rec.Registry(), begin); err != nil {
		t.Fatalf("the registry refused a plan that matches it: %v", err)
	}

	runner := saga.NewRunner(app, evidence.ParticipantRef{
		ID: "tool_payments", ManifestVersion: "1.0.0", Principal: "pr_bank", Kind: "TOOL",
	})
	if _, err := runner.Begin(ctx, begin); err != nil {
		t.Fatal(err)
	}
	argsHash := evidence.HashPayload([]byte(`{"account":"DE89","amount":100}`))
	if _, err := runner.PrepareStep(ctx, &janusv1.StepPrepare{
		SagaId:      begin.GetSagaId(),
		StepId:      "st_wire",
		Participant: &janusv1.ParticipantRef{Id: "tool_payments", ManifestVersion: "1.0.0", Principal: "pr_bank"},
		Action:      "payments.wire",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
		ArgsHash:    argsHash[:],
		IdemKey:     "DE89/100/in_roundtrip",
	}); err != nil {
		t.Fatal(err)
	}

	// ---- 5. change the manifest -----------------------------------------
	v2 := wireManifest()
	v2.Version = "2.0.0"
	v2.Runtime.ModelID = "gpt-next"
	sig2, err := registry.Sign(v2, signer)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := rec.Register(ctx, v2, sig2)
	if err != nil {
		t.Fatal(err)
	}

	// ---- 6. revalidation triggered --------------------------------------
	if len(changed.PendingTriggers) == 0 {
		t.Fatal("changing the model fired no revalidation trigger, so the evidence that cleared " +
			"the old version would silently carry over to a different model")
	}
	if err := rec.Activate(ctx, v2.Identity.ParticipantID, v2.Version); err == nil {
		t.Fatal("a version owing revalidation was activated")
	}
	report2, err := registry.Evaluate(ctx, v2, honestDoubles())
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Evaluate(ctx, v2.Identity.ParticipantID, v2.Version, report2); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, v2.Identity.ParticipantID, v2.Version); err != nil {
		t.Fatalf("after revalidation the new version could not be activated: %v", err)
	}

	// ---- the joins -------------------------------------------------------
	// The saga that began under 1.0.0 still resolves to 1.0.0, even though the
	// participant has moved on. This is invariant I8 and it is the reason the
	// registry lives in the log.
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	replayed, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	pinned, ok := replayed.Resolve("tool_payments", "1.0.0")
	if !ok {
		t.Fatal("the version the saga pinned no longer resolves")
	}
	if pinned.State != registry.StateSuperseded {
		t.Fatalf("the pinned version is %s after its successor was activated", pinned.State)
	}
	if pinned.ContentAddress != v1.ContentAddress() {
		t.Fatalf("the pinned version resolves to different bytes than were registered")
	}
	active, _ := replayed.Active("tool_payments")
	if active.Version != "2.0.0" {
		t.Fatalf("the active version is %s", active.Version)
	}

	rep, err := registry.Audit(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("the round trip does not survive its own audit:\n%s", rep)
	}
	if rep.Pins == 0 {
		t.Fatal("the audit resolved no saga pins, so the cross-check did not run")
	}
}

// TestTheRegistryTravelsInASagaBundle. An auditor is handed a bundle, not a
// database. If the manifests were not in it, the pins inside would resolve to
// nothing and every claim about what a participant was allowed to do would rest
// on asking the system that made the claim.
func TestTheRegistryTravelsInASagaBundle(t *testing.T) {
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	dir := filepath.Join(work, "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}

	principal, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust("pr_bank", principal.Public())
	rec := registry.NewRecorder(app, operator, registry.New(), trust)

	m := wireManifest()
	activated(t, rec, principal, m)
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	bundleDir := filepath.Join(work, "bundle")
	if _, err := bundle.Export(bundle.ExportOptions{
		SegmentDir: dir,
		Dest:       bundleDir,
		Keys:       keys.PublicKeySet{signer.KeyID(): signer.Public()},
		Producer:   "registry-test",
		SagaID:     "sg_roundtrip_0001",
		Rationale:  "audit request",
	}); err != nil {
		t.Fatal(err)
	}

	fromBundle, err := registry.Replay(filepath.Join(bundleDir, "segments"))
	if err != nil {
		t.Fatalf("the registry could not be rebuilt from the bundle: %v", err)
	}
	e, ok := fromBundle.Active("tool_payments")
	if !ok {
		t.Fatal("the bundle carries no active manifest, so a pin inside it resolves to nothing")
	}
	if e.ContentAddress != m.ContentAddress() {
		t.Fatal("the manifest in the bundle is not the one that was registered")
	}
}
