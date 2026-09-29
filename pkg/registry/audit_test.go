package registry_test

import (
	"context"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/registry"
	"google.golang.org/protobuf/proto"
)

// The audit tests all work the same way: write a log that a dishonest — or
// merely buggy — registry service would write, by appending the event directly
// rather than going through the recorder, and require the audit to find it.
//
// Appending directly is the point. The recorder refuses every one of these, and
// a check that only ever sees events the recorder produced is a check of the
// recorder. The threat model is a registry service that has been changed, and
// from the log a changed service and a lying one look identical.

// rawAppend writes a registry event with no lifecycle check in front of it.
func rawAppend(t *testing.T, app *evidence.Appender, ev *janusv1.RegistryEvent) {
	t.Helper()
	payload, err := proto.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Append(context.Background(), evidence.Request{
		Kind:        evidence.KindRegistry,
		Participant: operator,
		Payload:     payload,
	}); err != nil {
		t.Fatal(err)
	}
}

// honestLog registers, evaluates and activates one manifest through the
// recorder, and returns everything a test needs to add to that log afterwards.
func honestLog(t *testing.T) (*evidence.Appender, string, *keys.Signer, registry.TrustStore) {
	t.Helper()
	app, dir := newLog(t)
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())

	r := registry.NewRecorder(app, operator, registry.New(), trust)
	activated(t, r, signer, wireManifest())
	return app, dir, signer, trust
}

func auditOf(t *testing.T, dir string, trust registry.TrustStore) registry.Report {
	t.Helper()
	rep, err := registry.Audit(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func requireFinding(t *testing.T, rep registry.Report, kind registry.FindingKind) registry.Finding {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Kind == kind {
			return f
		}
	}
	t.Fatalf("the audit found no %s:\n%s", kind, rep)
	return registry.Finding{}
}

func TestAnHonestRegistryAudits(t *testing.T) {
	_, dir, _, trust := honestLog(t)
	rep := auditOf(t, dir, trust)
	if !rep.OK() {
		t.Fatalf("an honest registry produced findings:\n%s", rep)
	}
	if rep.Events == 0 || rep.Versions != 1 {
		t.Fatalf("the audit re-derived %d events and %d versions", rep.Events, rep.Versions)
	}
	if rep.Unchecked != 0 {
		t.Fatalf("%d signature(s) went unchecked despite a trust store", rep.Unchecked)
	}
}

// TestAuditCatchesAnActivationNothingEvaluated. The lifecycle refuses this at
// the recorder; the audit is what catches a service that no longer does.
func TestAuditCatchesAnActivationNothingEvaluated(t *testing.T) {
	app, dir, signer, trust := honestLog(t)

	v2 := wireManifest()
	v2.Version = "2.0.0"
	v2.Runtime.ModelID = "gpt-next"
	canonical, err := v2.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := registry.Sign(v2, signer)
	if err != nil {
		t.Fatal(err)
	}
	rawAppend(t, app, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_REGISTERED,
		ParticipantId:  v2.Identity.ParticipantID,
		Version:        v2.Version,
		ContentAddress: registry.ContentAddressOf(canonical),
		Manifest:       canonical,
		Signature:      sig,
		Change: &janusv1.ChangeRecord{
			FromVersion:   "1.0.0",
			Changed:       []string{"runtime.model_id"},
			TriggersFired: []string{registry.TriggerModelChange},
		},
	})
	rawAppend(t, app, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_ACTIVATED,
		ParticipantId:  v2.Identity.ParticipantID,
		Version:        v2.Version,
		ContentAddress: registry.ContentAddressOf(canonical),
	})

	f := requireFinding(t, auditOf(t, dir, trust), registry.FindingActivatedWithoutEvaluation)
	if f.Version != "2.0.0" {
		t.Fatalf("the finding names version %q", f.Version)
	}
}

// TestAuditCatchesAChangeRecordThatUnderstatesTheChange. The change record
// decides whether a revalidation was owed, so a service that writes its own is
// a service that can excuse itself. The audit recomputes the diff from the two
// manifests it has.
func TestAuditCatchesAChangeRecordThatUnderstatesTheChange(t *testing.T) {
	app, dir, signer, trust := honestLog(t)

	v2 := wireManifest()
	v2.Version = "2.0.0"
	v2.Runtime.ModelID = "gpt-next" // fires model_change, which v1 declares
	canonical, err := v2.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := registry.Sign(v2, signer)
	if err != nil {
		t.Fatal(err)
	}
	rawAppend(t, app, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_REGISTERED,
		ParticipantId:  v2.Identity.ParticipantID,
		Version:        v2.Version,
		ContentAddress: registry.ContentAddressOf(canonical),
		Manifest:       canonical,
		Signature:      sig,
		// "Nothing that matters changed."
		Change: &janusv1.ChangeRecord{FromVersion: "1.0.0"},
	})

	f := requireFinding(t, auditOf(t, dir, trust), registry.FindingChangeUnderstated)
	if !strings.Contains(f.Detail, "model_change") {
		t.Fatalf("the finding does not name the trigger that was dodged: %s", f.Detail)
	}
}

// TestAuditCatchesAVersionRegisteredTwiceWithDifferentContent. This is the
// failure that makes pinning decorative: every saga that pinned the string now
// resolves to two different declarations.
func TestAuditCatchesAVersionRegisteredTwiceWithDifferentContent(t *testing.T) {
	app, dir, signer, trust := honestLog(t)

	edited := wireManifest()
	edited.Actions[0].Limits.MaxAmount = 1000000
	canonical, err := edited.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := registry.Sign(edited, signer)
	if err != nil {
		t.Fatal(err)
	}
	rawAppend(t, app, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_REGISTERED,
		ParticipantId:  edited.Identity.ParticipantID,
		Version:        "1.0.0",
		ContentAddress: registry.ContentAddressOf(canonical),
		Manifest:       canonical,
		Signature:      sig,
	})

	requireFinding(t, auditOf(t, dir, trust), registry.FindingVersionReused)
}

// TestAuditCatchesAManifestNobodyTrustedSigned.
func TestAuditCatchesAManifestNobodyTrustedSigned(t *testing.T) {
	app, dir, _, trust := honestLog(t)

	impostor, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	v2 := wireManifest()
	v2.Version = "1.0.1"
	v2.Runtime.SBOMRef = "sbom:2"
	canonical, err := v2.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := registry.Sign(v2, impostor)
	if err != nil {
		t.Fatal(err)
	}
	rawAppend(t, app, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_REGISTERED,
		ParticipantId:  v2.Identity.ParticipantID,
		Version:        v2.Version,
		ContentAddress: registry.ContentAddressOf(canonical),
		Manifest:       canonical,
		Signature:      sig,
		Change:         &janusv1.ChangeRecord{FromVersion: "1.0.0", Changed: []string{"runtime.sbom_ref"}},
	})

	requireFinding(t, auditOf(t, dir, trust), registry.FindingSignatureUnverified)
}

// TestAuditCountsUncheckedSignaturesRatherThanFloodingFindings. With no trust
// store every manifest is unverifiable, and a page of identical findings would
// bury the real ones.
func TestAuditCountsUncheckedSignaturesRatherThanFloodingFindings(t *testing.T) {
	_, dir, _, _ := honestLog(t)

	rep := auditOf(t, dir, nil)
	if rep.Unchecked != 1 {
		t.Fatalf("audit with no trust store reports %d unchecked signatures", rep.Unchecked)
	}
	if !rep.OK() {
		t.Fatalf("auditing without a trust store produced findings:\n%s", rep)
	}
	if !strings.Contains(rep.String(), "not checked") {
		t.Fatalf("the report does not say the signatures went unchecked:\n%s", rep)
	}
}

// TestAuditCatchesAContentAddressThatDoesNotMatchItsBytes.
func TestAuditCatchesAContentAddressThatDoesNotMatchItsBytes(t *testing.T) {
	app, dir, signer, trust := honestLog(t)

	v2 := wireManifest()
	v2.Version = "1.0.1"
	v2.Runtime.SBOMRef = "sbom:2"
	canonical, err := v2.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := registry.Sign(v2, signer)
	if err != nil {
		t.Fatal(err)
	}
	rawAppend(t, app, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_REGISTERED,
		ParticipantId:  v2.Identity.ParticipantID,
		Version:        v2.Version,
		ContentAddress: "blake3:" + strings.Repeat("00", 32),
		Manifest:       canonical,
		Signature:      sig,
		Change:         &janusv1.ChangeRecord{FromVersion: "1.0.0", Changed: []string{"runtime.sbom_ref"}},
	})

	requireFinding(t, auditOf(t, dir, trust), registry.FindingContentMismatch)
}

// ---------------------------------------------------------------------------
// crossing the saga log against the registry
// ---------------------------------------------------------------------------

// beginSaga writes a SAGA_BEGIN directly, so a test can record a plan that
// admission would have refused.
func beginSaga(t *testing.T, app *evidence.Appender, begin *janusv1.SagaBegin) {
	t.Helper()
	payload, err := proto.Marshal(begin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Append(context.Background(), evidence.Request{
		Kind:        evidence.KindSagaBegin,
		SagaID:      begin.GetSagaId(),
		Participant: operator,
		Payload:     payload,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAuditPassesOnASagaPinnedToAnActiveManifest(t *testing.T) {
	app, dir, _, trust := honestLog(t)
	beginSaga(t, app, wirePlan())

	rep := auditOf(t, dir, trust)
	if !rep.OK() {
		t.Fatalf("an honest saga produced findings:\n%s", rep)
	}
	if rep.Pins != 2 {
		t.Fatalf("the audit resolved %d pins, want 2", rep.Pins)
	}
}

// TestAuditCatchesAStepRunningUnderAnUnderdeclaredClass. Admission refuses this
// plan; the audit is what catches a coordinator that skipped admission.
func TestAuditCatchesAStepRunningUnderAnUnderdeclaredClass(t *testing.T) {
	app, dir, _, trust := honestLog(t)
	plan := wirePlan()
	plan.Plan[1].EffectClass = janusv1.EffectClass_EFFECT_CLASS_PURE
	beginSaga(t, app, plan)

	f := requireFinding(t, auditOf(t, dir, trust), registry.FindingEffectClassMismatch)
	if !strings.Contains(f.Detail, "IRREVERSIBLE_GATED") {
		t.Fatalf("the finding does not say what the manifest registers: %s", f.Detail)
	}
}

// TestAuditCatchesAPinToAVersionThatWasNotActiveThen — invariant I8 as a claim
// about a moment.
func TestAuditCatchesAPinToAVersionThatWasNotActiveThen(t *testing.T) {
	app, dir, signer, trust := honestLog(t)

	// A second version is registered but never activated, and a saga pins it.
	v2 := wireManifest()
	v2.Version = "1.0.1"
	v2.Runtime.SBOMRef = "sbom:2"
	canonical, err := v2.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := registry.Sign(v2, signer)
	if err != nil {
		t.Fatal(err)
	}
	rawAppend(t, app, &janusv1.RegistryEvent{
		Kind:           janusv1.RegistryEvent_KIND_REGISTERED,
		ParticipantId:  v2.Identity.ParticipantID,
		Version:        v2.Version,
		ContentAddress: registry.ContentAddressOf(canonical),
		Manifest:       canonical,
		Signature:      sig,
		Change:         &janusv1.ChangeRecord{FromVersion: "1.0.0", Changed: []string{"runtime.sbom_ref"}},
	})

	plan := wirePlan()
	plan.ManifestPins["tool_payments"] = "1.0.1"
	beginSaga(t, app, plan)

	f := requireFinding(t, auditOf(t, dir, trust), registry.FindingPinUnresolvable)
	if !strings.Contains(f.Detail, "DRAFT") {
		t.Fatalf("the finding does not say what state the pinned version was in: %s", f.Detail)
	}
}

// TestAuditOfALogWithNoRegistrySaysSo rather than reporting every saga in a
// Phase 2 log as a finding.
func TestAuditOfALogWithNoRegistrySaysSo(t *testing.T) {
	app, dir := newLog(t)
	beginSaga(t, app, wirePlan())

	rep := auditOf(t, dir, nil)
	if !rep.OK() {
		t.Fatalf("a log with no registry produced findings:\n%s", rep)
	}
	if !strings.Contains(rep.String(), "no registry events") {
		t.Fatalf("the report does not say the log pins nothing to a declaration:\n%s", rep)
	}
}
