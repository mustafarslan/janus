package conformance_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/conformance"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/registry"
)

const (
	principal = "pr_bank"
	sagaID    = "sg_conformance"
)

// TestAConformantIntegrationPasses runs the suite over evidence a real
// integration produced — a saga begun, prepared, reported and committed through
// janus-orchd — rather than over a log this test wrote by hand. A suite checked
// only against evidence built to satisfy it is a suite that agrees with itself.
func TestAConformantIntegrationPasses(t *testing.T) {
	dir, set := runIntegration(t)

	report, err := conformance.Run(dir, expected(), options(set))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("a conformant integration failed:\n%s", report)
	}
	// Every check has to have actually run. A report of one passing check would
	// pass the assertion above and mean nothing.
	if len(report.Checks) < 7 {
		t.Fatalf("the suite ran %d checks; the invariants it claims to cover are more "+
			"than that:\n%s", len(report.Checks), report)
	}
	for _, c := range report.Checks {
		if c.Detail == "" {
			t.Fatalf("check %q passed and said nothing about what it looked at; a check "+
				"that reports no substance cannot be distinguished from one that did "+
				"not run", c.Name)
		}
	}
}

// TestAnEmptyExpectationIsRefused is the check the others rest on.
//
// Every invariant check here passes on a log with nothing in it. A suite that
// could be satisfied by an integration doing nothing measures nothing, so it
// refuses to run rather than reporting a pass.
func TestAnEmptyExpectationIsRefused(t *testing.T) {
	dir, set := runIntegration(t)

	_, err := conformance.Run(dir, conformance.Expectation{Integration: "nothing"}, options(set))
	if !errors.Is(err, conformance.ErrNothingExpected) {
		t.Fatalf("a run with nothing expected returned %v; it has to refuse, because "+
			"every check below it would pass", err)
	}
}

// TestAnIntegrationThatDidNotRunFails. The guarantees are only interesting
// about work that happened.
func TestAnIntegrationThatDidNotRunFails(t *testing.T) {
	dir, set := runIntegration(t)

	want := expected()
	want.Sagas[0].SagaID = "sg_never_happened"
	report, err := conformance.Run(dir, want, options(set))
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("the suite passed for a saga that is not in the log")
	}
	if !mentions(report, "is not in the log at all") {
		t.Fatalf("the failure does not say the saga is missing:\n%s", report)
	}
}

// TestAStepThatReachedTheLogAsADifferentEffectClassFails is the mismatch an
// adapter is most likely to make and least likely to notice.
//
// Every gate matches on the effect class. A step the integration meant to be
// COMPENSABLE that reaches the log as PURE is a step no rule applied to, and
// nothing else in this suite would notice: the chain verifies, the saga
// replays, no gate was violated because no gate was attached.
func TestAStepThatReachedTheLogAsADifferentEffectClassFails(t *testing.T) {
	dir, set := runIntegration(t)

	want := expected()
	want.Sagas[0].Steps[0].EffectClass = "IRREVERSIBLE_GATED"
	report, err := conformance.Run(dir, want, options(set))
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("the suite passed for a step whose effect class is not what the " +
			"integration declared")
	}
	if !mentions(report, "effect class") {
		t.Fatalf("the failure does not name the effect class:\n%s", report)
	}
}

// TestWithoutWriterKeysTheSignatureCheckIsReportedAsNotDone.
//
// A chain that verifies under no key is a chain anybody could have written, so
// the absence has to read as a failure rather than as a pass with a footnote.
func TestWithoutWriterKeysTheSignatureCheckIsReportedAsNotDone(t *testing.T) {
	dir, _ := runIntegration(t)

	report, err := conformance.Run(dir, expected(), conformance.Options{AllowUnsealedTail: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("the suite passed without checking a single signature")
	}
	if !mentions(report, "no writer keys were supplied") {
		t.Fatalf("the report does not say why the chain check did not run:\n%s", report)
	}
}

// ---- the integration under test --------------------------------------------

func expected() conformance.Expectation {
	return conformance.Expectation{
		Integration: "conformance self-test",
		Sagas: []conformance.SagaExpectation{{
			SagaID: sagaID,
			Status: "COMMITTED",
			Steps: []conformance.StepExpectation{{
				StepID: "st_quote", Participant: "tool_payments", Action: "payments.quote",
				EffectClass: "PURE", Status: "COMMITTED",
			}},
		}},
	}
}

func options(set keys.PublicKeySet) conformance.Options {
	return conformance.Options{Keys: set, AllowUnsealedTail: true}
}

// runIntegration drives one saga to commit through janus-orchd and returns the
// evidence directory it produced.
func runIntegration(t *testing.T) (string, keys.PublicKeySet) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)

	policy, err := gate.LoadPolicyFile("../../docs/policy/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	server, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: policy,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: principal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	begin := &janusv1.SagaBegin{
		SagaId: sagaID, Mode: "supervised",
		Intent: &janusv1.Intent{
			IntentId: "in_conformance", Principal: principal,
			Originator: "test", MandateRef: "mandate:payments", Scope: "quote one payment",
		},
		Plan: []*janusv1.PlannedStep{{
			StepId: "st_quote", Participant: "tool_payments", Action: "payments.quote",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
		}},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
	}
	if _, err := server.BeginSaga(ctx, &janusv1.BeginSagaRequest{Begin: begin}); err != nil {
		t.Fatal(err)
	}
	prepared, err := server.PrepareStep(ctx, &janusv1.PrepareStepRequest{
		SagaId: sagaID, StepId: "st_quote",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: sagaID, StepId: "st_quote", Attempt: prepared.GetAttempt(),
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		},
	}); err != nil {
		t.Fatal(err)
	}
	// Closed rather than left running: the suite reads the log, and a reader is
	// entitled to a log whose writer has finished with it.
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, keys.PublicKeySet{keys.KeyIDFor(signer.Public()): signer.Public()}
}

func registerManifest(t *testing.T, dir string, signer *keys.Signer) {
	t.Helper()
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	trust := registry.TrustStore{}
	trust.Trust(principal, signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_registry", Principal: principal, Kind: "SYSTEM",
	}, registry.New(), trust)

	m := &registry.Manifest{
		Version:  "1.0.0",
		Identity: registry.Identity{ParticipantID: "tool_payments", Kind: "TOOL", Principal: principal},
		Runtime:  registry.Runtime{ModelID: "none", PromptBundleHash: "blake3:conformance"},
		Actions:  []registry.Action{{Name: "payments.quote", EffectClass: "PURE"}},
		Risk: registry.Risk{
			Tier:                 1,
			RevalidationTriggers: []string{registry.TriggerModelChange, registry.TriggerActionChange},
		},
		Jurisdiction: registry.Jurisdiction{DeployableIn: []string{"EU"}, DataResidency: "EU"},
	}
	sig, err := registry.Sign(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := rec.Register(ctx, m, sig); err != nil {
		t.Fatal(err)
	}
	report, err := registry.Evaluate(ctx, m,
		registry.NewDoubles("conformance-sandbox").With("payments.quote", registry.Double{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Evaluate(ctx, "tool_payments", "1.0.0", report); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, "tool_payments", "1.0.0"); err != nil {
		t.Fatal(err)
	}
}

func mentions(r *conformance.Report, text string) bool {
	return strings.Contains(r.String(), text)
}
