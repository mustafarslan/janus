package registry_test

import (
	"context"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// wirePlan is a saga that sends a payment and then emails the customer, pinned
// to the manifest that declares both.
func wirePlan() *janusv1.SagaBegin {
	return &janusv1.SagaBegin{
		SagaId: "sg_admit_0001",
		Mode:   "supervised",
		Plan: []*janusv1.PlannedStep{
			{
				StepId:             "st_wire",
				Participant:        "tool_payments",
				Action:             "payments.wire",
				EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
				CompensationAction: "payments.refund",
			},
			{
				StepId:      "st_notify",
				Participant: "tool_payments",
				Action:      "notify.email",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
			},
		},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
	}
}

func activeRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	r, s, _ := newRecorder(t)
	activated(t, r, s, wireManifest())
	return r.Registry()
}

func TestAPlanThatMatchesTheRegistryIsAdmissible(t *testing.T) {
	if err := registry.Admit(activeRegistry(t), wirePlan()); err != nil {
		t.Fatalf("an honest plan was refused: %v", err)
	}
}

// TestAStepCannotUnderdeclareItsEffectClass is the attack this check exists for.
// Janus gates by effect class: IRREVERSIBLE_GATED is held in the outbox until
// the saga commits. A planner following an injected instruction has every
// reason to write PURE next to a wire, and it costs nothing to do — unless the
// registry outranks the plan.
func TestAStepCannotUnderdeclareItsEffectClass(t *testing.T) {
	reg := activeRegistry(t)
	plan := wirePlan()
	plan.Plan[1].EffectClass = janusv1.EffectClass_EFFECT_CLASS_PURE

	err := registry.Admit(reg, plan)
	if err == nil {
		t.Fatal("a step relabelled an irreversible email as PURE and the plan was admitted; " +
			"every gate downstream keys off that class")
	}
	if !strings.Contains(err.Error(), "IRREVERSIBLE_GATED") {
		t.Fatalf("the refusal does not name what the manifest actually registers: %v", err)
	}
	if !strings.Contains(err.Error(), "weaker effect") {
		t.Fatalf("the refusal does not say which way the disagreement runs: %v", err)
	}
}

// TestOverdeclaringIsAlsoRefused. It is safe, and it still leaves the log
// carrying two accounts of what an action does.
func TestOverdeclaringIsAlsoRefused(t *testing.T) {
	reg := activeRegistry(t)
	plan := wirePlan()
	plan.Plan[0].EffectClass = janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED

	err := registry.Admit(reg, plan)
	if err == nil {
		t.Fatal("a plan disagreeing with the registry in the safe direction was admitted silently")
	}
	if !strings.Contains(err.Error(), "stronger effect") {
		t.Fatalf("the refusal does not say which way the disagreement runs: %v", err)
	}
}

func TestAnActionNoManifestDeclaresIsRefused(t *testing.T) {
	reg := activeRegistry(t)
	plan := wirePlan()
	plan.Plan[0].Action = "payments.wire_faster"

	err := registry.Admit(reg, plan)
	if err == nil {
		t.Fatal("a step invoking an unregistered action was admitted")
	}
	if !strings.Contains(err.Error(), "payments.quote") {
		t.Fatalf("the refusal does not say what the participant does declare: %v", err)
	}
}

// TestACompensationThePlanInventedIsRefused. The compensation that was
// evaluated is the registered one; a plan naming another has an undo nothing
// tested.
func TestACompensationThePlanInventedIsRefused(t *testing.T) {
	reg := activeRegistry(t)
	plan := wirePlan()
	plan.Plan[0].CompensationAction = "payments.quote"

	if err := registry.Admit(reg, plan); err == nil {
		t.Fatal("a plan compensating with an action the manifest does not name was admitted")
	}
}

func TestAnUnpinnedParticipantIsRefused(t *testing.T) {
	reg := activeRegistry(t)
	plan := wirePlan()
	plan.ManifestPins = nil

	err := registry.Admit(reg, plan)
	if err == nil {
		t.Fatal("a saga whose steps pin no manifest version was admitted, so nothing would " +
			"resolve at replay time")
	}
	if !strings.Contains(err.Error(), "I8") {
		t.Fatalf("the refusal does not name the invariant it protects: %v", err)
	}
}

func TestAPinToAVersionThatIsNotActiveIsRefused(t *testing.T) {
	r, s, _ := newRecorder(t)
	m := wireManifest()
	activated(t, r, s, m)
	if err := r.Suspend(context.Background(), m.Identity.ParticipantID, m.Version,
		"under investigation"); err != nil {
		t.Fatal(err)
	}

	err := registry.Admit(r.Registry(), wirePlan())
	if err == nil {
		t.Fatal("a new saga pinned a suspended participant")
	}
	if !strings.Contains(err.Error(), "under investigation") {
		t.Fatalf("the refusal does not carry the reason it was suspended: %v", err)
	}
}

func TestAPinToAVersionNobodyRegisteredIsRefused(t *testing.T) {
	reg := activeRegistry(t)
	plan := wirePlan()
	plan.ManifestPins["tool_payments"] = "9.9.9"

	if err := registry.Admit(reg, plan); err == nil {
		t.Fatal("a saga pinned a manifest version that does not exist")
	}
}

// TestAStalePinIsRefused. A pin left behind after a step was removed reads
// later as though that participant took part.
func TestAStalePinIsRefused(t *testing.T) {
	reg := activeRegistry(t)
	plan := wirePlan()
	plan.ManifestPins["tool_ledger"] = "1.0.0"

	if err := registry.Admit(reg, plan); err == nil {
		t.Fatal("a saga pinning a participant no step uses was admitted")
	}
}

// TestAdmissionAsOfASequence. Whether a saga was admissible is a question about
// when it began: a participant suspended afterwards does not make yesterday's
// payment retrospectively inadmissible.
func TestAdmissionAsOfASequence(t *testing.T) {
	r, s, dir := newRecorder(t)
	m := wireManifest()
	activated(t, r, s, m)
	e, _ := r.Registry().Resolve(m.Identity.ParticipantID, m.Version)
	began := e.ActivatedSeq

	if err := r.Suspend(context.Background(), m.Identity.ParticipantID, m.Version,
		"withdrawn after an incident"); err != nil {
		t.Fatal(err)
	}

	events, err := registry.LoadEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.AdmitAt(events, began, wirePlan()); err != nil {
		t.Fatalf("a saga that was admissible when it began is reported as inadmissible now: %v", err)
	}
	if err := registry.AdmitAt(events, 0, wirePlan()); err == nil {
		t.Fatal("a saga beginning now against a suspended participant was admitted")
	}
}

// jurisdictionRegistry activates the wire manifest with a jurisdiction on it.
func jurisdictionRegistry(t *testing.T, j registry.Jurisdiction) *registry.Registry {
	t.Helper()
	r, s, _ := newRecorder(t)
	m := wireManifest()
	m.Jurisdiction = j
	activated(t, r, s, m)
	return r.Registry()
}

// TestAPinnedTenantRefusesAParticipantThatMayNotRunThere is the enforcement the
// declaration never had.
//
// deployable_in has been in the manifest since Phase 3 and until now nothing
// read it: a participant could declare it may run only in the US, be
// registered, and run every step of a German tenant's saga with nothing in
// Janus objecting. A compliance check confirmed participants *declared* a
// jurisdiction, which is a different property entirely — declaring is not
// pinning.
func TestAPinnedTenantRefusesAParticipantThatMayNotRunThere(t *testing.T) {
	reg := jurisdictionRegistry(t, registry.Jurisdiction{DeployableIn: []string{"US"}})

	err := registry.AdmitFor(reg, wirePlan(), tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"})
	if err == nil {
		t.Fatal("a tenant pinned to DE admitted a plan running on a US-only participant")
	}
	if !strings.Contains(err.Error(), "may be deployed in US") ||
		!strings.Contains(err.Error(), "pinned to DE") {
		t.Fatalf("the refusal does not name both sides of the mismatch: %v", err)
	}

	// The same plan is admissible for a tenant that has not pinned anything,
	// which is every deployment before Phase 5c.
	if err := registry.Admit(reg, wirePlan()); err != nil {
		t.Fatalf("an unpinned deployment was refused: %v", err)
	}
}

// TestAParticipantDeclaringNoJurisdictionIsRefusedByAPin is the fail-closed
// half, and the one that will actually bite.
//
// Every participant registered before anybody thought about jurisdiction
// declares nothing, and reading that as "no restriction" would make the pin
// useless on exactly that population. A participant that has not said where it
// may run has not been assessed for anywhere.
func TestAParticipantDeclaringNoJurisdictionIsRefusedByAPin(t *testing.T) {
	reg := jurisdictionRegistry(t, registry.Jurisdiction{})

	err := registry.AdmitFor(reg, wirePlan(), tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"})
	if err == nil {
		t.Fatal("a pinned tenant admitted a participant that declares no jurisdiction")
	}
	if !strings.Contains(err.Error(), "declares no jurisdiction") {
		t.Fatalf("the refusal does not say what is missing: %v", err)
	}
}

// TestDataResidencyIsCheckedSeparatelyFromDeployability: where a participant
// runs and where it keeps what it produces are different questions, and a tool
// running in Frankfurt that writes its results to Ohio has answered one.
func TestDataResidencyIsCheckedSeparatelyFromDeployability(t *testing.T) {
	reg := jurisdictionRegistry(t, registry.Jurisdiction{
		DeployableIn: []string{"DE"}, DataResidency: "US",
	})

	err := registry.AdmitFor(reg, wirePlan(), tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"})
	if err == nil {
		t.Fatal("a participant deployable in DE that stores its data in US was admitted for a DE pin")
	}
	if !strings.Contains(err.Error(), "keeps its data in US") {
		t.Fatalf("the refusal does not name the residency: %v", err)
	}
}

func TestAMatchingParticipantIsAdmitted(t *testing.T) {
	reg := jurisdictionRegistry(t, registry.Jurisdiction{
		DeployableIn: []string{"EU", "DE"}, DataResidency: "DE",
	})
	if err := registry.AdmitFor(reg, wirePlan(),
		tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"}); err != nil {
		t.Fatalf("a participant declaring DE was refused by a DE pin: %v", err)
	}
}
