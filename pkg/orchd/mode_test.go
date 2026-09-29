package orchd_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/template"
)

// These tests exist because nothing else drives the real machinery. Every check
// in pkg/outbox uses a test double that tells the outbox what mode a saga is in;
// `outbox.NewLogModes`, which reads it out of a real SAGA_BEGIN, and the daemon's
// wiring of it and of -sandbox-targets, were compile-checked and never run.
//
// Deleting `Modes:` and `SandboxTargets:` from orchd's releaser made no test
// fail. That is the fourth time in Phase 6 that a flag has been wired and not
// exercised, and the standing question is the one this file answers: what test
// would fail if the wiring were deleted?

func newModeServer(t *testing.T, sandbox []string) (*orchd.Server, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)

	p := &gate.Policy{
		ID: "orchd.mode.test",
		Rules: []gate.Rule{{
			ID:    "irreversible-needs-a-person",
			Match: gate.Match{EffectClasses: []string{"IRREVERSIBLE_GATED"}},
			Require: []gate.Requirement{{
				ID: "notify-four-eyes", Gate: gate.GateHuman, Phase: gate.PhasePreRelease,
				Human: &gate.HumanSpec{Roles: []string{"credit-officer"}, Quorum: 1},
			}},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: p,
		SandboxTargets: sandbox,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

func beginExploratory(t *testing.T, s *orchd.Server, ctx context.Context, sagaID string) {
	t.Helper()
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{
		Begin: &janusv1.SagaBegin{
			SagaId: sagaID,
			Mode:   string(saga.ModeExploratory),
			Intent: &janusv1.Intent{
				IntentId: "in_" + sagaID, Principal: testPrincipal,
				Originator: "human:desk@bank", MandateRef: "mandate:payments",
				Scope: "try something out",
			},
			Plan: []*janusv1.PlannedStep{{
				StepId: "st_notify", Participant: "tool_payments", Action: "notify.email",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
			}},
			ManifestPins: map[string]string{"tool_payments": "1.0.0"},
		},
	}); err != nil {
		t.Fatalf("beginning an exploratory saga: %v", err)
	}
}

func holdFor(sagaID, target string) *janusv1.HoldEffectRequest {
	return &janusv1.HoldEffectRequest{
		Effect: &janusv1.EffectHeld{
			EffectId: "ef_" + sagaID, SagaId: sagaID, StepId: "st_notify",
			Target: target, Action: "notify.email", IdemKey: "idem-" + sagaID,
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		},
	}
}

// TestAnExploratorySagaCannotHoldAnEffectForARealTarget is the daemon actually
// enforcing mode confinement, through its own configuration and its own log.
//
// Nothing here is a double: the mode is read from the SAGA_BEGIN the daemon
// recorded, by the resolver the daemon wired up.
func TestAnExploratorySagaCannotHoldAnEffectForARealTarget(t *testing.T) {
	s, dir := newModeServer(t, nil)
	ctx := context.Background()
	beginExploratory(t, s, ctx, "sg_explore")
	prepareStep(t, s, "sg_explore", "st_notify")

	_, err := s.HoldEffect(ctx, holdFor("sg_explore", "tool_payments"))
	if err == nil {
		t.Fatal("an exploratory saga captured an effect for a real target; exploratory mode's " +
			"\"sandbox effects only\" means nothing")
	}
	for _, want := range []string{"exploratory", "sandbox"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}

	// The refusal is a refusal, not a wedge: the saga is still readable, still
	// in a state the log describes, and has not committed.
	got := getSaga(t, s, "sg_explore")
	if got.GetStatus() == janusv1.SagaState_SAGA_STATE_COMMITTED {
		t.Error("the saga committed even though its effect was never held")
	}
	state, err := outbox.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Effects) != 0 {
		t.Errorf("the outbox holds %d effects for a saga whose hold was refused",
			len(state.Effects))
	}
}

// TestAnExploratorySagaReachesADeclaredSandbox: the mode is a restriction, not a
// prohibition, and -sandbox-targets is what lifts it.
func TestAnExploratorySagaReachesADeclaredSandbox(t *testing.T) {
	s, dir := newModeServer(t, []string{"tool_payments"})
	ctx := context.Background()
	beginExploratory(t, s, ctx, "sg_explore")
	prepareStep(t, s, "sg_explore", "st_notify")

	if _, err := s.HoldEffect(ctx, holdFor("sg_explore", "tool_payments")); err != nil {
		t.Fatalf("an exploratory saga could not reach a target the daemon declared a "+
			"sandbox: %v", err)
	}
	state, err := outbox.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Effects) != 1 {
		t.Fatalf("the outbox holds %d effects, want 1", len(state.Effects))
	}
}

// TestASupervisedSagaIsUnaffectedByModeEnforcement: every deployment that does
// not use exploratory mode must behave exactly as it did.
func TestASupervisedSagaIsUnaffectedByModeEnforcement(t *testing.T) {
	s, dir := newModeServer(t, nil)
	ctx := context.Background()
	beginGatedPlan(t, s, ctx)
	prepareStep(t, s, notifySaga, "st_notify")

	if _, err := s.HoldEffect(ctx, holdFor(notifySaga, "tool_payments")); err != nil {
		t.Fatalf("a supervised saga was refused: %v", err)
	}
	state, err := outbox.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Effects) != 1 {
		t.Fatalf("the outbox holds %d effects, want 1", len(state.Effects))
	}
}

// TestTheModeResolverReadsARealBeginning exercises `outbox.NewLogModes` against
// a log directly, including the case its shortcut does not cover.
//
// It reads only the saga's first event, because the mode is on SAGA_BEGIN and
// nothing can change it. A saga id whose first event is *not* a beginning —
// which an effect record carrying an unknown saga id would produce — must
// therefore refuse rather than return an empty mode that reads as unscoped.
func TestTheModeResolverReadsARealBeginning(t *testing.T) {
	s, dir := newModeServer(t, nil)
	ctx := context.Background()
	beginExploratory(t, s, ctx, "sg_explore")

	modes := outbox.NewLogModes(dir)
	mode, ok, err := modes.ModeOf(ctx, "sg_explore")
	if err != nil || !ok {
		t.Fatalf("reading the mode of a real saga: mode=%q ok=%v err=%v", mode, ok, err)
	}
	if mode != string(saga.ModeExploratory) {
		t.Errorf("the resolver reports mode %q, the log says %q", mode, saga.ModeExploratory)
	}

	// A saga the log has never begun. "Not found" and "unscoped" must not be the
	// same answer: an effect attributed to a saga nobody began is not a thing to
	// deliver.
	if _, ok, err := modes.ModeOf(ctx, "sg_never_existed"); ok || err != nil {
		t.Errorf("a saga the log never began resolved to ok=%v err=%v; it must be "+
			"neither found nor an empty mode", ok, err)
	}
}

// registerTemplateInLog puts a template through the registry's lifecycle in an
// evidence directory, before a daemon opens it.
//
// Before, because one process owns an evidence directory — which is
// also how a real deployment does it: the template is registered by the registry
// CLI, and the daemon reads what is in the log.
func registerTemplateInLog(t *testing.T, dir string, signer *keys.Signer, activate bool) {
	t.Helper()
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust(testPrincipal, signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "ag_operator", Principal: testPrincipal, Kind: "AGENT", ManifestVersion: "1.0.0",
	}, reg, trust)

	putTemplateThrough(t, rec, signer, "tpl_notify", "", activate)
}

// registerTemplateTreeInLog registers a child template and then a parent whose
// spawning step names it, which is the order registration forces: a constraint naming
// a document nobody holds constrains nothing, so `RegisterTemplate` refuses it.
func registerTemplateTreeInLog(t *testing.T, dir string, signer *keys.Signer) {
	t.Helper()
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust(testPrincipal, signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "ag_operator", Principal: testPrincipal, Kind: "AGENT", ManifestVersion: "1.0.0",
	}, reg, trust)

	putTemplateThrough(t, rec, signer, "tpl_child_notify", "", true)
	putTemplateThrough(t, rec, signer, "tpl_parent_notify", "tpl_child_notify", true)
	// A second activated template of the same shape, so that the "wrong
	// template" leg is refused by the parent's constraint and not by admission
	// finding nothing to resolve -- which would pass the test for the wrong
	// reason and leave the constraint untested.
	putTemplateThrough(t, rec, signer, "tpl_notify", "", true)
}

// putTemplateThrough registers one template, optionally naming the template its
// st_notify step's children must pin, and optionally activates it.
func putTemplateThrough(t *testing.T, rec *registry.Recorder, signer *keys.Signer,
	id, childTemplate string, activate bool) {

	t.Helper()
	ctx := context.Background()
	tpl := &template.Template{
		TemplateID: id, Version: "1.0.0", Principal: testPrincipal, Risk: 2,
		Steps: []template.Step{{
			StepID: "st_notify", Participant: "tool_payments", Action: "notify.email",
			EffectClass:   janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED.String(),
			ChildTemplate: childTemplate,
		}},
		Slots: []template.Slot{{Name: "amount", StepID: "st_notify", Kind: "TEXT"}},
		Provenance: template.Provenance{
			Runs: 3, ExtractedFrom: "supervised",
			SagaIDs:       []string{"sg1", "sg2", "sg3"},
			EvidenceRoots: []string{"aa", "bb", "cc"},
		},
	}
	sig, err := registry.SignTemplate(tpl, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RegisterTemplate(ctx, tpl, sig); err != nil {
		t.Fatalf("registering template %s: %v", id, err)
	}
	if !activate {
		return
	}
	if err := rec.Evaluate(ctx, id, "1.0.0", &janusv1.EvaluationReport{
		Passed: true, HarnessVersion: "test", Sandbox: "re-matched its source runs",
	}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, id, "1.0.0"); err != nil {
		t.Fatal(err)
	}
}

func crystallizedPlan(action string) *janusv1.SagaBegin {
	return &janusv1.SagaBegin{
		SagaId: "sg_crystal",
		Mode:   string(saga.ModeCrystallized),
		Intent: &janusv1.Intent{
			IntentId: "in_crystal", Principal: testPrincipal,
			Originator: "human:desk@bank", MandateRef: "mandate:payments",
			Scope: "notify under a template",
		},
		Plan: []*janusv1.PlannedStep{{
			StepId: "st_notify", Participant: "tool_payments", Action: action,
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
		TemplatePin:  &janusv1.TemplatePin{TemplateId: "tpl_notify", Version: "1.0.0"},
	}
}

// TestACrystallizedSagaRunsThroughTheDaemon is crystallized mode working end to
// end: a template registered in the log by an operator, and a daemon admitting a
// saga against it.
//
// Phase 6e refused crystallized mode outright because nothing could confine one.
// This is the test that says that is no longer true, and — deleting the template
// enforcement from `registry.AdmitFor` — the test that says the confinement is
// doing the work rather than being declared.
func TestACrystallizedSagaRunsThroughTheDaemon(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	registerTemplateInLog(t, dir, signer, true)

	s := serverOn(t, dir, signer, "")
	ctx := context.Background()

	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{
		Begin: crystallizedPlan("notify.email"),
	}); err != nil {
		t.Fatalf("a plan that is exactly its template was refused: %v", err)
	}
	if got := getSaga(t, s, "sg_crystal"); got.GetSagaId() != "sg_crystal" {
		t.Fatal("the saga did not begin")
	}
}

// TestADeviantCrystallizedPlanIsRefusedByTheDaemon.
func TestADeviantCrystallizedPlanIsRefusedByTheDaemon(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	registerTemplateInLog(t, dir, signer, true)

	s := serverOn(t, dir, signer, "")
	// The manifest declares notify.email and payments.wire; this plan runs the
	// other one, so it is a legal plan that the template does not describe.
	begin := crystallizedPlan("payments.wire")
	begin.Plan[0].EffectClass = janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE
	begin.Plan[0].CompensationAction = "payments.refund"

	_, err = s.BeginSaga(context.Background(), &janusv1.BeginSagaRequest{Begin: begin})
	if err == nil {
		t.Fatal("a crystallized saga ran a plan its template does not describe")
	}
	if !strings.Contains(err.Error(), "template") {
		t.Errorf("the refusal does not mention the template: %v", err)
	}
}

// TestACrystallizedSagaNeedsAnActiveTemplateInTheDaemon: registered is not
// validated, and crystallized mode requires a *validated* template.
func TestACrystallizedSagaNeedsAnActiveTemplateInTheDaemon(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	registerTemplateInLog(t, dir, signer, false)

	s := serverOn(t, dir, signer, "")
	_, err = s.BeginSaga(context.Background(), &janusv1.BeginSagaRequest{
		Begin: crystallizedPlan("notify.email"),
	})
	if err == nil {
		t.Fatal("a saga was confined to a template nobody had validated")
	}
	if !strings.Contains(err.Error(), "DRAFT") {
		t.Errorf("the refusal does not say what state the template is in: %v", err)
	}
}

// prepareWithFacts declares a step's facts — the arguments it proposes, which a
// pre-execution gate decides against and which a template's slots describe.
func prepareWithFacts(t *testing.T, s *orchd.Server, sagaID, stepID string,
	facts ...string) error {
	t.Helper()
	var declared []*janusv1.Fact
	for _, f := range facts {
		declared = append(declared, &janusv1.Fact{
			Key: f, Value: &janusv1.Fact_Text{Text: "v"},
		})
	}
	_, err := s.PrepareStep(context.Background(), &janusv1.PrepareStepRequest{
		SagaId: sagaID, StepId: stepID, Facts: declared,
	})
	return err
}

// TestACrystallizedSagaConfinesItsFacts is crystallized mode's other half, and the half that
// was built and wired to nothing until this test existed.
//
// Confining the plan's *shape* happens at admission and fixes what a saga will
// do. The facts are the model's degrees of freedom and they arrive with the
// step's result, afterwards — so a crystallized saga whose facts nobody checked
// would have a record that reads as confined and a step that carried whatever it
// liked.
func TestACrystallizedSagaConfinesItsFacts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	registerTemplateInLog(t, dir, signer, true)

	s := serverOn(t, dir, signer, "")
	ctx := context.Background()
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{
		Begin: crystallizedPlan("notify.email"),
	}); err != nil {
		t.Fatal(err)
	}

	// The template declares one slot, `amount`, on st_notify.
	if err := prepareWithFacts(t, s, "sg_crystal", "st_notify",
		"amount", "override"); err == nil {
		t.Fatal("a crystallized step declared a fact its template has no slot for; the free " +
			"part is not enumerated and the confinement is a word")
	} else if !strings.Contains(err.Error(), "override") {
		t.Errorf("the refusal does not name the undeclared fact: %v", err)
	}

	// And it was refused *before* the declaration was bound, so nothing about
	// the step moved.
	if step := stepOf(t, getSaga(t, s, "sg_crystal"), "st_notify"); step.GetAttempt() != 0 {
		t.Errorf("the step is on attempt %d after a refused declaration", step.GetAttempt())
	}

	// The declared slot alone is accepted, and the saga runs on.
	if err := prepareWithFacts(t, s, "sg_crystal", "st_notify", "amount"); err != nil {
		t.Fatalf("a step declaring only its template's slot was refused: %v", err)
	}
	if step := stepOf(t, getSaga(t, s, "sg_crystal"), "st_notify"); step.GetStatus() ==
		janusv1.StepState_STEP_STATE_PLANNED {
		t.Errorf("the step is still %s after a accepted declaration", step.GetStatus())
	}
}

// TestASupervisedSagaCarriesWhateverFactsItLikes: the confinement is scoped to a
// pinned template, and every other saga must be untouched by it.
func TestASupervisedSagaCarriesWhateverFactsItLikes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)

	s := serverOn(t, dir, signer, "")
	ctx := context.Background()
	beginGatedPlan(t, s, ctx)

	if err := prepareWithFacts(t, s, notifySaga, "st_notify",
		"anything", "at_all"); err != nil {
		t.Fatalf("a supervised saga's facts were confined to a template it never pinned: %v", err)
	}
}

// TestACrystallizedSagaRunsToCompletion.
//
// Everything else about crystallized mode stops at admission or at prepare. This
// drives one all the way: declare the template's slot, report the step, and reach
// a terminal state — because "crystallized mode works end to end" is a claim that
// wants a saga that finished, and the earlier version of this test was rewritten
// when the confinement moved to prepare and lost its commit assertion with it.
//
// It also covers what the confinement deliberately does *not* touch. The step
// publishes a fact the template has no slot for, and that is allowed: slots are
// extracted from the *declared* vocabulary, and published facts are constrained
// by whatever gate policy chose to read them.
func TestACrystallizedSagaRunsToCompletion(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	registerTemplateInLog(t, dir, signer, true)

	s := serverOn(t, dir, signer, "")
	ctx := context.Background()
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{
		Begin: crystallizedPlan("notify.email"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := prepareWithFacts(t, s, "sg_crystal", "st_notify", "amount"); err != nil {
		t.Fatalf("declaring the template's own slot: %v", err)
	}
	attempt := stepOf(t, getSaga(t, s, "sg_crystal"), "st_notify").GetAttempt()

	if _, err := s.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: "sg_crystal", StepId: "st_notify", Attempt: attempt,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			// Published, not declared. The template has no slot for it and must
			// not object: a published fact is what the step found, and what
			// constrains it is the policy that chose to read it.
			Facts: []*janusv1.Fact{{
				Key: "reference", Value: &janusv1.Fact_Text{Text: "bank-ref-9"},
			}},
		},
	}); err != nil {
		t.Fatalf("reporting a crystallized step: %v", err)
	}

	got := getSaga(t, s, "sg_crystal")
	step := stepOf(t, got, "st_notify")
	if step.GetStatus() == janusv1.StepState_STEP_STATE_PLANNED ||
		step.GetStatus() == janusv1.StepState_STEP_STATE_PREPARED {
		t.Fatalf("the step is %s after reporting; the saga did not move", step.GetStatus())
	}
	// The policy in newModeServer holds an irreversible step for a person, so a
	// gate is what it stops at rather than a commit. What matters here is that a
	// crystallized saga got all the way through its step under confinement.
	if len(step.GetPendingGates()) == 0 &&
		got.GetStatus() != janusv1.SagaState_SAGA_STATE_COMMITTED {
		t.Errorf("the saga is %s with no gate outstanding; it neither committed nor is "+
			"waiting for anybody", got.GetStatus())
	}
}

// TestACrystallizedParentMayNotDelegateToAnUnconfinedChild is the enforcement
// that had been called "now enforced" with nothing to say so.
//
// A claims sweep found `confineChildToItsParent` at 18.8% coverage: only the
// `parent == nil` early return had ever executed, and no test in this repository
// set `SagaBegin.Parent` against the daemon at all. The refusal branch — the
// whole control — had never run. `registry.AdmitFor` cannot make this check,
// because `spawns` is declared on STEP_PREPARE rather than on the plan, so the
// parent's admission cannot see that it will delegate; the child's admission has
// to read the parent's mode out of the log instead, which is what this exercises.
//
// Two refusals, because being crystallized is necessary and no
// longer sufficient: the parent's template must also name what its step
// delegates to. The admission case — a child pinning exactly the template its
// parent named — is `TestACrystallizedParentNamesTheTemplateItsChildMustPin`,
// which is where the "not a rule that refuses everything" half now lives.
func TestACrystallizedParentMayNotDelegateToAnUnconfinedChild(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	registerTemplateInLog(t, dir, signer, true)

	s := serverOn(t, dir, signer, "")
	ctx := context.Background()

	// The parent: crystallized, admitted against its template.
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{
		Begin: crystallizedPlan("notify.email"),
	}); err != nil {
		t.Fatalf("the crystallized parent was refused: %v", err)
	}

	child := func(id, mode string) *janusv1.SagaBegin {
		b := crystallizedPlan("notify.email")
		b.SagaId = id
		b.Mode = mode
		if saga.Mode(mode) != saga.ModeCrystallized {
			// A pin outside crystallized mode is refused for its own reason
			// (registry.AdmitFor), and that refusal would mask this one.
			b.TemplatePin = nil
		}
		b.Parent = &janusv1.ParentSaga{
			SagaId: "sg_crystal", StepId: "st_notify",
			CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE,
		}
		return b
	}

	_, err = s.BeginSaga(ctx, &janusv1.BeginSagaRequest{
		Begin: child("sg_child_loose", string(saga.ModeSupervised)),
	})
	if err == nil {
		t.Fatal("a crystallized saga delegated to a supervised child. The confinement then " +
			"stops at the first step that spawns: the parent's own plan is held to a " +
			"template and everything it causes is held to nothing")
	}
	if !strings.Contains(err.Error(), "confined to nothing") {
		t.Errorf("the refusal does not say what is wrong with it, so an operator reads it "+
			"as the template check failing: %v", err)
	}

	// A crystallized child is no longer enough on its own. This
	// parent's template says nothing about what its step delegates to, and a
	// shape extracted from runs that never spawned is no evidence about
	// spawning, so treating its silence as permission would reopen the hole by
	// another route: extract from runs that did not delegate, then delegate.
	_, err = s.BeginSaga(ctx, &janusv1.BeginSagaRequest{
		Begin: child("sg_child_confined", string(saga.ModeCrystallized)),
	})
	if err == nil {
		t.Fatal("a crystallized parent whose template names no child template still spawned " +
			"a child, so the child's shape was chosen by whoever wrote the child's plan")
	}
	if !strings.Contains(err.Error(), "does not say what a child of that step is confined to") {
		t.Errorf("the refusal does not say which half of the rule failed: %v", err)
	}
}

// TestACrystallizedParentNamesTheTemplateItsChildMustPin is the second half
// of confining a crystallized saga's children.
//
// The first half requires a child to be confined to *some* validated template;
// this requires it to be **the** template the parent's own template named for
// the spawning step. Without it the parent confined its own shape and left its
// delegates' to whoever wrote the child's plan, so a crystallized tree was one
// signed document at the root and an unsigned choice at every branch.
//
// Both directions, because a rule that refused every child would pass the half
// anybody thinks to write and silently remove sub-sagas from crystallized mode.
func TestACrystallizedParentNamesTheTemplateItsChildMustPin(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	registerTemplateTreeInLog(t, dir, signer)

	s := serverOn(t, dir, signer, "")
	ctx := context.Background()

	parent := crystallizedPlan("notify.email")
	parent.TemplatePin = &janusv1.TemplatePin{TemplateId: "tpl_parent_notify", Version: "1.0.0"}
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{Begin: parent}); err != nil {
		t.Fatalf("the crystallized parent was refused: %v", err)
	}

	child := func(id, templateID string) *janusv1.SagaBegin {
		b := crystallizedPlan("notify.email")
		b.SagaId = id
		b.TemplatePin = &janusv1.TemplatePin{TemplateId: templateID, Version: "1.0.0"}
		b.Parent = &janusv1.ParentSaga{
			SagaId: "sg_crystal", StepId: "st_notify",
			CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE,
		}
		return b
	}

	// A child confined to a validated, activated template that is not the one
	// its parent named. This is what the first half admitted.
	_, err = s.BeginSaga(ctx, &janusv1.BeginSagaRequest{
		Begin: child("sg_child_wrong", "tpl_notify"),
	})
	if err == nil {
		t.Fatal("a crystallized child pinned a template its parent did not name, so the " +
			"parent's document does not decide the shape of the tree")
	}
	// Naming both is what makes the refusal actionable: an operator has to know
	// which template to pin, not merely that this one was wrong.
	for _, want := range []string{"tpl_notify", "tpl_child_notify"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so it does not say what to pin instead: %v",
				want, err)
		}
	}

	// And the child its parent did name is admitted.
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{
		Begin: child("sg_child_named", "tpl_child_notify"),
	}); err != nil {
		t.Fatalf("a child pinning exactly the template its parent's template named was "+
			"refused, which confines nothing -- it removes sub-sagas from crystallized "+
			"mode: %v", err)
	}
}

// The constraint comes from the version the parent pinned, not from whichever
// version is active now.
//
// A saga admitted under one shape is confined to that shape for its whole life.
// Reading the active version here would mean that activating a
// successor silently re-confined every child of every parent still running --
// a saga's confinement changing under it because somebody registered a document
// elsewhere. It is the same care the supersede fix takes: superseding
// withdraws a shape from *new* admissions and leaves sagas in flight alone.
//
// This is also what separates a pin lookup from an active lookup in a test: in
// the ordinary fixture the pinned version is the active one, so both spellings
// pass and the difference is invisible.
func TestAChildIsHeldToTheTemplateVersionItsParentPinned(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	registerTemplateTreeInLog(t, dir, signer)

	// The parent begins under tpl_parent_notify@1.0.0, which names
	// tpl_child_notify.
	s := serverOn(t, dir, signer, "")
	ctx := context.Background()
	parent := crystallizedPlan("notify.email")
	parent.TemplatePin = &janusv1.TemplatePin{TemplateId: "tpl_parent_notify", Version: "1.0.0"}
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{Begin: parent}); err != nil {
		t.Fatalf("the crystallized parent was refused: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A correction is registered and activated: same shape, children now
	// confined to tpl_notify instead. 1.0.0 is superseded.
	supersedeParentTemplate(t, dir, signer)

	s = serverOn(t, dir, signer, "")
	child := func(id, templateID string) *janusv1.SagaBegin {
		b := crystallizedPlan("notify.email")
		b.SagaId = id
		b.TemplatePin = &janusv1.TemplatePin{TemplateId: templateID, Version: "1.0.0"}
		b.Parent = &janusv1.ParentSaga{
			SagaId: "sg_crystal", StepId: "st_notify",
			CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE,
		}
		return b
	}

	// The successor's answer is tpl_notify. The parent pinned 1.0.0, whose
	// answer is tpl_child_notify, and that is the one that binds.
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{
		Begin: child("sg_child_still_named", "tpl_child_notify"),
	}); err != nil {
		t.Fatalf("activating a successor re-confined a child of a parent already running "+
			"under the version it replaced: %v", err)
	}
	_, err = s.BeginSaga(ctx, &janusv1.BeginSagaRequest{
		Begin: child("sg_child_new_answer", "tpl_notify"),
	})
	if err == nil {
		t.Fatal("a child was admitted against the successor's child reference, so the " +
			"parent's confinement moved under it when somebody activated a new version")
	}
}

// supersedeParentTemplate registers and activates tpl_parent_notify@2.0.0,
// which repoints its step's children at tpl_notify. Activating it supersedes
// 1.0.0.
//
// With no daemon running, the way an operator would: one process owns an
// evidence directory.
func supersedeParentTemplate(t *testing.T, dir string, signer *keys.Signer) {
	t.Helper()
	ctx := context.Background()
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust(testPrincipal, signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "ag_operator", Principal: testPrincipal, Kind: "AGENT", ManifestVersion: "1.0.0",
	}, reg, trust)

	tpl := &template.Template{
		TemplateID: "tpl_parent_notify", Version: "2.0.0", Principal: testPrincipal, Risk: 2,
		Steps: []template.Step{{
			StepID: "st_notify", Participant: "tool_payments", Action: "notify.email",
			EffectClass:   janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED.String(),
			ChildTemplate: "tpl_notify",
		}},
		Slots: []template.Slot{{Name: "amount", StepID: "st_notify", Kind: "TEXT"}},
		Provenance: template.Provenance{
			Runs: 3, ExtractedFrom: "supervised",
			SagaIDs:       []string{"sg1", "sg2", "sg3"},
			EvidenceRoots: []string{"aa", "bb", "cc"},
		},
	}
	sig, err := registry.SignTemplate(tpl, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rec.RegisterTemplate(ctx, tpl, sig); err != nil {
		t.Fatal(err)
	}
	// Repointing a step's children is a shape change, so the
	// successor owes an evaluation that says it covered one.
	if err := rec.Evaluate(ctx, "tpl_parent_notify", "2.0.0", &janusv1.EvaluationReport{
		Passed: true, HarnessVersion: "test", Sandbox: "re-matched its source runs",
		TriggersCovered: []string{registry.TriggerShapeChange},
	}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, "tpl_parent_notify", "2.0.0"); err != nil {
		t.Fatal(err)
	}
}
