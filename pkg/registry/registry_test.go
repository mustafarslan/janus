package registry_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/registry"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

var operator = evidence.ParticipantRef{
	ID: "sys_registry", ManifestVersion: "1.0.0", Principal: "pr_bank", Kind: "SYSTEM",
}

func newLog(t *testing.T) (*evidence.Appender, string) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	return app, dir
}

// newRecorder returns a recorder with a trust store that knows one key for the
// manifest's principal, which is what a registry operator holds.
func newRecorder(t *testing.T) (*registry.Recorder, *keys.Signer, string) {
	t.Helper()
	app, dir := newLog(t)
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	return registry.NewRecorder(app, operator, registry.New(), trust), signer, dir
}

// register signs and registers a manifest, failing the test if either step does.
func register(t *testing.T, r *registry.Recorder, s *keys.Signer, m *registry.Manifest) *registry.Entry {
	t.Helper()
	sig, err := registry.Sign(m, s)
	if err != nil {
		t.Fatal(err)
	}
	e, err := r.Register(context.Background(), m, sig)
	if err != nil {
		t.Fatalf("register %s@%s: %v", m.Identity.ParticipantID, m.Version, err)
	}
	return e
}

// evaluate runs the conformance harness against honest doubles and attaches the
// report.
func evaluate(t *testing.T, r *registry.Recorder, m *registry.Manifest) {
	t.Helper()
	rep, err := registry.Evaluate(context.Background(), m, honestDoubles())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.GetPassed() {
		t.Fatalf("the honest manifest failed conformance:\n%s", registry.ReportText(rep))
	}
	if err := r.Evaluate(context.Background(), m.Identity.ParticipantID, m.Version, rep); err != nil {
		t.Fatal(err)
	}
}

// activated registers, evaluates and activates a manifest — the ordinary path.
func activated(t *testing.T, r *registry.Recorder, s *keys.Signer, m *registry.Manifest) {
	t.Helper()
	register(t, r, s, m)
	evaluate(t, r, m)
	if err := r.Activate(context.Background(), m.Identity.ParticipantID, m.Version); err != nil {
		t.Fatalf("activate: %v", err)
	}
}

func stateOf(t *testing.T, r *registry.Recorder, participant, version string) registry.State {
	t.Helper()
	e, ok := r.Registry().Resolve(participant, version)
	if !ok {
		t.Fatalf("%s@%s is not in the registry", participant, version)
	}
	return e.State
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

// TestADraftCannotBeActivated is the whole reason the conformance harness
// exists: the effect classes a manifest declares decide what Janus gates, so
// they are checked before they are believed.
func TestADraftCannotBeActivated(t *testing.T) {
	r, s, _ := newRecorder(t)
	m := wireManifest()
	register(t, r, s, m)

	err := r.Activate(context.Background(), m.Identity.ParticipantID, m.Version)
	if err == nil {
		t.Fatal("a manifest nothing had evaluated was activated")
	}
	if !strings.Contains(err.Error(), "never been evaluated") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// TestAFailedEvaluationDoesNotAdvanceTheVersion. A failing report is recorded —
// "this was tested and it did not pass" is the part somebody needs to see — but
// it is not a transition.
func TestAFailedEvaluationDoesNotAdvanceTheVersion(t *testing.T) {
	r, s, _ := newRecorder(t)
	m := wireManifest()
	register(t, r, s, m)

	liar := honestDoubles().With("payments.wire", registry.Double{
		Deltas: map[string]int64{"balance": -90},
	})
	rep, err := registry.Evaluate(context.Background(), m, liar)
	if err != nil {
		t.Fatal(err)
	}
	if rep.GetPassed() {
		t.Fatal("the dishonest sandbox passed, so this test proves nothing")
	}
	if err := r.Evaluate(context.Background(), m.Identity.ParticipantID, m.Version, rep); err != nil {
		t.Fatal(err)
	}

	if got := stateOf(t, r, m.Identity.ParticipantID, m.Version); got != registry.StateDraft {
		t.Fatalf("a failed evaluation moved the version to %s", got)
	}
	if err := r.Activate(context.Background(), m.Identity.ParticipantID, m.Version); err == nil {
		t.Fatal("a version whose evaluation failed was activated")
	}
}

// TestASuspendedVersionGoesBackThroughEvaluation. Re-activating with a click
// would record that somebody decided the problem was over, and nothing about
// what changed.
func TestASuspendedVersionGoesBackThroughEvaluation(t *testing.T) {
	r, s, _ := newRecorder(t)
	m := wireManifest()
	activated(t, r, s, m)

	if err := r.Suspend(context.Background(), m.Identity.ParticipantID, m.Version,
		"refund path returned a fee-adjusted amount in production"); err != nil {
		t.Fatal(err)
	}
	err := r.Activate(context.Background(), m.Identity.ParticipantID, m.Version)
	if err == nil {
		t.Fatal("a suspended version was re-activated with no fresh evidence")
	}
	if !strings.Contains(err.Error(), "evaluate it again") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	evaluate(t, r, m)
	if err := r.Activate(context.Background(), m.Identity.ParticipantID, m.Version); err != nil {
		t.Fatalf("a re-evaluated version could not be activated: %v", err)
	}
}

// TestASuspensionMustSayWhy. Without a reason the log records that a
// participant was stopped and nothing about what would have to be true to start
// it again.
func TestASuspensionMustSayWhy(t *testing.T) {
	r, s, _ := newRecorder(t)
	m := wireManifest()
	activated(t, r, s, m)

	if err := r.Suspend(context.Background(), m.Identity.ParticipantID, m.Version, "  "); err == nil {
		t.Fatal("a participant was suspended with no reason")
	}
}

// TestActivatingASuccessorSupersedesItsPredecessor, and the predecessor stays
// resolvable — sagas that pinned it are audited for years.
func TestActivatingASuccessorSupersedesItsPredecessor(t *testing.T) {
	r, s, _ := newRecorder(t)
	v1 := wireManifest()
	activated(t, r, s, v1)

	v2 := wireManifest()
	v2.Version = "1.1.0"
	v2.Runtime.SBOMRef = "sbom:2"
	register(t, r, s, v2)
	if err := r.InheritEvaluation(context.Background(), v2.Identity.ParticipantID, v2.Version); err != nil {
		t.Fatal(err)
	}
	if err := r.Activate(context.Background(), v2.Identity.ParticipantID, v2.Version); err != nil {
		t.Fatal(err)
	}

	if got := stateOf(t, r, v1.Identity.ParticipantID, "1.0.0"); got != registry.StateSuperseded {
		t.Fatalf("the predecessor is %s, want SUPERSEDED", got)
	}
	active, ok := r.Registry().Active(v1.Identity.ParticipantID)
	if !ok || active.Version != "1.1.0" {
		t.Fatalf("the active version is %v", active)
	}
	if _, ok := r.Registry().Resolve(v1.Identity.ParticipantID, "1.0.0"); !ok {
		t.Fatal("the superseded version stopped resolving, so every saga that pinned it " +
			"became unauditable")
	}
}

// TestASupersededVersionCanBeRolledBackTo. Superseded is not a judgment about
// the version, so going back to something already evaluated must be easy —
// otherwise operators re-register the same bytes under a new number.
func TestASupersededVersionCanBeRolledBackTo(t *testing.T) {
	r, s, _ := newRecorder(t)
	v1 := wireManifest()
	activated(t, r, s, v1)

	v2 := wireManifest()
	v2.Version = "1.1.0"
	v2.Runtime.SBOMRef = "sbom:2"
	register(t, r, s, v2)
	if err := r.InheritEvaluation(context.Background(), v2.Identity.ParticipantID, v2.Version); err != nil {
		t.Fatal(err)
	}
	if err := r.Activate(context.Background(), v2.Identity.ParticipantID, v2.Version); err != nil {
		t.Fatal(err)
	}

	if err := r.Activate(context.Background(), v1.Identity.ParticipantID, "1.0.0"); err != nil {
		t.Fatalf("rolling back to an already-evaluated version was refused: %v", err)
	}
	if got := stateOf(t, r, v1.Identity.ParticipantID, "1.1.0"); got != registry.StateSuperseded {
		t.Fatalf("after the rollback the newer version is %s", got)
	}
}

// TestRetirementIsTerminal.
func TestRetirementIsTerminal(t *testing.T) {
	r, s, _ := newRecorder(t)
	m := wireManifest()
	activated(t, r, s, m)

	if err := r.Retire(context.Background(), m.Identity.ParticipantID, m.Version,
		"replaced by the ledger service"); err != nil {
		t.Fatal(err)
	}
	if err := r.Activate(context.Background(), m.Identity.ParticipantID, m.Version); err == nil {
		t.Fatal("a retired version was activated")
	}
	if err := r.Evaluate(context.Background(), m.Identity.ParticipantID, m.Version,
		&janusv1.EvaluationReport{Passed: true}); err == nil {
		t.Fatal("a retired version was evaluated back into service")
	}
}

// TestAVersionCannotBeEditedUnderTheSameName is the property that makes pinning
// worth anything. Every saga that pinned the string recorded a claim about what
// the participant was declared to do.
func TestAVersionCannotBeEditedUnderTheSameName(t *testing.T) {
	r, s, _ := newRecorder(t)
	m := wireManifest()
	register(t, r, s, m)

	edited := wireManifest()
	edited.Actions[0].Limits.MaxAmount = 1000000
	sig, err := registry.Sign(edited, s)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Register(context.Background(), edited, sig)
	if err == nil {
		t.Fatal("one version string was registered twice with different content, so every pin " +
			"to it now resolves to two different declarations")
	}
	if !strings.Contains(err.Error(), "not a pin") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// ---------------------------------------------------------------------------
// change events and revalidation
// ---------------------------------------------------------------------------

// TestAModelChangeFiresTheRevalidationItsPredecessorDeclared. A new model
// version is a different participant wearing the same name.
func TestAModelChangeFiresTheRevalidationItsPredecessorDeclared(t *testing.T) {
	r, s, _ := newRecorder(t)
	v1 := wireManifest()
	activated(t, r, s, v1)

	v2 := wireManifest()
	v2.Version = "2.0.0"
	v2.Runtime.ModelID = "gpt-next"
	e := register(t, r, s, v2)

	if len(e.PendingTriggers) == 0 {
		t.Fatal("swapping the model fired no revalidation trigger")
	}
	if e.PendingTriggers[0] != registry.TriggerModelChange {
		t.Fatalf("triggers fired: %v", e.PendingTriggers)
	}
	if e.Change.GetFromVersion() != "1.0.0" {
		t.Fatalf("the change record names predecessor %q", e.Change.GetFromVersion())
	}

	// The predecessor's evidence does not carry over, and saying so is the
	// point of the trigger.
	if err := r.InheritEvaluation(context.Background(), v2.Identity.ParticipantID, v2.Version); err == nil {
		t.Fatal("a version that changed its model inherited the evidence that cleared the old one")
	}
	if err := r.Activate(context.Background(), v2.Identity.ParticipantID, v2.Version); err == nil {
		t.Fatal("a version owing revalidation was activated")
	}

	evaluate(t, r, v2)
	if err := r.Activate(context.Background(), v2.Identity.ParticipantID, v2.Version); err != nil {
		t.Fatalf("after revalidation the version could not be activated: %v", err)
	}
}

// TestAChangeThatFiresNoTriggerInheritsTheEvidence, and the inheritance is on
// the record rather than implied — "this version was never separately
// evaluated" is exactly what an inventory reviewer needs to see.
func TestAChangeThatFiresNoTriggerInheritsTheEvidence(t *testing.T) {
	r, s, _ := newRecorder(t)
	v1 := wireManifest()
	activated(t, r, s, v1)

	v2 := wireManifest()
	v2.Version = "1.0.1"
	v2.Jurisdiction.DeployableIn = []string{"EU", "TR"}
	e := register(t, r, s, v2)
	if len(e.PendingTriggers) != 0 {
		t.Fatalf("a jurisdiction note fired %v", e.PendingTriggers)
	}
	if err := r.InheritEvaluation(context.Background(), v2.Identity.ParticipantID, v2.Version); err != nil {
		t.Fatal(err)
	}

	e, _ = r.Registry().Resolve(v2.Identity.ParticipantID, v2.Version)
	if e.Evaluation.GetInheritedFrom() != "1.0.0" {
		t.Fatalf("the evaluation does not record where the evidence came from: %v", e.Evaluation)
	}
	if len(e.Evaluation.GetChecks()) != 0 {
		t.Fatal("an inherited evaluation carries checks, which reads as though they were run " +
			"against these bytes")
	}
}

// TestATriggerTheSuccessorDroppedStillFires. The predecessor's terms decide
// whether its evidence carries over; reading the successor's list would let a
// new manifest excuse itself.
func TestATriggerTheSuccessorDroppedStillFires(t *testing.T) {
	r, s, _ := newRecorder(t)
	v1 := wireManifest()
	activated(t, r, s, v1)

	v2 := wireManifest()
	v2.Version = "2.0.0"
	v2.Runtime.ModelID = "gpt-next"
	v2.Risk.RevalidationTriggers = nil // "we no longer revalidate on model changes"
	e := register(t, r, s, v2)

	if len(e.PendingTriggers) == 0 {
		t.Fatal("a manifest excused itself from revalidation by declaring fewer triggers than " +
			"the version it replaces")
	}
}

// TestACalendarRevalidationIsAnEvent. Nothing in the log implies a quarterly
// review has come due, so it has to be recorded when somebody decides it has.
func TestACalendarRevalidationIsAnEvent(t *testing.T) {
	r, s, _ := newRecorder(t)
	m := wireManifest()
	m.Risk.RevalidationTriggers = append(m.Risk.RevalidationTriggers, registry.TriggerPeriodic)
	activated(t, r, s, m)

	if err := r.RequireRevalidation(context.Background(), m.Identity.ParticipantID, m.Version,
		[]string{registry.TriggerPeriodic}, "quarterly model review"); err != nil {
		t.Fatal(err)
	}
	e, _ := r.Registry().Resolve(m.Identity.ParticipantID, m.Version)
	if len(e.PendingTriggers) != 1 {
		t.Fatalf("pending triggers: %v", e.PendingTriggers)
	}
	// It does not throw the participant out of service — that is an operational
	// decision — but the debt is visible and blocks the next activation.
	if e.State != registry.StateActive {
		t.Fatalf("a periodic review demand changed the state to %s", e.State)
	}
}

// ---------------------------------------------------------------------------
// the projection
// ---------------------------------------------------------------------------

// TestTheRegistryRebuildsFromTheLog. Nothing in the recorder is the system of
// record; a reader holding only the segments must reach the same state.
func TestTheRegistryRebuildsFromTheLog(t *testing.T) {
	r, s, dir := newRecorder(t)
	m := wireManifest()
	activated(t, r, s, m)
	v2 := wireManifest()
	v2.Version = "2.0.0"
	v2.Runtime.ModelID = "gpt-next"
	register(t, r, s, v2)

	replayed, err := registry.Replay(dir)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	live, ok := replayed.Active(m.Identity.ParticipantID)
	if !ok {
		t.Fatal("the replayed registry has no active version")
	}
	if live.Version != "1.0.0" || live.ContentAddress != m.ContentAddress() {
		t.Fatalf("replayed active version is %s (%s)", live.Version, live.ContentAddress)
	}
	pending, _ := replayed.Resolve(m.Identity.ParticipantID, "2.0.0")
	if pending.State != registry.StateDraft || len(pending.PendingTriggers) != 1 {
		t.Fatalf("replayed successor is %s owing %v", pending.State, pending.PendingTriggers)
	}
}

// TestResolutionCanBeAskedAsOfASequence. Invariant I8 is a claim about the
// moment a step ran, not about now.
func TestResolutionCanBeAskedAsOfASequence(t *testing.T) {
	r, s, dir := newRecorder(t)
	m := wireManifest()
	activated(t, r, s, m)
	before, _ := r.Registry().Resolve(m.Identity.ParticipantID, m.Version)
	activeAt := before.ActivatedSeq

	if err := r.Retire(context.Background(), m.Identity.ParticipantID, m.Version,
		"decommissioned"); err != nil {
		t.Fatal(err)
	}

	events, err := registry.LoadEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	asOf, err := registry.FoldUntil(events, activeAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := asOf.Active(m.Identity.ParticipantID); !ok {
		t.Fatal("the participant was not active as of the sequence that activated it")
	}
	now, err := registry.Fold(events)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := now.Active(m.Identity.ParticipantID); ok {
		t.Fatal("a retired participant is still active in the current fold")
	}
}

// TestTheClassifierAnswersFromTheActiveManifest — what replaces the static
// tool-to-class table janus-mcpd carried through Phase 0.
func TestTheClassifierAnswersFromTheActiveManifest(t *testing.T) {
	r, s, _ := newRecorder(t)
	m := wireManifest()
	activated(t, r, s, m)

	c := r.Registry().ClassifierFor(m.Identity.ParticipantID)
	got, ok := c.Classify("notify.email")
	if !ok {
		t.Fatal("the classifier does not know an action the active manifest declares")
	}
	if got != janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED {
		t.Fatalf("notify.email classified as %s", registry.ShortClass(got))
	}
	if _, ok := c.Classify("payments.unsend"); ok {
		t.Fatal("the classifier answered for an action no manifest declares; the caller's " +
			"fail-closed default has to apply instead")
	}
}
