package orchd_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
)

const (
	testPrincipal = "pr_bank"
	testSaga      = "sg_orchd"
)

// TestAStepWaitsForItsParticipantRatherThanBeingGivenAnOutcome is the property
// the whole daemon turns on.
//
// In every phase before this one the coordinator produced the outcome itself,
// so a step could not be outstanding. Hosted, the participant is somewhere
// else, and the gap between "prepared" and "reported" is real time in which the
// log must say nothing about how the step went. The failure this guards against
// is not a crash: it is a coordinator that fills the gap with an assumption and
// leaves a log that reads as though the participant answered.
func TestAStepWaitsForItsParticipantRatherThanBeingGivenAnOutcome(t *testing.T) {
	s, _ := newServer(t)
	ctx := context.Background()

	begin := quotePlan()
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{Begin: begin}); err != nil {
		t.Fatalf("beginning the saga: %v", err)
	}

	got := getSaga(t, s, testSaga)
	if got.GetStatus() == janusv1.SagaState_SAGA_STATE_COMMITTED {
		t.Fatal("the saga committed without its participant reporting anything; " +
			"the log now says a step ran that nobody ran")
	}
	if step := stepOf(t, got, "st_quote"); !step.GetAwaitingParticipant() {
		t.Fatalf("step is %s and awaiting_participant is false; a client polling for "+
			"work would never learn this step is unclaimed", step.GetStatus())
	}

	prepareStep(t, s, testSaga, "st_quote")
	step := stepOf(t, getSaga(t, s, testSaga), "st_quote")
	if step.GetStatus() != janusv1.StepState_STEP_STATE_PREPARED {
		t.Fatalf("after claiming it the step is %s, want PREPARED", step.GetStatus())
	}

	resp, err := s.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: testSaga, StepId: "st_quote", Attempt: step.GetAttempt(),
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		},
	})
	if err != nil {
		t.Fatalf("completing the step: %v", err)
	}
	if resp.GetRef().GetSeq() == 0 {
		t.Fatal("the response cites no evidence for the result it acknowledged; " +
			"a caller has nothing to check")
	}

	after := getSaga(t, s, testSaga)
	if after.GetStatus() != janusv1.SagaState_SAGA_STATE_COMMITTED {
		t.Fatalf("saga is %s, want COMMITTED once its only step reported", after.GetStatus())
	}
}

// TestTheRegistryStillOutranksThePlanOverTheWire is the constraint Phase 3d put
// on everything Phase 4 builds.
//
// A planner that follows an injected instruction has every reason to write PURE
// next to something that spends money. Admission believes the signed manifest
// instead — and a service is exactly where somebody would be tempted to skip
// that check to make an integration easier.
func TestTheRegistryStillOutranksThePlanOverTheWire(t *testing.T) {
	s, _ := newServer(t)

	begin := quotePlan()
	// The manifest says payments.wire is COMPENSABLE. The plan says PURE.
	begin.Plan = []*janusv1.PlannedStep{{
		StepId: "st_quote", Participant: "tool_payments", Action: "payments.wire",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
	}}

	_, err := s.BeginSaga(context.Background(), &janusv1.BeginSagaRequest{Begin: begin})
	if err == nil {
		t.Fatal("a plan that understates its effect class was admitted; the gate that " +
			"would have held the payment is attached to the class, so this is the whole " +
			"attack working")
	}
	if !containsText(err.Error(), "registry admission refused") {
		t.Fatalf("the refusal must say which admission check refused, so an operator "+
			"knows whether to look at the policy or the manifest; got %v", err)
	}
}

// TestBeginningTheSameSagaTwiceIsRefused. A client that retried a request whose
// response it never saw must not end up with two sagas for one intent.
func TestBeginningTheSameSagaTwiceIsRefused(t *testing.T) {
	s, _ := newServer(t)
	ctx := context.Background()

	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{Begin: quotePlan()}); err != nil {
		t.Fatalf("beginning the saga: %v", err)
	}
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{Begin: quotePlan()}); err == nil {
		t.Fatal("the same saga id was begun twice; the log now describes two starts " +
			"for one intent")
	}
}

// TestARepeatedReportIsNotASecondAttempt.
//
// A participant that times out waiting for the response and retries is behaving
// correctly. Recording the report twice would put two accounts of one attempt
// in the log; telling the participant it failed would strand a step that
// actually succeeded.
func TestARepeatedReportIsNotASecondAttempt(t *testing.T) {
	s, _ := newServer(t)
	ctx := context.Background()

	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{Begin: quotePlan()}); err != nil {
		t.Fatalf("beginning the saga: %v", err)
	}
	attempt := prepareStep(t, s, testSaga, "st_quote")
	report := &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: testSaga, StepId: "st_quote", Attempt: attempt,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		},
	}
	if _, err := s.CompleteStep(ctx, report); err != nil {
		t.Fatalf("first report: %v", err)
	}
	again, err := s.CompleteStep(ctx, report)
	if err != nil {
		t.Fatalf("a retried report must succeed, not fail: %v", err)
	}
	if !again.GetAlreadyRecorded() {
		t.Fatal("the retry was not reported as already recorded, so a participant " +
			"cannot tell a duplicate from a fresh attempt")
	}
}

// TestAnUnspecifiedOutcomeIsRefused. STATUS_UNSPECIFIED in the log would say
// the step ran and say nothing about how it went, which is the one thing a
// result record must never do.
func TestAnUnspecifiedOutcomeIsRefused(t *testing.T) {
	s, _ := newServer(t)
	ctx := context.Background()
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{Begin: quotePlan()}); err != nil {
		t.Fatalf("beginning the saga: %v", err)
	}
	attempt := prepareStep(t, s, testSaga, "st_quote")
	_, err := s.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: testSaga, StepId: "st_quote", Attempt: attempt,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_UNSPECIFIED},
		},
	})
	if err == nil {
		t.Fatal("a result with no outcome status was accepted")
	}
}

// --- fixtures ---------------------------------------------------------------

func quotePlan() *janusv1.SagaBegin {
	return &janusv1.SagaBegin{
		SagaId: testSaga,
		Mode:   "supervised",
		Intent: &janusv1.Intent{
			IntentId:   "in_orchd",
			Principal:  testPrincipal,
			Originator: "human:desk@bank",
			MandateRef: "mandate:payments",
			Scope:      "quote one payment",
		},
		Plan: []*janusv1.PlannedStep{{
			StepId: "st_quote", Participant: "tool_payments", Action: "payments.quote",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
		}},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
	}
}

// newServer returns a running orchd over a fresh evidence directory whose
// registry already holds an active manifest for tool_payments.
func newServer(t *testing.T) (*orchd.Server, string) {
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
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: policy,
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

// registerManifest writes an active manifest into the log before the daemon
// opens it. It is a separate process in a deployment — the registry CLI — and
// doing it here the same way keeps the daemon's own admission honest: it reads
// what is in the log rather than what a test handed it.
func registerManifest(t *testing.T, dir string, signer *keys.Signer) {
	t.Helper()
	registerManifestAt(t, dir, signer, time.Time{}, nil)
}

// registerManifestAt is registerManifest with the registry history written as
// of a given time, and with revalidation triggers on the manifest.
//
// The clock is injectable so a test can produce a genuinely old evaluation
// rather than manipulate the daemon's own clock: what a scheduled revalidation
// reacts to is an anchor in the log, and a test that faked "now" instead would
// be testing a situation that cannot happen.
func registerManifestAt(t *testing.T, dir string, signer *keys.Signer,
	at time.Time, triggers []string) {

	t.Helper()
	opts := evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone}
	if !at.IsZero() {
		opts.Clock = evidence.NewClockWithSource(func() time.Time { return at })
	}
	app, err := evidence.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	trust := registry.TrustStore{}
	trust.Trust(testPrincipal, signer.Public())

	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_registry", Principal: testPrincipal, Kind: "SYSTEM",
	}, registry.New(), trust)

	m := paymentsManifest()
	m.Risk.RevalidationTriggers = triggers
	sig, err := registry.Sign(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := rec.Register(ctx, m, sig); err != nil {
		t.Fatal(err)
	}
	// The evaluation is run for real rather than asserted. A manifest that has
	// not demonstrated its claims against doubles is a claim that survived no
	// test, and activating one here would make the daemon's admission check
	// meaningless.
	report, err := registry.Evaluate(ctx, m, paymentsDoubles())
	if err != nil {
		t.Fatal(err)
	}
	if !report.GetPassed() {
		t.Fatalf("the test manifest does not pass its own conformance:\n%s",
			registry.ReportText(report))
	}
	if err := rec.Evaluate(ctx, "tool_payments", "1.0.0", report); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, "tool_payments", "1.0.0"); err != nil {
		t.Fatal(err)
	}
}

func paymentsManifest() *registry.Manifest {
	return &registry.Manifest{
		Version: "1.0.0",
		Identity: registry.Identity{
			ParticipantID: "tool_payments", Kind: "TOOL", Principal: testPrincipal,
		},
		Runtime: registry.Runtime{ModelID: "none", PromptBundleHash: "blake3:prompt-v1"},
		Actions: []registry.Action{
			{Name: "payments.quote", EffectClass: "PURE"},
			{
				Name: "payments.wire", EffectClass: "COMPENSABLE",
				Compensation: &registry.Compensation{
					Action: "payments.refund", MaxDelaySeconds: 72 * 3600,
					ResidualEffects: "the statement line remains",
				},
				Idempotency: &registry.Idempotency{KeyRecipe: "account,amount,intent_id"},
				Limits: &registry.Limits{
					MaxAmount: 10000, AmountField: "amount", Currency: "EUR",
				},
			},
			{
				Name: "payments.refund", EffectClass: "REVERSIBLE",
				Compensation: &registry.Compensation{Action: "payments.wire"},
				Idempotency:  &registry.Idempotency{KeyRecipe: "account,amount,intent_id"},
			},
			{
				Name: "notify.email", EffectClass: "IRREVERSIBLE_GATED",
				Idempotency: &registry.Idempotency{KeyRecipe: "recipient,subject,intent_id"},
			},
		},
		Risk: registry.Risk{
			Tier:                 2,
			RevalidationTriggers: []string{registry.TriggerModelChange, registry.TriggerActionChange},
		},
		Jurisdiction: registry.Jurisdiction{DeployableIn: []string{"EU"}, DataResidency: "EU"},
	}
}

func paymentsDoubles() *registry.Doubles {
	return registry.NewDoubles("payments-sandbox/honest").
		With("payments.wire", registry.Double{Deltas: map[string]int64{"balance": -100}}).
		With("payments.refund", registry.Double{Deltas: map[string]int64{"balance": 100}}).
		With("notify.email", registry.Double{Deltas: map[string]int64{"sent": 1}}).
		With("payments.quote", registry.Double{})
}

// prepareStep is the participant claiming a step and saying what it will do.
// A hosted coordinator does not prepare a step on its own: the declaration is
// bound into the prepare and judged by the step's gate, so it has to come
// first.
func prepareStep(t *testing.T, s *orchd.Server, sagaID, stepID string) uint32 {
	t.Helper()
	resp, err := s.PrepareStep(context.Background(), &janusv1.PrepareStepRequest{
		SagaId: sagaID, StepId: stepID,
	})
	if err != nil {
		t.Fatalf("preparing %s/%s: %v", sagaID, stepID, err)
	}
	if resp.GetStatus() != janusv1.PrepareStatus_PREPARE_STATUS_PREPARED {
		t.Fatalf("preparing %s/%s: %s — %s", sagaID, stepID, resp.GetStatus(), resp.GetReason())
	}
	return resp.GetAttempt()
}

func getSaga(t *testing.T, s *orchd.Server, id string) *janusv1.SagaProjection {
	t.Helper()
	resp, err := s.GetSaga(context.Background(), &janusv1.GetSagaRequest{SagaId: id})
	if err != nil {
		t.Fatalf("reading saga %q: %v", id, err)
	}
	return resp.GetSaga()
}

func stepOf(t *testing.T, p *janusv1.SagaProjection, id string) *janusv1.StepProjection {
	t.Helper()
	for _, st := range p.GetSteps() {
		if st.GetStepId() == id {
			return st
		}
	}
	t.Fatalf("saga %q has no step %q in its projection", p.GetSagaId(), id)
	return nil
}

func containsText(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestTwoClientsBeginningOneSagaProduceOneSaga is the race a single-caller test
// cannot see.
//
// Both clients look, both find nothing, both append: one intent, two starts,
// and a log that can never be replayed into a single truth. It costs one lock
// to prevent and shows up once under load if that lock is missing.
func TestTwoClientsBeginningOneSagaProduceOneSaga(t *testing.T) {
	s, dir := newServer(t)
	ctx := context.Background()

	const callers = 8
	errs := make(chan error, callers)
	start := make(chan struct{})
	for range callers {
		go func() {
			<-start
			_, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{Begin: quotePlan()})
			errs <- err
		}()
	}
	close(start)

	var accepted int
	for range callers {
		if err := <-errs; err == nil {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("%d of %d concurrent begins were accepted, want exactly 1", accepted, callers)
	}

	// The count that actually matters is in the log, not in the responses: a
	// refused caller could still have appended before it was refused.
	events, err := saga.LoadEvents(dir, testSaga)
	if err != nil {
		t.Fatal(err)
	}
	var begins int
	for _, e := range events {
		if e.Kind == evidence.KindSagaBegin {
			begins++
		}
	}
	if begins != 1 {
		t.Fatalf("the log holds %d SAGA_BEGIN records for one saga id; the projection "+
			"can never be replayed into a single truth", begins)
	}
}

// TestResolveParticipantSaysWhatTheManifestDeclares is what lets an SDK refuse
// its own contradiction before a saga begins.
//
// A client cannot read the log — that is the whole point of the service — so
// without this it could only learn that its declared effect class contradicts
// the manifest by being refused at admission. Correct, but late: by then the
// saga exists and somebody is reading a refusal instead of a type error.
func TestResolveParticipantSaysWhatTheManifestDeclares(t *testing.T) {
	s, _ := newServer(t)

	resp, err := s.ResolveParticipant(context.Background(), &janusv1.ResolveParticipantRequest{
		ParticipantId: "tool_payments", Version: "1.0.0",
	})
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	byName := map[string]*janusv1.DeclaredAction{}
	for _, a := range resp.GetActions() {
		byName[a.GetName()] = a
	}
	if got := byName["payments.quote"].GetEffectClass(); got != janusv1.EffectClass_EFFECT_CLASS_PURE {
		t.Fatalf("payments.quote resolves as %s, want PURE", got)
	}
	wire := byName["payments.wire"]
	if got := wire.GetEffectClass(); got != janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE {
		t.Fatalf("payments.wire resolves as %s, want COMPENSABLE", got)
	}
	if wire.GetCompensationAction() != "payments.refund" {
		t.Fatalf("payments.wire names %q as its inverse, want payments.refund — a client "+
			"checking it declares a compensation has nothing to check against",
			wire.GetCompensationAction())
	}
	if resp.GetState() != "ACTIVE" {
		t.Fatalf("state is %q, want ACTIVE", resp.GetState())
	}
}

// TestResolvingAnUnpinnedVersionIsRefused. A saga pins a version, so "whatever
// is active now" answers a different question from the one it asks.
func TestResolvingAnUnpinnedVersionIsRefused(t *testing.T) {
	s, _ := newServer(t)
	if _, err := s.ResolveParticipant(context.Background(),
		&janusv1.ResolveParticipantRequest{ParticipantId: "tool_payments"}); err == nil {
		t.Fatal("a resolve with no version was accepted")
	}
}

// TestResolveParticipantReportsAWithdrawnVersionAsWithdrawn.
//
// A suspended version still declares what it declares, so a client checking
// only the effect classes would pass and then be refused at admission. The
// state is what lets it refuse for the right reason, and it is why the registry
// is folded on every call rather than cached: a version can be withdrawn
// between one saga and the next.
func TestResolveParticipantReportsAWithdrawnVersionAsWithdrawn(t *testing.T) {
	s := newServerWithWithdrawnManifest(t)

	resp, err := s.ResolveParticipant(context.Background(), &janusv1.ResolveParticipantRequest{
		ParticipantId: "tool_payments", Version: "1.0.0",
	})
	if err != nil {
		t.Fatalf("resolving a suspended version should still answer: %v", err)
	}
	if resp.GetState() != "SUSPENDED" {
		t.Fatalf("state is %q, want SUSPENDED — a client told only the effect classes "+
			"would pin a withdrawn version and find out at admission", resp.GetState())
	}
	if len(resp.GetActions()) == 0 {
		t.Fatal("a withdrawn version still declares what it declared; answering with " +
			"nothing would make it look like a different kind of refusal")
	}
}

// newServerWithWithdrawnManifest registers the manifest, suspends it, and only
// then starts the daemon.
//
// In that order because the daemon holds the writer lock for as long as it
// runs: withdrawing a version is an operator action taken through the registry
// CLI against a directory nobody is writing, which is exactly what this does.
func newServerWithWithdrawnManifest(t *testing.T) *orchd.Server {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	withdraw(t, dir, signer)

	policy, err := gate.LoadPolicyFile("../../docs/policy/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: policy,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func withdraw(t *testing.T, dir string, signer *keys.Signer) {
	t.Helper()
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	events, err := registry.LoadEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Fold(events)
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust(testPrincipal, signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_registry", Principal: testPrincipal, Kind: "SYSTEM",
	}, reg, trust)
	if err := rec.Suspend(context.Background(), "tool_payments", "1.0.0",
		"withdrawn for this test"); err != nil {
		t.Fatal(err)
	}
}
