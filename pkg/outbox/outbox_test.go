package outbox_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

var participant = evidence.ParticipantRef{
	ID: "ag_outbox", ManifestVersion: "1.0.0", Principal: "pr_test",
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

// target is a stand-in receiving system that honours idempotency keys, which is
// the half of exactly-once that does not belong to Janus.
type target struct {
	mu sync.Mutex
	// applied counts *distinct* effects applied, keyed by idempotency key. This
	// is the number that must be one: how many times the effect really happened
	// in the receiving system, not how many times Janus asked.
	applied map[string]int
	// attempts counts every call, including ones absorbed as duplicates.
	attempts int
	// failFor makes the first n attempts fail.
	failFor int
	// retryable controls whether those failures are reported as transient.
	retryable bool
	// hardFail makes every attempt fail forever.
	hardFail bool
}

func newTarget() *target { return &target{applied: map[string]int{}, retryable: true} }

func (tg *target) Deliver(_ context.Context, e outbox.Effect) (outbox.Receipt, error) {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	tg.attempts++

	if tg.hardFail || tg.attempts <= tg.failFor {
		return outbox.Receipt{Retryable: tg.retryable, Message: "target unavailable"},
			errors.New("target unavailable")
	}
	if _, seen := tg.applied[e.IdemKey]; seen {
		// The receiver recognises the key and does not apply the effect twice.
		return outbox.Receipt{Ref: "receipt/" + e.IdemKey, Duplicate: true}, nil
	}
	tg.applied[e.IdemKey] = 1
	return outbox.Receipt{Ref: "receipt/" + e.IdemKey}, nil
}

func (tg *target) appliedCount() int {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return len(tg.applied)
}

func (tg *target) attemptCount() int {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return tg.attempts
}

// fixedAuthority is a commit authority that can be told to lie, so tests can
// establish what the outbox does and does not take on trust.
type fixedAuthority struct {
	root      []byte
	committed bool
	err       error
}

func (a fixedAuthority) Committed(context.Context, string) ([]byte, bool, error) {
	return a.root, a.committed, a.err
}

func heldEffect(id, sagaID, stepID string) *janusv1.EffectHeld {
	return &janusv1.EffectHeld{
		EffectId: id, SagaId: sagaID, StepId: stepID,
		Target: "payments", Action: "transfer", IdemKey: "idem-" + id,
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
	}
}

// releaser builds a releaser over a log with one target.
func releaser(t *testing.T, app *evidence.Appender, auth outbox.CommitAuthority,
	tg *target, tune func(*outbox.Options)) *outbox.Releaser {
	t.Helper()
	opts := outbox.Options{
		Appender: app, Participant: participant, Authority: auth,
		Deliverers: map[string]outbox.Deliverer{"payments": tg},
	}
	if tune != nil {
		tune(&opts)
	}
	r, err := outbox.NewReleaser(opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func loadState(t *testing.T, dir string) outbox.State {
	t.Helper()
	s, err := outbox.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ---------------------------------------------------------------------------
// I4: nothing leaves before the saga commits
// ---------------------------------------------------------------------------

// The whole purpose of the package, stated as a test: a held effect does not
// reach the world while its saga is still running.
func TestAnEffectDoesNotFireBeforeItsSagaCommits(t *testing.T) {
	app, dir := newLog(t)
	ctx := context.Background()
	tg := newTarget()
	r := releaser(t, app, fixedAuthority{committed: false}, tg, nil)

	if _, err := r.Hold(ctx, heldEffect("ef_1", "sg_1", "s1")); err != nil {
		t.Fatal(err)
	}
	s := loadState(t, dir)
	e, ok := s.Effect("ef_1")
	if !ok {
		t.Fatal("the held effect is not in the projection")
	}
	if e.State != outbox.StateHeld {
		t.Fatalf("a freshly held effect is %s, want HELD", e.State)
	}

	err := r.Release(ctx, *e)
	if !errors.Is(err, outbox.ErrNotCommitted) {
		t.Fatalf("release before commit returned %v, want ErrNotCommitted", err)
	}
	if tg.attemptCount() != 0 {
		t.Fatalf("the target was contacted %d time(s) before the saga committed", tg.attemptCount())
	}
	// And nothing was written that would suggest otherwise.
	if got := loadState(t, dir).Effects["ef_1"]; got.Attempts != 0 {
		t.Fatalf("the log records %d attempt(s) for an effect that was never attempted", got.Attempts)
	}
}

// A committed saga with no evidence root is not an authority. Accepting it
// would mean the release record cited something nobody could look up.
func TestACommitWithNoEvidenceRootIsNotAnAuthority(t *testing.T) {
	app, dir := newLog(t)
	ctx := context.Background()
	tg := newTarget()
	r := releaser(t, app, fixedAuthority{committed: true, root: nil}, tg, nil)

	if _, err := r.Hold(ctx, heldEffect("ef_1", "sg_1", "s1")); err != nil {
		t.Fatal(err)
	}
	e := loadState(t, dir).Effects["ef_1"]
	if err := r.Release(ctx, *e); err == nil {
		t.Fatal("an effect was released on a commit with no evidence root")
	}
	if tg.attemptCount() != 0 {
		t.Fatal("the target was contacted on an authority that pointed at nothing")
	}
}

// The real authority reads the log, and must say no at every saga state that is
// not COMMITTED — including the ones that look nearly done.
func TestLogAuthorityRefusesEverySagaStateExceptCommitted(t *testing.T) {
	app, dir := newLog(t)
	ctx := context.Background()
	auth := outbox.NewLogAuthority(dir)

	r := saga.NewRunner(app, participant)
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1", Intent: &janusv1.Intent{IntentId: "in"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "s1", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		GatePolicyVersion: "blake3:test",
		GatePlan: []*janusv1.StepGates{{
			StepId: "s1", RuleId: "wires",
			Require: []*janusv1.GateRequirement{{
				Id:    "approval",
				Gate:  janusv1.GateType_GATE_TYPE_POLICY,
				Phase: janusv1.GatePhase_GATE_PHASE_PRE_RELEASE,
				Check: &janusv1.GateRequirement_Policy{
					Policy: &janusv1.PolicyCheck{Expr: "true"},
				},
			}},
		}},
	}
	steps := []struct {
		name string
		run  func() error
	}{
		{"CREATED", func() error { _, err := r.Begin(ctx, begin); return err }},
		{"RUNNING", func() error {
			_, err := r.PrepareStep(ctx, &janusv1.StepPrepare{SagaId: "sg_1", StepId: "s1"})
			return err
		}},
		{"GATED", func() error {
			_, err := r.StepResult(ctx, &janusv1.StepResult{
				SagaId: "sg_1", StepId: "s1",
				Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			})
			return err
		}},
		{"gate passed", func() error {
			_, err := r.Gate(ctx, &janusv1.GateVerdict{
				SagaId: "sg_1", StepId: "s1", Verdict: janusv1.Verdict_VERDICT_PASS,
				Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
				Decided: []string{"approval"},
			})
			return err
		}},
		{"SEALING", func() error {
			_, err := r.Seal(ctx, &janusv1.SealRequest{SagaId: "sg_1"})
			return err
		}},
	}

	for _, step := range steps {
		if err := step.run(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		root, ok, err := auth.Committed(ctx, "sg_1")
		if err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if ok {
			t.Fatalf("the authority permitted a release while the saga was at %q", step.name)
		}
		if root != nil {
			t.Fatalf("%s: a refusal returned a root anyway", step.name)
		}
	}

	// SEALING is the state that matters most here: every step is sealed, the
	// footprint is declared, and it still is not a commit.
	if _, err := r.Commit(ctx, &janusv1.Commit{
		SagaId: "sg_1", EvidenceRoot: []byte("root-1234"),
	}); err != nil {
		t.Fatal(err)
	}
	root, ok, err := auth.Committed(ctx, "sg_1")
	if err != nil || !ok {
		t.Fatalf("the authority refused a committed saga: ok=%v err=%v", ok, err)
	}
	if string(root) != "root-1234" {
		t.Fatalf("authority returned root %q, want the saga's commit root", root)
	}
}

// An effect naming a saga that does not exist must not be releasable. A missing
// saga is not a transient miss to retry past.
func TestAnEffectForANonexistentSagaIsRefused(t *testing.T) {
	_, dir := newLog(t)
	if _, _, err := outbox.NewLogAuthority(dir).Committed(context.Background(), "sg_ghost"); err == nil {
		t.Fatal("the authority accepted a saga with no log")
	}
}

// ---------------------------------------------------------------------------
// I1: evidence before effect
// ---------------------------------------------------------------------------

// If the evidence layer cannot record the attempt, the attempt does not happen.
// This is fail-closed at the point where it costs something.
func TestAnEffectDoesNotFireWhenTheAttemptCannotBeRecorded(t *testing.T) {
	app, dir := newLog(t)
	ctx := context.Background()
	tg := newTarget()
	r := releaser(t, app, fixedAuthority{committed: true, root: []byte("root")}, tg, nil)

	if _, err := r.Hold(ctx, heldEffect("ef_1", "sg_1", "s1")); err != nil {
		t.Fatal(err)
	}
	e := loadState(t, dir).Effects["ef_1"]

	// Take the evidence log away. An appender that is closed refuses writes,
	// which is what a full disk or a lost KMS looks like from here.
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	err := r.Release(ctx, *e)
	if err == nil {
		t.Fatal("an effect was released while the evidence log was unavailable")
	}
	if tg.attemptCount() != 0 {
		t.Fatalf("the target was contacted %d time(s) with no durable record of the attempt",
			tg.attemptCount())
	}
	if !strings.Contains(err.Error(), "recorded first") {
		t.Errorf("the error does not explain the ordering that was violated: %v", err)
	}
}

// A receipt for an attempt that was never announced is invalid. This is I1 seen
// from the projection: it means an effect reached the world with no durable
// evidence preceding it.
func TestAReceiptWithoutAnAnnouncedAttemptIsRejected(t *testing.T) {
	held := mustMarshal(t, heldEffect("ef_1", "sg_1", "s1"))
	s, err := outbox.Apply(outbox.State{}, outbox.Event{
		Seq: 1, Kind: evidence.KindEffectHeld, Payload: held,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = outbox.Apply(s, outbox.Event{
		Seq: 2, Kind: evidence.KindEffectDelivered,
		Payload: mustMarshal(t, &janusv1.EffectDelivered{
			EffectId: "ef_1", SagaId: "sg_1", Attempt: 1,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}),
	})
	if !errors.Is(err, outbox.ErrTransition) {
		t.Fatalf("a receipt with no announced attempt was accepted: %v", err)
	}
}

// Attempt numbers must be consecutive. A gap means an attempt was made whose
// announcement is missing, which is the exact situation I1 forbids.
func TestAGapInAttemptNumbersIsRejected(t *testing.T) {
	s := heldState(t, "ef_1")
	_, err := outbox.Apply(s, outbox.Event{
		Seq: 2, Kind: evidence.KindEffectReleasing,
		Payload: mustMarshal(t, &janusv1.EffectReleasing{
			EffectId: "ef_1", SagaId: "sg_1", Attempt: 2,
			CommitRoot: []byte("root"), IdemKey: "idem-ef_1",
		}),
	})
	if !errors.Is(err, outbox.ErrTransition) {
		t.Fatalf("an attempt numbered 2 was accepted with no attempt 1: %v", err)
	}
}

// ---------------------------------------------------------------------------
// exactly-once
// ---------------------------------------------------------------------------

// An effect that is already delivered cannot be released again. This is the
// second half of I4 in the state machine.
func TestADeliveredEffectCannotBeReleasedAgain(t *testing.T) {
	app, dir := newLog(t)
	ctx := context.Background()
	tg := newTarget()
	r := releaser(t, app, fixedAuthority{committed: true, root: []byte("root")}, tg, nil)

	if _, err := r.Hold(ctx, heldEffect("ef_1", "sg_1", "s1")); err != nil {
		t.Fatal(err)
	}
	e := loadState(t, dir).Effects["ef_1"]
	if err := r.Release(ctx, *e); err != nil {
		t.Fatal(err)
	}

	s := loadState(t, dir)
	if got := s.Effects["ef_1"].State; got != outbox.StateDelivered {
		t.Fatalf("effect is %s after a successful release, want DELIVERED", got)
	}

	// Asking again is a no-op rather than a second delivery.
	if err := r.Release(ctx, *s.Effects["ef_1"]); err != nil {
		t.Fatalf("releasing a delivered effect returned an error rather than doing nothing: %v", err)
	}
	if tg.appliedCount() != 1 || tg.attemptCount() != 1 {
		t.Fatalf("target applied %d effect(s) over %d attempt(s), want 1 over 1",
			tg.appliedCount(), tg.attemptCount())
	}

	// And the projection refuses a forged second delivery outright.
	_, err := outbox.Apply(s, outbox.Event{
		Seq: 99, Kind: evidence.KindEffectReleasing,
		Payload: mustMarshal(t, &janusv1.EffectReleasing{
			EffectId: "ef_1", SagaId: "sg_1", Attempt: 2,
			CommitRoot: []byte("root"), IdemKey: "idem-ef_1",
		}),
	})
	if !errors.Is(err, outbox.ErrTransition) {
		t.Fatalf("a delivered effect accepted a second release: %v", err)
	}
}

// The retry path: a transient failure is retried under the same idempotency
// key, and the receiving system applies the effect once.
func TestARetriedEffectIsAppliedOnceByTheReceiver(t *testing.T) {
	app, dir := newLog(t)
	ctx := context.Background()
	tg := newTarget()
	tg.failFor = 2
	r := releaser(t, app, fixedAuthority{committed: true, root: []byte("root")}, tg, nil)

	if _, err := r.Hold(ctx, heldEffect("ef_1", "sg_1", "s1")); err != nil {
		t.Fatal(err)
	}

	for range 3 {
		s := loadState(t, dir)
		e := s.Effects["ef_1"]
		if e.State == outbox.StateDelivered {
			break
		}
		_ = r.Release(ctx, *e)
	}

	final := loadState(t, dir).Effects["ef_1"]
	if final.State != outbox.StateDelivered {
		t.Fatalf("effect is %s after retries, want DELIVERED (last error %q)",
			final.State, final.LastError)
	}
	if tg.appliedCount() != 1 {
		t.Fatalf("the receiver applied the effect %d times, want once", tg.appliedCount())
	}
	// The log is honest about how many times it asked.
	if final.Attempts != 3 {
		t.Fatalf("the log records %d attempts, want 3", final.Attempts)
	}
}

// The idempotency key is fixed when the effect is held. A retry under a
// different key would be a second instruction wearing the first one's name.
func TestARetryUnderADifferentIdempotencyKeyIsRejected(t *testing.T) {
	s := heldState(t, "ef_1")
	_, err := outbox.Apply(s, outbox.Event{
		Seq: 2, Kind: evidence.KindEffectReleasing,
		Payload: mustMarshal(t, &janusv1.EffectReleasing{
			EffectId: "ef_1", SagaId: "sg_1", Attempt: 1,
			CommitRoot: []byte("root"), IdemKey: "a-different-key",
		}),
	})
	if !errors.Is(err, outbox.ErrTransition) {
		t.Fatalf("a release under a substituted idempotency key was accepted: %v", err)
	}
}

// An effect with no idempotency key cannot be held at all, because it could
// never be retried safely.
func TestAnEffectWithNoIdempotencyKeyIsRefused(t *testing.T) {
	bad := heldEffect("ef_1", "sg_1", "s1")
	bad.IdemKey = ""
	_, err := outbox.Apply(outbox.State{}, outbox.Event{
		Seq: 1, Kind: evidence.KindEffectHeld, Payload: mustMarshal(t, bad),
	})
	if !errors.Is(err, outbox.ErrTransition) {
		t.Fatalf("an effect with no idempotency key was held: %v", err)
	}
}

// An immediate irreversible effect cannot be held: it fires when its step runs,
// so calling it held would be a false statement about where it is.
func TestAnImmediateIrreversibleEffectCannotBeHeld(t *testing.T) {
	app, _ := newLog(t)
	tg := newTarget()
	r := releaser(t, app, fixedAuthority{committed: true, root: []byte("root")}, tg, nil)

	msg := heldEffect("ef_1", "sg_1", "s1")
	msg.EffectClass = janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE
	if _, err := r.Hold(context.Background(), msg); err == nil {
		t.Fatal("an IRREVERSIBLE_IMMEDIATE effect was accepted into the outbox")
	}
}

// ---------------------------------------------------------------------------
// quarantine and breakers
// ---------------------------------------------------------------------------

// A target that will not accept the effect gets a bounded number of attempts,
// then the effect is frozen for a human rather than retried forever.
func TestAnUndeliverableEffectIsQuarantinedRatherThanRetriedForever(t *testing.T) {
	app, dir := newLog(t)
	ctx := context.Background()
	tg := newTarget()
	tg.hardFail = true
	// A generous breaker, so this test measures the attempt budget rather than
	// the breaker.
	breakers := outbox.NewBreakers(outbox.BreakerConfig{Threshold: 1000})
	r := releaser(t, app, fixedAuthority{committed: true, root: []byte("root")}, tg,
		func(o *outbox.Options) { o.MaxAttempts = 3; o.Breakers = breakers })

	if _, err := r.Hold(ctx, heldEffect("ef_1", "sg_1", "s1")); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		s := loadState(t, dir)
		e := s.Effects["ef_1"]
		if e.State == outbox.StateQuarantined {
			break
		}
		_ = r.Release(ctx, *e)
	}

	final := loadState(t, dir).Effects["ef_1"]
	if final.State != outbox.StateQuarantined {
		t.Fatalf("effect is %s after exhausting its attempts, want QUARANTINED", final.State)
	}
	if final.Attempts != 3 {
		t.Fatalf("the target was attempted %d times, want the 3 permitted", final.Attempts)
	}
	if tg.appliedCount() != 0 {
		t.Fatal("a failing target somehow applied the effect")
	}
	if q := outbox.Quarantined(loadState(t, dir)); len(q) != 1 {
		t.Fatalf("quarantine list has %d effect(s), want 1", len(q))
	}
}

// The breaker's purpose: a target that is down must not consume the attempt
// budgets of every effect waiting on it, because those budgets are what stand
// between a transient outage and a pile of frozen payments.
func TestABreakerProtectsAttemptBudgetsDuringAnOutage(t *testing.T) {
	app, dir := newLog(t)
	ctx := context.Background()
	tg := newTarget()
	tg.hardFail = true

	now := time.Now()
	breakers := outbox.NewBreakers(outbox.BreakerConfig{
		Threshold: 2, Cooldown: time.Minute, Now: func() time.Time { return now },
	})
	r := releaser(t, app, fixedAuthority{committed: true, root: []byte("root")}, tg,
		func(o *outbox.Options) { o.MaxAttempts = 10; o.Breakers = breakers })

	for _, id := range []string{"ef_1", "ef_2", "ef_3", "ef_4"} {
		if _, err := r.Hold(ctx, heldEffect(id, "sg_1", "s1")); err != nil {
			t.Fatal(err)
		}
	}

	s := loadState(t, dir)
	for _, e := range outbox.Pending(s) {
		_ = r.Release(ctx, *e)
	}

	if got := breakers.State("payments"); got != outbox.BreakerOpen {
		t.Fatalf("breaker is %s after repeated failures, want OPEN", got)
	}
	// Only the attempts before the breaker opened were spent.
	if tg.attemptCount() != 2 {
		t.Fatalf("the failing target was contacted %d times; the breaker should have stopped it "+
			"after 2", tg.attemptCount())
	}
	after := loadState(t, dir)
	spent := 0
	for _, e := range after.Effects {
		spent += int(e.Attempts)
	}
	if spent != 2 {
		t.Fatalf("%d attempts were spent across the four effects, want 2", spent)
	}

	// After the cooldown, exactly one effect probes the target.
	now = now.Add(2 * time.Minute)
	tg.hardFail = false
	probed := tg.attemptCount()
	for _, e := range outbox.Pending(loadState(t, dir)) {
		_ = r.Release(ctx, *e)
	}
	if tg.attemptCount() <= probed {
		t.Fatal("after the cooldown no attempt was allowed through")
	}
	if got := breakers.State("payments"); got != outbox.BreakerClosed {
		t.Fatalf("breaker is %s after a successful trial, want CLOSED", got)
	}
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

// The auditor's question, answerable from the log alone: was anything released
// without a commit that authorised it?
func TestAuditCatchesAReleaseWithNoCommitBehindIt(t *testing.T) {
	// A saga that never committed, and an effect that claims it did.
	sagas := map[string]saga.State{
		"sg_1": {SagaID: "sg_1", Status: saga.StatusCompensating, Steps: map[string]*saga.Step{}},
	}
	s := releasedState(t, "ef_1", []byte("forged-root"))

	findings := outbox.Audit(s, sagas)
	crit := outbox.Unauthorised(findings)
	if len(crit) == 0 {
		t.Fatalf("an effect released against a COMPENSATING saga was not reported: %v", findings)
	}
	if !strings.Contains(crit[0].Detail, "without a commit authorising it") {
		t.Errorf("the finding does not name the problem: %s", crit[0])
	}
}

// A release citing a root that does not match the commit in the log is a
// forgery, and it is detectable afterwards by anyone.
func TestAuditCatchesAMismatchedCommitRoot(t *testing.T) {
	sagas := map[string]saga.State{
		"sg_1": {
			SagaID: "sg_1", Status: saga.StatusCommitted,
			EvidenceRoot: []byte("the-real-root"), Steps: map[string]*saga.Step{},
		},
	}
	s := releasedState(t, "ef_1", []byte("a-different-root"))

	if crit := outbox.Unauthorised(outbox.Audit(s, sagas)); len(crit) == 0 {
		t.Fatal("a release citing the wrong commit root was accepted by the audit")
	}
}

func TestAuditIsQuietOnAProperRelease(t *testing.T) {
	sagas := map[string]saga.State{
		"sg_1": {
			SagaID: "sg_1", Status: saga.StatusCommitted, EvidenceRoot: []byte("root"),
			Order: []string{"s1"},
			Steps: map[string]*saga.Step{"s1": {
				ID: "s1", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
			}},
		},
	}
	s := releasedState(t, "ef_1", []byte("root"))
	if f := outbox.Audit(s, sagas); len(f) != 0 {
		t.Fatalf("a correctly authorised release produced findings: %v", f)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func heldState(t *testing.T, effectID string) outbox.State {
	t.Helper()
	s, err := outbox.Apply(outbox.State{}, outbox.Event{
		Seq: 1, Kind: evidence.KindEffectHeld,
		Payload: mustMarshal(t, heldEffect(effectID, "sg_1", "s1")),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// releasedState builds a projection where an effect has been delivered under a
// given commit root.
func releasedState(t *testing.T, effectID string, root []byte) outbox.State {
	t.Helper()
	s := heldState(t, effectID)
	s, err := outbox.Apply(s, outbox.Event{
		Seq: 2, Kind: evidence.KindEffectReleasing,
		Payload: mustMarshal(t, &janusv1.EffectReleasing{
			EffectId: effectID, SagaId: "sg_1", Attempt: 1,
			CommitRoot: root, IdemKey: "idem-" + effectID,
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err = outbox.Apply(s, outbox.Event{
		Seq: 3, Kind: evidence.KindEffectDelivered,
		Payload: mustMarshal(t, &janusv1.EffectDelivered{
			EffectId: effectID, SagaId: "sg_1", Attempt: 1,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustMarshal(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
