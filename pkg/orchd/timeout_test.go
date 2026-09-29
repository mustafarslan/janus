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
	"github.com/mustafarslan/janus/pkg/saga"
)

// The daemon expiring a gate nobody answered.
//
// The composition's half is tested in pkg/gate against hand-recorded answers.
// This is the half that decides *when*: a saga held at a gate returns ErrWaiting
// and then nothing runs, so without the ticker there is no process to notice a
// deadline pass. Deleting the scan makes these fail, which is the point of
// having them.

func timeoutServer(t *testing.T, seconds uint32, tick time.Duration) (*orchd.Server, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)

	p := &gate.Policy{
		ID: "orchd.timeout.test",
		Rules: []gate.Rule{{
			ID:    "irreversible-needs-a-person",
			Match: gate.Match{EffectClasses: []string{"IRREVERSIBLE_GATED"}},
			Require: []gate.Requirement{{
				ID: "notify-four-eyes", Gate: gate.GateHuman, Phase: gate.PhasePreRelease,
				TimeoutSeconds: seconds,
				Human:          &gate.HumanSpec{Roles: []string{"credit-officer"}, Quorum: 1},
			}},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: p,
		TickInterval: tick,
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

// waitFor polls until cond holds or the deadline passes.
func waitFor(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestTheDaemonRefusesAGateNobodyAnswered.
func TestTheDaemonRefusesAGateNobodyAnswered(t *testing.T) {
	s, dir := timeoutServer(t, 1, 50*time.Millisecond)
	ctx := context.Background()
	beginGatedPlan(t, s, ctx)
	attempt := prepareStep(t, s, notifySaga, "st_notify")
	if _, err := s.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: notifySaga, StepId: "st_notify", Attempt: attempt,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Held, waiting for a person who never comes.
	st := stepOf(t, getSaga(t, s, notifySaga), "st_notify")
	if len(st.GetPendingGates()) == 0 {
		t.Fatal("the step is not waiting for anybody, so there is no deadline to pass")
	}

	waitFor(t, 5*time.Second, "the daemon to refuse the gate on the deadline's behalf", func() bool {
		state, err := saga.ReplaySaga(dir, notifySaga)
		if err != nil {
			return false
		}
		step, ok := state.Step("st_notify")
		if !ok {
			return false
		}
		for _, a := range step.Answers {
			if a.Reason == saga.ExpiryReason {
				return true
			}
		}
		return false
	})

	// And the expiry is the daemon's, not a person's: no human subject, so the
	// record cannot be read as somebody having declined.
	state, err := saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	step, _ := state.Step("st_notify")
	var expiries int
	for _, a := range step.Answers {
		if a.Reason != saga.ExpiryReason {
			continue
		}
		expiries++
		if a.Human {
			t.Error("the expiry was recorded as a human's answer; a clock is not a person")
		}
		if a.Verdict != janusv1.Verdict_VERDICT_FAIL {
			t.Errorf("the expiry is %s; an expiry can only ever refuse", a.Verdict)
		}
	}

	// Idempotence. The ticker fires repeatedly while the saga is still held --
	// nothing unwinds it until something drives it -- so without a guard a
	// person reading this log would find the gate refused dozens of times.
	time.Sleep(300 * time.Millisecond)
	state, err = saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	step, _ = state.Step("st_notify")
	var after int
	for _, a := range step.Answers {
		if a.Reason == saga.ExpiryReason {
			after++
		}
	}
	if after != expiries || after != 1 {
		t.Errorf("the gate was expired %d times and then %d; it should be recorded once",
			expiries, after)
	}
}

// TestAGateWithNoDeadlineIsLeftAlone: zero means wait forever, which is what
// every policy written before this field did, and a ticker that expired those
// would be a breaking change disguised as a feature.
func TestAGateWithNoDeadlineIsLeftAlone(t *testing.T) {
	s, dir := timeoutServer(t, 0, 20*time.Millisecond)
	ctx := context.Background()
	beginGatedPlan(t, s, ctx)
	attempt := prepareStep(t, s, notifySaga, "st_notify")
	if _, err := s.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: notifySaga, StepId: "st_notify", Attempt: attempt,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		},
	}); err != nil {
		t.Fatal(err)
	}

	time.Sleep(300 * time.Millisecond)
	state, err := saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	step, _ := state.Step("st_notify")
	for _, a := range step.Answers {
		if a.Reason == saga.ExpiryReason {
			t.Fatal("a gate with no deadline was expired")
		}
	}
	if !saga.HeldByGate(step) {
		t.Errorf("the step is %s; with no deadline it should still be waiting", step.Status)
	}
}

// TestAnAnsweredGateIsNotExpired: the deadline is for gates nobody answered.
func TestAnAnsweredGateIsNotExpired(t *testing.T) {
	// A long tick, so the answer lands first and the scan sees it.
	s, dir := timeoutServer(t, 1, time.Second)
	ctx := context.Background()
	beginGatedPlan(t, s, ctx)
	attempt := prepareStep(t, s, notifySaga, "st_notify")
	if _, err := s.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: notifySaga, StepId: "st_notify", Attempt: attempt,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordAnswer(ctx, &janusv1.RecordAnswerRequest{
		Answer: &janusv1.GateAnswer{
			SagaId: notifySaga, StepId: "st_notify",
			RequirementId: "notify-four-eyes", Attempt: attempt,
			Actor:   &janusv1.Actor{HumanSubject: "alice"},
			Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"},
		},
	}); err != nil {
		t.Fatalf("recording the approval: %v", err)
	}

	time.Sleep(2500 * time.Millisecond)
	state, err := saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	step, _ := state.Step("st_notify")
	for _, a := range step.Answers {
		if a.Reason == saga.ExpiryReason {
			t.Fatalf("a gate somebody answered was expired anyway: %s", a.Reason)
		}
	}
	// And the approval carried it through rather than leaving it held: a gate
	// that was answered *and* still waiting would expire on some later tick,
	// which is the same bug arriving late.
	if saga.HeldByGate(step) {
		t.Errorf("the step is still held after an approval that satisfies its gate")
	}
}

// An expired gate does not just get written down — the saga moves.
//
// This is the half gate timeouts first shipped without, and the gate-deadline chaos
// scenario is what found it: `expireSaga` recorded the refusal and returned, so
// the saga stayed GATED, still holding its resource frontiers, still an ageing
// row in a queue. That is the situation gate timeouts exist to end, and every
// earlier test passed because they all asserted the *record* rather than what
// happened next.
//
// `RecordAnswer` has driven the saga after appending since Phase 4a, with a
// comment saying why: an answer that is recorded and not acted on looks broken
// to whoever gave it. An expiry is an answer.
func TestAnExpiredGateUnwindsTheSaga(t *testing.T) {
	s, dir := timeoutServer(t, 1, 50*time.Millisecond)
	ctx := context.Background()
	beginGatedPlan(t, s, ctx)
	attempt := prepareStep(t, s, notifySaga, "st_notify")
	if _, err := s.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: notifySaga, StepId: "st_notify", Attempt: attempt,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		},
	}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, 10*time.Second, "the saga to reach a terminal state after its gate expired",
		func() bool {
			state, err := saga.ReplaySaga(dir, notifySaga)
			if err != nil {
				return false
			}
			return state.Terminal()
		})

	state, err := saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	if state.Status == saga.StatusCommitted {
		t.Fatalf("the saga committed after nobody answered its gate")
	}
}
