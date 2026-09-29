package saga_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

// planWith builds a saga plan with explicit dependencies and retry budgets.
func planWith(steps ...*janusv1.PlannedStep) *janusv1.SagaBegin {
	return &janusv1.SagaBegin{SagaId: "sg", Intent: &janusv1.Intent{IntentId: "in"}, Plan: steps}
}

func pureStep(id string, deps ...string) *janusv1.PlannedStep {
	return &janusv1.PlannedStep{
		StepId: id, EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE, DependsOn: deps,
	}
}

func begun(t *testing.T, begin *janusv1.SagaBegin) saga.State {
	t.Helper()
	s, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// step drives one step through prepare and an OK result.
func step(t *testing.T, s saga.State, id string, seq uint64) saga.State {
	t.Helper()
	s, err := saga.Apply(s, ev(t, seq, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: id}))
	if err != nil {
		t.Fatalf("prepare %s: %v", id, err)
	}
	s, err = saga.Apply(s, ev(t, seq+1, evidence.KindStepResult, &janusv1.StepResult{
		SagaId: "sg", StepId: id, Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	}))
	if err != nil {
		t.Fatalf("result %s: %v", id, err)
	}
	return s
}

// TestOnlyRootsAreReadyAtFirst.
func TestOnlyRootsAreReadyAtFirst(t *testing.T) {
	s := begun(t, planWith(
		pureStep("a"),
		pureStep("b"),
		pureStep("c", "a"),
		pureStep("d", "a", "b"),
	))

	got := saga.Ready(s)
	if !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("ready is %v, want the two roots", got)
	}
}

// TestParallelBranchesAreOfferedTogether: two independent branches must both be
// available, or the scheduler serialises work that has no reason to be serial.
func TestParallelBranchesAreOfferedTogether(t *testing.T) {
	s := begun(t, planWith(
		pureStep("a1"), pureStep("a2", "a1"),
		pureStep("b1"), pureStep("b2", "b1"),
	))

	if got := saga.Ready(s); !slices.Equal(got, []string{"a1", "b1"}) {
		t.Fatalf("ready is %v, want both branch roots", got)
	}

	s = step(t, s, "a1", 10)
	got := saga.Ready(s)
	if !slices.Contains(got, "a2") || !slices.Contains(got, "b1") {
		t.Fatalf("ready is %v, want a2 unlocked and b1 still available", got)
	}
}

// TestDependentWaitsForTheGateNotJustTheResult: a step whose effect is still
// awaiting a gate might yet be refused, so building on it would mean starting
// work on something that can still be withdrawn.
func TestDependentWaitsForTheGateNotJustTheResult(t *testing.T) {
	s := begun(t, planWith(
		&janusv1.PlannedStep{
			StepId: "pay", EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: "refund",
		},
		pureStep("notify", "pay"),
	))

	s = step(t, s, "pay", 10)
	// "pay" is effectful, so its result leaves it GATED rather than SEALED.
	if got := saga.Ready(s); slices.Contains(got, "notify") {
		t.Fatalf("ready is %v: a dependent started while its dependency was still gated", got)
	}

	s, err := saga.Apply(s, ev(t, 20, evidence.KindGateVerdict, &janusv1.GateVerdict{
		SagaId: "sg", StepId: "pay", Verdict: janusv1.Verdict_VERDICT_PASS,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got := saga.Ready(s); !slices.Contains(got, "notify") {
		t.Fatalf("ready is %v, want notify unlocked once the gate passed", got)
	}
}

// TestRetryBudgetArithmetic pins what MaxRetries means. One retry has to mean
// two attempts, and an off-by-one here would either deny a retry the plan
// promised or grant one it did not.
func TestRetryBudgetArithmetic(t *testing.T) {
	for _, tc := range []struct {
		maxRetries   uint32
		wantAttempts int
	}{
		{maxRetries: 0, wantAttempts: 1},
		{maxRetries: 1, wantAttempts: 2},
		{maxRetries: 3, wantAttempts: 4},
	} {
		s := begun(t, planWith(&janusv1.PlannedStep{
			StepId: "flaky", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
			MaxRetries: tc.maxRetries,
		}))

		attempts := 0
		seq := uint64(10)
		for slices.Contains(saga.Ready(s), "flaky") {
			next, err := saga.Apply(s, ev(t, seq, evidence.KindStepPrepare,
				&janusv1.StepPrepare{SagaId: "sg", StepId: "flaky"}))
			if err != nil {
				break
			}
			attempts++
			seq++
			s, err = saga.Apply(next, ev(t, seq, evidence.KindStepResult, &janusv1.StepResult{
				SagaId: "sg", StepId: "flaky",
				Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_RETRYABLE_ERROR},
			}))
			if err != nil {
				t.Fatal(err)
			}
			seq++
			if attempts > 10 {
				t.Fatalf("maxRetries=%d: the step kept retrying past any sane bound", tc.maxRetries)
			}
		}

		if attempts != tc.wantAttempts {
			t.Errorf("maxRetries=%d gave %d attempts, want %d", tc.maxRetries, attempts, tc.wantAttempts)
		}
		if got := saga.Poisoned(s); !slices.Contains(got, "flaky") {
			t.Errorf("maxRetries=%d: the exhausted step is not reported as poisoned (%v)", tc.maxRetries, got)
		}
	}
}

// TestRetryPastBudgetIsRefusedByTheStateMachine: the scheduler is advice, but
// the state machine is the boundary. A coordinator with a bug must not be able
// to retry forever, because every attempt holds the saga's resources against
// everyone else.
func TestRetryPastBudgetIsRefusedByTheStateMachine(t *testing.T) {
	s := begun(t, planWith(&janusv1.PlannedStep{
		StepId: "flaky", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE, MaxRetries: 1,
	}))

	seq := uint64(10)
	for range 2 {
		var err error
		s, err = saga.Apply(s, ev(t, seq, evidence.KindStepPrepare,
			&janusv1.StepPrepare{SagaId: "sg", StepId: "flaky"}))
		if err != nil {
			t.Fatal(err)
		}
		seq++
		s, err = saga.Apply(s, ev(t, seq, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: "flaky",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_RETRYABLE_ERROR},
		}))
		if err != nil {
			t.Fatal(err)
		}
		seq++
	}

	if _, err := saga.Apply(s, ev(t, seq, evidence.KindStepPrepare,
		&janusv1.StepPrepare{SagaId: "sg", StepId: "flaky"})); !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("got %v, want a third attempt to be refused with one retry budgeted", err)
	}
}

// TestTerminalFailureIsNotRetried: retrying something that failed permanently
// spends the budget on an outcome that will not change.
func TestTerminalFailureIsNotRetried(t *testing.T) {
	s := begun(t, planWith(&janusv1.PlannedStep{
		StepId: "doomed", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE, MaxRetries: 5,
	}))

	s = mustApply(t, s, 10, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "doomed"})
	s = mustApply(t, s, 11, evidence.KindStepResult, &janusv1.StepResult{
		SagaId: "sg", StepId: "doomed",
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_TERMINAL_ERROR},
	})

	if got := saga.Ready(s); slices.Contains(got, "doomed") {
		t.Fatalf("ready is %v: a terminally failed step was offered again despite having budget", got)
	}
	if got := saga.Poisoned(s); !slices.Contains(got, "doomed") {
		t.Fatalf("poisoned is %v, want the terminal failure named", got)
	}
	if _, err := saga.Apply(s, ev(t, 12, evidence.KindStepPrepare,
		&janusv1.StepPrepare{SagaId: "sg", StepId: "doomed"})); err == nil {
		t.Fatal("a terminally failed step was allowed to retry")
	}
}

// TestStalledExplainsWhy: a saga that stops progressing is the hardest thing to
// diagnose from a log, because the absence of events looks the same whatever
// caused it.
func TestStalledExplainsWhy(t *testing.T) {
	s := begun(t, planWith(
		&janusv1.PlannedStep{StepId: "a", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
		pureStep("b", "a"),
	))
	s = mustApply(t, s, 10, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "a"})
	s = mustApply(t, s, 11, evidence.KindStepResult, &janusv1.StepResult{
		SagaId: "sg", StepId: "a",
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_TERMINAL_ERROR},
	})

	stalled := saga.Stalled(s)
	if len(stalled) != 2 {
		t.Fatalf("stalled reports %d steps, want both: %+v", len(stalled), stalled)
	}
	byStep := map[string]saga.Blocked{}
	for _, b := range stalled {
		byStep[b.Step] = b
	}
	if byStep["a"].Reason == "" || byStep["b"].Reason == "" {
		t.Fatalf("stalled steps have no reason: %+v", stalled)
	}
	if !slices.Contains(byStep["b"].WaitingFor, "a") {
		t.Fatalf("b does not report waiting for a: %+v", byStep["b"])
	}

	p := saga.Describe(s)
	if p.CanAdvance {
		t.Fatal("a saga with a terminal failure and nothing running reports it can advance")
	}
}

// TestNoForwardWorkOnceUnwinding: offering steps to a saga that has begun
// undoing itself would add effects to something already being reversed.
func TestNoForwardWorkOnceUnwinding(t *testing.T) {
	s := begun(t, planWith(
		&janusv1.PlannedStep{
			StepId: "pay", EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: "refund",
		},
		pureStep("later"),
	))
	s = step(t, s, "pay", 10)
	s = mustApply(t, s, 20, evidence.KindGateVerdict, &janusv1.GateVerdict{
		SagaId: "sg", StepId: "pay", Verdict: janusv1.Verdict_VERDICT_PASS,
	})
	s = mustApply(t, s, 30, evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg"})

	if got := saga.Ready(s); len(got) != 0 {
		t.Fatalf("ready is %v while the saga is %s, want nothing", got, s.Status)
	}
}

// TestTimeoutIsDecidedFromTheLog: a scheduler that read a live clock would make
// two replays of the same history disagree about which steps expired.
func TestTimeoutIsDecidedFromTheLog(t *testing.T) {
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	s := begun(t, planWith(&janusv1.PlannedStep{
		StepId: "slow", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
		TimeoutNanos: int64(30 * time.Second),
	}))

	s, err := saga.Apply(s, saga.Event{
		Seq: 10, Kind: evidence.KindStepPrepare, Wall: start,
		Payload: mustMarshal(t, &janusv1.StepPrepare{SagaId: "sg", StepId: "slow"}),
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := saga.TimedOut(s, start.Add(10*time.Second)); len(got) != 0 {
		t.Fatalf("timed out %v after 10s of a 30s budget", got)
	}
	if got := saga.TimedOut(s, start.Add(31*time.Second)); !slices.Contains(got, "slow") {
		t.Fatalf("timed out %v after 31s of a 30s budget, want the step named", got)
	}

	// The same state asked twice gives the same answer, which is what makes the
	// decision replayable.
	at := start.Add(45 * time.Second)
	first := saga.TimedOut(s, at)
	for range 10 {
		if !slices.Equal(saga.TimedOut(s, at), first) {
			t.Fatal("TimedOut is not a function of its inputs")
		}
	}
}

// TestReadyIsDeterministic: two coordinators handed the same state must offer
// the same work in the same order, or a crash and a handover would produce a
// different execution than the one being replayed.
func TestReadyIsDeterministic(t *testing.T) {
	s := begun(t, planWith(
		pureStep("z"), pureStep("a"), pureStep("m"),
		pureStep("q", "a"), pureStep("b", "z"),
	))
	first := saga.Ready(s)
	for i := range 100 {
		if got := saga.Ready(s.Clone()); !slices.Equal(got, first) {
			t.Fatalf("call %d gave %v, first gave %v", i, got, first)
		}
	}
}

// TestCompleteRequiresEverySealed guards the precondition for sealing a saga.
func TestCompleteRequiresEverySealed(t *testing.T) {
	s := begun(t, planWith(pureStep("a"), pureStep("b")))
	if saga.Complete(s) {
		t.Fatal("a saga with nothing done reports complete")
	}
	s = step(t, s, "a", 10)
	if saga.Complete(s) {
		t.Fatal("a saga with one step outstanding reports complete")
	}
	s = step(t, s, "b", 20)
	if !saga.Complete(s) {
		t.Fatal("a saga with every step sealed does not report complete")
	}
}

func mustApply(t *testing.T, s saga.State, seq uint64, kind evidence.Kind, msg proto.Message) saga.State {
	t.Helper()
	next, err := saga.Apply(s, ev(t, seq, kind, msg))
	if err != nil {
		t.Fatalf("applying %s at %d: %v", kind, seq, err)
	}
	return next
}
