package saga_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

// compensable builds a plan of effectful steps with the given dependencies.
func compensable(sagaID string, deps map[string][]string, order ...string) *janusv1.SagaBegin {
	begin := &janusv1.SagaBegin{SagaId: sagaID, Intent: &janusv1.Intent{IntentId: "in_1"}}
	for _, id := range order {
		begin.Plan = append(begin.Plan, &janusv1.PlannedStep{
			StepId:             id,
			EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: id + ".undo",
			DependsOn:          deps[id],
		})
	}
	return begin
}

// runToSealed drives every named step to SEALED.
//
// A PURE step seals on its own result and a gate verdict afterwards is
// correctly refused, so the gate is only emitted for steps that actually wait
// for one.
func runToSealed(t *testing.T, begin *janusv1.SagaBegin, order ...string) saga.State {
	t.Helper()
	gated := map[string]bool{}
	for _, p := range begin.Plan {
		gated[p.GetStepId()] = p.GetEffectClass() != janusv1.EffectClass_EFFECT_CLASS_PURE
	}

	events := []saga.Event{ev(t, 1, evidence.KindSagaBegin, begin)}
	seq := uint64(2)
	for _, id := range order {
		events = append(events,
			ev(t, seq, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: begin.SagaId, StepId: id}),
			ev(t, seq+1, evidence.KindStepResult, &janusv1.StepResult{
				SagaId: begin.SagaId, StepId: id,
				Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			}),
		)
		seq += 2
		if gated[id] {
			events = append(events, ev(t, seq, evidence.KindGateVerdict, &janusv1.GateVerdict{
				SagaId: begin.SagaId, StepId: id,
				Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
				Verdict: janusv1.Verdict_VERDICT_PASS,
				// A passing verdict has to account for every requirement due,
				// so the helper reads them off the plan rather than asserting a
				// bare pass the state machine would refuse.
				Decided: releaseRequirements(begin, id),
			}))
			seq++
		}
	}
	s, err := saga.Replay(events)
	if err != nil {
		t.Fatalf("driving the saga forward: %v", err)
	}
	return s
}

// TestCompensationRunsInReverseTopologicalOrder is invariant I7. Undoing a
// dependency before its dependent would leave that dependent resting on an
// effect that no longer exists — a state no participant declared.
func TestCompensationRunsInReverseTopologicalOrder(t *testing.T) {
	// pay <- book <- notify: each depends on the one before.
	begin := compensable("sg", map[string][]string{
		"book":   {"pay"},
		"notify": {"book"},
	}, "pay", "book", "notify")
	s := runToSealed(t, begin, "pay", "book", "notify")

	s, err := saga.Apply(s, ev(t, 100, evidence.KindCompensate, &janusv1.Compensate{
		SagaId: "sg", ReasonRef: "customer withdrew",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if s.Status != saga.StatusCompensating {
		t.Fatalf("saga is %s, want COMPENSATING", s.Status)
	}

	plan, err := saga.PlanCompensation(s)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"notify", "book", "pay"}
	if !slices.Equal(plan.Order, want) {
		t.Fatalf("compensation order is %v, want %v", plan.Order, want)
	}

	// Undoing the dependency first must be refused.
	_, err = saga.Apply(s, ev(t, 101, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "pay~undo", Compensates: "pay",
	}))
	if !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("got %v, want the out-of-order compensation to be refused", err)
	}

	// In the right order it proceeds, and each step reports what undid it.
	seq := uint64(101)
	for _, id := range want {
		s, err = saga.Apply(s, ev(t, seq, evidence.KindStepPrepare, &janusv1.StepPrepare{
			SagaId: "sg", StepId: id + "~undo", Compensates: id,
		}))
		if err != nil {
			t.Fatalf("preparing compensation of %s: %v", id, err)
		}
		s, err = saga.Apply(s, ev(t, seq+1, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: id + "~undo",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}))
		if err != nil {
			t.Fatalf("completing compensation of %s: %v", id, err)
		}
		seq += 2
		if got := s.Steps[id].CompensatedBy; got != id+"~undo" {
			t.Fatalf("step %s says it was undone by %q", id, got)
		}
	}

	if !saga.Compensated(s) {
		t.Fatalf("saga is %s with outstanding %v, want fully compensated", s.Status, s.Outstanding)
	}
}

// TestFailedCompensationQuarantines: continuing after a failed undo would leave
// a hole in the middle of the sequence — later effects reversed, an earlier one
// still live — which is exactly what reverse ordering exists to prevent.
func TestFailedCompensationQuarantines(t *testing.T) {
	begin := compensable("sg", map[string][]string{"book": {"pay"}}, "pay", "book")
	s := runToSealed(t, begin, "pay", "book")

	s, err := saga.Apply(s, ev(t, 100, evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg"}))
	if err != nil {
		t.Fatal(err)
	}
	s, err = saga.Apply(s, ev(t, 101, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "book~undo", Compensates: "book",
	}))
	if err != nil {
		t.Fatal(err)
	}
	s, err = saga.Apply(s, ev(t, 102, evidence.KindStepResult, &janusv1.StepResult{
		SagaId: "sg", StepId: "book~undo",
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_TERMINAL_ERROR},
	}))
	if err != nil {
		t.Fatal(err)
	}

	if s.Status != saga.StatusQuarantine {
		t.Fatalf("saga is %s after a failed compensation, want QUARANTINE", s.Status)
	}
	if s.QuarantineReason == "" {
		t.Fatal("quarantine records no reason for whoever picks it up")
	}
	// The handover note must name everything still live, including the payment
	// that was never reached.
	if !slices.Contains(s.Outstanding, "pay") || !slices.Contains(s.Outstanding, "book") {
		t.Fatalf("outstanding is %v, want both steps named", s.Outstanding)
	}

	// And it must not carry on undoing the rest.
	_, err = saga.Apply(s, ev(t, 103, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "pay~undo", Compensates: "pay",
	}))
	if err == nil {
		t.Fatal("compensation continued after the saga was quarantined")
	}
}

// TestIrreversibleEffectQuarantinesImmediately: nothing can undo it, so the only
// honest response is to stop and say so.
func TestIrreversibleEffectQuarantinesImmediately(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId:            "sg",
		GatePolicyVersion: testPolicy,
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		GatePlan: []*janusv1.StepGates{plannedGates("wire", "PRE_RELEASE")},
	}
	s := runToSealed(t, begin, "wire")

	s, err := saga.Apply(s, ev(t, 100, evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg"}))
	if err != nil {
		t.Fatal(err)
	}
	if s.Status != saga.StatusQuarantine {
		t.Fatalf("saga is %s, want QUARANTINE: an irreversible effect cannot be undone", s.Status)
	}
	if !slices.Contains(s.Outstanding, "wire") {
		t.Fatalf("outstanding is %v, want the irreversible step named", s.Outstanding)
	}
}

// TestPureStepsNeedNoCompensation: a saga that only read things has nothing to
// undo and should not sit in COMPENSATING waiting for compensations that will
// never come.
func TestPureStepsNeedNoCompensation(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId: "sg",
		Plan: []*janusv1.PlannedStep{
			{StepId: "read", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
			{StepId: "think", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE, DependsOn: []string{"read"}},
		},
	}
	s := runToSealed(t, begin, "read", "think")

	s, err := saga.Apply(s, ev(t, 100, evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg"}))
	if err != nil {
		t.Fatal(err)
	}
	if s.Status != saga.StatusCompensated {
		t.Fatalf("saga is %s, want COMPENSATED with nothing to undo", s.Status)
	}
	if !saga.Compensated(s) {
		t.Fatal("Compensated reports otherwise")
	}
}

// TestStepsThatNeverRanAreNotCompensated: undoing something that never happened
// would be an effect of its own.
func TestStepsThatNeverRanAreNotCompensated(t *testing.T) {
	begin := compensable("sg", map[string][]string{"book": {"pay"}}, "pay", "book")
	// Only "pay" runs.
	s := runToSealed(t, begin, "pay")

	s, err := saga.Apply(s, ev(t, 100, evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg"}))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := saga.PlanCompensation(s)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Order, []string{"pay"}) {
		t.Fatalf("compensation plan is %v, want only the step that actually ran", plan.Order)
	}
}

// TestParallelBranchesUndoIndependently: two branches that never depended on
// each other must not block one another's undo.
func TestParallelBranchesUndoIndependently(t *testing.T) {
	begin := compensable("sg", map[string][]string{
		"a2": {"a1"},
		"b2": {"b1"},
	}, "a1", "b1", "a2", "b2")
	s := runToSealed(t, begin, "a1", "b1", "a2", "b2")

	s, err := saga.Apply(s, ev(t, 100, evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg"}))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := saga.PlanCompensation(s)
	if err != nil {
		t.Fatal(err)
	}

	// Whatever the interleaving, each leaf must come before its own root.
	posOf := func(id string) int { return slices.Index(plan.Order, id) }
	if posOf("a2") > posOf("a1") {
		t.Fatalf("a2 is undone after a1: %v", plan.Order)
	}
	if posOf("b2") > posOf("b1") {
		t.Fatalf("b2 is undone after b1: %v", plan.Order)
	}

	// Both leaves are ready straight away.
	if _, ok := plan.Next(); !ok {
		t.Fatal("no compensation was ready to run")
	}
}

// TestPlanIsStableAcrossRecomputation: a process picking up a half-compensated
// saga after a crash must follow the same order the previous one was following.
func TestPlanIsStableAcrossRecomputation(t *testing.T) {
	begin := compensable("sg", map[string][]string{
		"c": {"a", "b"}, "d": {"c"}, "e": {"a"},
	}, "a", "b", "c", "d", "e")
	s := runToSealed(t, begin, "a", "b", "c", "d", "e")
	s, err := saga.Apply(s, ev(t, 100, evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg"}))
	if err != nil {
		t.Fatal(err)
	}

	first, err := saga.PlanCompensation(s)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		again, err := saga.PlanCompensation(s.Clone())
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(again.Order, first.Order) {
			t.Fatalf("recomputation %d gave %v, first gave %v", i, again.Order, first.Order)
		}
	}
}

// TestCompensationSurvivesReplay: the undo phase is evidence like anything else,
// so replaying it has to land in the same place (invariant I5).
func TestCompensationSurvivesReplay(t *testing.T) {
	begin := compensable("sg", map[string][]string{"book": {"pay"}}, "pay", "book")

	events := []saga.Event{ev(t, 1, evidence.KindSagaBegin, begin)}
	seq := uint64(2)
	for _, id := range []string{"pay", "book"} {
		events = append(events,
			ev(t, seq, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: id}),
			ev(t, seq+1, evidence.KindStepResult, &janusv1.StepResult{
				SagaId: "sg", StepId: id, Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			}),
			ev(t, seq+2, evidence.KindGateVerdict, &janusv1.GateVerdict{
				SagaId: "sg", StepId: id, Verdict: janusv1.Verdict_VERDICT_PASS,
			}),
		)
		seq += 3
	}
	events = append(events, ev(t, seq, evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg"}))
	seq++
	for _, id := range []string{"book", "pay"} {
		events = append(events,
			ev(t, seq, evidence.KindStepPrepare, &janusv1.StepPrepare{
				SagaId: "sg", StepId: id + "~undo", Compensates: id,
			}),
			ev(t, seq+1, evidence.KindStepResult, &janusv1.StepResult{
				SagaId: "sg", StepId: id + "~undo",
				Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			}),
		)
		seq += 2
	}

	first, err := saga.Replay(events)
	if err != nil {
		t.Fatal(err)
	}
	if !saga.Compensated(first) {
		t.Fatalf("saga is %s, want fully compensated", first.Status)
	}
	for i := range 20 {
		again, err := saga.Replay(events)
		if err != nil {
			t.Fatal(err)
		}
		if diff := saga.Diff(first, again); len(diff) > 0 {
			t.Fatalf("replay %d diverged: %v", i, diff)
		}
	}
}

// TestCompensateNamingAnUnknownStepIsRefused.
func TestCompensateNamingAnUnknownStepIsRefused(t *testing.T) {
	begin := compensable("sg", nil, "pay")
	s := runToSealed(t, begin, "pay")
	_, err := saga.Apply(s, ev(t, 100, evidence.KindCompensate, &janusv1.Compensate{
		SagaId: "sg", StepIds: []string{"ghost"},
	}))
	if !errors.Is(err, saga.ErrUnknownStep) {
		t.Fatalf("got %v, want ErrUnknownStep", err)
	}
}

// TestCompensatingACommittedSagaIsRefused: commit released the effects
// deliberately, and undoing them is a new decision with its own authority, not
// a continuation of this saga.
func TestCompensatingACommittedSagaIsRefused(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId: "sg",
		Plan:   []*janusv1.PlannedStep{{StepId: "read", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE}},
	}
	s := runToSealed(t, begin, "read")
	s, err := saga.Apply(s, ev(t, 50, evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"}))
	if err != nil {
		t.Fatal(err)
	}
	s, err = saga.Apply(s, ev(t, 51, evidence.KindCommit, &janusv1.Commit{SagaId: "sg"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saga.Apply(s, ev(t, 52, evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg"})); !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("got %v, want compensation of a committed saga to be refused", err)
	}
}

var _ = fmt.Sprintf
