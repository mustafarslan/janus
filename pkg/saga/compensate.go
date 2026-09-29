package saga

import (
	"fmt"
	"slices"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"google.golang.org/protobuf/proto"
)

// Compensation is the undo half of a saga, and the half that decides whether
// Janus is a transaction system or a logging system.
//
// # Why the order is reverse topological
//
// Steps are undone in the reverse of the order they could have run in. If a
// booking depends on a payment, the booking is cancelled before the payment is
// refunded — never the other way round. Undoing the payment first would leave a
// booking backed by nothing, which is a state no participant declared and none
// of them can reason about. Reverse order is what keeps every intermediate
// state one that some forward prefix of the saga could also have produced
// (invariant I7).
//
// # Why failure means QUARANTINE rather than a retry loop
//
// When a compensation fails, the saga stops. It does not skip the step, does not
// continue undoing the rest, and does not retry indefinitely. Continuing would
// produce exactly the state reverse ordering exists to prevent: a hole in the
// middle of the undo sequence, with later effects reversed and an earlier one
// still live.
//
// So the saga freezes with its full evidence trail and hands over to a human.
// In a bank a stuck known state beats a guessed clean one — the second is
// indistinguishable from the first until someone reconciles, and by then the
// window to act has usually closed.

// beginUnwind marks what has to be undone and moves the saga into the state
// that follows from it.
//
// Every route into the undo phase goes through here — an explicit COMPENSATE,
// an abort, or a gate refusing a step — because they have to agree. A gate
// failure that set the status to COMPENSATING without marking the steps left
// the saga in a state where the compensation plan was empty, nothing could be
// undone, and the saga sat in COMPENSATING for ever while reporting nothing
// outstanding. That bug existed until a corpus fixture tried to record the
// gate-failure path and found the history would not replay.
func beginUnwind(s State, reason string) State {
	for _, id := range s.Order {
		s.Steps[id].Compensation = compensationStateFor(s.Steps[id])
	}
	if reason != "" {
		s.AbortReason = reason
	}

	// An irreversible effect that already escaped cannot be undone by anything,
	// so there is nothing to attempt and a human has to be told immediately.
	if impossible := stepsWith(s, CompImpossible); len(impossible) > 0 {
		s.Status = StatusQuarantine
		s.Outstanding = impossible
		s.QuarantineReason = fmt.Sprintf("cannot be undone: %v released irreversible effects", impossible)
		return s
	}
	if len(stepsWith(s, CompRequired)) > 0 {
		s.Status = StatusCompensating
	} else {
		// Nothing left a trace, so the saga is already as undone as it can be.
		s.Status = StatusCompensated
	}
	return s
}

// applyCompensate opens the undo phase.
func applyCompensate(s State, ev Event) (State, error) {
	var msg janusv1.Compensate
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode Compensate: %w", err)
	}
	if s.SagaID == "" {
		return s, fmt.Errorf("%w: COMPENSATE before the saga began", ErrTransition)
	}
	switch s.Status {
	case StatusCommitted, StatusCompensated, StatusQuarantine:
		return s, fmt.Errorf("%w: COMPENSATE of a saga that is already %s", ErrTransition, s.Status)
	}

	// The caller may name the steps, but the set that actually needs undoing is
	// derived from what the log says happened. Trusting a caller's list would
	// let a mistake there leave a live effect behind.
	named := msg.GetStepIds()
	for _, id := range named {
		if _, ok := s.Steps[id]; !ok {
			return s, fmt.Errorf("%w: COMPENSATE names step %q, which is not in the plan", ErrUnknownStep, id)
		}
	}

	// The caller's list does not narrow what gets undone. A step that left an
	// effect behind is compensated whether or not it was named, because a
	// mistake in that list would otherwise leave a live effect behind.
	return beginUnwind(s, msg.GetReasonRef()), nil
}

// needsCompensation reports whether a step left an effect in the world.
func needsCompensation(st *Step) bool {
	if st.EffectClass == janusv1.EffectClass_EFFECT_CLASS_PURE {
		return false
	}
	switch st.Status {
	case StepGated, StepSealed, StepCommitted:
		return true

	case StepRefused:
		// A refusal before the step ever ran leaves nothing behind, whatever
		// the effect class. This is the pre-execution gate's whole point: the
		// participant was never called, so there is no effect to reverse, and
		// compensating anyway would send a reversal for something that never
		// happened — a refund for a payment nobody made.
		if st.Attempt == 0 {
			return false
		}

		// A refusal after the fact means different things to different effect
		// classes, and getting this wrong is expensive in both directions.
		//
		// An irreversible effect is held in the outbox until the saga commits,
		// so a gate refusing it means it was never released — that is the gate
		// doing precisely its job, and there is nothing to undo. Treating it as
		// needing compensation would quarantine every saga a gate correctly
		// stopped.
		//
		// A reversible or compensable effect may already have executed
		// optimistically, so the refusal arrives after the fact and the effect
		// has to be reversed.
		switch st.EffectClass {
		case janusv1.EffectClass_EFFECT_CLASS_REVERSIBLE,
			janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE:
			return true
		default:
			return false
		}

	case StepPrepared:
		// A PREPARED step is the uncomfortable case: it was about to run and
		// may or may not have. For an ordinary participant call that ambiguity
		// is resolved by idempotency keys and delivery receipts in the outbox
		// (Phase 3), not by guessing here.
		//
		// A step that spawned a sub-saga is the exception, and the reason is
		// that a sub-saga is not an opaque call. It is a saga with its own
		// evidence log, so what it did is recorded rather than unknown, and
		// leaving it out of the undo would abandon a saga that is still running
		// with effects of its own.
		return st.Child != nil

	default:
		// PLANNED, FAILED, and COMPENSATED steps have nothing live.
		return false
	}
}

// compensationStateFor decides what has to happen to a step during undo.
func compensationStateFor(st *Step) CompensationState {
	if st.Compensation == CompDone || st.Compensation == CompFailed {
		return st.Compensation
	}
	if !needsCompensation(st) {
		return CompNotNeeded
	}
	if st.CompensationAction == "" {
		// Admission refused any compensable step without a declared undo, so
		// reaching here means the step was declared irreversible and a gate let
		// it out anyway.
		return CompImpossible
	}
	return CompRequired
}

// stepsWith lists the steps in plan order whose compensation is in a state.
func stepsWith(s State, want CompensationState) []string {
	var out []string
	for _, id := range s.Order {
		if s.Steps[id].Compensation == want {
			out = append(out, id)
		}
	}
	return out
}

// applyQuarantine freezes the saga.
func applyQuarantine(s State, ev Event) (State, error) {
	var msg janusv1.Quarantine
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode Quarantine: %w", err)
	}
	if s.SagaID == "" {
		return s, fmt.Errorf("%w: QUARANTINE before the saga began", ErrTransition)
	}
	if s.Status == StatusCommitted || s.Status == StatusCompensated {
		return s, fmt.Errorf("%w: QUARANTINE of a saga that already reached %s", ErrTransition, s.Status)
	}
	s.Status = StatusQuarantine
	s.QuarantineReason = msg.GetReason()
	if outstanding := msg.GetOutstanding(); len(outstanding) > 0 {
		s.Outstanding = slices.Clone(outstanding)
	} else {
		s.Outstanding = Outstanding(s)
	}
	return s, nil
}

// Outstanding lists the steps whose effects are still in the world.
//
// It is the handover note a quarantined saga leaves behind: these are the
// things a human has to deal with, named in plan order.
func Outstanding(s State) []string {
	var out []string
	for _, id := range s.Order {
		st := s.Steps[id]
		switch st.Compensation {
		case CompRequired, CompRunning, CompFailed, CompImpossible:
			out = append(out, id)
		}
	}
	return out
}

// CompensationPlan is the order in which steps must be undone.
//
// It is derived from the recorded state rather than stored, so a process that
// picks up a half-compensated saga after a crash computes the same plan the
// original one was following.
type CompensationPlan struct {
	// Order lists the steps still to undo, first to last. It is the reverse of
	// a topological order of the plan restricted to the steps that need it.
	Order []string
	// Blocked maps a step to the compensations that must finish before it can
	// start, for reporting when nothing is ready.
	Blocked map[string][]string
}

// PlanCompensation computes what is left to undo and in what order.
func PlanCompensation(s State) (CompensationPlan, error) {
	if err := checkAcyclic(s); err != nil {
		return CompensationPlan{}, err
	}

	// Forward topological order, then reversed. Kahn's algorithm over the plan
	// gives an order in which every step follows its dependencies; undoing runs
	// against that order so a step is reversed before anything it depended on.
	order, err := topological(s)
	if err != nil {
		return CompensationPlan{}, err
	}

	plan := CompensationPlan{Blocked: map[string][]string{}}
	for i := len(order) - 1; i >= 0; i-- {
		id := order[i]
		if s.Steps[id].Compensation != CompRequired {
			continue
		}
		plan.Order = append(plan.Order, id)
		if blockers := blockedBy(s, id); len(blockers) > 0 {
			plan.Blocked[id] = blockers
		}
	}
	return plan, nil
}

// Next returns the step whose compensation may run now, if any.
func (p CompensationPlan) Next() (string, bool) {
	for _, id := range p.Order {
		if len(p.Blocked[id]) == 0 {
			return id, true
		}
	}
	return "", false
}

// blockedBy lists the steps that depend on id and have not been undone yet.
// While any of them is outstanding, undoing id would leave a dependent effect
// resting on something that no longer exists.
func blockedBy(s State, id string) []string {
	var out []string
	for _, other := range s.Order {
		st := s.Steps[other]
		if !slices.Contains(st.DependsOn, id) {
			continue
		}
		switch st.Compensation {
		case CompRequired, CompRunning, CompFailed, CompImpossible:
			out = append(out, other)
		}
	}
	return out
}

// topological returns the steps in an order where every step follows the steps
// it depends on. Ties are broken by plan order so the result is deterministic,
// which matters because a compensation plan recomputed after a crash has to
// match the one the previous process was following.
func topological(s State) ([]string, error) {
	indegree := make(map[string]int, len(s.Steps))
	dependents := make(map[string][]string, len(s.Steps))
	for _, id := range s.Order {
		indegree[id] = len(s.Steps[id].DependsOn)
		for _, dep := range s.Steps[id].DependsOn {
			dependents[dep] = append(dependents[dep], id)
		}
	}

	var ready []string
	for _, id := range s.Order {
		if indegree[id] == 0 {
			ready = append(ready, id)
		}
	}

	out := make([]string, 0, len(s.Order))
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		out = append(out, id)
		for _, dep := range dependents[id] {
			indegree[dep]--
			if indegree[dep] == 0 {
				// Insert in plan order rather than appending, so the result
				// does not depend on map iteration.
				ready = insertInPlanOrder(s, ready, dep)
			}
		}
	}
	if len(out) != len(s.Order) {
		return nil, fmt.Errorf("%w: plan has a dependency cycle", ErrNotAdmitted)
	}
	return out, nil
}

func insertInPlanOrder(s State, ready []string, id string) []string {
	pos := slices.Index(s.Order, id)
	for i, existing := range ready {
		if slices.Index(s.Order, existing) > pos {
			return slices.Insert(ready, i, id)
		}
	}
	return append(ready, id)
}

// applyCompensationPrepare handles a StepPrepare that undoes another step.
func applyCompensationPrepare(s State, msg *janusv1.StepPrepare) (State, error) {
	target, ok := s.Steps[msg.GetCompensates()]
	if !ok {
		return s, fmt.Errorf("%w: compensation targets %q, which is not in the plan",
			ErrUnknownStep, msg.GetCompensates())
	}
	if s.Status != StatusCompensating {
		return s, fmt.Errorf("%w: a compensation was prepared while the saga is %s", ErrTransition, s.Status)
	}
	switch target.Compensation {
	case CompRequired:
	case CompDone:
		return s, fmt.Errorf("%w: step %q has already been compensated", ErrTransition, target.ID)
	default:
		return s, fmt.Errorf("%w: step %q is not awaiting compensation (state %q)",
			ErrTransition, target.ID, target.Compensation)
	}

	// Reverse topological order, enforced rather than assumed. Undoing a step
	// while something that depended on it is still live would leave that
	// dependent resting on an effect that no longer exists.
	if blockers := blockedBy(s, target.ID); len(blockers) > 0 {
		return s, fmt.Errorf("%w: cannot undo %q while %v still depend on it and are not yet undone",
			ErrTransition, target.ID, blockers)
	}

	target.Compensation = CompRunning
	target.CompensatedBy = msg.GetStepId()
	return s, nil
}

// applyCompensationResult handles the outcome of a compensating step.
func applyCompensationResult(s State, target *Step, outcome janusv1.Outcome_Status) (State, error) {
	if target.Compensation != CompRunning {
		return s, fmt.Errorf("%w: a compensation result arrived for %q, which is %q",
			ErrTransition, target.ID, target.Compensation)
	}

	if outcome != janusv1.Outcome_STATUS_OK {
		// No retry loop and no skipping ahead. Continuing would produce a hole
		// in the middle of the undo sequence — later effects reversed, an
		// earlier one still live — which is the state reverse ordering exists
		// to prevent.
		target.Compensation = CompFailed
		target.Status = StepFailed
		s.Status = StatusQuarantine
		s.Outstanding = Outstanding(s)
		s.QuarantineReason = fmt.Sprintf("compensation of %q failed; %d step(s) still have effects in the world",
			target.ID, len(s.Outstanding))
		return s, nil
	}

	target.Compensation = CompDone
	target.Status = StepCompensated

	if len(stepsWith(s, CompRequired)) == 0 && len(stepsWith(s, CompRunning)) == 0 {
		s.Status = StatusCompensated
		s.Outstanding = nil
	}
	return s, nil
}

// compensationTargetOf returns the step a compensating step undoes.
func compensationTargetOf(s State, compensatingStepID string) (*Step, bool) {
	for _, id := range s.Order {
		if s.Steps[id].CompensatedBy == compensatingStepID && s.Steps[id].Compensation == CompRunning {
			return s.Steps[id], true
		}
	}
	return nil, false
}

// Compensated reports whether every effect this saga produced has been undone.
func Compensated(s State) bool {
	if s.Status != StatusCompensated {
		return false
	}
	for _, id := range s.Order {
		switch s.Steps[id].Compensation {
		case CompRequired, CompRunning, CompFailed, CompImpossible:
			return false
		}
	}
	return true
}

var _ = evidence.KindCompensate
