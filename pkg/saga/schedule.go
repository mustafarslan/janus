package saga

import (
	"fmt"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// Scheduling answers one question: given everything the log records, which
// steps may run now?
//
// It is a pure function of the projection, deliberately. A coordinator that
// crashed mid-saga and a fresh one picking the saga up must reach the same
// answer, and they can only do that if the answer depends on nothing but
// recorded state — no in-memory queue, no wall clock, no arrival order. That is
// also what makes the schedule replayable: re-running the log produces the same
// sequence of decisions, which is what invariant I5 asks for.
//
// The scheduler does not run anything. It says what is eligible; the
// coordinator decides how much to run at once and records the results.

// Ready lists the steps that may start now, in a deterministic order.
//
// A step is ready when it is planned or awaiting a retry, all of its
// dependencies have sealed, and the saga is in a state where forward work is
// allowed at all. Order follows the plan, so two coordinators presented with
// the same state offer the same work in the same sequence.
func Ready(s State) []string {
	switch s.Status {
	case StatusCreated, StatusRunning, StatusGated:
	default:
		// A saga that is sealing, committed, compensating, or quarantined has
		// no forward work left. Offering some would mean adding effects to a
		// saga that has already declared its footprint or begun undoing it.
		return nil
	}

	var ready []string
	for _, id := range s.Order {
		st := s.Steps[id]
		if !runnable(st) {
			continue
		}
		if dependenciesSealed(s, st) {
			ready = append(ready, id)
		}
	}
	return ready
}

// runnable reports whether a step is waiting to be started.
func runnable(st *Step) bool {
	switch st.Status {
	case StepPlanned:
		return true
	case StepFailed:
		// A failed step is runnable again only while it still has budget. Once
		// the budget is gone the step is poison and the saga has to unwind.
		//
		// Attempt counts attempts made and MaxRetries counts retries allowed,
		// so a step with one retry gets two attempts in total: the comparison
		// is Attempt <= MaxRetries, not <.
		return st.Outcome == janusv1.Outcome_STATUS_RETRYABLE_ERROR && st.Attempt <= st.MaxRetries
	default:
		return false
	}
}

// dependenciesSealed reports whether everything this step waits on is done.
//
// SEALED is the bar rather than "the result arrived", because a step whose
// effect is still waiting on a gate might yet be refused, and starting
// dependent work on top of it would mean building on something that can still
// be withdrawn.
func dependenciesSealed(s State, st *Step) bool {
	for _, dep := range st.DependsOn {
		d, ok := s.Steps[dep]
		if !ok {
			return false
		}
		if d.Status != StepSealed && d.Status != StepCommitted {
			return false
		}
	}
	return true
}

// Blocked describes why a step cannot run yet, for reporting a stalled saga.
type Blocked struct {
	Step string
	// WaitingFor lists dependencies that have not sealed.
	WaitingFor []string
	// Reason explains anything other than dependencies.
	Reason string
}

// Stalled lists steps that are neither running nor ready, with why.
//
// A saga that stops making progress is the hardest thing to diagnose from a log
// alone, because the absence of events looks the same whatever caused it. This
// turns that absence into a statement.
func Stalled(s State) []Blocked {
	var out []Blocked
	for _, id := range s.Order {
		st := s.Steps[id]
		switch st.Status {
		case StepPlanned, StepFailed:
		default:
			continue
		}

		var waiting []string
		for _, dep := range st.DependsOn {
			if d, ok := s.Steps[dep]; !ok || (d.Status != StepSealed && d.Status != StepCommitted) {
				waiting = append(waiting, dep)
			}
		}

		b := Blocked{Step: id, WaitingFor: waiting}
		switch {
		case st.Status == StepFailed && st.Outcome != janusv1.Outcome_STATUS_RETRYABLE_ERROR:
			b.Reason = fmt.Sprintf("failed with %s, which is not retryable", shortOutcome(st.Outcome))
		case st.Status == StepFailed && st.Attempt > st.MaxRetries:
			b.Reason = fmt.Sprintf("exhausted its retry budget after %d attempt(s)", st.Attempt)
		case len(waiting) > 0:
			b.Reason = fmt.Sprintf("waiting for %v to seal", waiting)
		default:
			continue // it is ready, not stalled
		}
		out = append(out, b)
	}
	return out
}

// Poisoned lists steps that have failed terminally or run out of retries.
//
// A poisoned step is why a saga can no longer go forward, and the coordinator's
// answer is to compensate rather than to keep trying: a step that has spent its
// whole budget is unlikely to behave differently on an identical next attempt,
// and each attempt holds the saga's resources against everyone else.
func Poisoned(s State) []string {
	var out []string
	for _, id := range s.Order {
		st := s.Steps[id]
		if st.Status != StepFailed {
			continue
		}
		if st.Outcome != janusv1.Outcome_STATUS_RETRYABLE_ERROR || st.Attempt > st.MaxRetries {
			out = append(out, id)
		}
	}
	return out
}

// Progress describes where a saga has got to, for an operator or a dashboard.
type Progress struct {
	Total    int
	Sealed   int
	Running  int
	ReadyNow []string
	Stalled  []Blocked
	Poisoned []string
	// CanAdvance is false when the saga has forward work outstanding but
	// nothing it can do about it — the definition of stuck.
	CanAdvance bool
}

// Describe summarises a saga's schedulable state.
func Describe(s State) Progress {
	p := Progress{
		Total:    len(s.Order),
		ReadyNow: Ready(s),
		Stalled:  Stalled(s),
		Poisoned: Poisoned(s),
	}
	for _, id := range s.Order {
		switch s.Steps[id].Status {
		case StepSealed, StepCommitted, StepCompensated:
			p.Sealed++
		case StepPrepared, StepGated:
			p.Running++
		}
	}
	p.CanAdvance = len(p.ReadyNow) > 0 || p.Running > 0
	return p
}

// Complete reports whether every step has sealed, which is the precondition for
// sealing the saga.
func Complete(s State) bool {
	if len(s.Order) == 0 {
		return false
	}
	for _, id := range s.Order {
		if st := s.Steps[id]; st.Status != StepSealed && st.Status != StepCommitted {
			return false
		}
	}
	return true
}

// TimedOut reports which in-flight steps have exceeded their timeout, given the
// time each was prepared and the moment being asked about.
//
// Time is a parameter rather than read from a clock, because a scheduler that
// consulted the wall clock would stop being a pure function of the log: two
// replays of the same history would disagree about which steps had expired.
// The coordinator supplies "now" and records the resulting timeout as an event,
// so the decision becomes part of the evidence rather than an artefact of when
// somebody happened to look.
func TimedOut(s State, now time.Time) []string {
	var out []string
	for _, id := range s.Order {
		st := s.Steps[id]
		if st.Status != StepPrepared || st.Timeout <= 0 || st.PreparedAt.IsZero() {
			continue
		}
		if now.Sub(st.PreparedAt) > st.Timeout {
			out = append(out, id)
		}
	}
	return out
}

// shortOutcome renders an outcome without its enum prefix.
func shortOutcome(o janusv1.Outcome_Status) string {
	const prefix = "STATUS_"
	n := o.String()
	if len(n) > len(prefix) {
		return n[len(prefix):]
	}
	return n
}
