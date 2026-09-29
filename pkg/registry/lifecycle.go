package registry

import (
	"errors"
	"fmt"
	"slices"
)

// The registration lifecycle.
//
//	DRAFT ──evaluate──▶ EVALUATED ──activate──▶ ACTIVE
//	                        ▲                     │
//	                        │                     ├──suspend──▶ SUSPENDED
//	                        └──evaluate───────────┤                 │
//	                                              │                 │
//	                        SUPERSEDED ◀──────────┘                 │
//	                             │  ▲                               │
//	                             └──┘ activate (rollback)           │
//	                                                                ▼
//	  any state ────────────────────retire────────────────────▶ RETIRED
//
// Every arrow is an event in the evidence log. There is no path that sets a
// state without recording why, and RETIRED is terminal — a retired version can
// never act again, which is what makes retirement worth recording.
//
// Two of the rules are opinions rather than mechanics, and both are here on
// purpose.
//
// A suspended version does not go straight back to ACTIVE. It goes back through
// evaluation. A participant is suspended because something about it was wrong,
// and re-activating it with a click records that somebody decided the problem
// was over without recording anything about the problem. Making the return trip
// pass through evaluation means the record contains the evidence that the
// answer changed.
//
// A superseded version *can* go straight back to ACTIVE. Superseded is not a
// judgment about the version — it means a newer one took over — so a rollback
// after a bad deployment is exactly what should be easy. Refusing it would
// teach operators to re-register the same bytes under a new version number,
// which loses the fact that the fleet went back to something already evaluated.

// State is where a manifest version stands.
type State string

const (
	// StateDraft is registered and not yet evaluated. It may not be pinned.
	StateDraft State = "DRAFT"
	// StateEvaluated has passing conformance evidence attached.
	StateEvaluated State = "EVALUATED"
	// StateActive is the version new sagas pin.
	StateActive State = "ACTIVE"
	// StateSuspended was stopped for cause. The reason is part of the event.
	StateSuspended State = "SUSPENDED"
	// StateSuperseded had a newer version activated over it. It is still
	// resolvable — sagas that pinned it are still being audited years later —
	// but nothing new pins it.
	StateSuperseded State = "SUPERSEDED"
	// StateRetired is terminal.
	StateRetired State = "RETIRED"
)

// ErrLifecycle means a registry transition is not legal from where the version
// stands.
var ErrLifecycle = errors.New("registry: illegal transition")

// canEvaluate reports whether an evaluation may be attached.
func canEvaluate(from State) error {
	switch from {
	case StateDraft, StateEvaluated, StateActive, StateSuspended, StateSuperseded:
		return nil
	default:
		return fmt.Errorf("%w: cannot evaluate a %s version; retirement is terminal", ErrLifecycle, from)
	}
}

// canActivate reports whether a version may be activated, given its state, its
// latest evaluation and any revalidation it owes.
func canActivate(e *Entry) error {
	switch e.State {
	case StateEvaluated, StateSuperseded:
	case StateActive:
		return fmt.Errorf("%w: %s@%s is already active", ErrLifecycle, e.ParticipantID, e.Version)
	case StateSuspended:
		return fmt.Errorf("%w: %s@%s is suspended (%s); evaluate it again before activating it, "+
			"so the record carries the evidence that the reason for suspending it no longer holds",
			ErrLifecycle, e.ParticipantID, e.Version, e.Reason)
	case StateDraft:
		return fmt.Errorf("%w: %s@%s has never been evaluated; the effect classes it declares "+
			"decide what Janus gates, so they are checked before they are believed",
			ErrLifecycle, e.ParticipantID, e.Version)
	default:
		return fmt.Errorf("%w: %s@%s is %s", ErrLifecycle, e.ParticipantID, e.Version, e.State)
	}

	if e.Evaluation == nil || !e.Evaluation.GetPassed() {
		return fmt.Errorf("%w: %s@%s has no passing evaluation", ErrLifecycle,
			e.ParticipantID, e.Version)
	}
	if len(e.PendingTriggers) > 0 {
		return fmt.Errorf("%w: %s@%s owes revalidation for %v, and its evaluation covers %v; the "+
			"evidence that cleared this participant predates the change", ErrLifecycle,
			e.ParticipantID, e.Version, e.PendingTriggers, e.Evaluation.GetTriggersCovered())
	}
	return nil
}

// canSuspend reports whether a version may be suspended.
func canSuspend(from State) error {
	switch from {
	case StateActive, StateEvaluated, StateDraft, StateSuperseded:
		return nil
	case StateSuspended:
		return fmt.Errorf("%w: already suspended", ErrLifecycle)
	default:
		return fmt.Errorf("%w: cannot suspend a %s version", ErrLifecycle, from)
	}
}

// canRetire reports whether a version may be retired.
func canRetire(from State) error {
	if from == StateRetired {
		return fmt.Errorf("%w: already retired", ErrLifecycle)
	}
	return nil
}

// coveredBy reports which of the owed triggers an evaluation does not answer.
func coveredBy(owed []string, covered []string) []string {
	var out []string
	for _, t := range owed {
		if !slices.Contains(covered, t) {
			out = append(out, t)
		}
	}
	return out
}
