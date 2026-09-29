package orchd

import (
	"context"
	"fmt"
	"log"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Expiring gates nobody answered.
//
// A saga held at a gate returns `ErrWaiting` and then nothing runs: no
// coordinator is looping, so there is no process to notice a deadline pass. That
// is the part a deadline on its own does not say, and it decides where this lives —
// the daemon's ticker is the only thing that wakes up on its own and owns the
// log.
//
// # This is a daemon capability
//
// A library-embedded coordinator gets no expiry: its gates wait forever, which
// was the behaviour before this existed and is fail-closed. The same asymmetry
// as mode enforcement, and stated here rather than left for
// somebody to discover when a deadline they configured never fires.
//
// # Why the answer is appended here rather than through RecordAnswer
//
// `RecordAnswer` is the path a console uses, and it exists to carry a *person's*
// decision. An expiry is the daemon deciding, on the deadline's behalf, and it
// is appended by the process that owns the log. That keeps the forgery surface
// where it already was — whoever can append to the evidence directory — rather
// than widening it to whoever can reach the RPC.

// expireDueGates records a refusal for every gate whose deadline has passed.
//
// The clock is read exactly once per gate, here, and the decision is written
// down. Everything afterwards — the composition, the audit, a re-derivation
// years later — compares recorded times.
func (s *Server) expireDueGates(ctx context.Context) {
	waiting, err := s.sagasWaitingOnGates(ctx)
	if err != nil {
		log.Printf("orchd: could not look for gates past their deadline: %v", err)
		return
	}
	now := time.Now().UTC()
	for _, sagaID := range waiting {
		if err := s.expireSaga(ctx, sagaID, now); err != nil {
			// Logged and carried on. One saga whose expiry could not be
			// recorded must not stop the others being looked at -- the same
			// trade the spot-replay sampler makes, and for the same reason.
			log.Printf("orchd: expiring gates on saga %q: %v", sagaID, err)
		}
	}
}

// expireSaga appends an expiry for each of one saga's overdue gates.
func (s *Server) expireSaga(ctx context.Context, sagaID string, now time.Time) error {
	h := s.hostedSaga(sagaID)
	// TryLock, not Lock. The ticker must never wait on a saga somebody is
	// driving: the coordinator calls back into the participant's program while
	// it holds this, so a step waiting on a slow tool would block the ticker for
	// as long as the tool took — and a Close arriving in that window waits for
	// the ticker, which is a deadlock reachable from an ordinary slow step.
	//
	// A saga that is being driven is not one whose gate needs expiring anyway:
	// something is already moving it, and if it stops on a gate the next tick
	// finds it. Skipping is free; waiting is not.
	if !h.driving.TryLock() {
		return nil
	}
	defer h.driving.Unlock()

	// Whether anything was actually refused, so the saga is advanced once at
	// the end rather than per requirement.
	var expired bool

	// Read under the lock, like every other write path here: a state read
	// before the lock could have been moved past by a concurrent drive, and the
	// expiry would be recorded against a gate that had since been answered.
	state, err := saga.ReplaySaga(s.dir, sagaID)
	if err != nil {
		return err
	}
	stepID, _, waiting := saga.WaitingOnGate(state)
	if !waiting {
		return nil
	}
	st, ok := state.Step(stepID)
	if !ok {
		return nil
	}
	phase := saga.PhaseUnderDecision(st)
	openedAt := saga.GateOpenedAt(st, phase)
	attempt := saga.AttemptUnderDecision(st, phase)

	runner := saga.NewRunner(s.app, s.participant)
	runner.Adopt(state)

	for _, req := range saga.GatesFor(st, phase) {
		if !saga.DeadlineElapsed(req, openedAt, now) {
			continue
		}
		// The ticker fires again while the saga is still held -- nothing unwinds
		// it until something drives it -- so this requirement comes round on
		// every tick until then.
		//
		// The duplicate would be refused anyway: the state machine rejects a
		// second answer from the same actor for the same requirement and
		// attempt, which is checked and is not something this relies on being
		// added. What this avoids is the *error* -- without it the daemon logs
		// a failed expiry every few seconds for as long as the saga sits there,
		// which is how a log stops being worth reading. Removing it does not
		// corrupt anything, and that is why no test catches its absence.
		if answered(st, req.GetId(), attempt) {
			continue
		}
		answer := &janusv1.GateAnswer{
			SagaId: sagaID, StepId: stepID, RequirementId: req.GetId(), Attempt: attempt,
			Actor:   &janusv1.Actor{Participant: actorRef(s.participant)},
			Verdict: janusv1.Verdict_VERDICT_FAIL,
			Reason:  saga.ExpiryReason,
		}
		if _, err := runner.Answer(ctx, answer); err != nil {
			return fmt.Errorf("recording the expiry of %q: %w", req.GetId(), err)
		}
		expired = true
		log.Printf("orchd: saga %s step %s: gate %q went unanswered for %s and was refused "+
			"on the deadline's behalf", sagaID, stepID, req.GetId(),
			time.Duration(req.GetTimeoutSeconds())*time.Second)
	}

	if !expired {
		return nil
	}
	// Drive, with the lock still held, for the reason RecordAnswer drives after
	// an approval: an answer that is recorded and not acted on leaves the saga
	// exactly where it was. Without this the expiry was written down and the
	// saga stayed GATED — still holding its resource frontiers, still an ageing
	// row in a queue — which is the situation gate timeouts exist to end. The chaos
	// scenario found it; nothing else had, because every earlier test asserted
	// the *record* rather than what happened next.
	if _, err := s.driveLocked(ctx, sagaID, h); err != nil {
		return fmt.Errorf("advancing %q after its gate expired: %w", sagaID, err)
	}
	return nil
}

// actorRef renders the daemon's own identity as the actor of an expiry.
//
// A participant actor with no human subject, which is what makes an expiry
// structurally distinguishable from an approval: the console's path always
// records the authenticated subject, so an answer with none did not come from a
// person. That is one of the three things saga.IsExpiry checks together.
func actorRef(p evidence.ParticipantRef) *janusv1.ParticipantRef {
	return &janusv1.ParticipantRef{
		Id: p.ID, ManifestVersion: p.ManifestVersion, Principal: p.Principal,
	}
}

// answered reports whether this requirement already has an answer for this
// attempt.
func answered(st *saga.Step, reqID string, attempt uint32) bool {
	return len(saga.AnswersFor(st, reqID, attempt)) > 0
}

// sagasWaitingOnGates names the sagas with a step held at a gate.
//
// With a projection configured this is the `held_by_gate` shortlist Phase 6c
// already maintains; without one it replays the directory. Both are exercised,
// because a deployment without `-projection` must expire gates too -- a timeout
// that only works when a reporting database is attached is not a control.
func (s *Server) sagasWaitingOnGates(ctx context.Context) ([]string, error) {
	if s.projection != nil {
		ids, _, err := s.projection.SagasHeldAtAGate(ctx)
		return ids, err
	}
	states, err := saga.ReplayAll(s.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for id, st := range states {
		if _, _, waiting := saga.WaitingOnGate(st); waiting {
			out = append(out, id)
		}
	}
	return out, nil
}
