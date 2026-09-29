// Waiting for a participant that is somewhere else.
//
// Every Program in Phases 0–3 answers immediately: a test scripts its outcomes,
// and a chaos scenario computes them. That is why Run has no way to say "not
// yet" — there was never anything to wait for, and a return value nobody could
// produce would have been dead weight in the interface every scenario has to
// implement.
//
// A hosted coordinator changes that and nothing else. The participant is in
// another process, it is told what to do and answers later, and in between the
// step sits PREPARED with no result. The coordinator must not invent one: the
// whole point is that the log says what happened, and STATUS_UNSPECIFIED
// appended into the gap would be the log saying something happened.
//
// So the wait is expressed the same way the wait for a human already is — as a
// resting place with its own name, distinct from a stall. Reporter is the
// fourth optional half of Program, alongside Proposer, Answerer and Spawner,
// and a Program that does not implement it behaves exactly as it did before.

package saga

import "errors"

// ErrAwaitingParticipant means the saga cannot move because a step it has
// prepared is waiting for the participant that runs it.
//
// It is deliberately not ErrWaiting. Both mean "come back later", but an
// operator reading them acts differently: a saga held by a gate is waiting for
// a person or a policy and the queue is where to look, while a saga awaiting a
// participant is waiting for a machine that may simply be gone. Collapsing the
// two would hide a dead participant behind a screenful of sagas that are merely
// pending approval.
var ErrAwaitingParticipant = errors.New("saga: awaiting a participant")

// Reporter is the optional half of Program for participants that answer out of
// band.
//
// Run stays what it is — a pure function of (stepID, attempt) that a resumed
// coordinator can call again and be told the same thing. Reported is the
// separate question of whether Run has an answer to give yet, and it is asked
// first. Splitting it this way is what keeps the purity claim intact: a Run
// that returned "nothing yet" would be a function of when it was called.
type Reporter interface {
	// Reported says whether an outcome for this attempt has arrived.
	//
	// It must be monotonic per attempt: once true, it stays true. A coordinator
	// that saw an outcome and then did not would record a result for a step it
	// had already reported on, or worse, leave the log describing an attempt
	// twice.
	Reported(stepID string, attempt uint32) bool
}

// Declarer is the optional half of Program for participants that say what a
// step will do before it is prepared.
//
// It exists because of the order the state machine insists on: a step's
// declared facts are bound into its prepare record, and its pre-execution gate
// decides on those facts. So the facts have to exist *before* the step is
// prepared — the step that runs is the step that was judged, which is the whole
// point of declaring them at all.
//
// In process that is free: the Proposer is right there and answers instantly.
// Hosted, the participant has to send them, and a coordinator that prepared the
// step first would judge it on an empty declaration and refuse it. So a hosted
// program says "not yet" here, and the step waits to be prepared rather than
// being prepared and then refused for saying nothing.
//
// A Program that is not a Declarer declares everything immediately, which is
// what every Program written before this one did.
type Declarer interface {
	// Declared says whether this attempt's facts have arrived.
	Declared(stepID string, attempt uint32) bool
}

// declared answers whether the step may be prepared yet.
func (c *Coordinator) declared(stepID string, attempt uint32) bool {
	dec, ok := c.program.(Declarer)
	if !ok {
		return true
	}
	return dec.Declared(stepID, attempt)
}

// reported answers whether the program has an outcome for this attempt. A
// Program that is not a Reporter always does, which is what makes this change
// invisible to every caller written before it.
func (c *Coordinator) reported(stepID string, attempt uint32) bool {
	rep, ok := c.program.(Reporter)
	if !ok {
		return true
	}
	return rep.Reported(stepID, attempt)
}

// AwaitingParticipant reports the first step that has been prepared and is
// waiting for its participant to answer.
//
// Like WaitingOnGate it reads the projection rather than any coordinator's
// memory, so it gives the same answer to the process that prepared the step and
// to an operator asking about a saga from outside.
// A compensation counts: undoing a step is a participant call like any other,
// and a saga stuck halfway through an unwind because the compensating
// participant is silent is the case an operator most needs named, not the case
// to leave looking like a stall.
// A step that is ready and still PLANNED counts too. Reaching this function at
// all means the coordinator found nothing it could do, and an in-process one
// would have prepared that step already — so if it is still sitting there, what
// it is waiting for is a participant to say what it intends to do.
//
// There is a second reason not to prepare it in the meantime, beyond having
// nothing to judge: preparing starts the attempt's timeout. A step prepared
// before anybody is ready to run it spends its budget waiting for a client to
// appear, and then times out for a reason that has nothing to do with the
// participant.
func AwaitingParticipant(s State) (step string, waiting bool) {
	for _, id := range s.Order {
		if s.Steps[id].Status == StepPrepared {
			return id, true
		}
	}
	for _, id := range s.Order {
		if s.Steps[id].Compensation == CompRunning {
			return undoID(id), true
		}
	}
	if ready := Ready(s); len(ready) > 0 {
		return ready[0], true
	}
	return "", false
}
