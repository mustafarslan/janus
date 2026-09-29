package orchd

import (
	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
)

// hostedProgram is what the coordinator asks about a step whose participant is
// in another process.
//
// It answers from what has been reported, and nothing else. Run is still the
// pure function of (stepID, attempt) that the state machine requires — the same
// arguments give the same answer, because the answer is a value the participant
// already sent, not something computed when asked. Reported is the separate
// question of whether that value has arrived, which is what lets the coordinator
// wait instead of inventing a result.
//
// Begin is never called: BeginSaga records the plan itself and this program is
// only ever attached to a saga that already exists. It returns nil rather than
// a plausible empty plan, so that a future caller who reaches it fails loudly
// instead of starting a saga with no steps.
type hostedProgram struct{ h *hosted }

func (p hostedProgram) Begin() *janusv1.SagaBegin { return nil }

func (p hostedProgram) Run(stepID string, attempt uint32) saga.StepOutcome {
	p.h.mu.Lock()
	defer p.h.mu.Unlock()
	return p.h.outcomes[attemptKey(stepID, attempt)]
}

// Declared says whether the participant has sent the facts for this attempt.
// Until it has, the coordinator leaves the step alone rather than preparing it
// with an empty declaration and refusing it at its own gate.
func (p hostedProgram) Declared(stepID string, attempt uint32) bool {
	p.h.mu.Lock()
	defer p.h.mu.Unlock()
	_, ok := p.h.declared[attemptKey(stepID, attempt)]
	return ok
}

// Facts is the declaration itself, read back when the coordinator prepares the
// step. Like Run it is a pure function of its arguments: a resumed coordinator
// asks again and is told the same thing, which is what lets the state machine
// insist that the step which runs is the step that was judged.
func (p hostedProgram) Facts(stepID string, attempt uint32) map[string]saga.FactValue {
	p.h.mu.Lock()
	defer p.h.mu.Unlock()
	return p.h.declared[attemptKey(stepID, attempt)]
}

func (p hostedProgram) Reported(stepID string, attempt uint32) bool {
	p.h.mu.Lock()
	defer p.h.mu.Unlock()
	_, ok := p.h.outcomes[attemptKey(stepID, attempt)]
	return ok
}

// Spawns is the sub-saga a step delegates to, declared with its prepare.
//
// Like Facts it is a pure function of what was declared: a resumed coordinator
// asks again and is told the same thing, which is what stops a retry from
// silently delegating to a different child than the attempt it is retrying.
func (p hostedProgram) Spawns(stepID string) *janusv1.ChildSaga {
	p.h.mu.Lock()
	defer p.h.mu.Unlock()
	return p.h.spawns[stepID]
}

// Undo answers for a compensation, which is keyed by the undo step's own id at
// attempt zero. A compensation has no attempt counter: it runs once, and a
// compensation that failed puts the saga into QUARANTINE rather than being
// tried again with a higher number.
func (p hostedProgram) Undo(stepID string) janusv1.Outcome_Status {
	p.h.mu.Lock()
	defer p.h.mu.Unlock()
	return p.h.outcomes[attemptKey(undoStepID(stepID), 0)].Status
}

// undoStepID mirrors the coordinator's own derivation. It is duplicated rather
// than exported from pkg/saga because the value is part of the log's vocabulary
// — a client reporting a compensation names this id on the wire — and a
// vocabulary that can be changed by editing an unexported helper in another
// package is one that changes by accident.
func undoStepID(stepID string) string { return stepID + "~undo" }
