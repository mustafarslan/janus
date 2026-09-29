package orchd

import (
	"fmt"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/saga"
)

// projection converts the saga projection into the lossy view clients get.
//
// Lossy is deliberate and is the same rule the registry's AgentCard follows:
// this message says less than the log, and nothing may make
// a gating decision from it. What it does carry is what a client has to decide
// its own next move — which step is theirs to run, and what is holding the ones
// that are not.
func projection(s saga.State) *janusv1.SagaProjection {
	out := &janusv1.SagaProjection{
		SagaId:           s.SagaID,
		Status:           sagaState(s.Status),
		LastSeq:          s.LastSeq,
		AbortReason:      s.AbortReason,
		QuarantineReason: s.QuarantineReason,
		Intent: &janusv1.Intent{
			IntentId:   s.IntentID,
			Principal:  s.Intent.Principal,
			Originator: s.Intent.Originator,
			MandateRef: s.Intent.MandateRef,
			Scope:      s.Intent.Scope,
		},
	}
	waitingStep, waitingReason, gateWaiting := saga.WaitingOnGate(s)
	// Steps are only claimable while the saga is going forward. A saga that is
	// unwinding has work for a participant — the compensations — but it is not
	// this work, and a client told otherwise would try to run a step the saga
	// has already decided to undo. What is left of an unwind is reported by
	// awaiting_compensation, which is a different call to a different action.
	claimable := map[string]bool{}
	switch s.Status {
	case saga.StatusCreated, saga.StatusRunning, saga.StatusGated:
		for _, id := range saga.Ready(s) {
			claimable[id] = true
		}
	}
	for _, id := range s.Order {
		st := s.Steps[id]
		sp := &janusv1.StepProjection{
			StepId:      st.ID,
			Participant: st.Participant,
			Action:      st.Action,
			EffectClass: st.EffectClass,
			Status:      stepState(st.Status),
			Attempt:     st.Attempt,
			DependsOn:   st.DependsOn,
			// Unclaimed work, in either of its two forms: a step ready to be
			// declared and prepared, or one prepared and waiting for a result.
			AwaitingParticipant: st.Status == saga.StepPrepared || claimable[id],
			// An undo that has been prepared is unclaimed work in exactly the
			// same sense, and is invisible in the step's own status.
			AwaitingCompensation: st.Compensation == saga.CompRunning,
		}
		if gateWaiting && id == waitingStep {
			sp.WaitingOnGate = waitingReason
		}
		sp.PendingGates = pendingGates(s, st)
		out.Steps = append(out.Steps, sp)
	}
	return out
}

func sagaState(s saga.Status) janusv1.SagaState {
	switch s {
	case saga.StatusCreated:
		return janusv1.SagaState_SAGA_STATE_CREATED
	case saga.StatusRunning:
		return janusv1.SagaState_SAGA_STATE_RUNNING
	case saga.StatusGated:
		return janusv1.SagaState_SAGA_STATE_GATED
	case saga.StatusSealing:
		return janusv1.SagaState_SAGA_STATE_SEALING
	case saga.StatusCommitted:
		return janusv1.SagaState_SAGA_STATE_COMMITTED
	case saga.StatusCompensating:
		return janusv1.SagaState_SAGA_STATE_COMPENSATING
	case saga.StatusCompensated:
		return janusv1.SagaState_SAGA_STATE_COMPENSATED
	case saga.StatusQuarantine:
		return janusv1.SagaState_SAGA_STATE_QUARANTINE
	default:
		return janusv1.SagaState_SAGA_STATE_UNSPECIFIED
	}
}

func stepState(s saga.StepStatus) janusv1.StepState {
	switch s {
	case saga.StepPlanned:
		return janusv1.StepState_STEP_STATE_PLANNED
	case saga.StepPrepared:
		return janusv1.StepState_STEP_STATE_PREPARED
	case saga.StepGated:
		return janusv1.StepState_STEP_STATE_GATED
	case saga.StepSealed:
		return janusv1.StepState_STEP_STATE_SEALED
	case saga.StepCommitted:
		return janusv1.StepState_STEP_STATE_COMMITTED
	case saga.StepFailed:
		return janusv1.StepState_STEP_STATE_FAILED
	case saga.StepCompensated:
		return janusv1.StepState_STEP_STATE_COMPENSATED
	case saga.StepRefused:
		return janusv1.StepState_STEP_STATE_REFUSED
	default:
		return janusv1.StepState_STEP_STATE_UNSPECIFIED
	}
}

func evidenceRef(r evidence.Ref) *janusv1.EvidenceRef {
	return &janusv1.EvidenceRef{
		EventId:   r.EventID,
		Seq:       r.Seq,
		SegmentId: r.SegmentID,
		ChainHash: r.ChainHash[:],
		Hlc:       r.HLC,
	}
}

// pendingGates lists the requirements holding a step that somebody outside
// Janus has to answer.
//
// The verdicts come from gate.Decide — the same call the coordinator makes and
// the same one the console's queue makes. Deriving them any other way would be
// a second gate engine, and the interesting failure with a second engine is not
// that it disagrees but that it agrees convincingly while being wrong.
//
// The index is deliberately nil. It answers frontier questions, and a frontier
// gate is decided by Janus rather than by anybody outside — so it is filtered
// out by saga.External before its result is ever read. Building an index here
// would mean re-reading every saga in the log on every projection, to compute a
// value this message does not carry.
func pendingGates(s saga.State, st *saga.Step) []*janusv1.PendingGate {
	// Only a step the coordinator has actually escalated is waiting on anybody.
	// A step whose release gate has not been reached yet has requirements, but
	// nobody has been asked and an answer would be refused as an opinion about
	// a decision that has not been made.
	if len(st.Gates) == 0 || !saga.HeldByGate(st) {
		return nil
	}
	phase := saga.PhaseUnderDecision(st)
	// The same facts the coordinator decides on, so the reason a pending gate
	// gives and the facts it shows are about the question actually open.
	declared := saga.FactsUnderDecision(st, phase)
	decision := gate.Decide(phase, gate.Input{Saga: s, Step: st, Declared: declared})
	asked := gate.Environment(s, st, declared).Proto()
	byReq := make(map[string]gate.Result, len(decision.Results))
	for _, r := range decision.Results {
		byReq[r.RequirementID] = r
	}

	var out []*janusv1.PendingGate
	for _, req := range st.Gates {
		if !saga.External(req) || req.GetPhase() != phase {
			continue
		}
		r, evaluated := byReq[req.GetId()]
		if evaluated && r.Verdict == janusv1.Verdict_VERDICT_PASS {
			// Answered, and to everybody's satisfaction. Listing it would put
			// something in a queue that nobody needs to clear.
			continue
		}
		pg := &janusv1.PendingGate{
			RequirementId: req.GetId(),
			Gate:          req.GetGate(),
			Phase:         req.GetPhase(),
			Attempt:       saga.AttemptUnderDecision(st, phase),
			Detail:        describe(req),
			Facts:         asked,
		}
		if evaluated {
			pg.Reason = r.Reason
		}
		for _, a := range st.Answers {
			if a.RequirementID == req.GetId() && a.Attempt == pg.GetAttempt() {
				pg.AnswersRecorded++
			}
		}
		switch req.GetGate() {
		case janusv1.GateType_GATE_TYPE_HUMAN:
			pg.AnswerableBy = req.GetHuman().GetRoles()
			pg.Quorum = req.GetHuman().GetQuorum()
		case janusv1.GateType_GATE_TYPE_VALIDATOR:
			pg.AnswerableBy = req.GetValidator().GetValidators()
			pg.Quorum = req.GetValidator().GetQuorum()
		}
		if pg.Quorum == 0 {
			// The policy language treats zero as one. Saying so here rather
			// than leaving the caller to know that keeps "how many more answers
			// does this need" a question about the message.
			pg.Quorum = 1
		}
		out = append(out, pg)
	}
	return out
}

// describe is a one-line rendering of what a requirement asks for.
func describe(req *janusv1.GateRequirement) string {
	switch req.GetGate() {
	case janusv1.GateType_GATE_TYPE_HUMAN:
		h := req.GetHuman()
		s := fmt.Sprintf("%d approval(s) from %v", max(h.GetQuorum(), 1), h.GetRoles())
		if h.GetSeparationOfDuty() {
			s += ", none from the saga's initiator"
		}
		return s
	case janusv1.GateType_GATE_TYPE_VALIDATOR:
		v := req.GetValidator()
		return fmt.Sprintf("%d opinion(s) from %v", max(v.GetQuorum(), 1), v.GetValidators())
	default:
		return req.GetGate().String()
	}
}
