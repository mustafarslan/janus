// Driving a saga, and picking one up after a crash.
//
// Everything else in this package answers questions about a saga: which steps
// may run, what has to be undone, whether a commit is safe. The Coordinator is
// what acts on those answers, and it exists in this package rather than in a
// service because the Phase 2 exit gate turns on a property that is easier to
// state than to achieve: a coordinator that dies mid-saga and a fresh one that
// picks the saga up from its log must behave identically.
//
// That property comes from one rule, applied without exception: the Coordinator
// holds no memory. Every decision is derived from the projection, which is
// derived from the log. It has no queue of pending work, no note of which step
// it was about to run, no recollection of an attempt it already made. Where a
// conventional orchestrator would keep a work list, this one recomputes it, and
// recomputing it is precisely what recovery does.
//
// The Program is the other half. Executing a step means calling out to a
// participant, and a chaos test cannot call out to anything real, so a Program
// supplies the outcomes instead. It is a function of (step, attempt) rather
// than a stream of scripted results, because a resumed coordinator must be able
// to produce the same outcome for the same attempt without knowing how many
// times its predecessor asked.

package saga

import (
	"context"
	"errors"
	"fmt"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
)

// Program supplies what a step does when it runs, standing in for the
// participants a real coordinator would call.
type Program interface {
	// Begin is the saga to start when there is nothing in the log yet.
	Begin() *janusv1.SagaBegin
	// Run reports what the step's participant returned on this attempt. It
	// must be a pure function of its arguments: a coordinator resuming after a
	// crash calls it with the same arguments and has to get the same answer.
	Run(stepID string, attempt uint32) StepOutcome
	// Undo reports whether a compensation succeeded.
	Undo(stepID string) janusv1.Outcome_Status
}

// Proposer is the optional half of Program for steps whose gates decide on
// values rather than on what the step is.
//
// It is separate for the same reason Spawner is: most steps propose nothing,
// and a Program forced to answer a question about facts it never carries would
// answer it with an empty map that looks like an omission.
//
// Like Run, it must be a pure function of its arguments. A resumed coordinator
// re-proposes the facts its predecessor proposed, which is what lets the state
// machine insist that the step which runs is the step that was judged: if the
// facts drifted between attempts of the same attempt number, that check would
// fire on an honest retry.
type Proposer interface {
	Facts(stepID string, attempt uint32) map[string]FactValue
}

// Answerer is the optional half of Program for gates somebody outside decides.
//
// In a deployment there is no such interface: a human approves in the console
// and a validator agent replies, and either way the answer is appended to the
// log by another process. The coordinator's part is only to notice that the
// answer arrived, which it does by re-reading the projection. This exists so a
// test can play that other process without one.
//
// Returning nil means no answer has arrived yet, which is the ordinary case and
// not an error — a saga waiting on a person is waiting, not stuck.
type Answerer interface {
	// Answer returns the answer available for one gate, or nil. Like Run it
	// must be a pure function of its arguments: a resumed coordinator asks
	// again and must be told the same thing.
	Answer(stepID string, attempt uint32, requirementID string) *janusv1.GateAnswer
}

// Gatekeeper decides whether a step may proceed.
//
// It is an interface rather than a concrete type because deciding is the one
// part of a saga's progress that is not a pure function of the log: it reads a
// policy, and in a later phase it will wait on a human. Keeping it outside this
// package is what stops that nondeterminism leaking into the state machine —
// the decision arrives as a recorded event like any other participant's answer,
// and replay folds the record rather than asking again.
type Gatekeeper interface {
	// Decide judges a step at one phase, given the facts it has put forward.
	//
	// It returns the composite verdict to record and the provenance record
	// explaining how it was reached. The coordinator records the provenance
	// first and the verdict second, so a crash between them leaves a log that
	// says why nothing was decided rather than one that decided without
	// saying why.
	//
	// The two now go down under one durability barrier, which does
	// not change that. The order in the chain is the order here, and a crash
	// mid-batch can still leave the provenance record with no verdict after it
	// — the case this ordering exists for. What it changes is that no caller is
	// told about the provenance record until the verdict is durable too.
	Decide(phase janusv1.GatePhase, s State, st *Step, declared map[string]FactValue) (
		*janusv1.GateVerdict, *janusv1.DecisionProvenanceRecord, error)
}

// StepOutcome is what running a step produced.
type StepOutcome struct {
	Status janusv1.Outcome_Status
	// Code and Message are what the step says about how it went, beside the
	// status: a machine-readable reason and a sentence for whoever reads the
	// log. They go into the recorded result as reported; they were once accepted on the wire and dropped.
	Code    string
	Message string
	// Signature is the reporting participant's signature over the result,
	// recorded with it.
	Signature *janusv1.ParticipantSignature
	Touches   []*janusv1.ResourceTouch
	// Published are facts the step found and is putting on the record, for a
	// later step's gate to decide on. A balance read publishes the balance
	// here; the payment it constrains never gets to state it.
	Published map[string]FactValue
	// ResultHash and ResultRef are what the step produced, by hash and by
	// content-store reference. They go into the recorded result as reported.
	ResultHash []byte
	ResultRef  string
	// Provenance is why: the participant's own decision record, recorded
	// immediately before the result and cited by it.
	Provenance *janusv1.DecisionProvenanceRecord
}

// Coordinator drives one saga to a terminal state.
type Coordinator struct {
	runner  *Runner
	program Program
	// gates decides gate verdicts. A coordinator without one cannot run a step
	// that has requirements: refusing is the only honest answer when the thing
	// that would judge an effect is absent.
	gates Gatekeeper
	// authority is the parent commit that permits this saga's own, for a
	// cascade sub-saga. It is supplied rather than discovered because it lives
	// in a different saga's log.
	authority string
	// steps bounds how many transitions one Drive call will record, so a bug
	// that produces a state the coordinator cannot leave fails as a loud stall
	// rather than as an unbounded log.
	maxSteps int
	// onTransition observes each recorded transition. It exists for tests and
	// harnesses that need to know how far a coordinator got before it died.
	onTransition func(State)
	// dir is the evidence directory, needed to compute the evidence root a
	// commit has to carry.
	dir string
}

// Spawner is the optional half of Program for sagas that delegate work.
//
// It is separate from Program because most sagas do not delegate, and a
// Program that had to answer a question about sub-sagas it never creates would
// invite a nil return that means two different things.
type Spawner interface {
	// Spawns returns the sub-saga a step delegates to, or nil.
	Spawns(stepID string) *janusv1.ChildSaga
}

// NewCoordinator returns a coordinator for a saga.
func NewCoordinator(r *Runner, p Program) *Coordinator {
	return &Coordinator{runner: r, program: p, maxSteps: 1000}
}

// WithAuthority supplies the parent commit that authorises this sub-saga's
// commit. A cascade sub-saga cannot commit without it.
func (c *Coordinator) WithAuthority(parentSagaID string) *Coordinator {
	c.authority = parentSagaID
	return c
}

// WithGatekeeper supplies what decides this saga's gate verdicts.
func (c *Coordinator) WithGatekeeper(g Gatekeeper) *Coordinator {
	c.gates = g
	return c
}

// State returns the current projection.
func (c *Coordinator) State() State { return c.runner.State() }

// ErrStalled means the saga can make no further progress and is not terminal.
// It is a bug in the state machine or the scheduler, not a normal outcome.
var ErrStalled = errors.New("saga: the saga can neither advance nor finish")

// ErrWaiting means the saga is held by a gate that escalated rather than
// deciding. Unlike a stall it is an ordinary outcome: something outside this
// coordinator has to change before the saga can go further.
var ErrWaiting = errors.New("saga: held by a gate")

// WaitingOnGate reports the first step held by an escalated gate.
func WaitingOnGate(s State) (step, reason string, waiting bool) {
	for _, id := range s.Order {
		if st := s.Steps[id]; HeldByGate(st) {
			return id, st.Gate.Reason, true
		}
	}
	return "", "", false
}

// Resume adopts a projection rebuilt from the log.
//
// There is deliberately nothing to reconcile here. A coordinator taking over
// mid-saga does not need to know what its predecessor intended, only what the
// log says happened, and Drive recomputes the rest.
func (c *Coordinator) Resume(s State) { c.runner.Adopt(s) }

// OnTransition registers a callback invoked after each recorded transition.
func (c *Coordinator) OnTransition(f func(State)) { c.onTransition = f }

// Drive advances the saga until it reaches a terminal state.
func (c *Coordinator) Drive(ctx context.Context) (State, error) {
	return c.driveUntil(ctx, State.Terminal)
}

// DriveUntilSealed advances the saga up to the point of commit and stops.
//
// A cascade sub-saga needs this: it can do all of its work and declare its
// footprint, but the authority to release what it is holding belongs to its
// parent and does not exist yet. Stopping here is the correct resting place
// rather than a failure to finish.
func (c *Coordinator) DriveUntilSealed(ctx context.Context) error {
	_, err := c.driveUntil(ctx, func(s State) bool {
		return s.Terminal() || s.Status == StatusSealing
	})
	return err
}

func (c *Coordinator) driveUntil(ctx context.Context, stop func(State) bool) (State, error) {
	for range c.maxSteps {
		s := c.runner.State()
		if stop(s) {
			return s, nil
		}
		advanced, err := c.tick(ctx, s)
		if err != nil {
			return c.runner.State(), err
		}
		if !advanced {
			// A saga held by a gate is not stuck. Nothing this coordinator can
			// do will move it, which looks identical from here, but the two
			// call for opposite responses: a stall is a bug to investigate and
			// a wait is a saga to come back to. Reporting them the same way is
			// how a working system gets debugged for a week.
			if step, reason, waiting := WaitingOnGate(s); waiting {
				return s, fmt.Errorf("%w: saga %q is held at step %q: %s",
					ErrWaiting, s.SagaID, step, reason)
			}
			// Asked after the gate, because a step can be prepared and gated at
			// once and the gate is the more actionable of the two: somebody has
			// to decide before the participant is asked to do anything.
			if step, waiting := AwaitingParticipant(s); waiting {
				return s, fmt.Errorf("%w: saga %q has prepared step %q and is waiting for "+
					"its participant to report", ErrAwaitingParticipant, s.SagaID, step)
			}
			return s, fmt.Errorf("%w: saga %q is %s with %v ready, %v outstanding",
				ErrStalled, s.SagaID, s.Status, Ready(s), Outstanding(s))
		}
		if c.onTransition != nil {
			c.onTransition(c.runner.State())
		}
	}
	return c.runner.State(), fmt.Errorf("saga %q did not finish within %d transitions",
		c.runner.State().SagaID, c.maxSteps)
}

// tick performs the single next thing the saga needs, and reports whether it
// found anything to do.
//
// The order of the cases is the priority order, and it is not arbitrary:
// unwinding comes before starting new work, because a saga that has decided to
// undo itself must not acquire more to undo while it does so.
func (c *Coordinator) tick(ctx context.Context, s State) (bool, error) {
	if s.SagaID == "" {
		_, err := c.runner.Begin(ctx, c.program.Begin())
		return true, err
	}

	switch s.Status {
	case StatusCompensating:
		return c.unwind(ctx, s)

	case StatusSealing:
		return true, c.commit(ctx, s)

	case StatusCreated, StatusRunning, StatusGated:
		// A step that failed for good, or spent its retry budget, is why the
		// saga can no longer go forward. Deciding that here rather than
		// waiting for the scheduler to run out of work is what keeps a poisoned
		// saga from looking the same as a finished one.
		if poisoned := Poisoned(s); len(poisoned) > 0 {
			_, err := c.runner.Abort(ctx, &janusv1.Abort{
				SagaId: s.SagaID,
				ReasonRef: fmt.Sprintf("step %s cannot succeed and has no attempts left",
					poisoned[0]),
			})
			return true, err
		}
		if done, err := c.advance(ctx, s); done || err != nil {
			return done, err
		}
		if Complete(s) {
			return true, c.seal(ctx, s)
		}
		return false, nil

	default:
		return false, nil
	}
}

// advance runs the next ready step, or settles one that is waiting on a gate.
func (c *Coordinator) advance(ctx context.Context, s State) (bool, error) {
	// A step left PREPARED by a crashed predecessor comes first. Its
	// participant may or may not have run, and until a result is recorded that
	// step cannot move in either direction.
	//
	// A hosted coordinator can be told that the answer has not arrived yet
	// (Reporter), and then the honest thing is to skip that step rather than
	// stop the saga: an unrelated branch of the DAG is not waiting on this
	// participant, and refusing to start it would turn every parallel plan into
	// a serial one the moment it ran in a service. Nothing is skipped for an
	// in-process Program, which always has its answer ready.
	for _, id := range s.Order {
		if s.Steps[id].Status == StepPrepared {
			if !c.reported(id, s.Steps[id].Attempt) {
				continue
			}
			return true, c.result(ctx, s, id)
		}
	}
	// An answer that has arrived is recorded before anything is decided on it,
	// and as its own transition rather than folded into the verdict. Two
	// reasons, both about crashes: a coordinator that died between the two
	// leaves an answer nobody has acted on, which the successor simply reads;
	// and the moment between an approval and the decision it permits is exactly
	// where the chaos suite needs a crash point.
	if recorded, err := c.recordAnswer(ctx, s); recorded || err != nil {
		return recorded, err
	}

	for _, id := range s.Order {
		if s.Steps[id].Status == StepGated {
			return c.gate(ctx, s, id, janusv1.GatePhase_GATE_PHASE_PRE_RELEASE)
		}
	}
	for _, id := range Ready(s) {
		st := s.Steps[id]

		// A hosted participant has not said what it intends to do yet, so
		// there is nothing to judge and nothing to bind into the prepare. The
		// next ready step may well be declared, so this skips rather than
		// stops — the same reason the unreported branch above does.
		//
		// Attempt+1, matching proposedFacts: the step has not been prepared, so
		// the attempt being declared for is the one about to start, not the one
		// on the record. Asking about st.Attempt here would look right, find
		// the previous attempt's declaration, and prepare the step with facts
		// from the wrong try.
		if !c.declared(id, st.Attempt+1) {
			continue
		}

		// A step whose policy judges it before it runs is judged before it
		// runs. The state machine refuses the prepare otherwise, so this is not
		// the enforcement — it is the coordinator doing the thing the
		// enforcement exists to require.
		if !PreGateCleared(st) {
			return c.gate(ctx, s, id, janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION)
		}

		prepare := &janusv1.StepPrepare{
			SagaId: s.SagaID, StepId: id,
			EffectClass: st.EffectClass,
			Facts:       factsToProto(c.declaredFacts(s, st)),
		}
		if sp, ok := c.program.(Spawner); ok {
			// A retry has to delegate to a new sub-saga, because the previous
			// one already reached a conclusion of its own. Deriving the id from
			// the attempt keeps that true without the Program having to
			// remember how many attempts there have been — which it could not
			// do reliably across a crash anyway.
			if child := sp.Spawns(id); child != nil {
				prepare.Spawns = attemptScopedChild(child, st.Attempt)
			}
		}
		// The prepare names what the Program declares, not the pinned
		// delegation: if the two differ the fold refuses the prepare, which is
		// the enforcement. Substituting the pin here would be a
		// second, untestable copy of the rule -- a hosted prepare only happens
		// after a re-declaration the daemon has already held to the pin.
		_, err := c.runner.PrepareStep(ctx, prepare)
		return true, err
	}
	return false, nil
}

// recordAnswer appends one answer that has arrived for a gate somebody outside
// decides, and reports whether it recorded anything.
//
// One per call, because each answer is a transition of its own and the driving
// loop expects a single step of progress. Answers that are already on the
// record are skipped by comparing the answerer, which is also what stops a
// Program that keeps offering the same approval from recording it forever.
func (c *Coordinator) recordAnswer(ctx context.Context, s State) (bool, error) {
	answerer, ok := c.program.(Answerer)
	if !ok {
		return false, nil
	}

	for _, id := range s.Order {
		st := s.Steps[id]
		switch st.Status {
		case StepPlanned, StepFailed, StepGated:
		default:
			continue
		}
		phase := PhaseUnderDecision(st)
		attempt := AttemptUnderDecision(st, phase)
		// Under semantics 3 a pre-execution answer is only taken once the gate
		// has put a proposal to it; an answer offered earlier waits for the
		// escalation rather than being recorded about nothing.
		if s.Semantics >= 3 && phase == janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION {
			if _, asked := ProposalUnderDecision(st); !asked {
				continue
			}
		}

		for _, req := range GatesFor(st, phase) {
			if !External(req) {
				continue
			}
			answer := answerer.Answer(id, attempt, req.GetId())
			if answer == nil {
				continue
			}
			actorID, _ := actorIdentity(answer.GetActor())
			if answeredBy(st, req.GetId(), attempt, actorID) {
				continue
			}
			answer.SagaId, answer.StepId = s.SagaID, id
			answer.RequirementId, answer.Attempt = req.GetId(), attempt
			_, err := c.runner.Answer(ctx, answer)
			return true, err
		}
	}
	return false, nil
}

// answeredBy reports whether this actor has already answered this gate.
func answeredBy(st *Step, requirementID string, attempt uint32, actorID string) bool {
	for _, a := range st.Answers {
		if a.RequirementID == requirementID && a.Attempt == attempt && a.ActorID == actorID {
			return true
		}
	}
	return false
}

// declaredFacts returns the facts the step will run on.
//
// A step whose pre-execution gate has already passed runs on the facts that
// gate was shown — read off the projection rather than asked for again, because
// the whole value of judging a proposal is that the thing which runs is the
// thing that was judged. Only a step nobody judged beforehand proposes afresh.
func (c *Coordinator) declaredFacts(s State, st *Step) map[string]FactValue {
	// A gate that cleared this attempt cleared the facts it was shown, and an
	// empty set is a set it was shown: re-asking here would run the step on
	// whatever the Program says now.
	if st.PreGatedAttempt == st.Attempt+1 {
		return st.Facts
	}
	// Before semantics 4 a retry also reused an earlier attempt's facts, which
	// the fold then insisted on; from 4 only a judged attempt is bound, so an
	// ungated retry asks the Program afresh.
	if s.Semantics < 4 && st.Facts != nil {
		return st.Facts
	}
	return c.proposedFacts(st)
}

// proposedFacts asks the Program what the step puts forward.
func (c *Coordinator) proposedFacts(st *Step) map[string]FactValue {
	pr, ok := c.program.(Proposer)
	if !ok {
		return nil
	}
	return pr.Facts(st.ID, st.Attempt+1)
}

// attemptScopedChild gives each attempt at a delegating step its own sub-saga
// id, leaving the first attempt's id unadorned so the common case reads
// naturally in the log.
func attemptScopedChild(child *janusv1.ChildSaga, priorAttempts uint32) *janusv1.ChildSaga {
	if priorAttempts == 0 {
		return child
	}
	return &janusv1.ChildSaga{
		SagaId:     fmt.Sprintf("%s~%d", child.GetSagaId(), priorAttempts+1),
		CommitMode: child.GetCommitMode(),
	}
}

func (c *Coordinator) result(ctx context.Context, s State, id string) error {
	out := c.program.Run(id, s.Steps[id].Attempt)
	result := &janusv1.StepResult{
		SagaId: s.SagaID, StepId: id, Attempt: s.Steps[id].Attempt,
		Outcome:    &janusv1.Outcome{Status: out.Status, Code: out.Code, Message: out.Message},
		Touches:    out.Touches,
		Facts:      factsToProto(out.Published),
		ResultHash: out.ResultHash,
		ResultRef:  out.ResultRef,
		Signature:  out.Signature,
	}
	if out.Provenance != nil {
		_, _, err := c.runner.StepResultWithProvenance(ctx, out.Provenance, result)
		return err
	}
	_, err := c.runner.StepResult(ctx, result)
	return err
}

// gate consults the gatekeeper and records what it decided.
//
// The ordering is the same discipline as everywhere else in Janus, placed by
// what a crash immediately after each write would mean. The provenance record
// goes first: a crash between it and the verdict leaves a log holding an
// explanation with no decision attached, which is a saga that has not been
// gated yet and will be gated again on resume. The reverse order would leave a
// decision nothing explains — a step let through, permanently, with no record
// of what permitted it.
//
// It reports whether anything was recorded, because a gate that escalates for
// the same reason it escalated last time has nothing to add. Recording it again
// would grow the log for as long as the wait lasts and bury the moment the
// answer actually changed.
func (c *Coordinator) gate(ctx context.Context, s State, id string,
	phase janusv1.GatePhase) (bool, error) {

	st := s.Steps[id]
	if c.gates == nil {
		return false, fmt.Errorf("saga %q step %q needs a gate decision and this coordinator has "+
			"no gatekeeper; an effect whose judge is absent does not proceed", s.SagaID, id)
	}

	declared := st.Facts
	if phase == janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION {
		// A proposal already escalated is decided on as recorded. Asking the
		// Program again would decide on whatever it says now — a different
		// amount, or nothing at all after a restart emptied a daemon's memory —
		// and count answers given about the first.
		if pinned, ok := ProposalUnderDecision(st); ok {
			declared = pinned
		} else {
			declared = c.proposedFacts(st)
		}
	}

	verdict, dpr, err := c.gates.Decide(phase, s, st, declared)
	if err != nil {
		return false, fmt.Errorf("gate step %q: %w", id, err)
	}
	if verdict == nil {
		return false, fmt.Errorf("the gatekeeper returned no verdict for step %q, which is not a "+
			"decision either way", id)
	}
	// Semantics 3: a proposal is its delegation as well as its facts, and the
	// escalation is where it is written down.
	if phase == janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION && s.Semantics >= 3 {
		if pinned, ok := SpawnUnderDecision(s, st); ok {
			verdict.Spawns = pinned
		} else if sp, ok := c.program.(Spawner); ok {
			verdict.Spawns = ScopedSpawn(sp.Spawns(id), st.Attempt)
		}
	}

	if repeatedEscalation(st, verdict) {
		return false, nil
	}

	// The provenance record and the verdict that cites it go down together,
	// under one durability barrier. They are the only adjacent pair in a gated
	// saga's nine records with no decision between them: the verdict needs the
	// DPR's event id and nothing else, and no effect is released on a DPR alone.
	// Every other boundary is a barrier
	// somebody is entitled to — a policy reads the record before it, a
	// participant runs, or the commit's evidence root is computed over a log
	// that must already hold the seal.
	if dpr != nil {
		_, _, err := c.runner.GateWithProvenance(ctx, dpr, verdict)
		return true, err
	}
	_, err = c.runner.Gate(ctx, verdict)
	return true, err
}

// repeatedEscalation reports whether this verdict says nothing the log does not
// already say.
func repeatedEscalation(st *Step, verdict *janusv1.GateVerdict) bool {
	return verdict.GetVerdict() == janusv1.Verdict_VERDICT_ESCALATE &&
		st.Gate.Verdict == janusv1.Verdict_VERDICT_ESCALATE &&
		st.Gate.Reason == verdict.GetReason()
}

func (c *Coordinator) seal(ctx context.Context, s State) error {
	ix := NewIndex(s)
	_, err := c.runner.Seal(ctx, &janusv1.SealRequest{
		SagaId: s.SagaID, Frontiers: ix.Claims(s.SagaID),
	})
	return err
}

// WithEvidenceDir tells the coordinator where the log lives, so a commit can
// carry the evidence root over the saga's own events.
func (c *Coordinator) WithEvidenceDir(dir string) *Coordinator {
	c.dir = dir
	return c
}

func (c *Coordinator) commit(ctx context.Context, s State) error {
	// A commit must carry the root of the evidence it is committing. It is not decoration: an outbox release cites this value as the
	// authority that permitted an irreversible effect, so a commit without one
	// authorises nothing and the release path is right to refuse it.
	var root []byte
	if c.dir != "" {
		var err error
		// Live, for the same reason ResumeSaga is: the commit that is about to
		// cite this root is being appended to the log it is computed from.
		if root, err = EvidenceRoot(c.dir, s.SagaID, c.runner.LiveRead()...); err != nil {
			return fmt.Errorf("saga %q cannot commit because its evidence root could not be "+
				"computed, and a commit that cites no evidence cannot authorise an effect: %w",
				s.SagaID, err)
		}
	}
	_, err := c.runner.Commit(ctx, &janusv1.Commit{
		SagaId: s.SagaID, LastSeq: s.LastSeq, AuthorizedBy: c.authority, EvidenceRoot: root,
	})
	return err
}

// unwind runs the next compensation, or finishes the undo phase.
func (c *Coordinator) unwind(ctx context.Context, s State) (bool, error) {
	// A compensation left in flight by a crash is settled first, for the same
	// reason a PREPARED step is: nothing else can be decided until the log
	// says how it turned out. And for the same reason as there, a hosted
	// coordinator may be told the undo's participant has not answered yet —
	// in which case the next compensation in the plan can still start, because
	// PlanCompensation already refuses to offer one that must wait for this.
	var awaitingUndo bool
	for _, id := range s.Order {
		if s.Steps[id].Compensation == CompRunning {
			if !c.reported(undoID(id), 0) {
				awaitingUndo = true
				continue
			}
			return true, c.undoResult(ctx, s, id)
		}
	}

	plan, err := PlanCompensation(s)
	if err != nil {
		return false, err
	}
	if next, ok := plan.Next(); ok {
		_, err := c.runner.PrepareStep(ctx, &janusv1.StepPrepare{
			SagaId: s.SagaID, StepId: undoID(next), Compensates: next,
			Action: s.Steps[next].CompensationAction,
		})
		return true, err
	}

	if len(plan.Order) > 0 {
		// Something is left to undo but nothing may run: the compensation
		// order has a cycle or a blocker that never clears. Reporting it as a
		// stall is right — quarantining here would hide a scheduling bug
		// behind an operational state.
		return false, nil
	}

	// A compensation is in flight and its participant has not answered. There
	// is nothing left to *start*, which is not the same as nothing left to do,
	// and the difference is the whole saga: falling through from here would
	// quarantine one that is merely mid-undo, with the compensating step still
	// running and about to succeed. QUARANTINE is a state a human has to leave,
	// so entering it by accident is expensive in exactly the way an operational
	// state should never be.
	if awaitingUndo {
		return false, nil
	}

	// Nothing left to undo. Whether that is a clean unwind or a quarantine is
	// decided by what could not be reversed.
	if stuck := Outstanding(s); len(stuck) > 0 {
		_, err := c.runner.Quarantine(ctx, &janusv1.Quarantine{
			SagaId: s.SagaID, FailedStep: stuck[0], Outstanding: stuck,
			Reason: "a compensation did not succeed, so the saga is frozen for a human",
		})
		return true, err
	}
	return false, nil
}

func (c *Coordinator) undoResult(ctx context.Context, s State, id string) error {
	_, err := c.runner.StepResult(ctx, &janusv1.StepResult{
		SagaId: s.SagaID, StepId: undoID(id),
		Outcome: &janusv1.Outcome{Status: c.program.Undo(id)},
	})
	return err
}

// undoID is the step id a compensation records under. It is derived rather
// than generated so that a resumed coordinator names the compensation the same
// way its predecessor did.
func undoID(stepID string) string { return stepID + "~undo" }

// ResumeSaga rebuilds a saga's projection from the log and returns a
// coordinator positioned to continue it.
//
// A saga with nothing in the log yet is not an error: it is the ordinary case
// of starting one, and treating it as a distinct path would mean the recovery
// route and the first-run route were different code, which is how they drift.
func ResumeSaga(app *evidence.Appender, dir, sagaID string,
	participant evidence.ParticipantRef, p Program) (*Coordinator, error) {
	r := NewRunner(app, participant)
	c := NewCoordinator(r, p).WithEvidenceDir(dir)

	// Read live: this process is appending to the directory it is about to
	// read, and on a busy node something else is mid-write almost always.
	events, err := LoadEvents(dir, sagaID, r.LiveRead()...)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return c, nil
	}
	s, err := Replay(events)
	if err != nil {
		return nil, fmt.Errorf("saga %q cannot be resumed because its log does not replay: %w", sagaID, err)
	}
	c.Resume(s)
	return c, nil
}
