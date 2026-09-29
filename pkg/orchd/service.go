package orchd

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/callersig"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/identity"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/telemetry"
	"github.com/mustafarslan/janus/pkg/template"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// BeginSaga admits a plan and records it.
//
// Both admission checks run, and they are different questions. Gate admission
// asks whether the plan can be protected at all — whether every irreversible
// step has either a compensation or a gate standing in for one. Registry
// admission asks whether the plan is what the participants say they do. A
// planner following an injected instruction has every reason to write PURE next
// to a wire transfer, and the manifest is the signed, separately recorded
// account that catches it.
func (s *Server) BeginSaga(ctx context.Context, req *janusv1.BeginSagaRequest) (
	*janusv1.BeginSagaResponse, error) {

	begin := req.GetBegin()
	if begin.GetSagaId() == "" {
		return nil, status.Error(codes.InvalidArgument, "a saga id is required")
	}
	ctx, span := s.telemetry.Start(ctx, telemetry.OperationInvokeAgent, "janus.saga.begin",
		telemetry.Saga(begin.GetSagaId(), begin.GetIntent().GetPrincipal())...)
	var beginErr error
	defer func() { span.End(beginErr) }()

	// The lock is taken before the check, not after it. Two clients retrying
	// the same begin would otherwise both find nothing, both append, and leave
	// the log describing two starts for one intent — a race that shows up once
	// under load and never in a test written for one caller.
	h := s.hostedSaga(begin.GetSagaId())
	h.driving.Lock()
	defer h.driving.Unlock()

	// A saga that already exists is not begun again. A client that retried a
	// request whose response it never saw deserves a clear answer rather than a
	// second saga.
	if existing, err := saga.ReplaySaga(s.dir, begin.GetSagaId()); err == nil &&
		existing.SagaID != "" {
		return nil, status.Errorf(codes.AlreadyExists,
			"saga %q already exists and is %s", begin.GetSagaId(), existing.Status)
	}

	// A refusal is not a span error: admission declining a plan is the system
	// working, and colouring it red would teach an operator to ignore the
	// colour that means something is broken.
	if err := s.engine.Admit(begin); err != nil {
		span.Set(attribute.String(telemetry.AttrVerdict, "REFUSED_BY_GATE_ADMISSION"))
		return nil, status.Errorf(codes.FailedPrecondition,
			"gate admission refused this plan: %v", err)
	}
	if err := s.admitAgainstRegistry(ctx, begin); err != nil {
		span.Set(attribute.String(telemetry.AttrVerdict, "REFUSED_BY_REGISTRY"))
		return nil, status.Errorf(codes.FailedPrecondition,
			"registry admission refused this plan: %v", err)
	}
	// Who is asking, after what the plan is: a plan the registry refuses is
	// refused whoever signed it.
	if reg, err := s.signingRegistry(ctx); err != nil {
		return nil, err
	} else if err := s.checkBegin(reg, begin, req.GetSignature()); err != nil {
		return nil, err
	}

	// A sub-saga folds under its parent's rules. A parent admitted before an
	// upgrade that delegates after it would otherwise have a child whose
	// history means something different from its own.
	//
	// Only a child its parent's step actually recorded spawning inherits them.
	// Naming a parent is the caller's claim; the spawn is the log's. Before
	// this, any new saga naming a version-1 saga as its parent was admitted
	// under version 1, where the proposal swap is legal again. A child begun
	// before its parent recorded the spawn gets the
	// current rules, which can only be stricter.
	//
	// A child of a parent under the current rules gets them either way. A
	// child of an older parent that has not yet recorded spawning it is refused
	// for now rather than admitted under different rules from its parent: the
	// family would disagree about what a history means, and the
	// alternative -- the parent's rules on the caller's say-so -- is route (a).
	// Beginning it again once the parent's step has prepared succeeds.
	version := saga.SemanticsVersion
	if p := begin.GetParent(); p != nil {
		if parent, err := saga.ReplaySaga(s.dir, p.GetSagaId()); err == nil && parent.SagaID != "" &&
			parent.Semantics != saga.SemanticsVersion {
			st, ok := parent.Steps[p.GetStepId()]
			if !ok || st.Child == nil || st.Child.SagaID != begin.GetSagaId() {
				return nil, status.Errorf(codes.FailedPrecondition,
					"saga %q names step %q of %q as its parent, which folds under semantics %d "+
						"and has not recorded spawning it; a sub-saga takes its parent's rules "+
						"only once the parent's step has recorded the delegation, so begin it "+
						"after that step prepares", begin.GetSagaId(), p.GetStepId(),
					p.GetSagaId(), parent.Semantics)
			}
			version = parent.Semantics
		}
	}

	runner := saga.NewRunner(s.app, s.participant)
	ref, err := runner.BeginUnder(ctx, begin, version)
	if err != nil {
		beginErr = err
		return nil, status.Errorf(codes.Internal, "recording the saga: %v", err)
	}
	// After the append, never before: the sequence does not exist until the
	// record is durable, and a span naming one earlier would point at evidence
	// that may not be there.
	span.Evidence(ref.Seq)

	if _, err := s.driveLocked(ctx, begin.GetSagaId(), h); err != nil {
		// The saga exists — the begin is durable and the response says so.
		// Failing to advance it afterwards is a separate problem from failing
		// to start it, and reporting the begin as failed would leave the caller
		// believing nothing was recorded when something was.
		return nil, status.Errorf(codes.Internal,
			"saga %q was recorded at seq %d but could not be advanced: %v",
			begin.GetSagaId(), ref.Seq, err)
	}
	return &janusv1.BeginSagaResponse{SagaId: begin.GetSagaId(), Ref: evidenceRef(ref)}, nil
}

// admitAgainstRegistry folds the registry out of this log and checks the plan.
//
// It is folded per call rather than cached. The registry is a projection of the
// log, a manifest can be suspended between one saga and the next, and
// a cache would admit a plan against a version that had been withdrawn — which
// is precisely the check this is.
func (s *Server) admitAgainstRegistry(ctx context.Context, begin *janusv1.SagaBegin) error {
	reg, err := s.registryNow(ctx)
	if err != nil {
		return err
	}
	if err := registry.AdmitFor(reg, begin, s.tenant); err != nil {
		return err
	}
	// The same fold, not a second one. Two folds can straddle an append, and the
	// child would then be confined against a registry the manifest check never
	// saw -- the sort of difference that shows up once, under load, as a saga
	// admitted against a document that was not there a moment earlier.
	return s.confineChildToItsParent(reg, begin)
}

// confineChildToItsParent refuses a child of a crystallized saga that is not
// itself crystallized.
//
// # The hole this closes
//
// Phase 6f confines a crystallized saga's own plan to a template. A child saga
// is admitted separately, with its own mode and its own plan — so a crystallized
// parent whose step delegated to a `supervised` child had confined its own steps
// and handed the rest to a saga nobody was holding to any shape. The
// confinement stopped at the saga boundary, and "this saga is confined to a
// template" reads as a statement about everything it causes.
//
// # Why the check is here and not in registry.AdmitFor
//
// It needs the *parent's* mode, which is in the parent's SAGA_BEGIN in the log.
// `registry.AdmitFor` has a registry and no log, deliberately — it is the same
// function an auditor runs over a bundle. This is the same lookup
// `outbox.LogModes` does for the exploratory check, in the one place that has
// the directory.
//
// # What this rule is
//
// Two halves, and the second is what makes a crystallized *tree* confined.
// Every saga in the tree must be confined to some validated,
// activated template — that removes the escape hatch, a crystallized parent
// delegating to something held to nothing. And it must be **the template the
// parent's own template named for that step**: `template.Step.ChildTemplate`.
//
// Without the second half the parent confined its own shape and not its
// delegates', because the child's template was chosen by whoever wrote the
// child's plan. With it, the shape of the whole tree is decided by the one
// signed document at its root.
//
// A step that declares no child template refuses the spawn outright. That is
// not a gap left open, it is the rule: a template extracted from runs that never
// delegated has no evidence about delegating, and treating silence as permission
// would reopen the hole by a different route — extract from runs that did not
// spawn, then spawn under it.
func (s *Server) confineChildToItsParent(reg *registry.Registry, begin *janusv1.SagaBegin) error {
	parent := begin.GetParent()
	if parent == nil {
		return nil
	}
	events, err := saga.LoadEvents(s.dir, parent.GetSagaId())
	if err != nil {
		return fmt.Errorf("reading the parent saga %q to check what it confines its children "+
			"to: %w", parent.GetSagaId(), err)
	}
	if len(events) == 0 {
		// A child whose parent the log has never begun is refused by the saga
		// state machine anyway; saying nothing here would be relying on that.
		return fmt.Errorf("saga %q declares parent %q, which the log has no beginning for",
			begin.GetSagaId(), parent.GetSagaId())
	}
	// The mode is on SAGA_BEGIN and cannot change, so the first event answers it.
	head, err := saga.Replay(events[:1])
	if err != nil {
		return fmt.Errorf("reading the parent saga %q: %w", parent.GetSagaId(), err)
	}
	if saga.Mode(head.Mode) != saga.ModeCrystallized {
		return nil
	}
	if saga.Mode(begin.GetMode()) != saga.ModeCrystallized {
		return fmt.Errorf("%w: saga %q is a child of %q, which is crystallized, and runs in "+
			"mode %q; a crystallized saga may not delegate to one confined to nothing, or the "+
			"confinement would stop at the first step that spawns",
			registry.ErrNotAdmissible, begin.GetSagaId(), parent.GetSagaId(), begin.GetMode())
	}
	return confineChildToTheTemplateItsParentNamed(reg, begin, head)
}

// confineChildToTheTemplateItsParentNamed is the second half of child confinement.
//
// The parent's pin and the spawning step both come off the parent's SAGA_BEGIN,
// which this has already read — `ParentSaga` carries `step_id` precisely so a
// child can say which step of its parent produced it.
//
// The parent's template is resolved by the pin it recorded, not by whichever
// version is active now. A saga admitted under one shape is confined to that
// shape for its whole life, and reading the active version here would
// mean activating a successor silently re-confined every child of every parent
// still running — which is the thing the supersede fix is careful *not*
// to do.
func confineChildToTheTemplateItsParentNamed(reg *registry.Registry,
	begin *janusv1.SagaBegin, parentBegin saga.State) error {

	pin := parentBegin.TemplatePin
	if pin == nil {
		// A crystallized saga with no pin is refused at its own admission, so
		// this is unreachable through BeginSaga. Refusing rather than returning
		// nil keeps it that way: a caller that reached here with no pin would
		// otherwise get the child admitted with nothing checked.
		return fmt.Errorf("%w: saga %q is a child of crystallized saga %q, which records no "+
			"template pin, so there is no document saying what its children are confined to",
			registry.ErrNotAdmissible, begin.GetSagaId(), parentBegin.SagaID)
	}
	e, ok := reg.ResolveTemplate(pin.ID, pin.Version)
	if !ok {
		return fmt.Errorf("%w: saga %q is a child of %q, which pins template %s@%s that the "+
			"registry does not hold; its children cannot be confined by a document nobody has",
			registry.ErrNotAdmissible, begin.GetSagaId(), parentBegin.SagaID, pin.ID, pin.Version)
	}

	stepID := begin.GetParent().GetStepId()
	var step *template.Step
	for i := range e.Template.Steps {
		if e.Template.Steps[i].StepID == stepID {
			step = &e.Template.Steps[i]
			break
		}
	}
	if step == nil {
		return fmt.Errorf("%w: saga %q says it was spawned by step %q of %q, and template "+
			"%s@%s has no such step", registry.ErrNotAdmissible, begin.GetSagaId(), stepID,
			parentBegin.SagaID, pin.ID, pin.Version)
	}
	if step.ChildTemplate == "" {
		return fmt.Errorf("%w: saga %q was spawned by step %q of %q, and template %s@%s does "+
			"not say what a child of that step is confined to; a shape extracted from runs "+
			"that never delegated is no evidence about delegating, so the spawn is refused "+
			"rather than left to whatever the child chose to pin",
			registry.ErrNotAdmissible, begin.GetSagaId(), stepID, parentBegin.SagaID,
			pin.ID, pin.Version)
	}
	if got := begin.GetTemplatePin().GetTemplateId(); got != step.ChildTemplate {
		return fmt.Errorf("%w: saga %q pins template %q, and step %q of its parent's template "+
			"%s@%s confines its children to %q; the parent's document is what decides the "+
			"shape of the tree",
			registry.ErrNotAdmissible, begin.GetSagaId(), got, stepID, pin.ID, pin.Version,
			step.ChildTemplate)
	}
	return nil
}

// registryNow folds the registry as the log stands.
//
// With a projection configured this reads the projected event stream, having
// first required it to have caught up to the head of the log; without one it
// walks the segment directory as it always did. The two produce the same
// registry from the same events by the same state machine — the difference is
// where the events were read from, which is the whole of what the projection
// changes.
//
// The head is read before the catch-up, not after, for this reason:
// what must be projected is everything that existed when the question was asked,
// and reading it afterwards would let a concurrent append move the bar.
func (s *Server) registryNow(ctx context.Context) (*registry.Registry, error) {
	if s.projector != nil {
		reg, err := s.projector.Registry(ctx, s.app.Stats().LastSeq)
		if err != nil {
			return nil, fmt.Errorf("reading the registry from the projection: %w", err)
		}
		return reg, nil
	}
	// Live: this process owns the writer lock on the directory it is reading,
	// so a half-written record is not damage. Without the head, an
	// ordinary Begin could fail with "recover the log" while the daemon was
	// simply busy — which is the operator-facing harm naming the head
	// prevents, on the admission path of all places.
	events, err := registry.LoadEvents(s.dir, evidence.AsOf(s.app.Stats().LastSeq))
	if err != nil {
		return nil, fmt.Errorf("reading the registry from the log: %w", err)
	}
	reg, err := registry.Fold(events)
	if err != nil {
		return nil, fmt.Errorf("folding the registry: %w", err)
	}
	return reg, nil
}

// PrepareStep advances the saga and hands back the step if it is the caller's
// to run.
//
// The refusals are typed rather than collapsed into one "not now", because a
// client acts differently on each: a gated step needs somebody to decide, an
// unready step needs its dependencies to finish, and an unavailable one is
// never coming. A client told only "not yet" would poll all three the same way,
// including the one waiting on a human.
func (s *Server) PrepareStep(ctx context.Context, req *janusv1.PrepareStepRequest) (
	*janusv1.PrepareStepResponse, error) {

	if req.GetSagaId() == "" || req.GetStepId() == "" {
		return nil, status.Error(codes.InvalidArgument, "a saga id and a step id are required")
	}
	facts, err := saga.FactsFromProto(req.GetFacts())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"the declared facts are not usable: %v", err)
	}

	h := s.hostedSaga(req.GetSagaId())
	h.driving.Lock()
	defer h.driving.Unlock()

	// The declaration is recorded before the saga is advanced, because
	// advancing is what prepares the step and the prepare binds the facts. The
	// other order judges the step on nothing.
	state, err := saga.ReplaySaga(s.dir, req.GetSagaId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "saga %q: %v", req.GetSagaId(), err)
	}
	// Confined before the declaration is recorded, because recording it is what
	// binds the facts a gate then decides against. Doing it afterwards would
	// judge the step on a declaration this refuses.
	if err := s.confineToTemplate(ctx, state, req.GetStepId(), req.GetFacts()); err != nil {
		return nil, err
	}

	st, ok := state.Steps[req.GetStepId()]
	if !ok {
		return nil, status.Errorf(codes.NotFound,
			"saga %q has no step %q", req.GetSagaId(), req.GetStepId())
	}
	// The declaration is the step's participant's to make.
	if err := s.checkStepCaller(ctx, req.GetSagaId(), st.Participant, req.GetSignature(),
		callersig.Prepare(req.GetSagaId(), req.GetStepId(), req.GetFacts(), req.GetSpawns()),
		"a declaration for step "+strconv.Quote(st.ID)); err != nil {
		return nil, err
	}
	// A proposal a gate has escalated on is not the participant's to change
	// while the decision is open: the answers being collected are about it. The
	// state machine would refuse the verdict that followed a swap anyway; this
	// says so to the one party that can do something about it, instead of
	// leaving its new proposal silently unused.
	if pinned, held := saga.ProposalUnderDecision(st); held && !maps.Equal(pinned, facts) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"step %q attempt %d is waiting on a decision about %s; a different proposal "+
				"cannot replace it while that decision is open",
			st.ID, st.Attempt+1, strings.Join(saga.DescribeFacts(pinned), " "))
	}

	// Attempt+1 for the same reason the coordinator asks its Proposer for
	// Attempt+1: the step has not been prepared, so what is being declared is
	// the attempt about to start. The response reports that same number back,
	// which is what the participant then sends with its result.
	// The delegation is part of the proposal (semantics 3): while the
	// decision is open the participant may not change the sub-saga either. The
	// pin is read from the log, so a restart does not forget it.
	if pinned, held := saga.SpawnUnderDecision(state, st); held &&
		!saga.SameSpawn(pinned, saga.ScopedSpawn(req.GetSpawns(), st.Attempt)) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"step %q attempt %d is waiting on a decision about a proposal that %s; a "+
				"proposal that %s cannot replace it while that decision is open",
			st.ID, st.Attempt+1, saga.DescribeSpawn(pinned),
			saga.DescribeSpawn(saga.ScopedSpawn(req.GetSpawns(), st.Attempt)))
	}

	h.declare(req.GetStepId(), st.Attempt+1, facts)
	if child := req.GetSpawns(); child != nil {
		h.mu.Lock()
		h.spawns[req.GetStepId()] = child
		h.mu.Unlock()
	}

	state, err = s.driveLocked(ctx, req.GetSagaId(), h)
	if err != nil {
		return nil, driveError(req.GetSagaId(), err)
	}
	if st, ok = state.Steps[req.GetStepId()]; !ok {
		return nil, status.Errorf(codes.NotFound,
			"saga %q has no step %q", req.GetSagaId(), req.GetStepId())
	}

	if st.Status == saga.StepPrepared {
		_, span := s.telemetry.Start(ctx, telemetry.OperationExecuteTool, "janus.step.prepare",
			append(telemetry.Saga(req.GetSagaId(), state.Intent.Principal),
				telemetry.Step(st.ID, st.Action, registry.ShortClass(st.EffectClass),
					st.Attempt)...)...)
		prepare, ref, err := s.preparedRecord(req.GetSagaId(), req.GetStepId())
		span.Evidence(ref.GetSeq())
		span.End(err)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "reading the prepare record: %v", err)
		}
		return &janusv1.PrepareStepResponse{
			Prepare: prepare, Ref: ref, Attempt: st.Attempt,
			Status: janusv1.PrepareStatus_PREPARE_STATUS_PREPARED,
		}, nil
	}

	resp := &janusv1.PrepareStepResponse{}
	switch {
	case st.Status == saga.StepPlanned && state.Status == saga.StatusCompensating,
		st.Status != saga.StepPlanned,
		state.Terminal():
		resp.Status = janusv1.PrepareStatus_PREPARE_STATUS_UNAVAILABLE
		resp.Reason = fmt.Sprintf("step is %s and the saga is %s", st.Status, state.Status)
	default:
		if step, reason, waiting := saga.WaitingOnGate(state); waiting && step == req.GetStepId() {
			resp.Status = janusv1.PrepareStatus_PREPARE_STATUS_GATED
			resp.Reason = reason
			break
		}
		if !saga.PreGateCleared(st) {
			resp.Status = janusv1.PrepareStatus_PREPARE_STATUS_GATED
			resp.Reason = "the step's pre-execution gate has not passed"
			break
		}
		resp.Status = janusv1.PrepareStatus_PREPARE_STATUS_NOT_READY
		resp.Reason = fmt.Sprintf("waiting on %v", st.DependsOn)
	}
	return resp, nil
}

// preparedRecord finds the StepPrepare the coordinator appended.
//
// It is read back from the log rather than reconstructed from the projection.
// The two would almost always agree, and the caller is about to act on it: an
// "almost" in the arguments a participant is handed is how a step does
// something slightly different from what the evidence says it was asked to do.
func (s *Server) preparedRecord(sagaID, stepID string) (*janusv1.StepPrepare,
	*janusv1.EvidenceRef, error) {

	var msg janusv1.StepPrepare
	seq, err := s.lastRecordFor(sagaID, evidence.KindStepPrepare, stepID, &msg,
		func() string { return msg.GetStepId() })
	if err != nil {
		return nil, nil, err
	}
	return &msg, &janusv1.EvidenceRef{Seq: seq}, nil
}

// resultRef locates the result the coordinator appended for a step, so the
// response can cite it.
//
// The caller has to be able to point at the evidence for what it reported, not
// merely be told the call worked. "It was recorded" with nothing to check is
// the shape of claim this whole system exists to replace.
func (s *Server) resultRef(sagaID, stepID string) (*janusv1.EvidenceRef, error) {
	var msg janusv1.StepResult
	seq, err := s.lastRecordFor(sagaID, evidence.KindStepResult, stepID, &msg,
		func() string { return msg.GetStepId() })
	if err != nil {
		return nil, err
	}
	return &janusv1.EvidenceRef{Seq: seq}, nil
}

// lastRecordFor scans a saga's log backwards for the most recent record of one
// kind naming one step.
//
// Backwards because the answer wanted is always the latest: a retried step has
// a prepare and a result per attempt, and the caller is asking about the
// attempt that is live now.
func (s *Server) lastRecordFor(sagaID string, kind evidence.Kind, stepID string,
	into proto.Message, stepOf func() string) (uint64, error) {

	events, err := saga.LoadEvents(s.dir, sagaID)
	if err != nil {
		return 0, err
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Kind != kind {
			continue
		}
		if err := proto.Unmarshal(events[i].Payload, into); err != nil {
			return 0, err
		}
		if stepOf() == stepID {
			return events[i].Seq, nil
		}
	}
	return 0, fmt.Errorf("saga %q has no %s record for step %q", sagaID, kind, stepID)
}

// CompleteStep records what a participant did.
func (s *Server) CompleteStep(ctx context.Context, req *janusv1.CompleteStepRequest) (
	*janusv1.CompleteStepResponse, error) {

	res := req.GetResult()
	if res.GetSagaId() == "" || res.GetStepId() == "" {
		return nil, status.Error(codes.InvalidArgument, "a saga id and a step id are required")
	}
	if res.GetOutcome().GetStatus() == janusv1.Outcome_STATUS_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument,
			"an outcome status is required; UNSPECIFIED would record that the step ran "+
				"and say nothing about how it went")
	}

	// Everything from here — reading the state, deciding whether this attempt
	// is already settled, storing the outcome, appending it — is one critical
	// section. Deciding "not yet recorded" from a state read before the lock is
	// how two reports of one attempt both get through.
	h := s.hostedSaga(res.GetSagaId())
	h.driving.Lock()
	defer h.driving.Unlock()

	state, err := saga.ReplaySaga(s.dir, res.GetSagaId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "saga %q: %v", res.GetSagaId(), err)
	}
	stepID, isUndo := compensatedStep(res.GetStepId())
	if !isUndo && res.GetAttempt() == 0 {
		// Attempts count from one. A report for attempt zero is about an attempt
		// that never existed, and answering it "already recorded" would tell the
		// reporter its account is on the record when nothing is.
		return nil, status.Error(codes.InvalidArgument,
			"attempt 0 is not an attempt; report the attempt number PrepareStep returned")
	}
	if isUndo && (req.GetProvenance() != nil || len(res.GetResultHash()) > 0 || res.GetResultRef() != "" ||
		res.GetOutcome().GetCode() != "" || res.GetOutcome().GetMessage() != "" ||
		len(res.GetTouches()) > 0 || len(res.GetFacts()) > 0) {
		// A compensation's outcome is reported through Program.Undo, which
		// carries a status and nothing else. Accepting what it cannot record
		// would be the dropped-result defect again, one path over: a call that
		// succeeds and a log that does not contain what it was sent.
		return nil, status.Error(codes.FailedPrecondition,
			"a compensation's result hash, reference, provenance, code, message, touches "+
				"and facts are not recorded; report its outcome status alone")
	}
	if err := checkProvenance(req.GetProvenance()); err != nil {
		return nil, err
	}
	st, ok := state.Steps[stepID]
	if !ok {
		return nil, status.Errorf(codes.NotFound,
			"saga %q has no step %q", res.GetSagaId(), stepID)
	}
	// The result is the step's participant's to report, including a retry of
	// one already recorded: an unsigned caller may not even probe.
	if err := s.checkStepCaller(ctx, res.GetSagaId(), st.Participant, res.GetSignature(),
		callersig.Result(res), "a result for step "+strconv.Quote(res.GetStepId())); err != nil {
		return nil, err
	}

	if already, err := alreadyRecorded(st, res, isUndo); err != nil {
		return nil, err
	} else if already {
		// A participant that timed out waiting for this response and retried is
		// doing the right thing. Telling it the request failed would be a lie
		// that turns a healthy retry into a stuck step.
		//
		// But only a retry is a retry. A second report that tells a different
		// story — another status, another hash, another reason — is two
		// accounts of one attempt, and answering it "already recorded" told the
		// second reporter its account was on the record when the first one
		// was. Before this, the write-once refusal below was only reached by a
		// report the log did not yet hold, which is almost never.
		if err := s.sameAsRecorded(res, req.GetProvenance(), isUndo); err != nil {
			return nil, err
		}
		return &janusv1.CompleteStepResponse{AlreadyRecorded: true}, nil
	}

	_, span := s.telemetry.Start(ctx, telemetry.OperationExecuteTool, "janus.step.complete",
		append(telemetry.Saga(res.GetSagaId(), state.Intent.Principal),
			telemetry.Step(stepID, st.Action, registry.ShortClass(st.EffectClass),
				res.GetAttempt())...)...)
	span.Set(attribute.String(telemetry.AttrOutcome, res.GetOutcome().GetStatus().String()))
	var completeErr error
	defer func() { span.End(completeErr) }()

	if err := h.record(res, req.GetProvenance(), isUndo); err != nil {
		completeErr = err
		return nil, err
	}
	after, err := s.driveLocked(ctx, res.GetSagaId(), h)
	if err != nil {
		// A report the log refused is not an account of the attempt. Keeping
		// it in memory would make the participant's corrected report "a
		// different account" of a report nobody recorded, and wedge the step. What
		// reached the log is the account; what did not
		// is forgotten.
		// Unconditionally: once a result is in the log nothing reads the
		// in-memory copy, so forgetting one that did get recorded costs
		// nothing, while deciding from a re-read of the log could fail and
		// leave the wedge in place.
		h.forget(res.GetStepId(), res.GetAttempt(), isUndo)
		return nil, driveError(res.GetSagaId(), err)
	}
	ref, err := s.resultRef(res.GetSagaId(), res.GetStepId())
	if err == nil {
		span.Evidence(ref.GetSeq())
	}
	if err != nil {
		completeErr = err
		return nil, status.Errorf(codes.Internal,
			"saga %q is %s but the result for %q is not in the log: %v",
			res.GetSagaId(), after.Status, res.GetStepId(), err)
	}
	return &janusv1.CompleteStepResponse{Ref: ref}, nil
}

// record stores the outcome for the coordinator to append.
//
// Write-once per attempt. A second, different outcome for the same attempt is
// refused rather than overwriting: two accounts of one attempt is a
// participant bug or an impersonation, and picking the later one silently would
// let whichever arrived last decide what the log says happened.
func (h *hosted) record(res *janusv1.StepResult, dpr *janusv1.DecisionProvenanceRecord,
	isUndo bool) error {
	attempt := res.GetAttempt()
	if isUndo {
		attempt = 0
	}
	key := attemptKey(res.GetStepId(), attempt)
	published, err := saga.FactsFromProto(res.GetFacts())
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "the reported facts are not usable: %v", err)
	}
	outcome := saga.StepOutcome{
		Status:     res.GetOutcome().GetStatus(),
		Code:       res.GetOutcome().GetCode(),
		Message:    res.GetOutcome().GetMessage(),
		Signature:  res.GetSignature(),
		Touches:    res.GetTouches(),
		Published:  published,
		ResultHash: res.GetResultHash(),
		ResultRef:  res.GetResultRef(),
		Provenance: dpr,
	}

	// No comparison with an earlier report held here. CompleteStep reaches
	// this only for an attempt the log has not recorded, under the lock that
	// then drives it into the log; a report whose drive failed is forgotten.
	// So the account that counts is always the log's, and sameAsRecorded is
	// the one place a retry is compared with it.
	h.mu.Lock()
	defer h.mu.Unlock()
	h.outcomes[key] = outcome
	return nil
}

// forget drops a report that never reached the log.
func (h *hosted) forget(stepID string, attempt uint32, isUndo bool) {
	if isUndo {
		attempt = 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.outcomes, attemptKey(stepID, attempt))
}

// sameAsRecorded refuses a report of an attempt whose result is already in the
// log, unless it is the same report.
func (s *Server) sameAsRecorded(res *janusv1.StepResult, dpr *janusv1.DecisionProvenanceRecord,
	isUndo bool) error {

	events, err := saga.LoadEvents(s.dir, res.GetSagaId())
	if err != nil {
		return status.Errorf(codes.Internal, "reading what was recorded: %v", err)
	}
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Kind != evidence.KindStepResult {
			continue
		}
		var got janusv1.StepResult
		if err := proto.Unmarshal(events[i].Payload, &got); err != nil {
			return status.Errorf(codes.Internal, "decoding a recorded result: %v", err)
		}
		if got.GetStepId() != res.GetStepId() || (!isUndo && got.GetAttempt() != res.GetAttempt()) {
			continue
		}
		var recorded *janusv1.DecisionProvenanceRecord
		if got.GetDprRef() != "" && i > 0 && events[i-1].Kind == evidence.KindDPR {
			recorded = &janusv1.DecisionProvenanceRecord{}
			if err := proto.Unmarshal(events[i-1].Payload, recorded); err != nil {
				return status.Errorf(codes.Internal, "decoding a recorded provenance: %v", err)
			}
		}
		if proto.Equal(got.GetOutcome(), res.GetOutcome()) &&
			bytes.Equal(got.GetResultHash(), res.GetResultHash()) &&
			got.GetResultRef() == res.GetResultRef() &&
			sameTouches(got.GetTouches(), res.GetTouches()) &&
			samePublished(got.GetFacts(), res.GetFacts()) &&
			sameProvenance(recorded, dpr) {
			return nil
		}
		return status.Errorf(codes.FailedPrecondition,
			"step %q attempt %d is already recorded as %s with a different account of what "+
				"it produced or why; one attempt has one account",
			res.GetStepId(), res.GetAttempt(), got.GetOutcome().GetStatus())
	}
	// Nothing recorded under that attempt: an older attempt settled some other
	// way, which alreadyRecorded has already judged.
	return nil
}

// sameProvenance compares a recorded decision record with a resent one, after
// the stamping the runner applies — the resent one never carried the identity
// the log gave it.
func sameProvenance(recorded, resent *janusv1.DecisionProvenanceRecord) bool {
	if recorded == nil || resent == nil {
		return recorded == nil && resent == nil
	}
	cp := proto.Clone(resent).(*janusv1.DecisionProvenanceRecord)
	cp.DprId, cp.SagaId, cp.StepId = recorded.GetDprId(), recorded.GetSagaId(), recorded.GetStepId()
	return proto.Equal(recorded, cp)
}

// sameTouches compares touches as a set: the order a participant lists them in
// is not part of what it touched.
func sameTouches(a, b []*janusv1.ResourceTouch) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, x := range a {
		i := slices.IndexFunc(b, func(y *janusv1.ResourceTouch) bool { return proto.Equal(x, y) })
		for i >= 0 && used[i] {
			next := slices.IndexFunc(b[i+1:], func(y *janusv1.ResourceTouch) bool { return proto.Equal(x, y) })
			if next < 0 {
				i = -1
				break
			}
			i += next + 1
		}
		if i < 0 {
			return false
		}
		used[i] = true
	}
	return true
}

// samePublished compares published facts as the fold reads them -- a map, so
// wire order does not matter and a fact that does not decode is not the same
// as anything.
func samePublished(a, b []*janusv1.Fact) bool {
	fa, errA := saga.FactsFromProto(a)
	fb, errB := saga.FactsFromProto(b)
	return errA == nil && errB == nil && maps.Equal(fa, fb)
}

// checkProvenance refuses a decision record that is not a participant's to
// make. Its identity is not checked here because it is not trusted at all:
// the runner stamps dpr_id, saga_id and step_id from the result it explains.
func checkProvenance(dpr *janusv1.DecisionProvenanceRecord) error {
	if dpr == nil {
		return nil
	}
	switch dpr.GetDecisionKind() {
	case janusv1.DecisionProvenanceRecord_DECISION_KIND_PLAN,
		janusv1.DecisionProvenanceRecord_DECISION_KIND_ACT,
		janusv1.DecisionProvenanceRecord_DECISION_KIND_ROUTE:
		return nil
	case janusv1.DecisionProvenanceRecord_DECISION_KIND_UNSPECIFIED:
		return status.Error(codes.InvalidArgument,
			"a decision provenance record needs a decision kind; UNSPECIFIED would record "+
				"that a decision was made and say nothing about which")
	default:
		// VALIDATE is the gate's own record, written by the coordinator beside
		// its verdict. A participant writing one would be a step
		// putting its own judgement on the record in the gate's voice.
		// COMPENSATE belongs to an undo, whose provenance is not recorded.
		return status.Errorf(codes.InvalidArgument,
			"a step's result cannot carry a %s decision record; a participant records "+
				"PLAN, ACT or ROUTE", dpr.GetDecisionKind())
	}
}

// declare stores what a participant says it will do on this attempt.
//
// Re-declaring the same attempt is allowed and overwrites: a client that
// retried its prepare after a timeout is sending the same declaration again,
// and the coordinator has not bound anything yet — the prepare that binds it is
// the append that follows. Once the step is prepared the declaration is in the
// log and this map no longer decides anything.
func (h *hosted) declare(stepID string, attempt uint32, facts map[string]saga.FactValue) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.declared[attemptKey(stepID, attempt)] = facts
}

// alreadyRecorded says whether the log already holds this attempt's result.
func alreadyRecorded(st *saga.Step, res *janusv1.StepResult, isUndo bool) (bool, error) {
	if isUndo {
		// A compensation that is still RUNNING is the one being reported on.
		// Anything else — DONE, FAILED, or never required — means the log has
		// already settled it.
		return st.Compensation != saga.CompRunning, nil
	}
	switch {
	case res.GetAttempt() < st.Attempt:
		return true, nil
	case res.GetAttempt() > st.Attempt:
		return false, status.Errorf(codes.FailedPrecondition,
			"step %q is on attempt %d and the report names attempt %d; a result from an "+
				"attempt that has not started cannot be recorded",
			st.ID, st.Attempt, res.GetAttempt())
	case st.Status != saga.StepPrepared:
		return true, nil
	}
	return false, nil
}

// compensatedStep maps an undo step id back to the step it undoes.
func compensatedStep(stepID string) (string, bool) {
	const suffix = "~undo"
	if len(stepID) > len(suffix) && stepID[len(stepID)-len(suffix):] == suffix {
		return stepID[:len(stepID)-len(suffix)], true
	}
	return stepID, false
}

// RegisterCredential enrols a WebAuthn authenticator, so that a console beside a
// running coordinator can complete the ceremony it cannot append for itself.
//
// The public key is parsed before it is recorded rather than stored as opaque
// bytes. A credential written under a key nothing can verify with would sit in
// the trust store looking like coverage and refuse every step-up it was
// enrolled for — a control that fails closed, but for a reason nobody could
// find. Parsing here means the refusal names the problem at registration.
//
// What this deliberately does not offer is issuer-key trust. A caller that
// could add a trusted OIDC issuer could mint tokens establishing any role it
// liked, which is a larger authority than anything else this service grants.
// Registering a credential is bounded by comparison: verification requires the
// credential's subject to match the subject of a verified ID token, so a rogue
// registration is useless without a token this service cannot produce.
func (s *Server) RegisterCredential(ctx context.Context,
	req *janusv1.RegisterCredentialRequest) (*janusv1.RegisterCredentialResponse, error) {

	if req.GetCredentialId() == "" || req.GetSubject() == "" {
		return nil, status.Error(codes.InvalidArgument,
			"a credential id and a subject are required; a credential belonging to nobody "+
				"establishes nothing about anybody")
	}
	key, err := x509.ParsePKIXPublicKey(req.GetPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument,
			"the credential's public key is not readable SPKI: %v", err)
	}
	rec := identity.NewRecorder(s.app, s.participant)
	if err := rec.RegisterCredential(ctx, req.GetCredentialId(), req.GetSubject(), key); err != nil {
		return nil, status.Errorf(codes.Internal, "recording the registration: %v", err)
	}
	return &janusv1.RegisterCredentialResponse{}, nil
}

// RevokeCredential withdraws an authenticator that has been lost or stolen.
//
// `identity.Recorder.RevokeCredential` has existed since Phase 5b and, until
// this, had no caller at all — the fold honoured a revocation correctly and
// nothing could record one. That was the gap: a control
// implemented and unreachable, which in a compliance report reads exactly like a
// control that works.
//
// It is on the daemon and not on the console, and the placement is the decision.
// Item 21's own reasoning is that a page which can revoke a credential from a
// session is a page a stolen session can use to remove the control it is about
// to bypass. Reaching this means reaching the daemon's address, which a browser
// session does not.
//
// It does not check that the credential exists. A revocation naming an unknown
// credential is harmless — the fold applies it to nothing — and refusing one
// would turn an operator's typo, made while an authenticator is loose, into an
// error message instead of a recorded intent. Fail toward having the revocation
// on the record.
func (s *Server) RevokeCredential(ctx context.Context,
	req *janusv1.RevokeCredentialRequest) (*janusv1.RevokeCredentialResponse, error) {

	if req.GetCredentialId() == "" {
		return nil, status.Error(codes.InvalidArgument,
			"a credential id is required; a revocation naming nothing withdraws nothing")
	}
	if req.GetReason() == "" {
		return nil, status.Error(codes.InvalidArgument,
			"a reason is required: \"lost laptop\" and \"employee left\" call for different "+
				"follow-up, and the difference is not recoverable later")
	}
	rec := identity.NewRecorder(s.app, s.participant)
	if err := rec.RevokeCredential(ctx, req.GetCredentialId(), req.GetReason()); err != nil {
		return nil, status.Errorf(codes.Internal, "recording the revocation: %v", err)
	}
	return &janusv1.RevokeCredentialResponse{}, nil
}

// RevokeIssuerKey withdraws one signing key of one OIDC issuer.
//
// The counterpart to `-issuer-jwks`, and the asymmetry between them is the
// decision. Trusting an issuer is configuration on the daemon's command line
// because whoever can do it can mint a token establishing any role;
// revoking removes authority and moves the system fail-closed, so it is allowed
// through the wire for the same reason RevokeCredential is. A deployment that
// has just learned a key is compromised should not have to schedule a restart to
// stop honouring it.
//
// One key, not the whole issuer. An issuer rotating a compromised key keeps
// working on its others, and an operator who does mean to distrust the issuer
// entirely can say so key by key rather than have one command quietly mean both.
//
// Like RevokeCredential, it does not check that the key is trusted. Revoking one
// that is not is harmless — the fold applies it to nothing — and refusing would
// turn a typo made under pressure into an error instead of a recorded intent.
func (s *Server) RevokeIssuerKey(ctx context.Context,
	req *janusv1.RevokeIssuerKeyRequest) (*janusv1.RevokeIssuerKeyResponse, error) {

	if req.GetIssuer() == "" {
		return nil, status.Error(codes.InvalidArgument,
			"an issuer is required; keys are trusted per issuer, so a key id alone does "+
				"not say which trust to withdraw")
	}
	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument,
			"a key id is required; to distrust an issuer entirely, revoke its keys one "+
				"by one, so that the log says which keys were withdrawn and when")
	}
	if req.GetReason() == "" {
		return nil, status.Error(codes.InvalidArgument,
			"a reason is required: a rotation and a compromise look identical without "+
				"one, and they call for opposite responses to every approval this key verified")
	}
	rec := identity.NewRecorder(s.app, s.participant)
	if err := rec.RevokeIssuerKey(ctx, req.GetIssuer(), req.GetKeyId(), req.GetReason()); err != nil {
		return nil, status.Errorf(codes.Internal, "recording the revocation: %v", err)
	}
	return &janusv1.RevokeIssuerKeyResponse{}, nil
}

// RecordAnswer records a validator's or a human's answer to a gate.
//
// The answer is a recorded input, not a call: this appends it and the
// coordinator composes the verdict from the log. No caller gets a shorter path
// to a released effect by answering its own gate.
func (s *Server) RecordAnswer(ctx context.Context, req *janusv1.RecordAnswerRequest) (
	*janusv1.RecordAnswerResponse, error) {

	answer := req.GetAnswer()
	if answer.GetSagaId() == "" || answer.GetStepId() == "" {
		return nil, status.Error(codes.InvalidArgument, "a saga id and a step id are required")
	}
	h := s.hostedSaga(answer.GetSagaId())
	h.driving.Lock()
	defer h.driving.Unlock()

	// Read the state under the lock. A runner adopting a projection that a
	// concurrent drive has already moved past would append an answer against a
	// state that no longer exists.
	state, err := saga.ReplaySaga(s.dir, answer.GetSagaId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "saga %q: %v", answer.GetSagaId(), err)
	}
	if state.SagaID == "" {
		return nil, status.Errorf(codes.NotFound, "saga %q has not begun", answer.GetSagaId())
	}
	// Whose answer it is: the validator's own signature, or a relayer
	// allowed to carry a person's.
	reg, err := s.signingRegistry(ctx)
	if err != nil {
		return nil, err
	}
	pins, err := s.pinsOf(answer.GetSagaId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reading saga %q's pins: %v", answer.GetSagaId(), err)
	}
	if err := s.checkAnswer(reg, pins, answer); err != nil {
		return nil, err
	}
	runner := saga.NewRunner(s.app, s.participant)
	runner.Adopt(state)
	ref, err := runner.Answer(ctx, answer)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "recording the answer: %v", err)
	}

	// Drive afterwards so the answer takes effect in the same call that
	// recorded it. A console that had to wait for a background sweep to notice
	// an approval would look broken to the person who just gave it.
	if _, err := s.driveLocked(ctx, answer.GetSagaId(), h); err != nil {
		return nil, status.Errorf(codes.Internal,
			"the answer is recorded at seq %d but the saga could not be advanced: %v",
			ref.Seq, err)
	}
	return &janusv1.RecordAnswerResponse{Ref: evidenceRef(ref)}, nil
}

// HoldEffect withholds an effect until its saga commits.
func (s *Server) HoldEffect(ctx context.Context, req *janusv1.HoldEffectRequest) (
	*janusv1.HoldEffectResponse, error) {

	effect := req.GetEffect()
	if effect.GetSagaId() == "" || effect.GetStepId() == "" {
		return nil, status.Error(codes.InvalidArgument, "a saga id and a step id are required")
	}
	h := s.hostedSaga(effect.GetSagaId())
	h.driving.Lock()
	defer h.driving.Unlock()

	// Capturing the same effect twice would put two claims on one payment, and
	// a client that retried a request whose answer it never saw has no way to
	// know it already succeeded. So the second one is a success that changed
	// nothing, which is the same bargain CompleteStep makes.
	if held, err := outbox.Load(s.dir); err == nil {
		if _, exists := held.Effect(effect.GetEffectId()); exists {
			return &janusv1.HoldEffectResponse{AlreadyHeld: true}, nil
		}
	}

	ref, err := s.currentReleaser().Hold(ctx, effect)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "holding the effect: %v", err)
	}
	return &janusv1.HoldEffectResponse{Ref: evidenceRef(ref)}, nil
}

// ReleaseEffects delivers what a committed saga was holding.
func (s *Server) ReleaseEffects(ctx context.Context, req *janusv1.ReleaseEffectsRequest) (
	*janusv1.ReleaseEffectsResponse, error) {

	if req.GetSagaId() == "" {
		return nil, status.Error(codes.InvalidArgument, "a saga id is required")
	}
	h := s.hostedSaga(req.GetSagaId())
	h.driving.Lock()
	defer h.driving.Unlock()

	state, err := outbox.Load(s.dir)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "reading held effects: %v", err)
	}
	held := heldFor(state, req.GetSagaId())
	if err := s.currentReleaser().ReleaseAll(ctx, state, req.GetSagaId()); err != nil {
		if errors.Is(err, outbox.ErrNotCommitted) {
			// Not an error to route around. The outbox refusing to release
			// from an uncommitted saga is invariant I4 doing its job, and a
			// caller that treated it as a transient failure would retry until
			// the saga committed for some other reason.
			return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "releasing effects: %v", err)
	}
	return &janusv1.ReleaseEffectsResponse{Released: uint32(held)}, nil
}

// ResolveParticipant returns what a pinned manifest version declares.
//
// It reads the registry afresh on every call, like admission does and for the
// same reason: a manifest version can be suspended between one call and the
// next, and a cached answer is a claim about the past. With a projection
// configured, "afresh" means caught up to the head of the log rather than
// re-walked from it.
func (s *Server) ResolveParticipant(ctx context.Context,
	req *janusv1.ResolveParticipantRequest) (*janusv1.ResolveParticipantResponse, error) {

	if req.GetParticipantId() == "" || req.GetVersion() == "" {
		return nil, status.Error(codes.InvalidArgument,
			"a participant id and a version are required; resolving whatever is active now "+
				"would answer a different question from the one a saga asks")
	}
	reg, err := s.registryNow(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	entry, ok := reg.Resolve(req.GetParticipantId(), req.GetVersion())
	if !ok {
		return nil, status.Errorf(codes.NotFound,
			"%s@%s is not registered", req.GetParticipantId(), req.GetVersion())
	}

	out := &janusv1.ResolveParticipantResponse{
		ParticipantId: entry.ParticipantID,
		Version:       entry.Version,
		State:         string(entry.State),
	}
	for _, a := range entry.Manifest.Actions {
		// A manifest that got this far was validated at registration, so an
		// unparseable class here would mean the log disagrees with itself.
		// UNSPECIFIED is the honest thing to send in that case: it matches
		// nothing a client could declare, so the check refuses rather than
		// passing on a value nobody can interpret.
		class, _ := registry.EffectClassFor(a.EffectClass)
		declared := &janusv1.DeclaredAction{Name: a.Name, EffectClass: class}
		if a.Compensation != nil {
			declared.CompensationAction = a.Compensation.Action
		}
		out.Actions = append(out.Actions, declared)
	}
	return out, nil
}

// GetSaga returns the projection as the log says it stands.
func (s *Server) GetSaga(_ context.Context, req *janusv1.GetSagaRequest) (
	*janusv1.GetSagaResponse, error) {

	if req.GetSagaId() == "" {
		return nil, status.Error(codes.InvalidArgument, "a saga id is required")
	}
	state, err := saga.ReplaySaga(s.dir, req.GetSagaId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "saga %q: %v", req.GetSagaId(), err)
	}
	return &janusv1.GetSagaResponse{Saga: projection(state)}, nil
}

// WatchSagas streams projections as they change.
func (s *Server) WatchSagas(req *janusv1.WatchSagasRequest,
	stream janusv1.OrchestratorService_WatchSagasServer) error {

	wt := s.watch.add(req.GetSagaIds())
	defer wt.remove()

	// The first thing a watcher gets is where things stand, not the next
	// change. A client that had to wait for something to move could not tell a
	// quiet system from a broken subscription.
	for _, id := range req.GetSagaIds() {
		if state, err := saga.ReplaySaga(s.dir, id); err == nil && state.SagaID != "" {
			if err := stream.Send(&janusv1.WatchSagasResponse{Saga: projection(state)}); err != nil {
				return err
			}
		}
	}

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-wt.signal:
			if !ok {
				return nil
			}
			for _, p := range wt.drain() {
				if err := stream.Send(&janusv1.WatchSagasResponse{Saga: p}); err != nil {
					return err
				}
			}
		}
	}
}

// drive advances one saga as far as it will go.
//
// The two waits are resting places, not failures. A saga held by a gate is
// waiting for a person and a saga awaiting a participant is waiting for a
// machine; both mean this process has done everything it can, and reporting
// either as an error would make every ordinary pause look like an incident.
// A stall still is one, and is returned.
// driveLocked assumes the caller holds h.driving.
func (s *Server) driveLocked(ctx context.Context, sagaID string, h *hosted) (saga.State, error) {
	// A saga with nothing in the log is not a saga this process can advance.
	// Driving one would reach the coordinator's "there is no saga yet" branch
	// and ask the program to begin it — and a hosted program has no plan to
	// begin with. Refusing here makes that a clear NotFound rather than
	// whatever a nil begin happens to produce.
	resumed, err := saga.ReplaySaga(s.dir, sagaID)
	if err != nil || resumed.SagaID == "" {
		return saga.State{}, errNoSuchSaga
	}
	c, err := saga.ResumeSaga(s.app, s.dir, sagaID, s.participant, hostedProgram{h: h})
	if err != nil {
		return saga.State{}, err
	}
	c = c.WithGatekeeper(s.keeper)

	// A cascade sub-saga commits only on its parent's authority, and
	// that authority is resolved here rather than supplied by the caller.
	//
	// It has to be. The authority is a fact about the parent's log — that it
	// committed, and that it committed a step which spawned this child — and a
	// client that could assert it would be able to release a child's held
	// effects on an authority that never existed. This process has the log, so
	// it looks.
	state, err := s.driveWithAuthority(ctx, c, resumed)
	switch {
	case err == nil,
		errors.Is(err, saga.ErrWaiting),
		errors.Is(err, saga.ErrAwaitingParticipant):
	default:
		return state, err
	}

	// A committed saga's held effects go out now, without waiting for anybody
	// to ask. "Drives sagas to completion" has to include this: an effect held
	// until commit and then held indefinitely because no client called
	// ReleaseEffects is a payment that never happens, and the log would show a
	// clean commit with nothing to explain the silence.
	if state.Status == saga.StatusCommitted {
		s.releaseHeld(ctx, sagaID)
	}

	s.watch.publish(projection(state))
	if state.Terminal() {
		s.forget(sagaID)
	}
	return state, nil
}

// releaseHeld delivers what a committed saga was holding.
//
// It deliberately does not report failure to its caller. The saga committed —
// that is durable and true, and it is what the caller asked about. A target
// being down, or having no deliverer connected, leaves the effect held and
// retryable, and the outbox has already written why into the log. Failing the
// RPC instead would tell a participant that its step did not go through, which
// is a different and false statement.
func (s *Server) releaseHeld(ctx context.Context, sagaID string) {
	state, err := outbox.Load(s.dir)
	if err != nil {
		return
	}
	if heldFor(state, sagaID) == 0 {
		return
	}
	_ = s.currentReleaser().ReleaseAll(ctx, state, sagaID)
}

// heldFor counts what a saga is still holding, so the response can say how much
// left rather than only that the call succeeded.
func heldFor(state outbox.State, sagaID string) uint32 {
	var n uint32
	for _, id := range state.Order {
		if e := state.Effects[id]; e != nil && e.SagaID == sagaID {
			n++
		}
	}
	return n
}

// errNoSuchSaga is returned by driveLocked when the log holds no such saga.
var errNoSuchSaga = errors.New("no saga with that id is in this log")

// driveError maps a drive failure onto a status code. A saga that is not here
// is the caller's mistake; a saga that would not advance is this process's.
func driveError(sagaID string, err error) error {
	if errors.Is(err, errNoSuchSaga) {
		return status.Errorf(codes.NotFound, "saga %q: %v", sagaID, err)
	}
	return status.Errorf(codes.Internal, "advancing saga %q: %v", sagaID, err)
}

// driveWithAuthority drives a saga, supplying a cascade child's commit
// authority when its parent has created one.
//
// A cascade child whose parent has not committed is not stuck and has not
// failed: it has done everything it can and is holding its effects, which is
// precisely the resting place DriveUntilSealed exists for. Driving it any
// further would attempt a commit the state machine must refuse, and turn a
// correct wait into an error somebody would go looking for.
func (s *Server) driveWithAuthority(ctx context.Context, c *saga.Coordinator,
	resumed saga.State) (saga.State, error) {

	if !resumed.Parent.Cascades() {
		return c.Drive(ctx)
	}

	parent, err := saga.ReplaySaga(s.dir, resumed.Parent.SagaID)
	if err != nil {
		return c.State(), fmt.Errorf("reading the parent of %q: %w", resumed.SagaID, err)
	}
	authority, aerr := saga.AuthorizeCommit(parent, resumed.SagaID)
	if aerr != nil {
		// No authority yet. Seal and stop, holding what it is holding.
		if err := c.DriveUntilSealed(ctx); err != nil {
			return c.State(), err
		}
		return c.State(), nil
	}
	return c.WithAuthority(authority).Drive(ctx)
}

// confineToTemplate refuses a step declaring facts its saga's template has no
// slot for.
//
// It runs only for a saga that pinned a template, which is only a crystallized
// one — every other saga reaches this and returns immediately.
//
// # Why the declared facts and not the published ones
//
// The first version of this checked `StepResult.facts`, and those are the wrong
// set. A result's facts are what a step *published* from what it found; the
// declared facts arrive with the request to prepare, are what a pre-execution
// gate decides against, and are the arguments the model actually chose. Crystallized mode's
// "confined to declared slots" is about those, and a template's slots are
// extracted from them — `applyStepPrepare` is what puts them in the projection.
//
// Checking the published set would have compared two different vocabularies and
// left the one that matters unchecked.
//
// # Why the pinned version and not the active one
//
// The template is resolved at the version the saga pinned, not at whatever is
// active now. A template suspended while a saga is in flight still describes the
// shape that saga was admitted under, and requiring ACTIVE here would wedge every
// running crystallized saga the moment an operator withdrew a template — turning
// a decision about *future* sagas into an outage for present ones. That is the
// same distinction invariant I8 draws for manifest pins, and `FoldUntil` exists
// because of it.
//
// # Fail closed
//
// A pin that cannot be resolved refuses the result. The alternative is that a
// registry read failing lets an unconfined fact through, and "we could not
// check" reading as "it was fine" is the failure mode this repository keeps
// finding.
func (s *Server) confineToTemplate(ctx context.Context, state saga.State, stepID string,
	declared []*janusv1.Fact) error {

	pin := state.TemplatePin
	if pin == nil {
		return nil
	}
	reg, err := s.registryNow(ctx)
	if err != nil {
		return status.Errorf(codes.Internal,
			"saga %q pins template %s@%s and the registry could not be read, so its facts "+
				"could not be checked against it: %v", state.SagaID, pin.ID, pin.Version, err)
	}
	e, ok := reg.ResolveTemplate(pin.ID, pin.Version)
	if !ok {
		return status.Errorf(codes.FailedPrecondition,
			"saga %q pins template %s@%s, which the registry does not hold; its facts cannot "+
				"be confined to a shape nobody can produce", state.SagaID, pin.ID, pin.Version)
	}

	names := make([]string, 0, len(declared))
	for _, f := range declared {
		names = append(names, f.GetKey())
	}
	if err := template.ConfinesFacts(e.Template, stepID, names); err != nil {
		return status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return nil
}
