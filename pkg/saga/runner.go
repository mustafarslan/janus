package saga

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"google.golang.org/protobuf/proto"
)

// Runner drives one saga, recording every transition in the evidence log.
//
// The ordering inside each step is the whole point: validate the transition
// against the pure state machine, append the event and wait for it to be
// durable, and only then advance the in-memory projection. A transition the
// state machine rejects is never written, so the log contains only legal
// history and replay over it can never fail. A transition whose append fails
// never advances the projection, so the projection can never claim something
// the log does not support.
type Runner struct {
	app         *evidence.Appender
	participant evidence.ParticipantRef
	traceID     string

	mu    sync.Mutex
	state State
	refs  []evidence.Ref
}

// NewRunner returns a runner that records under the given participant identity.
func NewRunner(app *evidence.Appender, participant evidence.ParticipantRef) *Runner {
	return &Runner{app: app, participant: participant}
}

// AsOfHead is the read option for reading this runner's own log while it is
// being written.
//
// The head comes from the appender this runner writes through, which publishes
// a sequence only once the batch holding it is durable. So it is exactly the
// bound `evidence.AsOf` wants: everything at or below it is in the file, and a
// torn tail can only be bytes of something nobody has been promised yet.
//
// It must be called before the read it guards, not during it — see AsOf.
func (r *Runner) AsOfHead() evidence.ReadOption {
	return evidence.AsOf(r.app.Stats().LastSeq)
}

// LiveRead is how this runner reads its own directory: the acknowledged head it
// requires, and the appender as the locator that knows where its records are.
//
// The two travel together because a reader that has one almost always wants the
// other, and because forgetting the locator is invisible — the read still
// returns the right answer, just by walking the entire directory.
func (r *Runner) LiveRead() []evidence.ReadOption {
	return []evidence.ReadOption{
		evidence.AsOf(r.app.Stats().LastSeq),
		evidence.WithLocator(r.app),
	}
}

// WithTrace sets the OpenTelemetry trace id stamped on this saga's events, so a
// saga can be correlated with the surrounding distributed trace.
func (r *Runner) WithTrace(traceID string) *Runner {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.traceID = traceID
	return r
}

// State returns a snapshot of the projection.
func (r *Runner) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state.Clone()
}

// Adopt replaces the runner's projection with one rebuilt from the log.
//
// It is how a coordinator picks up a saga somebody else started, and it takes a
// whole State rather than merging into the existing one on purpose: a runner
// resuming a saga has no legitimate prior knowledge of it, and anything it
// thought it knew would be a guess competing with the evidence.
func (r *Runner) Adopt(s State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.state = s.Clone()
	r.refs = nil
}

// Refs returns the evidence references produced so far, in order.
func (r *Runner) Refs() []evidence.Ref {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]evidence.Ref(nil), r.refs...)
}

// Begin records the saga's intent and plan.
//
// It stamps the semantics version rather than trusting the caller to, and that
// is the whole reason the stamp is here and not in the callers. Every
// SAGA_BEGIN in production goes through this method; a pin that each call site
// had to remember would be set by the ones somebody thought of and missing from
// the rest, and a pin that is absent on half the sagas is worse than no pin,
// because the absent case has to stay readable as "version 1" forever.
//
// A caller that set it itself is overruled. There is nothing a caller could
// know about the rules this build implements that this build does not, and
// letting one declare a version would let it claim semantics the code folding
// the saga does not have.
func (r *Runner) Begin(ctx context.Context, msg *janusv1.SagaBegin) (evidence.Ref, error) {
	return r.BeginUnder(ctx, msg, SemanticsVersion)
}

// BeginUnder records a saga admitted under a named rule set rather than this
// build's own. It exists for one caller: a sub-saga, which folds under its
// parent's rules. A family split across two rule sets is one whose members
// disagree about what the same history means, and subsaga.go reasons about a
// family as though one set governs it.
//
// Still the runner's stamp, not the caller's: the version is chosen by whoever
// read the parent. A version this build cannot fold is refused before anything
// is written, by the same fold every record passes through on its way in.
func (r *Runner) BeginUnder(ctx context.Context, msg *janusv1.SagaBegin,
	version uint32) (evidence.Ref, error) {

	stamped := proto.Clone(msg).(*janusv1.SagaBegin)
	stamped.SemanticsVersion = version
	return r.record(ctx, evidence.KindSagaBegin, stamped.GetSagaId(), "", stamped)
}

// PrepareStep records that a step is about to run.
func (r *Runner) PrepareStep(ctx context.Context, msg *janusv1.StepPrepare) (evidence.Ref, error) {
	return r.record(ctx, evidence.KindStepPrepare, msg.GetSagaId(), msg.GetStepId(), msg)
}

// StepResult records what a step produced.
func (r *Runner) StepResult(ctx context.Context, msg *janusv1.StepResult) (evidence.Ref, error) {
	return r.record(ctx, evidence.KindStepResult, msg.GetSagaId(), msg.GetStepId(), msg)
}

// Gate records a gate's verdict.
func (r *Runner) Gate(ctx context.Context, msg *janusv1.GateVerdict) (evidence.Ref, error) {
	return r.record(ctx, evidence.KindGateVerdict, msg.GetSagaId(), msg.GetStepId(), msg)
}

// Answer records an answer to a gate from outside Janus — a validator's
// opinion or a human's approval.
//
// It moves no step by itself. The answer is an input the next verdict reads,
// which is what lets a person be in the loop without a replay having to ask
// them again: a resumed coordinator folds the approval that was given.
func (r *Runner) Answer(ctx context.Context, msg *janusv1.GateAnswer) (evidence.Ref, error) {
	return r.record(ctx, evidence.KindGateAnswer, msg.GetSagaId(), msg.GetStepId(), msg)
}

// Seal records that the saga's footprint is complete.
func (r *Runner) Seal(ctx context.Context, msg *janusv1.SealRequest) (evidence.Ref, error) {
	return r.record(ctx, evidence.KindSealRequest, msg.GetSagaId(), "", msg)
}

// Commit records the commit that releases held effects.
func (r *Runner) Commit(ctx context.Context, msg *janusv1.Commit) (evidence.Ref, error) {
	return r.record(ctx, evidence.KindCommit, msg.GetSagaId(), "", msg)
}

// Compensate opens the undo phase.
func (r *Runner) Compensate(ctx context.Context, msg *janusv1.Compensate) (evidence.Ref, error) {
	return r.record(ctx, evidence.KindCompensate, msg.GetSagaId(), "", msg)
}

// Quarantine freezes a saga that could not be undone.
func (r *Runner) Quarantine(ctx context.Context, msg *janusv1.Quarantine) (evidence.Ref, error) {
	return r.record(ctx, evidence.KindQuarantine, msg.GetSagaId(), msg.GetFailedStep(), msg)
}

// Abort records an abort.
func (r *Runner) Abort(ctx context.Context, msg *janusv1.Abort) (evidence.Ref, error) {
	return r.record(ctx, evidence.KindAbort, msg.GetSagaId(), "", msg)
}

// RecordDPR attaches a decision provenance record to a step. It carries the
// "why" and does not move the state machine.
func (r *Runner) RecordDPR(ctx context.Context, msg *janusv1.DecisionProvenanceRecord) (evidence.Ref, error) {
	return r.record(ctx, evidence.KindDPR, msg.GetSagaId(), msg.GetStepId(), msg)
}

// GateWithProvenance records a decision-provenance record and the verdict that
// cites it, under one durability barrier rather than two.
//
// The two have no decision between them. The verdict's DprRef is the DPR's
// event id and nothing else; no policy runs between them, nothing reads the
// DPR back, and no effect is released on the strength of a DPR alone. The only
// reason they were two barriers was that the id was not known until the first
// append returned — and it need not be, because evidence.Request.EventID is the
// caller's to choose. Choosing it here turns a dependency on an acknowledgement
// into a dependency on a value.
//
// Both are validated against the state machine before either is written, in the
// order they will be recorded, so the log still contains only legal history.
// Both are appended or neither is acknowledged.
//
// RecordDPR and Gate are unchanged and still used on their own: a DPR without a
// verdict is a legal thing to record, and janus-skeleton records one.
func (r *Runner) GateWithProvenance(ctx context.Context, dpr *janusv1.DecisionProvenanceRecord,
	verdict *janusv1.GateVerdict) (evidence.Ref, evidence.Ref, error) {

	return r.withProvenance(ctx, dpr, evidence.KindGateVerdict, verdict,
		verdict.GetSagaId(), verdict.GetStepId(), func(id string) { verdict.DprRef = id })
}

// StepResultWithProvenance records a participant's decision provenance record
// and the step result that cites it, under one durability barrier.
//
// The same pair as GateWithProvenance, from the other side of a step: the
// "why" of what an agent did, arriving with what it did. There is no decision between the two either — the result needs the
// record's event id and nothing else — so they share a barrier for the same
// reason, and a saga's barrier count does not change.
//
// The record's identity is the runner's to stamp, not the caller's: its dpr_id
// is the event id the result cites, and its saga and step are the result's.
func (r *Runner) StepResultWithProvenance(ctx context.Context,
	dpr *janusv1.DecisionProvenanceRecord, result *janusv1.StepResult) (evidence.Ref, evidence.Ref, error) {

	stamped := proto.Clone(dpr).(*janusv1.DecisionProvenanceRecord)
	stamped.SagaId = result.GetSagaId()
	stamped.StepId = result.GetStepId()
	return r.withProvenance(ctx, stamped, evidence.KindStepResult, result,
		result.GetSagaId(), result.GetStepId(), func(id string) {
			stamped.DprId = id
			result.DprRef = id
		})
}

// withProvenance appends a decision provenance record and the record that
// cites it as one pair, both filed under the citing record's saga and step —
// never the provenance record's own, which is only as trustworthy as whoever
// wrote it. cite is called with the provenance record's event id before either
// is marshalled.
func (r *Runner) withProvenance(ctx context.Context, dpr *janusv1.DecisionProvenanceRecord,
	kind evidence.Kind, citing proto.Message, sagaID, stepID string,
	cite func(id string)) (evidence.Ref, evidence.Ref, error) {

	none := evidence.Ref{}

	// The id the citing record will name, chosen before either record exists.
	// A v7 is what the appender would have generated, so nothing downstream
	// can tell a caller-chosen id from an appender-chosen one — which is the
	// point: this changes when the id is decided, not what it is.
	id, err := uuid.NewV7()
	if err != nil {
		return none, none, fmt.Errorf("generate event id for the decision provenance record: %w", err)
	}
	cite(id.String())

	dprPayload, err := proto.Marshal(dpr)
	if err != nil {
		return none, none, fmt.Errorf("marshal %s: %w", evidence.KindDPR, err)
	}
	citingPayload, err := proto.Marshal(citing)
	if err != nil {
		return none, none, fmt.Errorf("marshal %s: %w", kind, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Validate before writing, in the order the two will be recorded. The
	// citing record is checked against the state the DPR leaves behind rather
	// than against the state now, because that is the state it will be
	// replayed against. Provisional seq and wall, discarded, as in record.
	now := time.Now().UTC()
	mid, err := Apply(r.state, Event{
		Seq: r.state.LastSeq, Kind: evidence.KindDPR, Wall: now, Payload: dprPayload,
	})
	if err != nil {
		return none, none, err
	}
	if _, err := Apply(mid, Event{
		Seq: mid.LastSeq, Kind: kind, Wall: now, Payload: citingPayload,
	}); err != nil {
		return none, none, err
	}

	dprRef, citingRef, err := r.app.AppendPair(ctx,
		evidence.Request{
			Kind:        evidence.KindDPR,
			EventID:     id.String(),
			SagaID:      sagaID,
			StepID:      stepID,
			TraceID:     r.traceID,
			Participant: r.participant,
			Payload:     dprPayload,
		},
		evidence.Request{
			Kind:        kind,
			SagaID:      sagaID,
			StepID:      stepID,
			TraceID:     r.traceID,
			Participant: r.participant,
			Payload:     citingPayload,
		})
	if err != nil {
		// Neither has been acknowledged, so the projection does not advance —
		// the same rule record follows, applied to both.
		return none, none, err
	}

	st, err := r.advanceProjection(r.state, evidence.KindDPR, dprPayload, dprRef)
	if err != nil {
		return none, none, err
	}
	st, err = r.advanceProjection(st, kind, citingPayload, citingRef)
	if err != nil {
		return none, none, err
	}

	r.state = st
	r.refs = append(r.refs, dprRef, citingRef)
	return dprRef, citingRef, nil
}

// advanceProjection applies one durably recorded event using what the log
// actually recorded, not what was guessed before the write.
//
// This is what keeps the live projection identical to the one a replay produces
// (invariant I5). The provisional values the validation pass uses are not
// cosmetic: a step's recorded touches carry the sequence of the result that
// reported them, which is the authority for deciding which saga reached a
// resource first (I6), and a step's PreparedAt is what a later timeout decision
// is measured from. Patching LastSeq alone and keeping the rest would leave a
// running coordinator holding different numbers from the ones anybody reading
// the log would reconstruct.
func (r *Runner) advanceProjection(st State, kind evidence.Kind, payload []byte, ref evidence.Ref) (State, error) {
	next, err := Apply(st, Event{Seq: ref.Seq, Kind: kind, Wall: ref.Wall, Payload: payload})
	if err != nil {
		// Unreachable by construction: the same state and payload validated a
		// moment ago, and only the recorded seq and wall differ. If it ever
		// happens, the event is already durable while the projection is not,
		// so the only honest answer is to stop using this runner and rebuild
		// from the log.
		return State{}, fmt.Errorf(
			"saga: event %d is durably recorded but the projection could not advance, "+
				"so this runner is out of date; resume the saga from the log: %w", ref.Seq, err)
	}
	return next, nil
}

// record is the single path every saga event takes.
func (r *Runner) record(ctx context.Context, kind evidence.Kind, sagaID, stepID string, msg proto.Message) (evidence.Ref, error) {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return evidence.Ref{}, fmt.Errorf("marshal %s: %w", kind, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Validate before writing, so the log can only ever contain legal history.
	// The sequence number and wall time are not known until the event is
	// recorded, and no transition decision depends on either, so provisional
	// values are used here and the result is discarded.
	if _, err := Apply(r.state, Event{
		Seq: r.state.LastSeq, Kind: kind, Wall: time.Now().UTC(), Payload: payload,
	}); err != nil {
		return evidence.Ref{}, err
	}

	ref, err := r.app.Append(ctx, evidence.Request{
		Kind:        kind,
		SagaID:      sagaID,
		StepID:      stepID,
		TraceID:     r.traceID,
		Participant: r.participant,
		Payload:     payload,
	})
	if err != nil {
		// The projection deliberately does not advance: nothing may act on a
		// transition that is not durably recorded.
		return evidence.Ref{}, err
	}

	final, err := r.advanceProjection(r.state, kind, payload, ref)
	if err != nil {
		return evidence.Ref{}, err
	}

	r.state = final
	r.refs = append(r.refs, ref)
	return ref, nil
}
