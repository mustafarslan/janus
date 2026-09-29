package outbox

import (
	"context"
	"errors"
	"fmt"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"google.golang.org/protobuf/proto"
)

// Deliverer performs a side effect against the outside world.
//
// Implementations must treat the idempotency key as the receiver's means of
// recognising a repeat. A Deliverer that ignores it turns Janus's at-least-once
// retry into a source of duplicates, which for an irreversible effect is the
// worst failure the system has.
type Deliverer interface {
	// Deliver attempts the effect. Returning Duplicate is how a target says it
	// recognised the idempotency key and had already applied this effect; that
	// is a success, and a different one from having applied it now.
	Deliver(ctx context.Context, e Effect) (Receipt, error)
}

// Receipt is what a target returned.
type Receipt struct {
	// Ref and Hash locate the target's own record of the effect, so an auditor
	// can tie Janus's evidence to the receiving system's.
	Ref  string
	Hash []byte
	// Duplicate means the target had already applied this effect.
	Duplicate bool
	// Retryable distinguishes a target that is temporarily unable from one that
	// has refused. Retrying a refusal forever is how a stuck effect becomes an
	// operational incident nobody is looking at.
	Retryable bool
	Message   string
}

// CommitAuthority answers whether a saga has committed, and on what evidence.
//
// It is an interface so that the check can be exercised adversarially. The
// question "may this effect be released?" is the single most consequential one
// in the system, and a test has to be able to lie to the outbox about the
// answer in order to prove the outbox does not simply take its word for it.
type CommitAuthority interface {
	// Committed returns the commit's evidence root, or ok=false if the saga has
	// not committed.
	Committed(ctx context.Context, sagaID string) (root []byte, ok bool, err error)
}

// Errors returned by the release path.
var (
	// ErrNotCommitted means the saga has not committed, so nothing may leave.
	ErrNotCommitted = errors.New("outbox: the saga has not committed")
	// ErrBreakerOpen means the target's circuit breaker is open.
	ErrBreakerOpen = errors.New("outbox: circuit breaker is open for this target")
	// ErrPoisoned means the effect has exhausted its attempts.
	ErrPoisoned = errors.New("outbox: effect cannot be delivered")
)

// Releaser drives held effects out into the world.
type Releaser struct {
	app         *evidence.Appender
	participant evidence.ParticipantRef
	authority   CommitAuthority
	deliverers  map[string]Deliverer
	residency   Residency
	modes       SagaModes
	sandbox     map[string]struct{}
	breakers    *Breakers
	// beforeRelease is the writer-lease check; nil when unfenced.
	beforeRelease func() error
	// maxAttempts bounds how many times one effect may be attempted before it
	// is quarantined for a human.
	maxAttempts uint32
}

// Options configures a Releaser.
type Options struct {
	Appender    *evidence.Appender
	Participant evidence.ParticipantRef
	Authority   CommitAuthority
	// Deliverers is keyed by target.
	Deliverers map[string]Deliverer
	// Residency resolves where a target is, for a log bound to a jurisdiction.
	// It is only consulted when the log's tenant
	// has pinned one; an unpinned deployment never reaches it, and does not
	// have to supply one.
	//
	// A pinned deployment that supplies none is refused rather than allowed
	// through, because the alternative is a deployment that believes it is
	// pinned and is not.
	Residency Residency
	// Modes resolves what mode a saga was admitted under, so an exploratory
	// saga's effects can be kept out of the world.
	// Nil means modes are not enforced, which is every deployment before
	// Phase 6e.
	Modes SagaModes
	// BeforeRelease is consulted before an effect is allowed out, and a non-nil
	// error holds it rather than delivering it.
	//
	// This is the second place a writer lease is checked, and it is
	// there for a different reason than the one at segment seal. Sealing is
	// about history: a fenced-out writer must not turn its divergence into
	// signed record. Releasing is about the world: an effect that has left the
	// building cannot be taken back by deciding afterwards which log was the
	// real one. Of the two, this is the one whose absence is irreversible.
	//
	// Nil means unchecked, which is every deployment that has not armed a fence.
	BeforeRelease func() error
	// SandboxTargets are the targets an exploratory saga may reach. It is
	// configuration and never anything a caller sends: a plan that could
	// nominate its own sandbox would put the exemption in the hands of the
	// party the mode exists to constrain.
	//
	// Empty means an exploratory saga releases nothing at all, which is the
	// right default for a mode whose entire meaning is "not for real".
	SandboxTargets []string
	// MaxAttempts defaults to 5. Zero is not accepted as "unlimited": an
	// irreversible effect retried without bound against a target that keeps
	// half-failing is how a duplicate payment eventually happens.
	MaxAttempts uint32
	Breakers    *Breakers
}

// NewReleaser builds a releaser.
func NewReleaser(opts Options) (*Releaser, error) {
	if opts.Appender == nil {
		return nil, errors.New("outbox: an appender is required, because a release that is not " +
			"recorded first is exactly what this package exists to prevent")
	}
	if opts.Authority == nil {
		return nil, errors.New("outbox: a commit authority is required; without one there is " +
			"nothing to stop an effect leaving before its saga commits")
	}
	max := opts.MaxAttempts
	if max == 0 {
		max = 5
	}
	breakers := opts.Breakers
	if breakers == nil {
		breakers = NewBreakers(BreakerConfig{})
	}
	rel := &Releaser{
		app:           opts.Appender,
		participant:   opts.Participant,
		authority:     opts.Authority,
		deliverers:    opts.Deliverers,
		residency:     opts.Residency,
		modes:         opts.Modes,
		beforeRelease: opts.BeforeRelease,
		sandbox:       make(map[string]struct{}, len(opts.SandboxTargets)),
		breakers:      breakers,
		maxAttempts:   max,
	}
	for _, t := range opts.SandboxTargets {
		rel.sandbox[t] = struct{}{}
	}
	return rel, nil
}

// Hold captures an effect and withholds it.
//
// This is appended before the step that produced the effect reports its result.
// A step that sealed while its effect existed only in memory would let the saga
// commit on the strength of something nobody was holding, and a crash in that
// window would lose the effect entirely with the log showing a clean commit.
func (r *Releaser) Hold(ctx context.Context, msg *janusv1.EffectHeld) (evidence.Ref, error) {
	if msg.GetEffectClass() == janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE {
		// An immediate irreversible effect is by definition one that fires when
		// it runs. Accepting it here would say it was being held while it had
		// already happened.
		return evidence.Ref{}, fmt.Errorf("outbox: effect %q is IRREVERSIBLE_IMMEDIATE and "+
			"cannot be held, because it fires when the step runs rather than on release",
			msg.GetEffectId())
	}
	// Refused here rather than only at release, so the saga fails while it can
	// still be compensated. An effect held for a target it may never reach
	// would commit, then sit undeliverable forever — fail-closed, and stuck in
	// the one state that needs a person.
	if err := r.exploratoryAllows(ctx, msg.GetSagaId(), msg.GetTarget()); err != nil {
		return evidence.Ref{}, err
	}
	if err := r.residencyAllows(ctx, msg.GetTarget()); err != nil {
		return evidence.Ref{}, err
	}
	return r.record(ctx, evidence.KindEffectHeld, msg.GetSagaId(), msg.GetStepId(), msg)
}

// ReleaseAll attempts every effect a committed saga is holding.
//
// Effects are attempted in the order they were held, and one failure does not
// stop the others: they are separate effects with separate targets, and holding
// the rest hostage to a single unreachable endpoint would turn one broken
// integration into a system-wide stall.
func (r *Releaser) ReleaseAll(ctx context.Context, s State, sagaID string) error {
	var firstErr error
	for _, e := range EffectsFor(s, sagaID) {
		if !e.Pending() {
			continue
		}
		if err := r.Release(ctx, *e); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Release attempts one effect, in the only order that is safe.
//
// The sequence is: check the authority, announce the attempt durably, act, then
// record the outcome. Each step is there because of what a crash immediately
// after it would mean.
//
//	After the authority check   nothing has happened; the effect is still held.
//	After the announcement      the effect may or may not have landed, and the
//	                            log says so. Recovery retries under the same
//	                            idempotency key, and the receiver absorbs it.
//	After acting                same as above; the receipt is simply missing.
//	After the receipt           the effect is settled and will not be retried.
//
// Reversing any two of those steps breaks something. Recording the receipt
// before acting would let a crash leave the log claiming an effect was
// delivered when it never left the building — the one failure that is not
// recoverable, because nobody would ever look for it again.
func (r *Releaser) Release(ctx context.Context, e Effect) error {
	if e.State == StateDelivered {
		return nil
	}
	if e.State == StateQuarantined {
		return fmt.Errorf("%w: effect %q is quarantined", ErrPoisoned, e.ID)
	}

	// Before the authority check, and well before anything leaves: a writer that
	// is not entitled to this log is not entitled to act on its behalf, and the
	// cheapest place to find that out is before any of the four steps below has
	// happened. The effect stays held, which is the state it was already in.
	if r.beforeRelease != nil {
		if err := r.beforeRelease(); err != nil {
			return fmt.Errorf("holding effect %q: %w", e.ID, err)
		}
	}

	// I4, first half: only from COMMITTED. This is asked of the authority every
	// time rather than cached, because a cached answer is a claim about the past
	// and this is a question about the present.
	root, committed, err := r.authority.Committed(ctx, e.SagaID)
	if err != nil {
		return fmt.Errorf("outbox: cannot establish whether saga %q has committed, so effect %q "+
			"stays held: %w", e.SagaID, e.ID, err)
	}
	if !committed {
		return fmt.Errorf("%w: effect %q stays held because saga %q has not committed",
			ErrNotCommitted, e.ID, e.SagaID)
	}
	if len(root) == 0 {
		return fmt.Errorf("outbox: saga %q is reported committed but with no evidence root, and "+
			"an authority that cannot be pointed at is not an authority", e.SagaID)
	}

	if e.Attempts >= r.maxAttempts {
		return r.quarantine(ctx, e, fmt.Sprintf(
			"delivery failed on all %d permitted attempts", r.maxAttempts))
	}

	// Checked again at release, not only at hold. An effect held before a
	// deployment declared its jurisdiction — or before a target's manifest was
	// suspended — has already passed the first check, and this is the one that
	// runs immediately before the bytes leave.
	// Checked again at release, not only at hold. Between the two the saga
	// commits, which is the moment an effect stops being a plan and starts being
	// an instruction — and it is the last point at which anything can stop it.
	if err := r.exploratoryAllows(ctx, e.SagaID, e.Target); err != nil {
		return err
	}
	if err := r.residencyAllows(ctx, e.Target); err != nil {
		return err
	}

	deliverer, ok := r.deliverers[e.Target]
	if !ok {
		return fmt.Errorf("outbox: no deliverer is configured for target %q, so effect %q stays "+
			"held", e.Target, e.ID)
	}

	// A breaker that is open means this target has been failing. Attempting
	// anyway would spend the effect's limited attempts on a target that is
	// known to be down, and those attempts are what stand between a transient
	// outage and a quarantined payment.
	if !r.breakers.Allow(e.Target) {
		return fmt.Errorf("%w: %q", ErrBreakerOpen, e.Target)
	}

	// I1: announce, durably, before anything leaves.
	attempt := e.Attempts + 1
	if _, err := r.record(ctx, evidence.KindEffectReleasing, e.SagaID, e.StepID,
		&janusv1.EffectReleasing{
			EffectId: e.ID, SagaId: e.SagaID, Attempt: attempt,
			CommitRoot: root, IdemKey: e.IdemKey,
		}); err != nil {
		// The announcement is not durable, so nothing may be attempted. This is
		// the fail-closed case: an evidence layer that cannot write
		// must stop effects rather than let them proceed unrecorded.
		return fmt.Errorf("outbox: effect %q was not released because its release could not be "+
			"recorded first: %w", e.ID, err)
	}

	receipt, derr := deliverer.Deliver(ctx, e)

	outcome := &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK}
	switch {
	case derr != nil:
		outcome.Status = janusv1.Outcome_STATUS_RETRYABLE_ERROR
		if !receipt.Retryable {
			outcome.Status = janusv1.Outcome_STATUS_TERMINAL_ERROR
		}
		outcome.Message = derr.Error()
	case receipt.Message != "":
		outcome.Message = receipt.Message
	}

	// The receipt is recorded whatever happened, including when the delivery
	// failed. An attempt whose outcome went unrecorded is indistinguishable
	// from one that may have landed, so every attempt that concludes says so.
	if _, err := r.record(ctx, evidence.KindEffectDelivered, e.SagaID, e.StepID,
		&janusv1.EffectDelivered{
			EffectId: e.ID, SagaId: e.SagaID, Attempt: attempt,
			Outcome: outcome, ReceiptRef: receipt.Ref, ReceiptHash: receipt.Hash,
			Duplicate: receipt.Duplicate,
		}); err != nil {
		return fmt.Errorf("outbox: effect %q was attempted but its outcome could not be "+
			"recorded, so it must be treated as possibly delivered: %w", e.ID, err)
	}

	if derr != nil {
		r.breakers.Failure(e.Target)
		return fmt.Errorf("outbox: effect %q was attempted and refused: %w", e.ID, derr)
	}
	r.breakers.Success(e.Target)
	return nil
}

// quarantine freezes an effect for a human.
func (r *Releaser) quarantine(ctx context.Context, e Effect, reason string) error {
	if _, err := r.record(ctx, evidence.KindEffectQuarantined, e.SagaID, e.StepID,
		&janusv1.EffectQuarantined{
			EffectId: e.ID, SagaId: e.SagaID, Attempts: e.Attempts,
			Reason: reason, LastError: e.LastError,
		}); err != nil {
		return fmt.Errorf("outbox: effect %q could not be quarantined: %w", e.ID, err)
	}
	return fmt.Errorf("%w: effect %q after %d attempts: %s", ErrPoisoned, e.ID, e.Attempts, reason)
}

// record appends one outbox event and waits for it to be durable.
func (r *Releaser) record(ctx context.Context, kind evidence.Kind, sagaID, stepID string,
	msg proto.Message) (evidence.Ref, error) {
	payload, err := proto.Marshal(msg)
	if err != nil {
		return evidence.Ref{}, fmt.Errorf("marshal %s: %w", kind, err)
	}
	return r.app.Append(ctx, evidence.Request{
		Kind:        kind,
		SagaID:      sagaID,
		StepID:      stepID,
		Participant: r.participant,
		Payload:     payload,
	})
}
