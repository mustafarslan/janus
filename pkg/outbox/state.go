// Package outbox holds irreversible effects until the saga that produced them
// commits, and then releases them exactly once.
//
// This is where the system's central promise stops being a design intention and
// becomes a mechanism. An IRREVERSIBLE_GATED effect — a payment instruction, a
// regulatory filing, an outbound email — cannot be undone, but it can be
// delayed. Janus delays it: the step that produces such an effect does not
// perform it, it hands it here. Nothing leaves until the saga commits, and a
// saga that never commits never releases anything. That is the difference
// between an agent that can be stopped and one that cannot.
//
// Two invariants govern the code in this package, and both are about ordering
// rather than about effort:
//
//	I1  Evidence-before-effect: no release without a durable, chained append
//	    that precedes it.
//	I4  Commit safety: an effect releases only from COMMITTED, and only once,
//	    under any crash schedule.
//
// Like the saga projection, outbox state is rebuilt from the log rather than
// stored beside it. The reason is the same and it is not
// architectural neatness: a queue that remembered which effects were in flight
// would be a second source of truth about whether money had moved, and after a
// crash the two sources would disagree with no way to tell which was right.
//
// On "exactly once", stated honestly: Janus cannot guarantee it alone, and no
// system that talks to the outside world can. A crash between announcing an
// attempt and hearing back leaves the question of whether the effect landed
// genuinely unanswerable from this side. What Janus provides is at-least-once
// delivery under a stable idempotency key, so that a receiver which honours
// that key applies the effect once however many times it arrives; plus a log
// that says exactly how many attempts were made, so nobody has to guess later.
// At-least-once delivery and receiver idempotency together are what "exactly
// once" means in practice. Neither half is sufficient, and claiming the
// property without the second half would be claiming something untrue.
package outbox

import (
	"errors"
	"fmt"
	"slices"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"google.golang.org/protobuf/proto"
)

// EffectState is where a held effect stands.
type EffectState string

const (
	// StateHeld means the effect is captured and going nowhere. Every effect
	// starts here, and an effect whose delivery attempt failed returns here.
	StateHeld EffectState = "HELD"
	// StateReleasing means an attempt has been announced and its outcome is not
	// yet recorded. After a crash this is the state that matters: the effect may
	// or may not have landed, and the only safe reading is that it might have.
	StateReleasing EffectState = "RELEASING"
	// StateDelivered is terminal: the target accepted the effect.
	StateDelivered EffectState = "DELIVERED"
	// StateQuarantined is terminal until a human intervenes.
	StateQuarantined EffectState = "QUARANTINED"
)

// Effect is one withheld side effect.
type Effect struct {
	ID      string
	SagaID  string
	StepID  string
	Target  string
	Action  string
	IdemKey string
	Class   janusv1.EffectClass

	PayloadHash []byte
	PayloadRef  string

	State EffectState
	// Attempts counts delivery attempts announced, not deliveries achieved.
	//
	// The distinction is the point. After a crash mid-attempt, Janus knows an
	// attempt was made and cannot know whether it landed, so this is the honest
	// number: how many times the effect may have reached the target. An operator
	// reconciling a duplicate needs this figure, not a count of successes.
	Attempts uint32
	// CommitRoot is the evidence root of the saga commit that authorised the
	// release, recorded from the first attempt.
	CommitRoot []byte
	// Duplicate is set when the target reported it had already applied this
	// effect, recognising the idempotency key.
	Duplicate bool
	// Outcome is the target's verdict on the last concluded attempt.
	Outcome janusv1.Outcome_Status
	// LastError is what the target said when it refused.
	LastError string
	// QuarantineReason explains a frozen effect.
	QuarantineReason string
	// FirstHeldAt and DeliveredAt come from the log's wall-clock readings, for
	// reporting how long an effect sat.
	FirstHeldAt time.Time
	DeliveredAt time.Time
}

// Pending reports whether this effect still owes the world something.
func (e *Effect) Pending() bool {
	return e.State == StateHeld || e.State == StateReleasing
}

// MayHaveLanded reports whether the effect could already be in the world.
//
// This is the question that matters after a crash, and it is deliberately
// pessimistic: an announced attempt whose outcome was never recorded counts as
// possibly delivered, because it is. Anything that reasons about reconciliation
// has to start from what might have happened rather than from what was
// confirmed.
func (e *Effect) MayHaveLanded() bool {
	return e.State == StateDelivered || e.Attempts > 0
}

// State is the outbox projection.
type State struct {
	Effects map[string]*Effect
	// Order is effect ids in the order they were first held, so iteration is
	// deterministic and two readers of the same log agree on it.
	Order      []string
	LastSeq    uint64
	EventCount int
}

// Clone returns a deep copy.
func (s State) Clone() State {
	out := s
	out.Effects = make(map[string]*Effect, len(s.Effects))
	for id, e := range s.Effects {
		cp := *e
		cp.PayloadHash = slices.Clone(e.PayloadHash)
		cp.CommitRoot = slices.Clone(e.CommitRoot)
		out.Effects[id] = &cp
	}
	out.Order = slices.Clone(s.Order)
	return out
}

// Effect returns one effect by id.
func (s State) Effect(id string) (*Effect, bool) {
	e, ok := s.Effects[id]
	return e, ok
}

// Event is one evidence record as the outbox projection sees it.
type Event struct {
	Seq     uint64
	Kind    evidence.Kind
	Wall    time.Time
	Payload []byte
}

// Errors returned by Apply.
var (
	// ErrTransition means the event is not legal in the current state.
	ErrTransition = errors.New("outbox: illegal transition")
	// ErrUnknownEffect means an event refers to an effect that was never held.
	ErrUnknownEffect = errors.New("outbox: unknown effect")
)

// Apply folds one event into the projection. It never mutates prev.
func Apply(prev State, ev Event) (State, error) {
	next := prev.Clone()
	next.LastSeq = ev.Seq
	next.EventCount++

	switch ev.Kind {
	case evidence.KindEffectHeld:
		return applyHeld(next, ev)
	case evidence.KindEffectReleasing:
		return applyReleasing(next, ev)
	case evidence.KindEffectDelivered:
		return applyDelivered(next, ev)
	case evidence.KindEffectQuarantined:
		return applyQuarantined(next, ev)
	default:
		// Every other kind belongs to another projection. Counting it keeps a
		// replay over the whole log landing on the same numbers.
		return next, nil
	}
}

func applyHeld(s State, ev Event) (State, error) {
	var msg janusv1.EffectHeld
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode EffectHeld: %w", err)
	}
	switch {
	case msg.GetEffectId() == "":
		return s, fmt.Errorf("%w: EffectHeld has no effect id", ErrTransition)
	case msg.GetSagaId() == "":
		return s, fmt.Errorf("%w: effect %q is not attached to a saga, so nothing could ever "+
			"authorise releasing it", ErrTransition, msg.GetEffectId())
	case msg.GetTarget() == "":
		return s, fmt.Errorf("%w: effect %q names no target", ErrTransition, msg.GetEffectId())
	case msg.GetIdemKey() == "":
		// Without a stable idempotency key a retry is indistinguishable from a
		// second instruction, which for an irreversible effect means a
		// duplicate payment. Refusing to hold the effect at all is the only
		// safe response: an effect that cannot be retried safely must not be
		// accepted in the first place.
		return s, fmt.Errorf("%w: effect %q has no idempotency key, so a retry could not be "+
			"told apart from a second instruction", ErrTransition, msg.GetEffectId())
	}
	if _, dup := s.Effects[msg.GetEffectId()]; dup {
		return s, fmt.Errorf("%w: effect %q is already held", ErrTransition, msg.GetEffectId())
	}

	if s.Effects == nil {
		s.Effects = map[string]*Effect{}
	}
	s.Effects[msg.GetEffectId()] = &Effect{
		ID:          msg.GetEffectId(),
		SagaID:      msg.GetSagaId(),
		StepID:      msg.GetStepId(),
		Target:      msg.GetTarget(),
		Action:      msg.GetAction(),
		IdemKey:     msg.GetIdemKey(),
		Class:       msg.GetEffectClass(),
		PayloadHash: slices.Clone(msg.GetPayloadHash()),
		PayloadRef:  msg.GetPayloadRef(),
		State:       StateHeld,
		FirstHeldAt: ev.Wall,
	}
	s.Order = append(s.Order, msg.GetEffectId())
	return s, nil
}

func applyReleasing(s State, ev Event) (State, error) {
	var msg janusv1.EffectReleasing
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode EffectReleasing: %w", err)
	}
	e, ok := s.Effects[msg.GetEffectId()]
	if !ok {
		return s, fmt.Errorf("%w: %q announced for release without ever being held",
			ErrUnknownEffect, msg.GetEffectId())
	}

	switch e.State {
	case StateHeld, StateReleasing:
		// Releasing from RELEASING is a retry after a crash: the previous
		// attempt's outcome was never recorded, so a fresh attempt is announced
		// rather than the old one being resumed.
	case StateDelivered:
		return s, fmt.Errorf("%w: effect %q has already been delivered and may not be released "+
			"again", ErrTransition, e.ID)
	case StateQuarantined:
		return s, fmt.Errorf("%w: effect %q is quarantined and may not be released without a "+
			"human decision", ErrTransition, e.ID)
	}

	// Attempts must be consecutive. A gap would mean an attempt happened whose
	// announcement is missing from the log, which is exactly the situation I1
	// exists to make impossible — so seeing one means the log is not the record
	// of what happened, and continuing would build on that.
	if msg.GetAttempt() != e.Attempts+1 {
		return s, fmt.Errorf("%w: effect %q is on attempt %d but the log jumps to %d, so an "+
			"attempt was made without being recorded first", ErrTransition,
			e.ID, e.Attempts, msg.GetAttempt())
	}
	// The idempotency key is fixed when the effect is held. A retry under a
	// different key is a second instruction wearing the first one's name.
	if msg.GetIdemKey() != e.IdemKey {
		return s, fmt.Errorf("%w: effect %q was held under idempotency key %q and is being "+
			"released under %q", ErrTransition, e.ID, e.IdemKey, msg.GetIdemKey())
	}
	if len(msg.GetCommitRoot()) == 0 {
		return s, fmt.Errorf("%w: effect %q is being released without naming the commit that "+
			"authorises it", ErrTransition, e.ID)
	}
	if e.Attempts > 0 && !slices.Equal(e.CommitRoot, msg.GetCommitRoot()) {
		return s, fmt.Errorf("%w: effect %q is being retried under a different commit authority "+
			"than the one it was first released under", ErrTransition, e.ID)
	}

	e.State = StateReleasing
	e.Attempts = msg.GetAttempt()
	e.CommitRoot = slices.Clone(msg.GetCommitRoot())
	return s, nil
}

func applyDelivered(s State, ev Event) (State, error) {
	var msg janusv1.EffectDelivered
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode EffectDelivered: %w", err)
	}
	e, ok := s.Effects[msg.GetEffectId()]
	if !ok {
		return s, fmt.Errorf("%w: %q reported delivered without ever being held",
			ErrUnknownEffect, msg.GetEffectId())
	}

	// A receipt for a delivery that was never announced is the I1 violation
	// itself, seen from the other end: it says an effect reached the world
	// without durable evidence preceding it.
	if e.State != StateReleasing {
		return s, fmt.Errorf("%w: effect %q reported a delivery outcome while %s, so an effect "+
			"was attempted without being announced first", ErrTransition, e.ID, e.State)
	}
	if msg.GetAttempt() != e.Attempts {
		return s, fmt.Errorf("%w: effect %q has a receipt for attempt %d while attempt %d is "+
			"outstanding", ErrTransition, e.ID, msg.GetAttempt(), e.Attempts)
	}

	e.Outcome = msg.GetOutcome().GetStatus()
	if msg.GetDuplicate() {
		e.Duplicate = true
	}

	if e.Outcome == janusv1.Outcome_STATUS_OK {
		e.State = StateDelivered
		e.DeliveredAt = ev.Wall
		e.LastError = ""
		return s, nil
	}

	// The target refused. The effect is still owed, so it returns to held and
	// keeps its attempt count — which is what stops a refusing target from
	// being retried forever.
	e.State = StateHeld
	e.LastError = msg.GetOutcome().GetMessage()
	return s, nil
}

func applyQuarantined(s State, ev Event) (State, error) {
	var msg janusv1.EffectQuarantined
	if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
		return s, fmt.Errorf("decode EffectQuarantined: %w", err)
	}
	e, ok := s.Effects[msg.GetEffectId()]
	if !ok {
		return s, fmt.Errorf("%w: %q quarantined without ever being held",
			ErrUnknownEffect, msg.GetEffectId())
	}
	if e.State == StateDelivered {
		return s, fmt.Errorf("%w: effect %q was delivered and cannot be quarantined afterwards",
			ErrTransition, e.ID)
	}
	e.State = StateQuarantined
	e.QuarantineReason = msg.GetReason()
	if msg.GetLastError() != "" {
		e.LastError = msg.GetLastError()
	}
	return s, nil
}

// Replay folds a sequence of events into a projection.
func Replay(events []Event) (State, error) {
	var s State
	for i, ev := range events {
		next, err := Apply(s, ev)
		if err != nil {
			return s, fmt.Errorf("replay event %d (seq %d, %s): %w", i, ev.Seq, ev.Kind, err)
		}
		s = next
	}
	return s, nil
}

// EffectsFor lists every effect a saga owns, in the order they were captured,
// whatever state each is in.
//
// It was called HeldFor, and the name was wrong in a way that reached a page a
// compliance officer reads: the console rendered `len(HeldFor(...))` in a column
// headed "held", so an effect released and delivered weeks ago still counted as
// held, and on a mature saga the number never went down. Nothing was wrong with the function; the name invited exactly one wrong
// assumption and got it.
//
// Use PendingFor for "what is still outstanding". Use this for "what did this
// saga do", which is what a per-saga list wants.
func EffectsFor(s State, sagaID string) []*Effect {
	var out []*Effect
	for _, id := range s.Order {
		if e := s.Effects[id]; e.SagaID == sagaID {
			out = append(out, e)
		}
	}
	return out
}

// PendingFor lists the effects a saga still owes the world: held, or announced
// and unconfirmed.
//
// This is the number an operator means by "outstanding". A delivered effect is
// finished, and counting it as pending would tell somebody looking at a queue
// that there is work to do when there is not.
func PendingFor(s State, sagaID string) []*Effect {
	var out []*Effect
	for _, id := range s.Order {
		if e := s.Effects[id]; e.SagaID == sagaID && e.Pending() {
			out = append(out, e)
		}
	}
	return out
}

// Pending lists every effect that still owes the world something.
func Pending(s State) []*Effect {
	var out []*Effect
	for _, id := range s.Order {
		if e := s.Effects[id]; e.Pending() {
			out = append(out, e)
		}
	}
	return out
}

// Quarantined lists frozen effects, which is the operator's work list.
//
// Cross-saga on purpose: a quarantined effect is not the problem of the saga
// that produced it. Its saga is very often COMMITTED — nothing drives a saga to
// QUARANTINE when one of its effects freezes — so the person who has to
// reconcile it has no reason to be looking at that saga's page. This is the
// question they can actually ask: what is frozen, anywhere.
func Quarantined(s State) []*Effect {
	var out []*Effect
	for _, id := range s.Order {
		if e := s.Effects[id]; e.State == StateQuarantined {
			out = append(out, e)
		}
	}
	return out
}

// QuarantinedFor lists the frozen effects of one saga.
//
// The narrow form exists because the cross-saga list is assembled from a
// shortlist: something names the sagas worth looking at, and the effects come
// from replaying those. Which sagas is a hint; what is frozen on them is read
// from the log, here.
func QuarantinedFor(s State, sagaID string) []*Effect {
	var out []*Effect
	for _, id := range s.Order {
		if e := s.Effects[id]; e.SagaID == sagaID && e.State == StateQuarantined {
			out = append(out, e)
		}
	}
	return out
}
