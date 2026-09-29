package outbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/mustafarslan/janus/pkg/saga"
)

// An exploratory saga's effects do not leave.
//
// Exploratory mode has one meaning — "sandbox effects only" — and until
// Phase 6e nothing implemented it. A saga could declare `mode: "exploratory"`,
// be admitted, run a COMPENSABLE step against a real payment target, and have
// the outbox deliver it, because the outbox had never heard of modes.
//
// # Why this is enforced here and not only at admission
//
// Admission could refuse an exploratory plan whose steps name real targets, and
// that would be worth having. It is not sufficient, for a reason that holds
// about targets in general: a target is a string chosen by whoever composed the
// effect and resolved to a transport by whoever runs the daemon, and nothing
// requires the effect's target to be the step's participant. Admission judges a
// plan; the outbox is the last thing between a decision and the world.
//
// So the check lives at the two points an effect can move — when it is held and
// when it is released — and it fails closed: a saga whose mode cannot be
// determined is treated as one that might be exploratory, because the
// alternative is that a lookup failure delivers a payment.
//
// # What counts as a sandbox
//
// A target is a sandbox because a deployment said so, in the daemon's own
// configuration, and not because of anything in the plan. Nothing a caller
// sends can make a target a sandbox — that would put the exemption in the hands
// of the party the mode exists to constrain.
//
// The default set is empty, so by default an exploratory saga cannot release
// anything at all. That is the correct default for a mode whose entire meaning
// is "not for real", and it means a deployment that has configured no sandbox
// has not accidentally granted one.

// ErrExploratory means an exploratory saga's effect was going somewhere that is
// not a declared sandbox.
var ErrExploratory = errors.New(
	"outbox: an exploratory saga's effects may only reach a declared sandbox")

// SagaModes answers what mode a saga was admitted under.
//
// An interface for the same reason CommitAuthority and Residency are: the
// question is consequential, and a test has to be able to lie to the outbox
// about the answer in order to prove the outbox does not simply take its word
// for it.
type SagaModes interface {
	// ModeOf returns the mode recorded in the saga's SAGA_BEGIN. ok is false
	// when the log has nothing for that saga, which is refused rather than
	// treated as unscoped: an effect attributed to a saga nobody began is not a
	// thing to deliver.
	ModeOf(ctx context.Context, sagaID string) (mode string, ok bool, err error)
}

// LogModes reads a saga's mode out of an evidence directory.
//
// Read per call rather than cached, for the reason the residency check is: the
// mode is recorded once in SAGA_BEGIN and cannot change, but the *saga* being
// asked about differs per effect, and a cache keyed on nothing is a cache that
// answers about the wrong saga.
type LogModes struct{ dir string }

// NewLogModes returns a mode resolver over an evidence directory.
func NewLogModes(dir string) *LogModes { return &LogModes{dir: dir} }

// ModeOf replays the saga far enough to read what it was admitted under.
func (l *LogModes) ModeOf(_ context.Context, sagaID string) (string, bool, error) {
	if l == nil || l.dir == "" {
		return "", false, nil
	}
	events, err := saga.LoadEvents(l.dir, sagaID)
	if err != nil {
		return "", false, fmt.Errorf("outbox: read saga %q to find its mode: %w", sagaID, err)
	}
	if len(events) == 0 {
		return "", false, nil
	}
	// The mode is on SAGA_BEGIN and nothing can change it afterwards, so the
	// first event answers the question and the rest of the history is not read
	// into a state machine to get it.
	st, err := saga.Replay(events[:1])
	if err != nil {
		return "", false, fmt.Errorf("outbox: read saga %q to find its mode: %w", sagaID, err)
	}
	return st.Mode, true, nil
}

// exploratoryAllows refuses an effect whose saga is exploratory and whose target
// is not a declared sandbox.
//
// A deployment that has configured no mode resolver is unaffected, which is
// every deployment before Phase 6e — the same asymmetry the jurisdiction pin
// uses. What is *not* optional once one is configured is the answer: a resolver
// that errors, or that has never heard of the saga, refuses.
func (r *Releaser) exploratoryAllows(ctx context.Context, sagaID, target string) error {
	if r.modes == nil {
		return nil
	}
	mode, ok, err := r.modes.ModeOf(ctx, sagaID)
	if err != nil {
		return fmt.Errorf("%w: could not determine the mode of saga %q, and an effect whose "+
			"mode is unknown might be exploratory: %w", ErrExploratory, sagaID, err)
	}
	if !ok {
		return fmt.Errorf("%w: the log has no beginning for saga %q, so nothing says whether "+
			"this effect was meant to reach the world", ErrExploratory, sagaID)
	}
	if !saga.IsExploratory(mode) {
		return nil
	}
	if _, sandboxed := r.sandbox[target]; sandboxed {
		return nil
	}
	return fmt.Errorf("%w: saga %q is exploratory and %q is not a declared sandbox",
		ErrExploratory, sagaID, target)
}
