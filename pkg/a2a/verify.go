package a2a

import (
	"errors"
	"fmt"

	"github.com/mustafarslan/janus/pkg/registry"
)

// ErrCounterpartRefused means the agent on the other side is not somebody the
// registry knows, or not in a state that may be talked to.
var ErrCounterpartRefused = errors.New("a2a: counterpart refused")

// Verifier decides whether a counterpart may be talked to.
//
// The decision is made from the registry, folded out of the evidence log, and
// never from the counterpart's own AgentCard. That is the whole point of the
// check and it is worth being explicit about why, because the card is right
// there and looks like it says the same thing.
//
// A card is an unauthenticated document served by whoever answers that address.
// An agent that wanted to be trusted would serve a card saying it is trusted.
// The registry's entry is a different kind of object: a signed manifest, an
// immutable version, a lifecycle recorded in a log somebody else owns. Checking
// the card would be asking the counterpart to vouch for itself, which is not a
// check — it is a formality that reads like one, which is the failure mode this
// project keeps refusing.
type Verifier struct {
	// dir is the evidence directory the registry is folded from. Reading it is
	// safe while a daemon writes it: the writer lock is a writer's lock.
	dir string
}

// NewVerifier reads the registry out of an evidence directory.
func NewVerifier(dir string) *Verifier { return &Verifier{dir: dir} }

// Verify checks a counterpart against the registry.
//
// The version comes from the caller — a pin, or the card's own claim about
// which manifest it was projected from. Either way the *answer* is the
// registry's: a card claiming a version the registry does not know, or knows in
// a state that is not active, is refused.
func (v *Verifier) Verify(participantID, version string) (*registry.Entry, error) {
	if participantID == "" || version == "" {
		return nil, fmt.Errorf("%w: a counterpart has to be named and pinned before it "+
			"can be checked", ErrCounterpartRefused)
	}
	events, err := registry.LoadEvents(v.dir)
	if err != nil {
		return nil, fmt.Errorf("a2a: reading the registry: %w", err)
	}
	reg, err := registry.Fold(events)
	if err != nil {
		return nil, fmt.Errorf("a2a: folding the registry: %w", err)
	}
	entry, ok := reg.Resolve(participantID, version)
	if !ok {
		return nil, fmt.Errorf("%w: %s@%s is not registered. A card claiming otherwise is "+
			"a document the counterpart wrote about itself",
			ErrCounterpartRefused, participantID, version)
	}
	if entry.State != registry.StateActive {
		return nil, fmt.Errorf("%w: %s@%s is %s; only an active version may be talked to",
			ErrCounterpartRefused, participantID, version, entry.State)
	}
	return entry, nil
}
