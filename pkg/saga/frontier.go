package saga

import (
	"fmt"
	"maps"
	"slices"
	"sort"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// Frontiers are what keep two sagas touching the same resource from producing a
// result neither of them would have produced alone.
//
// # The problem
//
// Saga A reads an account balance and decides to lend against it. Saga B, still
// running, wrote that balance and may yet fail and refund. If A commits first,
// its decision rests on a fact that is subsequently revoked — and nothing in
// A's own evidence shows anything wrong, because from A's point of view the read
// succeeded and the decision followed from it. The damage is only visible by
// looking at both sagas together.
//
// A hash chain does not help here. It proves what each saga did; it says nothing
// about whether one of them should have waited.
//
// # The rule
//
// A saga may commit only when, for every resource it touched, every conflicting
// touch that came *earlier* belongs to a saga that has finished — committed or
// compensated. Anything still in flight might yet reverse itself, so committing
// on top of it means committing on top of a fact that can be withdrawn
// (invariant I6).
//
// Ordering comes from the evidence log's sequence numbers, which are a total
// order across every saga. That is why the log being the system of record
// is load-bearing rather than merely tidy: two coordinators on
// different machines reach the same conclusion about who was first because they
// are reading the same numbers.
//
// # Why quarantine blocks forever
//
// A quarantined saga is not finished. Its effects are still in the world, and
// nobody has yet decided what to do about them. Letting a later saga commit over
// them would build on a state a human has explicitly not signed off. So
// quarantine holds the frontier on every resource it touched until someone
// resolves it, which is deliberately inconvenient: a stuck
// saga should be visible as pressure on the resources it holds, not quietly
// stepped around.

// Touch records that a step read or wrote a resource.
type Touch struct {
	Resource string
	Mode     janusv1.ResourceTouch_Mode
	// Seq is the evidence sequence of the result that reported the touch.
	Seq uint64
}

// IsWrite reports whether the touch changed the resource.
func (t Touch) IsWrite() bool { return t.Mode == janusv1.ResourceTouch_MODE_WRITE }

// conflictsWith reports whether two touches on the same resource can interfere.
// Two reads cannot: neither changes anything, so their order is immaterial.
func (t Touch) conflictsWith(other Touch) bool { return t.IsWrite() || other.IsWrite() }

// Index answers commit-safety questions across sagas.
//
// It is a projection, rebuildable by replaying the log, and holds no authority
// of its own — every answer it gives is derived from saga states that came from
// evidence.
type Index struct {
	sagas map[string]State
}

// NewIndex builds an index over a set of saga projections.
func NewIndex(states ...State) *Index {
	ix := &Index{sagas: make(map[string]State, len(states))}
	for _, s := range states {
		ix.Add(s)
	}
	return ix
}

// Add records or replaces a saga's projection.
func (ix *Index) Add(s State) {
	if s.SagaID == "" {
		return
	}
	ix.sagas[s.SagaID] = s.Clone()
}

// SagaIDs lists the sagas the index knows about, sorted.
func (ix *Index) SagaIDs() []string {
	out := slices.Collect(maps.Keys(ix.sagas))
	sort.Strings(out)
	return out
}

// indexedTouch is a touch together with who made it.
type indexedTouch struct {
	Touch
	SagaID string
	StepID string
}

// touchesOn returns every touch on a resource, ordered by sequence. Ties break
// by saga then step id so the result never depends on map iteration.
func (ix *Index) touchesOn(resource string) []indexedTouch {
	var out []indexedTouch
	for _, sagaID := range ix.SagaIDs() {
		s := ix.sagas[sagaID]
		for _, stepID := range s.Order {
			for _, t := range s.Steps[stepID].Touches {
				if t.Resource == resource {
					out = append(out, indexedTouch{Touch: t, SagaID: sagaID, StepID: stepID})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		if out[i].SagaID != out[j].SagaID {
			return out[i].SagaID < out[j].SagaID
		}
		return out[i].StepID < out[j].StepID
	})
	return out
}

// Resources lists every resource any known saga has touched, sorted.
func (ix *Index) Resources() []string {
	set := map[string]struct{}{}
	for _, s := range ix.sagas {
		for _, stepID := range s.Order {
			for _, t := range s.Steps[stepID].Touches {
				set[t.Resource] = struct{}{}
			}
		}
	}
	out := slices.Collect(maps.Keys(set))
	sort.Strings(out)
	return out
}

// settled reports whether a saga has finished in a way that will not be undone.
//
// QUARANTINE is deliberately absent: it is frozen, not finished, and its effects
// are still in the world awaiting a human decision.
func (ix *Index) settled(sagaID string) bool {
	s, ok := ix.sagas[sagaID]
	if !ok {
		// A saga the index has never seen cannot be assumed finished. Treating
		// unknown as settled would make commit safety depend on how complete
		// the index happens to be, which is the opposite of a safety property.
		return false
	}
	switch s.Status {
	case StatusCommitted, StatusCompensated:
		return true
	default:
		return false
	}
}

// Frontier is the watermark on a resource: the highest sequence at or below
// which every touch belongs to a finished saga.
//
// It stops at the first unfinished touch rather than skipping past it. A
// watermark that jumped over a saga still in flight would say the resource is
// clear up to a point that a later reversal could invalidate.
func (ix *Index) Frontier(resource string) uint64 {
	var watermark uint64
	for _, t := range ix.touchesOn(resource) {
		if !ix.settled(t.SagaID) {
			return watermark
		}
		watermark = t.Seq
	}
	return watermark
}

// Blocker is one reason a saga may not commit yet.
type Blocker struct {
	// Resource is the contended resource.
	Resource string
	// BlockedStep is the step of the waiting saga that touched it.
	BlockedStep string
	// BlockingSaga reached the resource first and has not finished.
	BlockingSaga string
	BlockingStep string
	BlockingSeq  uint64
	// BlockingStatus is where that saga has got to, which is what tells an
	// operator whether this will clear on its own.
	BlockingStatus Status
	// Reason is a sentence an operator can act on.
	Reason string
}

func (b Blocker) String() string { return b.Reason }

// Blockers lists every reason the named saga may not commit, in a stable order.
// An empty result means the saga is clear.
func (ix *Index) Blockers(sagaID string) []Blocker {
	s, ok := ix.sagas[sagaID]
	if !ok {
		return nil
	}

	var out []Blocker
	seen := map[string]struct{}{}

	for _, stepID := range s.Order {
		for _, t := range s.Steps[stepID].Touches {
			for _, other := range ix.touchesOn(t.Resource) {
				switch {
				case other.SagaID == sagaID:
					continue
				case other.Seq >= t.Seq:
					// Later work waits for this saga, not the other way round.
					continue
				case !t.conflictsWith(other.Touch):
					// Two reads do not interfere.
					continue
				case ix.settled(other.SagaID):
					continue
				}

				key := t.Resource + "\x00" + other.SagaID + "\x00" + other.StepID + "\x00" + stepID
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}

				status := StatusCreated
				if bs, known := ix.sagas[other.SagaID]; known {
					status = bs.Status
				}
				out = append(out, Blocker{
					Resource:       t.Resource,
					BlockedStep:    stepID,
					BlockingSaga:   other.SagaID,
					BlockingStep:   other.StepID,
					BlockingSeq:    other.Seq,
					BlockingStatus: status,
					Reason: fmt.Sprintf(
						"%s touched %s at sequence %d in step %s and is %s; committing over work that "+
							"may still be reversed would rest this saga on a fact that can be withdrawn",
						other.SagaID, t.Resource, other.Seq, other.StepID, describeStatus(status)),
				})
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Resource != out[j].Resource {
			return out[i].Resource < out[j].Resource
		}
		return out[i].BlockingSeq < out[j].BlockingSeq
	})
	return out
}

func describeStatus(s Status) string {
	if s == StatusQuarantine {
		return "QUARANTINE, which holds until a human resolves it"
	}
	return string(s)
}

// MayCommit reports whether a saga is clear to commit, and why not if it is not.
func (ix *Index) MayCommit(sagaID string) (bool, []Blocker) {
	blockers := ix.Blockers(sagaID)
	return len(blockers) == 0, blockers
}

// Claims returns the frontier claims a saga should present when it seals: one
// per resource it touched, carrying the watermark that resource stood at.
func (ix *Index) Claims(sagaID string) []*janusv1.FrontierClaim {
	s, ok := ix.sagas[sagaID]
	if !ok {
		return nil
	}
	seen := map[string]struct{}{}
	var resources []string
	for _, stepID := range s.Order {
		for _, t := range s.Steps[stepID].Touches {
			if _, dup := seen[t.Resource]; dup {
				continue
			}
			seen[t.Resource] = struct{}{}
			resources = append(resources, t.Resource)
		}
	}
	sort.Strings(resources)

	out := make([]*janusv1.FrontierClaim, 0, len(resources))
	for _, r := range resources {
		out = append(out, &janusv1.FrontierClaim{ResourceId: r, LastSealedSeq: ix.Frontier(r)})
	}
	return out
}

// TouchedResources lists the resources a saga touched, sorted.
func TouchedResources(s State) []string {
	set := map[string]struct{}{}
	for _, stepID := range s.Order {
		for _, t := range s.Steps[stepID].Touches {
			set[t.Resource] = struct{}{}
		}
	}
	out := slices.Collect(maps.Keys(set))
	sort.Strings(out)
	return out
}
