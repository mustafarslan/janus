package main

import (
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
)

// The scenario's own guards make it hard to prove the invariant can fail: every
// way of breaking invariant I6 that this harness can reach also stops the two
// sagas contending, and the dirCheck catches that first — which is the guard
// doing its job, and leaves the invariant itself unexercised by any break.
//
// So it is exercised directly, on a state the scenario cannot produce while the
// gate works: a saga committed over an earlier touch that is still in flight.
// That is exactly what a regression in the frontier index, or a resumed
// coordinator committing out of order, would leave in the log.

func touched(sagaID, resource string, seq uint64, status saga.Status) saga.State {
	return saga.State{
		SagaID: sagaID, Status: status,
		Order: []string{"wire"},
		Steps: map[string]*saga.Step{"wire": {
			ID: "wire",
			Touches: []saga.Touch{{
				Resource: resource, Mode: janusv1.ResourceTouch_MODE_WRITE, Seq: seq,
			}},
		}},
	}
}

func TestTheInvariantCatchesACommitOverAnUnsettledTouch(t *testing.T) {
	// The earlier saga is still running; the later one has committed over it.
	states := map[string]saga.State{
		"sg_race_a": touched("sg_race_a", "acct:contended", 10, saga.StatusRunning),
		"sg_race_b": touched("sg_race_b", "acct:contended", 20, saga.StatusCommitted),
	}
	err := contendingInvariant(states)
	if err == nil {
		t.Fatal("a saga committed over an earlier touch that is still in flight and the " +
			"invariant said nothing; that is invariant I6")
	}
	if !strings.Contains(err.Error(), "sg_race_b") {
		t.Errorf("the failure does not name the saga that committed: %v", err)
	}
}

func TestTheInvariantAcceptsCommittingInOrder(t *testing.T) {
	// The earlier saga settled first, which is the whole point: two sagas may
	// both commit over one resource, one after the other. I6 is an ordering
	// property, not an exclusion.
	states := map[string]saga.State{
		"sg_race_a": touched("sg_race_a", "acct:contended", 10, saga.StatusCommitted),
		"sg_race_b": touched("sg_race_b", "acct:contended", 20, saga.StatusCommitted),
	}
	if err := contendingInvariant(states); err != nil {
		t.Fatalf("both sagas committed in frontier order and the invariant objected: %v", err)
	}
}

// TestQuarantineHoldsTheResource is the second predicted culprit for a
// contention violation.
//
// A quarantined saga is frozen, not finished: its effects are still in the world
// and nobody has decided what to do about them. So it goes on blocking, and a
// later saga that committed over it is a saga resting on something a human has
// explicitly not signed off.
func TestQuarantineHoldsTheResource(t *testing.T) {
	states := map[string]saga.State{
		"sg_race_a": touched("sg_race_a", "acct:contended", 10, saga.StatusQuarantine),
		"sg_race_b": touched("sg_race_b", "acct:contended", 20, saga.StatusCommitted),
	}
	if err := contendingInvariant(states); err == nil {
		t.Fatal("a saga committed over a quarantined earlier touch; quarantine is frozen, " +
			"not finished, and its effects are still in the world")
	}
}
