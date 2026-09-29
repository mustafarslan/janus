package saga

import (
	"fmt"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// The delegation half of a pinned proposal (semantics 3).
//
// Semantics 2 pinned the facts an escalation was asked about. A step that delegates
// also proposes the delegation -- which sub-saga, and whether it commits on its
// own -- and that lived only in the memory of the daemon holding it, so a
// participant could re-declare the same facts with a different child while the
// question was open, and a restart forgot what had been asked. These helpers are
// the one definition of "the same delegation" that the fold, the coordinator and
// the daemon share.

// linkOf is the recorded form of a declared child, or nil for none.
func linkOf(c *janusv1.ChildSaga) *ChildLink {
	if c == nil || c.GetSagaId() == "" {
		return nil
	}
	return &ChildLink{SagaID: c.GetSagaId(), Mode: c.GetCommitMode()}
}

// sameSpawn says whether a declared child is the pinned one. Nil and nil are
// the same: a proposal that delegated nothing must still delegate nothing.
func sameSpawn(pinned *ChildLink, declared *janusv1.ChildSaga) bool {
	got := linkOf(declared)
	if pinned == nil || got == nil {
		return pinned == nil && got == nil
	}
	return *pinned == *got
}

func describeSpawn(l *ChildLink) string {
	if l == nil {
		return "delegates nothing"
	}
	return fmt.Sprintf("delegates to %s sub-saga %q", strings.ToLower(shortCommitMode(l.Mode)), l.SagaID)
}

func shortPhase(p janusv1.GatePhase) string {
	return strings.ToLower(strings.TrimPrefix(p.String(), "GATE_PHASE_"))
}

// ScopedSpawn is the child a step's next prepare will name for a declared
// delegation: attempt-scoped, because a retry must delegate to a new sub-saga.
// It is what an escalation records, so what was asked about and what runs are
// compared in the same form.
func ScopedSpawn(child *janusv1.ChildSaga, priorAttempts uint32) *janusv1.ChildSaga {
	if child == nil {
		return nil
	}
	return attemptScopedChild(child, priorAttempts)
}

// SpawnUnderDecision returns the delegation a pre-execution escalation pinned
// for the attempt about to be made, and whether one is pinned at all (a pinned
// "delegates nothing" returns nil, true). Only semantics 3 pins it.
func SpawnUnderDecision(s State, st *Step) (*janusv1.ChildSaga, bool) {
	if s.Semantics < 3 {
		return nil, false
	}
	if _, ok := ProposalUnderDecision(st); !ok {
		return nil, false
	}
	if st.ProposalSpawn == nil {
		return nil, true
	}
	return &janusv1.ChildSaga{SagaId: st.ProposalSpawn.SagaID, CommitMode: st.ProposalSpawn.Mode}, true
}

// SameSpawn is sameSpawn for callers outside the fold, on the wire form.
func SameSpawn(pinned, declared *janusv1.ChildSaga) bool {
	return sameSpawn(linkOf(pinned), declared)
}

// DescribeSpawn renders a delegation for an error an operator reads.
func DescribeSpawn(c *janusv1.ChildSaga) string { return describeSpawn(linkOf(c)) }
