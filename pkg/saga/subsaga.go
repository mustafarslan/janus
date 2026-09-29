// Sub-sagas: delegated work that is still part of a transaction.
//
// An agent that spawns other agents produces a tree of work, not a list. Janus
// models each delegation as a saga in its own right — its own plan, its own
// steps, its own evidence — linked to the step that spawned it. The link is
// what turns a tree of independent sagas into one transaction, and the only
// question it has to answer is: when the parent changes its mind, what happens
// to the child?
//
// The answer is declared at spawn time, in one of two modes.
//
//   - CASCADE means the child is part of the parent's transaction. Its held
//     effects are released only when the parent commits, and a parent that
//     unwinds unwinds the child with it. The child pays for this by being
//     restricted at admission: it may not contain an effect that fires the
//     moment it runs, because such an effect cannot be withdrawn later.
//
//   - AUTONOMOUS means the child commits on its own authority and keeps what it
//     did. The parent pays for this by having to declare, at admission, how it
//     will compensate for a child it can no longer recall.
//
// Declaring the mode up front rather than deciding at failure time is the same
// discipline as the admission-time compensability check (invariant I3):
// discovering mid-saga that delegated work cannot be taken back is discovering
// it too late.
//
// The functions here are the cross-saga half of that model. Apply sees exactly
// one saga, so it can enforce everything a saga can check about itself — a
// cascade child refusing to commit unauthorised, a parent refusing to spawn
// from a PURE step. It cannot check a parent against its child, because it
// never sees both. That is what these functions are for, and they are pure
// functions over projections for the same reason Apply is: two coordinators
// looking at the same evidence must reach the same conclusion.

package saga

import (
	"fmt"
	"sort"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// Children lists the sub-sagas this saga has spawned, in plan order.
func Children(s State) []ChildLink {
	var out []ChildLink
	for _, id := range s.Order {
		if c := s.Steps[id].Child; c != nil {
			out = append(out, *c)
		}
	}
	return out
}

// ChildOf returns the sub-saga a step spawned.
func ChildOf(s State, stepID string) (ChildLink, bool) {
	st, ok := s.Steps[stepID]
	if !ok || st.Child == nil {
		return ChildLink{}, false
	}
	return *st.Child, true
}

// StepForChild returns the step that spawned a given sub-saga.
func StepForChild(s State, childSagaID string) (string, bool) {
	for _, id := range s.Order {
		if c := s.Steps[id].Child; c != nil && c.SagaID == childSagaID {
			return id, true
		}
	}
	return "", false
}

// CascadeUnwind lists the sub-sagas that have to be unwound because their
// parent is unwinding.
//
// Only cascade children appear. An autonomous child was spawned on the explicit
// understanding that it keeps what it did, so the parent compensates for it
// with its own declared compensation rather than reaching into someone else's
// transaction.
func CascadeUnwind(s State) []ChildLink {
	var out []ChildLink
	for _, id := range s.Order {
		st := s.Steps[id]
		if !st.Child.Cascades() {
			continue
		}
		if st.Compensation == CompRequired || st.Compensation == CompRunning {
			out = append(out, *st.Child)
		}
	}
	return out
}

// ErrNotAuthorized means a sub-saga's commit is not yet permitted.
var ErrNotAuthorized = fmt.Errorf("saga: sub-saga commit is not authorized")

// AuthorizeCommit returns the value a sub-saga's commit must carry in its
// authorized_by field, or an error explaining why it may not commit yet.
//
// A cascade child may commit exactly when its parent has committed. The order
// is not negotiable and it is not symmetric: the parent commits first and the
// child follows, never the reverse.
//
// That ordering is what makes a crash between the two safe. If the coordinator
// dies after the parent commits and before the child does, the child's effects
// are all still held — cascade children may not contain effects that fire on
// their own — and the recorded parent commit is a standing authorisation that
// any later coordinator can read and act on. The opposite order would leave a
// committed child whose parent might still abort, which nothing could repair.
func AuthorizeCommit(parent State, childSagaID string) (string, error) {
	stepID, ok := StepForChild(parent, childSagaID)
	if !ok {
		return "", fmt.Errorf("%w: saga %q did not spawn %q", ErrNotAuthorized, parent.SagaID, childSagaID)
	}
	child := parent.Steps[stepID].Child
	if !child.Cascades() {
		return "", fmt.Errorf("%w: sub-saga %q is autonomous and commits on its own authority, so it "+
			"must not ask %q for one", ErrNotAuthorized, childSagaID, parent.SagaID)
	}
	if parent.Status != StatusCommitted {
		return "", fmt.Errorf("%w: sub-saga %q cascades with %q, which is %s and has not committed",
			ErrNotAuthorized, childSagaID, parent.SagaID, parent.Status)
	}
	return parent.SagaID, nil
}

// Family is a parent saga together with the sub-sagas it spawned, keyed by
// saga id. It exists so the checks below can be given everything they need to
// judge a delegation, rather than half of it.
type Family struct {
	Parent   State
	Children map[string]State
}

// Check reports every way a family's projections contradict each other.
//
// This is the sub-saga counterpart to replay determinism: each saga is
// internally consistent by construction, because Apply refused anything else,
// but nothing inside a single saga's state machine can notice that a child
// committed while its parent was compensating. An empty result is what a
// well-formed delegation looks like.
func (f Family) Check() []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	seen := make(map[string]bool, len(f.Children))

	for _, link := range Children(f.Parent) {
		stepID, _ := StepForChild(f.Parent, link.SagaID)
		child, ok := f.Children[link.SagaID]
		if !ok {
			add("step %s spawned sub-saga %s, which is missing from the family",
				stepID, link.SagaID)
			continue
		}
		seen[link.SagaID] = true
		out = append(out, checkChild(f.Parent, stepID, link, child)...)
	}

	for id := range f.Children {
		if !seen[id] {
			add("sub-saga %s is in the family but no step of %s spawned it", id, f.Parent.SagaID)
		}
	}

	sort.Strings(out)
	return out
}

// checkChild judges one parent-child pair.
func checkChild(parent State, stepID string, link ChildLink, child State) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	// Both sides must tell the same story about the link. A child that thinks
	// it is autonomous while its parent thinks it cascades is the worst case:
	// each side believes someone else is responsible for withdrawing the
	// effects, so nobody is.
	switch {
	case child.Parent == nil:
		add("sub-saga %s does not record a parent, but step %s of %s spawned it",
			child.SagaID, stepID, parent.SagaID)
	case child.Parent.SagaID != parent.SagaID:
		add("sub-saga %s records %s as its parent, but %s spawned it",
			child.SagaID, child.Parent.SagaID, parent.SagaID)
	case child.Parent.StepID != stepID:
		add("sub-saga %s records step %s as its origin, but step %s spawned it",
			child.SagaID, child.Parent.StepID, stepID)
	case child.Parent.Mode != link.Mode:
		add("sub-saga %s believes it is %s while its parent spawned it as %s",
			child.SagaID, shortCommitMode(child.Parent.Mode), shortCommitMode(link.Mode))
	}

	// One family, one rule set. A child folding under different rules from its
	// parent can reach a status its parent's rules would not have let it reach,
	// and every check below assumes they agree about what a history means.
	if child.Semantics != parent.Semantics {
		add("sub-saga %s folds under semantics %d while its parent %s folds under %d",
			child.SagaID, child.Semantics, parent.SagaID, parent.Semantics)
	}

	if link.Mode != janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE {
		return out
	}

	// A cascade child's commit must have happened after, and because of, its
	// parent's. Any other combination means effects were released on an
	// authority that did not exist.
	if child.Status == StatusCommitted {
		if child.AuthorizedBy != parent.SagaID {
			add("cascade sub-saga %s committed on authority %q rather than its parent %s",
				child.SagaID, child.AuthorizedBy, parent.SagaID)
		}
		if parent.Status != StatusCommitted {
			add("cascade sub-saga %s has committed while its parent %s is %s",
				child.SagaID, parent.SagaID, parent.Status)
		}
	}

	// A parent that unwound must not leave a cascade child running. The child
	// holds effects that belong to the parent's transaction, and a running
	// saga nobody is going to finish is how resources stay locked forever.
	switch parent.Status {
	case StatusCompensated, StatusCompensating, StatusQuarantine:
		switch child.Status {
		case StatusCompensated, StatusQuarantine, StatusCompensating:
		case StatusCommitted:
			add("cascade sub-saga %s committed although its parent %s is %s",
				child.SagaID, parent.SagaID, parent.Status)
		default:
			add("parent %s is %s but its cascade sub-saga %s is still %s",
				parent.SagaID, parent.Status, child.SagaID, child.Status)
		}
	case StatusCommitted:
		// The window between the parent committing and the child following is
		// legitimate and is exactly where a crash is safe, so a child that has
		// not committed yet is not an error. A child that unwound after its
		// parent committed is, because the parent committed on the strength of
		// work that was then taken away.
		switch child.Status {
		case StatusCompensated, StatusCompensating, StatusQuarantine:
			add("parent %s committed but its cascade sub-saga %s is %s, so the parent committed on "+
				"work that was withdrawn", parent.SagaID, child.SagaID, child.Status)
		}
	}

	return out
}

// PendingAuthorization lists cascade sub-sagas that are waiting for a commit
// their parent has already authorised.
//
// This is the recovery work list. After a crash between a parent's commit and
// its children's, a coordinator picking the family up reads this to learn what
// it still owes, without having to reason about how far the previous one got.
func (f Family) PendingAuthorization() []string {
	if f.Parent.Status != StatusCommitted {
		return nil
	}
	var out []string
	for _, link := range Children(f.Parent) {
		if link.Mode != janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE {
			continue
		}
		child, ok := f.Children[link.SagaID]
		if !ok {
			continue
		}
		if child.Status == StatusSealing {
			out = append(out, link.SagaID)
		}
	}
	sort.Strings(out)
	return out
}
