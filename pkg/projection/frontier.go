package projection

import (
	"context"
	"fmt"
	"sort"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
)

// FrontierIndex builds the cross-saga index a frontier gate needs, reading only
// the sagas that could possibly bear on the subject.
//
// # Why a scoped index gives the same answer as a whole one
//
// `saga.Index.Blockers(id)` looks at exactly two things: the touches on each
// resource the subject itself touched, and the status of whichever sagas made
// them. It never consults a saga that shares no resource with the subject. So an
// index holding the subject plus every saga with a touch on one of the subject's
// resources returns the same blockers, in the same order, as an index built by
// replaying the entire log — and `Frontier` and `Claims` agree too, because they
// are also asked only about the subject's own resources.
//
// That equivalence is the whole point of the exercise and it is asserted as a
// test against the fixture corpus rather than left as an argument, because it is
// the kind of claim that stays true until someone adds a rule to Blockers.
//
// # Why the subject comes from the caller
//
// The subject's projection is passed in rather than read back out of the
// database. The coordinator holds the live one, and it is by construction at
// least as current as anything the projection has folded. Reading it back would
// make a decision about a saga depend on how recently a background process had
// run, and it is the subject's own touches that determine which resources are
// even looked at — a subject read one event too early asks about fewer
// resources than it occupies, and a frontier check that does not ask about a
// resource does not defend it.
//
// # The staleness contract
//
// requireSeq is the sequence the caller insists the projection has reached,
// normally the head of the log. Below it, this returns ErrStale and the caller
// must refuse the step.
//
// This is not belt and braces. A saga that began after `last_event_seq` has no
// rows at all, so it appears in no resource query, so it is not merely treated
// as unfinished — it is not seen. `Index.settled` fails closed for a saga it
// knows about and cannot fail closed for one nobody mentioned, which makes
// "caught up to the head" the property that carries the safety rather than a
// performance nicety.
func (s *Store) FrontierIndex(ctx context.Context, subject saga.State, requireSeq uint64) (*saga.Index, error) {
	head, _, err := s.Head(ctx)
	if err != nil {
		return nil, err
	}
	if head < requireSeq {
		return nil, fmt.Errorf("%w: projected to sequence %d, the log is at %d",
			ErrStale, head, requireSeq)
	}

	resources := resourcesOf(subject)
	states := map[string]*saga.State{}
	if len(resources) > 0 {
		rows, err := s.pool.Query(ctx, `
			SELECT rt.saga_id, sg.status, rt.step_id, COALESCE(st.ordinal, 0),
			       rt.resource_id, rt.mode, rt.frontier_seq
			FROM resource_touches rt
			JOIN sagas sg ON sg.saga_id = rt.saga_id
			LEFT JOIN steps st ON st.saga_id = rt.saga_id AND st.step_id = rt.step_id
			WHERE rt.resource_id = ANY($1) AND rt.saga_id <> $2
			ORDER BY rt.saga_id, COALESCE(st.ordinal, 0), rt.step_id, rt.frontier_seq`,
			resources, subject.SagaID)
		if err != nil {
			return nil, fmt.Errorf("projection: read contending touches: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var sagaID, status, stepID, resource, mode string
			var ordinal int32
			var seq int64
			if err := rows.Scan(&sagaID, &status, &stepID, &ordinal, &resource, &mode, &seq); err != nil {
				return nil, fmt.Errorf("projection: read contending touches: %w", err)
			}
			st, ok := states[sagaID]
			if !ok {
				st = &saga.State{
					SagaID: sagaID,
					Status: saga.Status(status),
					Steps:  map[string]*saga.Step{},
				}
				states[sagaID] = st
			}
			step, ok := st.Steps[stepID]
			if !ok {
				step = &saga.Step{ID: stepID}
				st.Steps[stepID] = step
				st.Order = append(st.Order, stepID)
			}
			m, known := janusv1.ResourceTouch_Mode_value[mode]
			if !known {
				// An unrecognised mode is not something to default. Treating it
				// as a read would make an unknown write invisible to the very
				// check that exists to see writes.
				return nil, fmt.Errorf("projection: saga %q step %q records touch mode %q, "+
					"which this build does not know", sagaID, stepID, mode)
			}
			step.Touches = append(step.Touches, saga.Touch{
				Resource: resource,
				Mode:     janusv1.ResourceTouch_Mode(m),
				Seq:      uint64(seq),
			})
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("projection: read contending touches: %w", err)
		}
	}

	ix := saga.NewIndex()
	ids := make([]string, 0, len(states))
	for id := range states {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ix.Add(*states[id])
	}
	// The subject goes in last so that it wins over anything the projection may
	// hold for it. It is the one saga in this index whose projection did not
	// come from the database.
	ix.Add(subject)
	return ix, nil
}

// resourcesOf lists the resources a saga has touched, sorted and deduplicated.
func resourcesOf(s saga.State) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, stepID := range s.Order {
		st := s.Steps[stepID]
		if st == nil {
			continue
		}
		for _, t := range st.Touches {
			if _, dup := seen[t.Resource]; dup {
				continue
			}
			seen[t.Resource] = struct{}{}
			out = append(out, t.Resource)
		}
	}
	sort.Strings(out)
	return out
}

// FrontierIndex adapts a projector to `gate.IndexFunc`.
//
// It is written as a plain function value rather than referring to gate's named
// type so that this package does not import the gate engine: the projection is
// below the decision layer and should not know what a gate is.
//
// The order of the two steps is the contract. `head()` is read *before* the
// catch-up, so what the projection must contain is everything that existed when
// the decision started — not everything that exists when it finishes. Reading it
// afterwards would let a concurrent append move the bar and make the answer
// depend on a race. Requiring the earlier head is also sufficient: a touch
// appended after the subject's own touches carries a higher sequence, and
// `Blockers` already lets later work wait rather than blocking on it.
//
// ctx belongs to whatever owns the projector, normally the daemon. When it is
// cancelled every frontier gate refuses, which is the correct behaviour during
// shutdown and the same shape as having no index at all.
func (p *Projector) FrontierIndex(ctx context.Context, head func() uint64) func(saga.State) (*saga.Index, error) {
	return func(subject saga.State) (*saga.Index, error) {
		want := head()
		// catchUpTo rather than CatchUp: eight decisions arriving together
		// share one fold instead of performing eight. It may return
		// short of want, and that is deliberate — the read below is what
		// refuses, and refusing is its job.
		if _, err := p.catchUpTo(ctx, want); err != nil {
			return nil, err
		}
		return p.store.FrontierIndex(ctx, subject, want)
	}
}
