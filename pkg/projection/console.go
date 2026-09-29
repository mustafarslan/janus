package projection

import (
	"context"
	"fmt"
)

// SagaSummary is one saga as the projection holds it: enough for a list, and
// deliberately not enough to decide anything.
//
// The console's overview is a list of what is happening, and every field here is
// a recorded fact folded by the saga state machine. What is *not* here is any
// gate's standing: which requirement is outstanding and what it is waiting for
// is decided by `gate.Decide` over a real projection, never read from a column.
type SagaSummary struct {
	SagaID   string
	Tenant   string
	Status   string
	Mode     string
	IntentID string
	LastSeq  uint64
	Terminal bool
	Steps    int
	Done     int
	Waiting  int
	Held     int
	// Quarantined is how many of this saga's effects are frozen. It is not part
	// of Held: a frozen effect has stopped being pending, so it drops out of
	// that count entirely.
	Quarantined int
	// The rest of what an overview row shows, so that a projection-backed page
	// is the same page and not a quietly poorer one.
	Principal  string
	EventCount int
	Reason     string
	Parent     string
}

// Overview lists every saga, most recently moved first, and says which sequence
// the answer is as of.
//
// It does not refuse a stale read the way a frontier gate does, and that
// difference is the point of the staleness contract's two halves. A gate is *acting* on the
// answer, so it insists on the head of the log; a console is *showing* it to a
// person, so it shows the sequence instead. A console that refused to render
// because a fold was a second behind would be useless, and one that rendered
// without saying when would be lying by omission.
func (s *Store) Overview(ctx context.Context) (rows []SagaSummary, asOf uint64, err error) {
	asOf, _, err = s.Head(ctx)
	if err != nil {
		return nil, 0, err
	}
	q, err := s.pool.Query(ctx, `
		SELECT sg.saga_id, sg.tenant, sg.status, sg.mode, sg.intent_ref, sg.last_seq,
		       sg.terminal, sg.held_effects, sg.quarantined_effects,
		       sg.principal, sg.event_count, sg.reason, sg.parent,
		       count(st.step_id),
		       count(*) FILTER (WHERE st.status IN ('COMMITTED', 'COMPENSATED', 'REFUSED')),
		       count(*) FILTER (WHERE st.held_by_gate)
		FROM sagas sg
		LEFT JOIN steps st ON st.saga_id = sg.saga_id
		GROUP BY sg.saga_id
		ORDER BY sg.last_seq DESC, sg.saga_id`)
	if err != nil {
		return nil, 0, fmt.Errorf("projection: read the saga overview: %w", err)
	}
	defer q.Close()
	for q.Next() {
		var r SagaSummary
		var lastSeq, eventCount int64
		var steps, done, waiting int64
		if err := q.Scan(&r.SagaID, &r.Tenant, &r.Status, &r.Mode, &r.IntentID, &lastSeq,
			&r.Terminal, &r.Held, &r.Quarantined, &r.Principal, &eventCount, &r.Reason, &r.Parent,
			&steps, &done, &waiting); err != nil {
			return nil, 0, fmt.Errorf("projection: read the saga overview: %w", err)
		}
		r.LastSeq, r.EventCount = uint64(lastSeq), int(eventCount)
		r.Steps, r.Done, r.Waiting = int(steps), int(done), int(waiting)
		rows = append(rows, r)
	}
	if err := q.Err(); err != nil {
		return nil, 0, fmt.Errorf("projection: read the saga overview: %w", err)
	}
	return rows, asOf, nil
}

// SagasHeldAtAGate names the sagas with at least one step stopped at a gate.
//
// This is the whole of what the approval queue takes from the projection: a
// shortlist. The queue then replays those sagas from the log and runs
// `gate.Decide` over what it finds, because what a gate is waiting for is a
// decision and decisions are not read from tables. A projection that was a
// little behind therefore produces a queue that is missing a row, never a queue
// with a wrong row on it — and the page says which sequence it is as of, so a
// missing row is visible as staleness rather than as absence.
func (s *Store) SagasHeldAtAGate(ctx context.Context) (ids []string, asOf uint64, err error) {
	asOf, _, err = s.Head(ctx)
	if err != nil {
		return nil, 0, err
	}
	q, err := s.pool.Query(ctx,
		`SELECT DISTINCT saga_id FROM steps WHERE held_by_gate ORDER BY saga_id`)
	if err != nil {
		return nil, 0, fmt.Errorf("projection: read the approval shortlist: %w", err)
	}
	defer q.Close()
	for q.Next() {
		var id string
		if err := q.Scan(&id); err != nil {
			return nil, 0, fmt.Errorf("projection: read the approval shortlist: %w", err)
		}
		ids = append(ids, id)
	}
	if err := q.Err(); err != nil {
		return nil, 0, fmt.Errorf("projection: read the approval shortlist: %w", err)
	}
	return ids, asOf, nil
}

// SagasWithQuarantinedEffects names the sagas holding at least one frozen effect.
//
// The same shortlist bargain SagasHeldAtAGate strikes, and here the reason it
// has to be a bargain rather than a query is written into the schema: effect
// state is commit authority (invariant I1), so the projection may say which
// sagas to look at and may not say what is on them. There is no effect id in
// these tables to return. The caller replays the sagas this names and asks
// `outbox.Quarantined` over what the log actually contains.
//
// A projection that is behind therefore yields a work list missing a row, never
// a work list with a wrong row on it, and the page carries the sequence so a
// missing row reads as staleness rather than as absence.
func (s *Store) SagasWithQuarantinedEffects(ctx context.Context) (ids []string, asOf uint64, err error) {
	asOf, _, err = s.Head(ctx)
	if err != nil {
		return nil, 0, err
	}
	q, err := s.pool.Query(ctx,
		`SELECT saga_id FROM sagas WHERE quarantined_effects > 0 ORDER BY saga_id`)
	if err != nil {
		return nil, 0, fmt.Errorf("projection: read the quarantine shortlist: %w", err)
	}
	defer q.Close()
	for q.Next() {
		var id string
		if err := q.Scan(&id); err != nil {
			return nil, 0, fmt.Errorf("projection: read the quarantine shortlist: %w", err)
		}
		ids = append(ids, id)
	}
	if err := q.Err(); err != nil {
		return nil, 0, fmt.Errorf("projection: read the quarantine shortlist: %w", err)
	}
	return ids, asOf, nil
}

// ParticipantCount is how many participants the registry holds.
func (s *Store) ParticipantCount(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM participants`).Scan(&n); err != nil {
		return 0, fmt.Errorf("projection: count participants: %w", err)
	}
	return n, nil
}
