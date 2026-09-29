package saga

import (
	"fmt"
	"maps"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"google.golang.org/protobuf/proto"
)

// LoadEvents reads every event belonging to sagaID out of an evidence
// directory, in log order.
//
// Reading straight from the segments rather than from an index is deliberate at
// this phase: the log is the system of record, and a replay that consulted a
// projection would be checking the projection against itself. Phase 2 adds the
// resource and saga indexes that make this fast; correctness comes first.
func LoadEvents(dir, sagaID string, opts ...evidence.ReadOption) ([]Event, error) {
	var out []Event
	err := evidence.WalkSaga(dir, sagaID, func(h evidence.EventHeader, rec segment.Record) error {
		// Re-check the record against its own hashes before feeding it to
		// the state machine. Replaying unverified bytes would let a tampered
		// log dictate the reconstructed history — the opposite of the point.
		if len(rec.Payload) > 0 {
			if got := evidence.HashPayload(rec.Payload); got != h.PayloadHash {
				return fmt.Errorf("seq %d: payload does not match its recorded hash", h.Seq)
			}
		}
		if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
			return fmt.Errorf("seq %d: chain hash mismatch", h.Seq)
		}
		out = append(out, Event{Seq: h.Seq, Kind: h.Kind, Wall: h.TS.Wall(), Payload: rec.Payload})
		return nil
	}, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReplaySaga rebuilds a saga's projection from the evidence log.
func ReplaySaga(dir, sagaID string) (State, error) {
	events, err := LoadEvents(dir, sagaID)
	if err != nil {
		return State{}, err
	}
	if len(events) == 0 {
		return State{}, fmt.Errorf("no events found for saga %q in %s", sagaID, dir)
	}
	return Replay(events)
}

// ReplayAll rebuilds every saga in an evidence directory, keyed by saga id.
//
// A frontier gate is a question about other sagas, so answering it needs their
// projections and not only this one's. Reading them from the log rather than
// from a shared cache is the same choice the outbox makes about commit
// authority: slower, and the only version that cannot be answering with a
// belief that has since been overtaken. Phase 6's partitioned orchestrator is
// where this stops being affordable and starts needing the saga index Phase 2
// built.
//
// A saga whose events do not form a legal history is returned as an error
// rather than skipped. Skipping it would quietly shrink the set of sagas a
// frontier check can see, and a check that cannot see a contending saga passes.
func ReplayAll(dir string, opts ...evidence.ReadOption) (map[string]State, error) {
	byID := map[string][]Event{}
	var order []string

	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		if h.SagaID == "" {
			return nil
		}
		if len(rec.Payload) > 0 {
			if got := evidence.HashPayload(rec.Payload); got != h.PayloadHash {
				return fmt.Errorf("seq %d: payload does not match its recorded hash", h.Seq)
			}
		}
		if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
			return fmt.Errorf("seq %d: chain hash mismatch", h.Seq)
		}
		if _, seen := byID[h.SagaID]; !seen {
			order = append(order, h.SagaID)
		}
		byID[h.SagaID] = append(byID[h.SagaID],
			Event{Seq: h.Seq, Kind: h.Kind, Wall: h.TS.Wall(), Payload: rec.Payload})
		return nil
	}, opts...); err != nil {
		return nil, err
	}

	out := make(map[string]State, len(byID))
	for _, sagaID := range order {
		s, err := Replay(byID[sagaID])
		if err != nil {
			return nil, fmt.Errorf("replay saga %q: %w", sagaID, err)
		}
		out[sagaID] = s
	}
	return out, nil
}

// ReplaySome rebuilds the named sagas, and only those, in one pass over the log.
//
// It exists for a caller that already knows which sagas it cares about — the
// console's approval queue, which asks a projection which sagas have a step
// waiting on a gate and then needs their real projections to decide what each
// gate is waiting for.
//
// One pass rather than one call to ReplaySaga per id, which is the obvious
// implementation and is worse than ReplayAll: each of those walks the whole
// segment directory, so a queue of twenty items would read the log twenty
// times. This reads it once and replays only what was asked for.
//
// A saga named here that the log has no events for is returned as an error
// rather than omitted. The caller learned the id from somewhere, and quietly
// returning fewer sagas than were asked for would turn a stale projection into
// a short queue rather than into a complaint.
func ReplaySome(dir string, ids []string, opts ...evidence.ReadOption) (map[string]State, error) {
	if len(ids) == 0 {
		return map[string]State{}, nil
	}
	wanted := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		wanted[id] = struct{}{}
	}

	byID := map[string][]Event{}
	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		if _, ok := wanted[h.SagaID]; !ok {
			return nil
		}
		// The same verification ReplayAll does. A projection told this caller
		// which sagas to look at; it does not get to tell it what they contain.
		if len(rec.Payload) > 0 {
			if got := evidence.HashPayload(rec.Payload); got != h.PayloadHash {
				return fmt.Errorf("seq %d: payload does not match its recorded hash", h.Seq)
			}
		}
		if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
			return fmt.Errorf("seq %d: chain hash mismatch", h.Seq)
		}
		byID[h.SagaID] = append(byID[h.SagaID],
			Event{Seq: h.Seq, Kind: h.Kind, Wall: h.TS.Wall(), Payload: rec.Payload})
		return nil
	}, opts...); err != nil {
		return nil, err
	}

	out := make(map[string]State, len(byID))
	for _, sagaID := range ids {
		events, ok := byID[sagaID]
		if !ok {
			return nil, fmt.Errorf("saga %q was asked for but the log has no events for it", sagaID)
		}
		s, err := Replay(events)
		if err != nil {
			return nil, fmt.Errorf("replay saga %q: %w", sagaID, err)
		}
		out[sagaID] = s
	}
	return out, nil
}

// Diff describes how two projections of the same saga disagree. An empty slice
// is what determinism looks like (invariant I5).
func Diff(a, b State) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	if a.SagaID != b.SagaID {
		add("saga id: %q vs %q", a.SagaID, b.SagaID)
	}
	if a.Status != b.Status {
		add("status: %s vs %s", a.Status, b.Status)
	}
	if a.IntentID != b.IntentID {
		add("intent: %q vs %q", a.IntentID, b.IntentID)
	}
	if a.Mode != b.Mode {
		add("mode: %q vs %q", a.Mode, b.Mode)
	}
	if a.LastSeq != b.LastSeq {
		add("last sequence: %d vs %d", a.LastSeq, b.LastSeq)
	}
	if a.EventCount != b.EventCount {
		add("event count: %d vs %d", a.EventCount, b.EventCount)
	}
	if len(a.Steps) != len(b.Steps) {
		add("step count: %d vs %d", len(a.Steps), len(b.Steps))
	}
	for _, id := range a.Order {
		sa, sb := a.Steps[id], b.Steps[id]
		if sb == nil {
			add("step %q present in the first projection only", id)
			continue
		}
		if sa.Status != sb.Status {
			add("step %q status: %s vs %s", id, sa.Status, sb.Status)
		}
		if sa.Attempt != sb.Attempt {
			add("step %q attempts: %d vs %d", id, sa.Attempt, sb.Attempt)
		}
		if sa.Outcome != sb.Outcome {
			add("step %q outcome: %s vs %s", id, sa.Outcome, sb.Outcome)
		}
		// Touches and PreparedAt are compared because they are the inputs to
		// decisions taken later — which saga reached a resource first, and
		// whether an attempt has timed out. A divergence here does not change
		// how the saga looks today but changes what it decides tomorrow, which
		// is the harder kind of drift to notice.
		if len(sa.Touches) != len(sb.Touches) {
			add("step %q touch count: %d vs %d", id, len(sa.Touches), len(sb.Touches))
		} else {
			for i := range sa.Touches {
				if sa.Touches[i] != sb.Touches[i] {
					add("step %q touch %d: %+v vs %+v", id, i, sa.Touches[i], sb.Touches[i])
				}
			}
		}
		if !sa.PreparedAt.Equal(sb.PreparedAt) {
			add("step %q prepared at: %s vs %s", id,
				sa.PreparedAt.Format(time.RFC3339Nano), sb.PreparedAt.Format(time.RFC3339Nano))
		}
		// ResultAt is compared for the same reason PreparedAt is: it is an input
		// to a decision taken later. It anchors a PRE_RELEASE gate's deadline,
		// so a divergence here does not change how the saga looks today and
		// changes when it times out tomorrow.
		if !sa.ResultAt.Equal(sb.ResultAt) {
			add("step %q result at: %s vs %s", id,
				sa.ResultAt.Format(time.RFC3339Nano), sb.ResultAt.Format(time.RFC3339Nano))
		}
		if sa.Compensation != sb.Compensation {
			add("step %q compensation: %q vs %q", id, sa.Compensation, sb.Compensation)
		}
		// The pinned proposal is an input to a decision taken later too: it is
		// what every verdict on the escalated attempt must be about.
		if (sa.ProposalSpawn == nil) != (sb.ProposalSpawn == nil) ||
			(sa.ProposalSpawn != nil && *sa.ProposalSpawn != *sb.ProposalSpawn) {
			add("step %q pinned delegation: %s vs %s", id,
				describeSpawn(sa.ProposalSpawn), describeSpawn(sb.ProposalSpawn))
		}
		if sa.ProposalAttempt != sb.ProposalAttempt || !maps.Equal(sa.Proposal, sb.Proposal) {
			add("step %q proposal: attempt %d %v vs attempt %d %v", id,
				sa.ProposalAttempt, DescribeFacts(sa.Proposal),
				sb.ProposalAttempt, DescribeFacts(sb.Proposal))
		}
	}
	for _, id := range b.Order {
		if _, ok := a.Steps[id]; !ok {
			add("step %q present in the second projection only", id)
		}
	}
	return out
}

// BeginOf returns the SAGA_BEGIN a saga was admitted with.
//
// The recorded plan, not the projection of what happened. Template extraction
// needs it because a template is a claim about what a later saga *will*
// do, and a shape taken from what a run did would confine future sagas to the
// outcomes of past ones — which is a stranger claim than it sounds, and not the
// one crystallized mode makes.
//
// It reads only the first event: a second SAGA_BEGIN is refused by the state
// machine, so there is exactly one and it is first.
func BeginOf(dir, sagaID string) (*janusv1.SagaBegin, error) {
	events, err := LoadEvents(dir, sagaID)
	if err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, fmt.Errorf("saga %q has no events in %s", sagaID, dir)
	}
	if events[0].Kind != evidence.KindSagaBegin {
		return nil, fmt.Errorf("saga %q begins with a %s rather than a SAGA_BEGIN",
			sagaID, events[0].Kind)
	}
	var msg janusv1.SagaBegin
	if err := proto.Unmarshal(events[0].Payload, &msg); err != nil {
		return nil, fmt.Errorf("decode the beginning of saga %q: %w", sagaID, err)
	}
	return &msg, nil
}
