package outbox

import (
	"context"
	"fmt"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/saga"
)

// LogAuthority answers the commit question by reading the log.
//
// It replays the saga rather than consulting a projection somebody is
// maintaining, and that is the entire point of it. The question "has this saga
// committed?" is the one the release path stakes an irreversible effect on, so
// the answer has to come from the record, not from a cache that was correct
// when it was written. Replaying is slower; it is also the only version of this
// that cannot be wrong.
//
// Replaying stayed the answer even after it stopped being slow. The appender's
// record locator means this reads the saga's own events rather than
// walking the directory, so the cost argument that used to sit here is gone —
// and the reason to replay never was cost. An outbox that releases on a stale
// belief is worse than a slow one, and a projection is a belief with a sequence
// attached; the log is the thing itself.
type LogAuthority struct {
	dir  string
	live func() []evidence.ReadOption
}

// NewLogAuthority returns an authority backed by an evidence directory.
func NewLogAuthority(dir string) *LogAuthority { return &LogAuthority{dir: dir} }

// NewLiveLogAuthority is NewLogAuthority for a releaser that shares the
// directory with an appender.
//
// live supplies the read options each time: the appender's acknowledged
// sequence, which lets the replay read a log that is being written instead of
// refusing it as damaged, and the locator that finds
// the saga's records without walking the directory.
//
// It is a function rather than a value because the head moves. This is the
// release path, so the bound is doing more work here than anywhere else: an
// answer built from a prefix that stopped before the COMMIT would report a
// committed saga as uncommitted, and the effect would be withheld — fail-closed,
// but a stall nobody could explain.
func NewLiveLogAuthority(dir string, live func() []evidence.ReadOption) *LogAuthority {
	return &LogAuthority{dir: dir, live: live}
}

// Committed replays the saga and reports whether it has committed.
func (a *LogAuthority) Committed(_ context.Context, sagaID string) ([]byte, bool, error) {
	var opts []evidence.ReadOption
	if a.live != nil {
		opts = a.live()
	}
	events, err := saga.LoadEvents(a.dir, sagaID, opts...)
	if err != nil {
		return nil, false, fmt.Errorf("read saga %q: %w", sagaID, err)
	}
	if len(events) == 0 {
		// No log for the saga at all. This is not a transient miss to retry
		// past: an effect claiming to belong to a saga that does not exist is
		// either a bug or an attempt to release something nothing authorised.
		return nil, false, fmt.Errorf("saga %q has no events, so nothing could have authorised "+
			"releasing an effect on its behalf", sagaID)
	}
	state, err := saga.Replay(events)
	if err != nil {
		return nil, false, fmt.Errorf("replay saga %q: %w", sagaID, err)
	}
	if state.Status != saga.StatusCommitted {
		return nil, false, nil
	}

	// A commit with no evidence root cannot serve as an authority, because
	// nothing in the release record would point at what permitted it.
	if len(state.EvidenceRoot) == 0 {
		return nil, false, fmt.Errorf("saga %q is committed but its commit records no evidence "+
			"root, so there is nothing for a release to cite", sagaID)
	}
	return state.EvidenceRoot, true, nil
}

// LoadEvents reads the outbox events out of an evidence directory.
//
// Outbox events are scattered through the same log as everything else, so this
// walks the segments and keeps the four kinds this projection understands. It
// uses the reader's directory scan, which skips a segment that is still being
// created — a releaser reads the log while its own appender is running, so that
// is the ordinary case here rather than an exotic one.
func LoadEvents(dir string, opts ...evidence.ReadOption) ([]Event, error) {
	var out []Event
	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		switch h.Kind {
		case evidence.KindEffectHeld, evidence.KindEffectReleasing,
			evidence.KindEffectDelivered, evidence.KindEffectQuarantined:
		default:
			return nil
		}
		// Re-check the record against its own hashes before it reaches the
		// projection. This is the projection that decides whether money
		// moves; feeding it unverified bytes would let a tampered log
		// dictate that decision.
		if len(rec.Payload) > 0 {
			if got := evidence.HashPayload(rec.Payload); got != h.PayloadHash {
				return fmt.Errorf("seq %d: payload does not match its recorded hash", h.Seq)
			}
		}
		if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
			return fmt.Errorf("seq %d: chain hash mismatch", h.Seq)
		}
		out = append(out, Event{
			Seq: h.Seq, Kind: h.Kind, Wall: h.TS.Wall(), Payload: rec.Payload,
		})
		return nil
	}, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

// LoadEventsFor reads the outbox events belonging to a named set of sagas.
//
// It is LoadEvents with a filter, and it exists for the same reason
// `saga.ReplaySome` does: a projection can say which sagas are worth looking at
// without being allowed to say what is on them. The filter is the header's saga
// id, which every outbox event carries — the releaser records all four kinds
// through one path that sets it — so each effect's history arrives whole or not
// at all. A partial history would be worse than none: EFFECT_QUARANTINED
// applied to an effect whose EFFECT_HELD was filtered out is an event about a
// stranger.
//
// The saving is folds, not reads. This still walks the whole log, exactly as
// ReplaySome does; what it avoids is running the outbox state machine over
// every effect the deployment has ever held to answer a question about a
// handful of them.
func LoadEventsFor(dir string, sagaIDs []string, opts ...evidence.ReadOption) ([]Event, error) {
	if len(sagaIDs) == 0 {
		return nil, nil
	}
	wanted := make(map[string]struct{}, len(sagaIDs))
	for _, id := range sagaIDs {
		wanted[id] = struct{}{}
	}
	var out []Event
	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		switch h.Kind {
		case evidence.KindEffectHeld, evidence.KindEffectReleasing,
			evidence.KindEffectDelivered, evidence.KindEffectQuarantined:
		default:
			return nil
		}
		if _, ok := wanted[h.SagaID]; !ok {
			return nil
		}
		// The same verification LoadEvents does, for the same reason: a
		// projection told this caller which sagas to look at; it does not get
		// to tell it what they contain.
		if len(rec.Payload) > 0 {
			if got := evidence.HashPayload(rec.Payload); got != h.PayloadHash {
				return fmt.Errorf("seq %d: payload does not match its recorded hash", h.Seq)
			}
		}
		if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
			return fmt.Errorf("seq %d: chain hash mismatch", h.Seq)
		}
		out = append(out, Event{
			Seq: h.Seq, Kind: h.Kind, Wall: h.TS.Wall(), Payload: rec.Payload,
		})
		return nil
	}, opts...); err != nil {
		return nil, err
	}
	return out, nil
}

// Load rebuilds the outbox projection from an evidence directory.
func Load(dir string) (State, error) {
	events, err := LoadEvents(dir)
	if err != nil {
		return State{}, err
	}
	return Replay(events)
}
