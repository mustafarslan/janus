package spotreplay

import (
	"fmt"
	"sort"
	"sync"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// Sampler finds sagas worth checking by tailing an evidence directory.
//
// # Why it tails the log rather than reading the projection
//
// The projection knows exactly which sagas are terminal and could hand over a
// list. It is deliberately not asked, for one reason that is convenience and
// one that is not.
//
// The convenience: a deployment without `-projection` still deserves
// spot-replay, and this tool belongs to the family — `janus-verify`, the
// continuous verifier, the soak — whose whole virtue is needing nothing but the
// evidence directory.
//
// The one that matters: a verification tool whose candidate list came from the
// projection could never detect a saga the projection had missed. Its coverage
// would be bounded by a component it exists to be independent of, and the
// failure would be silent — a saga nobody checked, in a report that said
// everything checked out.
type Sampler struct {
	dir string

	mu sync.Mutex
	// fromSegment is the lowest segment id that may still hold unseen records.
	//
	// It advances past *records*, never past the highest filename listed. An
	// open appender pre-creates the next segment, so `segment.ScanComplete`
	// reports an empty one beyond the one being written and that file is removed
	// at the next rotation; resuming from it means resuming from a segment id
	// that no longer exists, and every later scan skips the whole log. That is
	// not hypothetical — it is exactly what the projector did until a test that
	// kept one appender open caught it.
	fromSegment uint64
	// seen dedupes by saga id and the sequence it was last checked at, so a saga
	// is re-checked when it moves and not before.
	seen map[string]uint64
}

// NewSampler returns a sampler over an evidence directory.
func NewSampler(dir string) *Sampler {
	return &Sampler{dir: dir, seen: map[string]uint64{}}
}

// Candidate is a saga the sampler thinks is worth checking.
type Candidate struct {
	SagaID string
	// LastSeq is the highest sequence seen for this saga, which is what the
	// sampler dedupes on.
	LastSeq uint64
}

// Next returns the sagas that have moved since the last call.
//
// It does not decide which of them are finished, and the first version of this
// did: it looked for COMMIT, ABORT and QUARANTINE records and called those
// terminal. That silently missed every compensated saga, because a saga becomes
// COMPENSATED when its last compensation reports — there is no event kind that
// says so — and deciding it from event kinds would have been a second
// implementation of the state machine's terminal rule, disagreeing with the
// first in exactly one case.
//
// So the sampler answers the cheap question it can answer from headers alone —
// which sagas have new events — and whether a saga is finished is decided by
// `saga.State.Terminal` after a replay, by the only code that gets to decide it.
func (s *Sampler) Next() ([]Candidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids, err := segment.ScanComplete(s.dir)
	if err != nil {
		return nil, err
	}

	// lastSeq per saga among the records looked at.
	lastSeq := map[string]uint64{}
	resume := s.fromSegment
	var highest uint64

	for _, id := range ids {
		if id < s.fromSegment {
			continue
		}
		path := segment.Path(s.dir, id)
		insp, err := segment.Inspect(path)
		if err != nil {
			return nil, fmt.Errorf("spotreplay: inspect %s: %w", path, err)
		}
		if insp.Torn {
			return nil, fmt.Errorf("spotreplay: segment %d ends in an incomplete record; "+
				"recover the log before sampling it", id)
		}
		for i, rec := range insp.Records {
			h, err := evidence.DecodeHeader(rec.Header)
			if err != nil {
				return nil, fmt.Errorf("spotreplay: segment %d record %d: %w", id, i, err)
			}
			if h.Seq >= highest {
				highest = h.Seq
				resume = id
			}
			if h.SagaID == "" {
				continue
			}
			if h.Seq > lastSeq[h.SagaID] {
				lastSeq[h.SagaID] = h.Seq
			}
		}
	}
	s.fromSegment = resume

	out := make([]Candidate, 0, len(lastSeq))
	for id, seq := range lastSeq {
		if was, dup := s.seen[id]; dup && was >= seq {
			continue
		}
		out = append(out, Candidate{SagaID: id, LastSeq: seq})
	}
	// Sorted so that a run over one directory checks sagas in a stable order and
	// a report can be diffed against the last one.
	sort.Slice(out, func(i, j int) bool { return out[i].SagaID < out[j].SagaID })
	return out, nil
}

// Accept records that a candidate has been checked, so it is not offered again
// until it moves.
//
// Separate from Next because a candidate that could not be checked — a
// transient read failure — must be offered again rather than skipped. Marking
// on emission would turn a failure to look into a silent gap in coverage.
func (s *Sampler) Accept(c Candidate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if was, ok := s.seen[c.SagaID]; !ok || c.LastSeq > was {
		s.seen[c.SagaID] = c.LastSeq
	}
}
