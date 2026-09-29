package evidence

import (
	"errors"
	"fmt"

	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// Reading a log while it is being written.
//
// Five readers in this repository walked an evidence directory with the same
// twenty lines copied between them, and all five refused any segment that ended
// in an incomplete record. That is right for a directory nobody is writing to,
// where a torn tail is the signature of a crash. It is wrong for the live case,
// and the live case is the ordinary one: `segment.Writer` buffers through a
// bufio.Writer that flushes when its buffer fills — at a byte boundary, not a
// record boundary — so a reader that arrives mid-flush sees half a record in a
// log that is in perfect health. `janus-latency` reproduces it at concurrency 8
// within about sixty sagas.
//
// # Why reading past a tear is safe, and what makes it safe
//
// A torn record was never acknowledged. The appender publishes a sequence only
// after the batch has been flushed and synced — phase 3 of its batch loop — so
// no caller has been told that a torn record succeeded and no effect can have
// been released on its authority (this is also the basis for truncation
// during recovery; it is the same fact). Stopping at the last complete record
// therefore loses nothing anybody was promised.
//
// # Why that is not sufficient on its own
//
// Silently returning a prefix is the fail-open direction for the reader that
// matters most. A frontier gate asks "is anything else holding this resource",
// and a saga the reader did not see reads as a saga that is not in the way. That
// is exactly the hole the projection's staleness contract closes,
// and the answer here is the same one: **a caller that decides on the result
// names the sequence it requires, and is refused below it.**
//
// So tolerance is not a property of the reader, it is a permission the caller
// grants with AsOf. A caller with no appender to ask — an offline tool, an
// auditor, `janus-verify` — passes nothing and gets the old refusal, which is
// the correct answer when there is nobody who could say what the log's head is.
//
// # Gaps, and why a live read stops at one instead of refusing
//
// Sequences are contiguous, so a jump means the records between are missing.
// Offline that is damage and it is refused outright.
//
// On a live read it usually is not damage, and this took a `-race` run to
// notice. A reader walks segments oldest-first, and the appender creates the
// next segment ahead of a rotation — so a reader can read segment N,
// see the writer's next records land in N, watch it rotate, and then read N+1
// and find the sequence has jumped. Nothing is wrong with the log; the reader's
// view of N was taken too early.
//
// So a live read *stops* at a gap and treats what came before it as its prefix,
// which is exactly what it already does with a torn tail. The required sequence
// then decides: if the prefix reaches it, the read answered the question it was
// asked, and if it does not, the read is refused and the caller may ask again
// against a newer head. Genuine damage is caught by the same rule — records
// permanently missing at sequence 36 leave every read requiring more than 35
// refused, forever.
//
// What this gives up is that a live read no longer *detects* damage beyond what
// it needed to see. That is the right trade and it is not a new one: the same is
// true of the torn tail above, and finding damage is `janus-verify`'s job, not
// the read path's.

// ErrGap reports unreadable records in the middle of a log, which — unlike a
// torn tail — is always damage: sequences are contiguous, so a jump means
// acknowledged records cannot be read.
var ErrGap = errors.New("evidence: gap in the sequence")

// ReadOption configures how a directory walk treats a log that is in use.
type ReadOption func(*readOpts)

type readOpts struct {
	require uint64
	live    bool
	locator Locator
}

// AsOf permits reading a log that is being written, on the condition that the
// walk reaches at least require.
//
// Pass the appender's acknowledged head — `Appender.Stats().LastSeq` — and read
// it *before* starting the walk. Reading it afterwards would let a concurrent
// append move the bar and make the result depend on a race; requiring the
// earlier head is also sufficient, because anything appended after the question
// was asked is not part of the answer to it.
//
// A require of zero permits an empty log, which is the correct reading: an
// appender that has published nothing has promised nothing.
func AsOf(require uint64) ReadOption {
	return func(o *readOpts) { o.require, o.live = require, true }
}

// WithLocator lets a saga-scoped read skip the records of other sagas.
//
// Pass the appender when there is one: it wrote the records and knows where
// they are, and a reader without it walks the whole directory to find a
// handful. A locator that has not heard of the saga
// costs nothing — the read falls back to the scan and teaches the locator what
// it saw on the way past.
func WithLocator(l Locator) ReadOption {
	return func(o *readOpts) { o.locator = l }
}

// WalkSaga visits one saga's records, in log order.
//
// It is Walk narrowed to a saga, and the narrowing is the point: with a locator
// that knows the saga it reads only that saga's records, so the cost is the
// saga's length rather than the log's. Without one it is exactly Walk with a
// filter, including every check Walk makes about tears and gaps.
//
// The fallback indexes *every* saga it passes, not only the one asked for.
// That is what makes a cold start affordable: a daemon resuming ten thousand
// in-flight sagas pays one scan in total instead of ten thousand.
func WalkSaga(dir, sagaID string, visit func(EventHeader, segment.Record) error, opts ...ReadOption) error {
	var o readOpts
	for _, f := range opts {
		f(&o)
	}

	if o.locator != nil {
		if locs, known := o.locator.Locate(sagaID); known {
			return readAt(dir, locs, visit)
		}
	}

	// The scan. Everything it learns is handed back, so this is paid once.
	learned := map[string][]Location{}
	var reached uint64
	err := walkLocated(dir, func(h EventHeader, rec segment.Record, at Location) error {
		reached = h.Seq
		if h.SagaID != "" {
			learned[h.SagaID] = append(learned[h.SagaID], at)
		}
		if h.SagaID != sagaID {
			return nil
		}
		return visit(h, rec)
	}, opts...)
	if err != nil {
		return err
	}
	if o.locator != nil {
		o.locator.Learn(learned, reached)
	}
	return nil
}

// readAt reads the located records, one segment at a time and forwards within
// each, and hands them to the visitor in log order.
func readAt(dir string, locs []Location, visit func(EventHeader, segment.Record) error) error {
	if len(locs) == 0 {
		return nil
	}
	// Locations arrive in log order, and records of one saga can span segments.
	// Group by segment while preserving that order.
	type group struct {
		seg     uint64
		offsets []int64
	}
	var groups []group
	for _, l := range locs {
		if n := len(groups); n > 0 && groups[n-1].seg == l.Segment {
			groups[n-1].offsets = append(groups[n-1].offsets, l.Offset)
			continue
		}
		groups = append(groups, group{seg: l.Segment, offsets: []int64{l.Offset}})
	}

	for _, g := range groups {
		recs, err := segment.ReadRecordsAt(segment.Path(dir, g.seg), g.offsets)
		if err != nil {
			return fmt.Errorf("segment %d: %w", g.seg, err)
		}
		for _, rec := range recs {
			h, err := DecodeHeader(rec.Header)
			if err != nil {
				return fmt.Errorf("segment %d: %w", g.seg, err)
			}
			if err := visit(h, rec); err != nil {
				return err
			}
		}
	}
	return nil
}

// Walk visits every record in an evidence directory, in log order.
//
// The visitor is called with the decoded header and the raw record. It does not
// verify payload or chain hashes: each caller keeps a small fraction of the
// records and pays for verifying only those, and the reason a given reader
// verifies is worth stating where that reader is. Callers that keep a record
// must verify it.
//
// A visitor error stops the walk and is returned unwrapped.
func Walk(dir string, visit func(EventHeader, segment.Record) error, opts ...ReadOption) error {
	return walkLocated(dir, func(h EventHeader, rec segment.Record, _ Location) error {
		return visit(h, rec)
	}, opts...)
}

// walkLocated is Walk with each record's position, which the saga index needs
// and no ordinary caller does.
func walkLocated(dir string, visit func(EventHeader, segment.Record, Location) error, opts ...ReadOption) error {
	var o readOpts
	for _, f := range opts {
		f(&o)
	}

	// ScanComplete rather than ScanDir: the appender creates the next segment
	// ahead of a rotation, so a reader can see a file that is
	// part-way through becoming a segment. Skipping it is safe — nothing can
	// have been acknowledged on the authority of a file with no header.
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		return err
	}

	var (
		lastSeq uint64
		started bool
		// short says the walk stopped before the end of the directory, and why.
		// Both reasons produce a valid prefix and an incomplete one; which of
		// those matters is decided below, by the sequence the caller required.
		short   error
		shortIn uint64
	)
scan:
	for _, id := range ids {
		path := segment.Path(dir, id)
		insp, err := segment.Inspect(path)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		for i, rec := range insp.Records {
			h, err := DecodeHeader(rec.Header)
			if err != nil {
				return fmt.Errorf("segment %d record %d: %w", id, i, err)
			}
			if started && h.Seq != lastSeq+1 {
				short, shortIn = ErrGap, id
				break scan
			}
			lastSeq, started = h.Seq, true
			if err := visit(h, rec, Location{Segment: id, Offset: insp.Offsets[i]}); err != nil {
				return err
			}
		}
		if insp.Torn {
			short, shortIn = segment.ErrTornTail, id
			break scan
		}
	}

	if short == nil {
		return nil
	}
	if !o.live {
		if errors.Is(short, ErrGap) {
			return fmt.Errorf("%w: segment %d jumps past sequence %d, so records between "+
				"cannot be read and they were acknowledged; recover the log",
				ErrGap, shortIn, lastSeq)
		}
		return fmt.Errorf("segment %d ends in an incomplete record; recover the log "+
			"before reading it, or name the acknowledged head to read it live (%w)",
			shortIn, segment.ErrTornTail)
	}
	if lastSeq < o.require {
		// The prefix stopped short of what the caller was promised. On a busy
		// directory the ordinary cause is that the writer moved on mid-read and
		// the caller should ask again; the other cause is damage. This cannot
		// tell them apart and does not try, because the response is the same:
		// do not answer from a prefix that is missing records somebody needs.
		return fmt.Errorf("%w: the log reads only to sequence %d, below the acknowledged "+
			"%d — segment %d stops short. Read again against a newer head; if it keeps "+
			"happening the log needs recovering", short, lastSeq, o.require, shortIn)
	}
	return nil
}
