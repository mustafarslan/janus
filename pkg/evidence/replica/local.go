package replica

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// LocalSource serves a primary's directory from the same process.
//
// It exists for two reasons and both are about keeping the hard part separate
// from the easy part. The rules a follower has to get right — the acknowledged
// bound, the torn tail, resuming past records — are all about *what* is copied,
// not how it travels, and testing them over gRPC would mean debugging the wire
// while trying to establish them. And the daemon's streaming RPC (6g's second
// half) is then a transport for an interface that already has its behaviour
// pinned, rather than a place where behaviour is invented again.
//
// The head comes from a live appender, which is the arrangement `janus-orchd`
// has: the process serving the replication stream is the one that owns the
// writer lock, so its own `Stats().LastSeq` is the authority on what has been
// acknowledged. Nothing else in the system may answer that question.
type LocalSource struct {
	dir  string
	head func() Head
}

// NewLocalSource serves dir, taking the acknowledged head from head.
func NewLocalSource(dir string, head func() Head) *LocalSource {
	return &LocalSource{dir: dir, head: head}
}

// FromAppender is NewLocalSource wired to an appender's own acknowledged head.
//
// The head it serves covers everything the appender has acknowledged, and that
// ordering is load-bearing rather than incidental.
//
// An earlier version did not: the appender answered every caller in a
// group-commit batch and updated its counters afterwards, so **2,980 of 3,000**
// concurrent appends observed a head below the Ref they had just been handed. A
// follower asking in that window was told a head excluding an acknowledged
// record, and a primary dying before the next poll left that record on no
// replica. Phase 3 publishes before it replies now.
//
// The head may now be momentarily *ahead* of what a caller has been told, which
// is the safe direction: those records are durable, and a record that is durable
// but unacknowledged is the case a tenure records by name
// (AcknowledgedSeq, and the adopted span). A follower still never claims
// anything the primary has not synced.
func FromAppender(dir string, app *evidence.Appender) *LocalSource {
	return NewLocalSource(dir, func() Head {
		s := app.Stats()
		return Head{Seq: s.LastSeq, Chain: s.LastChain}
	})
}

// Head reports what the primary has acknowledged.
func (s *LocalSource) Head(context.Context) (Head, error) { return s.head(), nil }

// Segments lists the primary's segment ids.
//
// ScanDir, not ScanComplete: a follower wants every file the writer has,
// including one created ahead of a rotation and not yet written to. Filtering
// it out here would be the source deciding what the follower may see, and the
// follower's own framing already ignores a file with nothing in it.
func (s *LocalSource) Segments(context.Context) ([]uint64, error) {
	ids, err := segment.ScanDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return ids, err
}

// Read returns up to max bytes of one segment from off, with the segment's
// current length.
//
// Reading a file the writer is appending to is safe and is the point: bytes
// below the length reported here do not move, because the writer only ever
// appends and only ever truncates *below* what it has acknowledged. A follower
// that reads a partial record gets a partial record, which its framing stops at.
func (s *LocalSource) Read(_ context.Context, id uint64, off int64, max int) (Chunk, error) {
	path := segment.Path(s.dir, id)
	fh, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Chunk{}, nil
	}
	if err != nil {
		return Chunk{}, err
	}
	defer func() { _ = fh.Close() }()

	info, err := fh.Stat()
	if err != nil {
		return Chunk{}, err
	}
	length := info.Size()
	if off >= length {
		return Chunk{Length: length}, nil
	}
	n := length - off
	if int64(max) < n {
		n = int64(max)
	}
	buf := make([]byte, n)
	read, err := fh.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return Chunk{}, err
	}
	return Chunk{Bytes: buf[:read], Length: length}, nil
}
