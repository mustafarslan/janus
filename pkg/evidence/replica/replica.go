// Package replica mirrors an evidence directory from the process that owns it.
//
// Phase 6 asks for multi-region evidence replication, async and
// integrity-checked. This is the following half: a reader
// that copies a primary's segment files and states how far it has verified.
// Promotion — a follower becoming a writer — is 6i and deliberately not here.
//
// # Three rules, and they are the design
//
// **Mirror bytes, never re-append.** A sealed segment's footer signs the bytes
// as they were written, and `projection.logIdentity` is the first record's chain
// hash. A follower that re-appended through an Appender would produce a log that
// is internally consistent and *different* — different rotation points, invalid
// footers, a projection that refuses to bind to it. Byte identity is what makes
// a promoted replica's history the same history rather than a faithful retelling
// of it.
//
// **Acknowledge no further than the primary says it has.** A record can be
// complete and correctly chained on disk and still be lost: the writer's buffer
// flushes on byte boundaries, so a crash can leave a whole record that was never
// covered by a durability barrier, and recovery truncates to what the chain
// establishes — which may sit below a record this follower has already seen
// whole. So the follower's acknowledged head is the *lower* of its own verified
// prefix and the head the primary states. This is the rule "a live read names
// the head it requires", moved onto the wire.
//
// One nuance about what "the primary says it has" means after a *restart*, worth
// stating because the answer changed: a recovered appender's head includes
// records that no barrier ever covered, because recovery keeps every complete
// record. Reporting them is nonetheless right — the primary has
// adopted them and is building on them, so they are what it will continue from
// and cannot now be lost without losing the log. The rule is about records the
// primary *might still discard*, and after recovery it will not.
//
// **Resume past records, never past filenames.** The cursor is a segment id and
// a byte offset. Resuming at "the highest segment id I have seen" is the bug
// Phase 6a's projector shipped with, and it is worse here: the writer creates
// the next segment file *before* it rotates into it, so a follower
// that treated the newest filename as progress would skip the segment still
// being written.
//
// # What "integrity-checked" means here
//
// Four layers, and any one of them alone is hollow:
//
//   - every chunk, as it arrives: sequence contiguous, each record's recorded
//     predecessor equal to the running chain, payload matching its hash;
//   - every segment, when it gains a footer: signature and Merkle root, which
//     `pkg/evidence/verify` already does;
//   - continuously thereafter: `pkg/evidence/continuous` runs unchanged against
//     a replica directory, because a replica directory is just a log;
//   - at promotion or restore: the whole directory against an expected head.
//
// Verifying only at seal time is the trap. It leaves a window a whole segment
// long in which the replica reports a head derived from bytes nothing has
// checked.
//
// # Keys are not replicated, and that is what makes this shred-safe
//
// The follower copies the segment directory and nothing else. The keyring lives
// outside it, so a replica holds ciphertext for every subject-bearing event and
// no key to read it: destroying a data subject's key on the primary
// leaves the replica's copy exactly as unreadable. A follower that also copied
// keys would turn replication into a way for erased data to survive erasure.
package replica

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// Head is what a primary says it has durably acknowledged.
//
// Both halves matter. The sequence bounds what a follower may acknowledge; the
// chain hash is what makes the claim checkable, so a primary that lied about its
// head would have to produce a chain the follower cannot reconstruct.
type Head struct {
	Seq   uint64
	Chain evidence.Hash
}

// Chunk is a slice of one segment, as the primary currently has it.
type Chunk struct {
	// Bytes are the segment's contents starting at the requested offset.
	Bytes []byte
	// Length is the primary's current size of this whole segment. It is here so
	// a follower can notice its own copy is *longer* — which means the primary
	// crashed and truncated a torn tail that the follower had already copied.
	Length int64
}

// Source is a primary, seen from a follower.
//
// An interface rather than a gRPC client so that the rules above can be tested
// against a live appender with no wire in the way. The transport is 6g's second
// half; the rules are what has to be right first.
type Source interface {
	// Head reports what the primary has durably acknowledged.
	Head(ctx context.Context) (Head, error)
	// Segments lists the primary's segment ids, ascending.
	Segments(ctx context.Context) ([]uint64, error)
	// Read returns up to max bytes of one segment from off.
	Read(ctx context.Context, id uint64, off int64, max int) (Chunk, error)
}

// ErrDiverged means the primary's bytes do not continue the chain this follower
// already holds.
//
// It is fatal to the follower rather than something to retry. Every other error
// here is a reason to try again later; this one says the two logs are not the
// same log, and continuing to copy would be assembling a directory that verifies
// as neither.
var ErrDiverged = errors.New("replica: the primary's log diverges from this copy")

// ErrUntrustedWriter means the primary's bytes continue this follower's chain
// perfectly well and are sealed by a key this follower cannot reach from its
// roots.
//
// It is a separate sentinel from ErrDiverged because it is a separate finding.
// Divergence is about *bytes*: they do not continue the chain this copy holds,
// so two directories are claiming to be one log. This is about *signatures*: the
// bytes are one log — they framed, they chain, their payload hashes check — and
// the footer is signed by a key that no root supplied and no WRITER_KEY
// declaration this follower verified introduced.
//
// What it does **not** say is which of two things happened, because the bytes do
// not carry intent and this follower cannot tell:
//
//   - a promotion whose standby key was never declared while the previous writer
//     was healthy (`janus-keys rotate -standby-keys` before the failover), or a
//     follower started with `-keys` that does not reach the log's own root. This
//     is the common one, and it is a flag somebody forgot.
//   - segments sealed by a key that is not this log's writer at all, which is
//     what a re-signed segment looks like — internally consistent, and not ours.
//
// Reported as divergence, the first one sent an operator hunting a fork that was
// not there while the actual cause sat on the second line. Reported as
// this, both are named and neither is guessed.
//
// Fatal to the follower either way, for the reason that covers both: copying
// segments it cannot authenticate would build a directory that verifies for
// nobody.
var ErrUntrustedWriter = errors.New("replica: the primary's log is sealed by a key this copy cannot reach from its roots")

// Options configures a Follower.
type Options struct {
	// Dir is the directory to mirror into. Created if absent, and it must not
	// be a directory an Appender owns: one process writes an evidence
	// directory, and a follower is that process for its own copy.
	Dir string
	// Source is the primary.
	Source Source
	// ChunkBytes bounds one read. Zero takes a default.
	ChunkBytes int
	// Keys are the writer public keys this follower trusts as roots, so that a
	// segment can be checked against its signature the moment it is sealed.
	//
	// Public keys, and the distinction from the keyring matters: these
	// authenticate, they do not decrypt. Copying them to a replica is not a
	// shred risk, because nothing here can read a payload sealed under a data
	// subject's key. Empty means signatures are not checked, which is a
	// supported configuration and a weaker one — the follower says so in
	// Status rather than pretending otherwise.
	Keys keys.PublicKeySet
	// VerifierVersion is stamped on the reports this follower produces.
	VerifierVersion string
}

// Follower mirrors a primary's evidence directory.
type Follower struct {
	dir   string
	src   Source
	chunk int

	// Cursor: where the next read starts. A segment id and a byte offset,
	// never a filename — see the package comment.
	seg uint64
	off int64

	// The acknowledged prefix: framed by this copy *and* acknowledged by the
	// primary. This is the only figure a promotion may rest on.
	seq   uint64
	chain evidence.Hash

	// Framing cursor and state. Separate from the copy cursor above because
	// bytes arrive before they are framed, and framing is incremental: a
	// follower is called on a ticker over a log that only grows, so re-framing
	// the directory each pass would make following cost history rather than
	// news.
	framedSeg   uint64
	framedOff   int64
	framedSeq   uint64
	framedChain evidence.Hash
	// pending holds records framed but not yet acknowledged by the primary.
	// Holding them is the normal state of a follower reading a live log.
	pending  []point
	reported point

	// framed counts records this follower has decoded and chained, ever. It is
	// the witness for the incremental claim: a pass that brings no new records
	// must decode none, and without a number nothing would notice a return to
	// re-framing the directory every tick.
	framed uint64

	// truncated records that the primary shortened a segment during this pass,
	// which invalidates framing and forces the rare full re-frame.
	truncated bool

	// Signature checking, layer two. verifiedThrough is the highest segment id
	// whose footer has been checked; anchor is the chain position at its end,
	// which is what lets the next range be verified without re-reading the log.
	trust           keys.PublicKeySet
	verifierVersion string
	verifiedThrough uint64
	anchor          verify.Anchor
	// accepted is the trust set the last verified range ended with: the roots
	// plus whatever the log introduced. Empty until a range
	// has verified, and it *replaces* `trust` rather than joining it, because a
	// revocation is only honoured if the narrower set is the one carried on.
	//
	// Without this a follower running across a failover raises ErrDiverged —
	// "the primary's log diverges from this copy" — on the first segment the
	// promoted writer sealed, because the WRITER_KEY declaration introducing
	// that writer is in a segment this follower verified in an earlier range.
	// It is not a divergence, it is a key rotation, and it reads to an operator
	// as split-brain.
	accepted keys.PublicKeySet
	// boundaries is the chain position at the end of each segment, captured
	// while framing so that a range verification has an anchor to start from.
	boundaries map[uint64]verify.Anchor
	// scan lists this mirror's complete segments without re-stat-ing every file
	// on every poll. A follower is the worst case for that: it polls three
	// times a second forever, and at 10,000 segments the stats are 17 of the
	// 21.5 ms a listing costs.
	scan *segment.Scanner
}

const defaultChunkBytes = 1 << 20

// ErrPromoted means the directory is a writer's and must not be followed.
var ErrPromoted = errors.New("replica: this directory belongs to a writer")

// New opens a follower over a directory.
func New(opts Options) (*Follower, error) {
	if opts.Dir == "" {
		return nil, errors.New("replica: a directory is required")
	}
	if opts.Source == nil {
		return nil, errors.New("replica: a source is required; a follower with no " +
			"primary would report a head it invented")
	}
	if err := os.MkdirAll(opts.Dir, 0o750); err != nil {
		return nil, err
	}
	// Refused before a single byte is written. This process copies with WriteAt
	// at offsets the *primary* names, so aiming it at a directory some appender
	// owns would overwrite that writer's history on disk — before any
	// divergence check could look, because the check reads what is on disk
	// after the write. There is no in-memory state that survives a restart to
	// prevent it, so the answer has to be on disk.
	//
	// The question is "is this directory a writer's", and it is asked of the
	// writer marker rather than of the log. It used to be asked of the log — a
	// tenure meant promoted — and that was wrong in a way nothing caught until
	// the second failover was tried: a tenure is *replicated*, so after one
	// promotion every replica of the log carried one, and every replica was
	// refused. `janus-replicad` could not be restarted on a log that had ever
	// failed over; the message told the operator to re-seed, which at 100M
	// events is a 30 GB copy, for a directory that had never been
	// promoted at all. See pkg/evidence/writermark.go.
	owned, err := evidence.HasWriterMark(opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("replica: checking %s for a writer: %w", opts.Dir, err)
	}
	if owned {
		return nil, fmt.Errorf("%w: %s. An appender has owned this directory; following a "+
			"primary into it would overwrite the history that writer wrote. Re-seed into an "+
			"empty directory if this node is meant to follow again", ErrPromoted, opts.Dir)
	}

	chunk := opts.ChunkBytes
	if chunk <= 0 {
		chunk = defaultChunkBytes
	}
	return &Follower{
		dir: opts.Dir, src: opts.Source, chunk: chunk,
		trust: opts.Keys, verifierVersion: opts.VerifierVersion,
		boundaries: map[uint64]verify.Anchor{},
		scan:       segment.NewScanner(opts.Dir),
	}, nil
}

// Status is how far this follower has got.
type Status struct {
	// Seq and Chain are what this replica has verified *and* the primary has
	// acknowledged — the lower of the two, which is the only figure a promotion
	// may rest on.
	Seq   uint64
	Chain evidence.Hash
	// Segment and Offset are the cursor, for an operator watching progress.
	Segment uint64
	Offset  int64
	// SignaturesCheckedThrough is the highest segment whose footer this
	// follower has verified. It is deliberately separate from Seq: a replica
	// can be byte-current and signature-unchecked, and reporting one number
	// would hide which.
	//
	// **It is a statement about what this follower copied, not about what is on
	// disk now.** A poll asks only about segments at or above its cursor,
	// so a sealed segment corrupted underneath it afterwards — a bad
	// disk, a careless operator, anything that is not the primary — is not
	// noticed here and does not lower this number. Nothing about a follower ever
	// re-read its own history; what changed is that the omission is now
	// deliberate and written down. **Whoever runs the replica host should run
	// `janus-tier watch` over the mirror**, which is the thing that re-reads
	// history on a schedule and alerts.
	SignaturesCheckedThrough uint64
	// SignaturesChecked is false when no trust root was configured, so that
	// "nothing has failed" is never mistaken for "everything has been checked".
	SignaturesChecked bool
	// RecordsFramed is how many records this follower has decoded and chained
	// since it started. Following costs news, not history, and this is the
	// number that says so.
	RecordsFramed uint64
}

// Status reports the verified, acknowledged prefix.
func (f *Follower) Status() Status {
	return Status{
		Seq: f.seq, Chain: f.chain, Segment: f.seg, Offset: f.off,
		SignaturesCheckedThrough: f.verifiedThrough,
		SignaturesChecked:        len(f.trust) > 0,
		RecordsFramed:            f.framed,
	}
}

// Follow makes one pass: fetch whatever the primary has that this copy does not,
// verify it, and advance.
//
// One pass rather than a loop, so the caller owns the cadence and the tests own
// the clock. A daemon calls this on a ticker; a test calls it once and asserts.
//
// **Not safe for concurrent calls.** All the cursor and framing state is plain
// fields, and the copy path assumes it is the only writer of this directory. The
// daemon that drives this serializes passes; a transport that fanned them out
// would interleave two cursors over one set of files.
func (f *Follower) Follow(ctx context.Context) error {
	f.truncated = false

	head, err := f.src.Head(ctx)
	if err != nil {
		return fmt.Errorf("replica: reading the primary's head: %w", err)
	}
	ids, err := f.src.Segments(ctx)
	if err != nil {
		return fmt.Errorf("replica: listing the primary's segments: %w", err)
	}

	for _, id := range ids {
		if id < f.seg {
			continue
		}
		if err := f.followSegment(ctx, id); err != nil {
			return err
		}
	}
	if err := f.setResumePoint(); err != nil {
		return err
	}
	if f.truncated {
		f.resetFraming()
	}
	if err := f.frame(); err != nil {
		return err
	}
	if err := f.report(head); err != nil {
		return err
	}
	return f.verifySeals()
}

// followSegment copies whatever the primary has of one segment that this copy
// does not, and moves the cursor onto it.
func (f *Follower) followSegment(ctx context.Context, id uint64) error {
	path := segment.Path(f.dir, id)
	off := int64(0)
	if id == f.seg {
		off = f.off
	}

	for {
		chunk, err := f.src.Read(ctx, id, off, f.chunk)
		if err != nil {
			return fmt.Errorf("replica: reading segment %d at %d: %w", id, off, err)
		}
		// The primary's copy is shorter than ours: it crashed and recovery
		// truncated a torn tail we had already copied. Cut back to what the
		// primary now has and refetch. Safe because our acknowledged prefix is
		// never above the primary's head, so nothing we told anyone about can
		// be in the part being discarded.
		if err := f.truncateIfLonger(path, chunk.Length); err != nil {
			return err
		}
		if len(chunk.Bytes) == 0 {
			break
		}
		if err := appendBytes(path, off, chunk.Bytes); err != nil {
			return err
		}
		off += int64(len(chunk.Bytes))
		if off >= chunk.Length {
			break
		}
	}

	return nil
}

// setResumePoint moves the cursor to the earliest segment that could still
// grow.
//
// **Only a sealed segment may be passed.** This is rule three, and getting it
// wrong is the bug this cost a test to find: the writer creates the next segment
// file *before* it rotates into it, so a follower that advanced to
// "the highest id I have seen" lands on an empty pre-created file and then skips
// every record the writer appends to the *previous* segment before the rotation
// actually happens. The first pass looks perfect and the second silently loses a
// segment's worth of history.
//
// A footer is the only thing that says a segment is finished, which is why it is
// the condition here rather than "the file stopped growing" — a quiet writer and
// a rotated-away segment are indistinguishable by size alone.
func (f *Follower) setResumePoint() error {
	ids, err := segment.ScanDir(f.dir)
	if err != nil || len(ids) == 0 {
		return err
	}
	for _, id := range ids {
		// Everything below the last resume point is sealed and stays sealed:
		// this follower only ever copies into segments at or above `f.seg`, so
		// nothing below it can be truncated back open behind this loop. Without
		// the skip, an idle poll opens, stats and reads the footer of every
		// segment in the mirror — four syscalls each, on a loop that runs three
		// times a second.
		if id < f.seg {
			continue
		}
		sealed, err := segment.IsSealed(segment.Path(f.dir, id))
		if err != nil {
			// A file too short to classify is one the writer has just created
			// and not yet written a header into. It cannot be passed either.
			sealed = false
		}
		if !sealed {
			info, err := os.Stat(segment.Path(f.dir, id))
			if err != nil {
				return err
			}
			f.seg, f.off = id, info.Size()
			return nil
		}
	}
	// Every segment is sealed: resume at the end of the last one. It cannot
	// grow, and a higher id appearing on the primary is picked up by the scan.
	last := ids[len(ids)-1]
	info, err := os.Stat(segment.Path(f.dir, last))
	if err != nil {
		return err
	}
	f.seg, f.off = last, info.Size()
	return nil
}

// truncateIfLonger cuts a local segment back to the primary's length.
func (f *Follower) truncateIfLonger(path string, length int64) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Size() <= length {
		return nil
	}
	if err := os.Truncate(path, length); err != nil {
		return fmt.Errorf("replica: truncating %s to the primary's %d bytes: %w",
			filepath.Base(path), length, err)
	}
	// The cursor may now point past the end of the file, and anything framed
	// from the discarded bytes has to be unwound — which the next pass does by
	// re-framing from the start.
	if f.off > length {
		f.off = length
	}
	f.truncated = true
	return nil
}

// appendBytes writes at a known offset, refusing a gap.
//
// Writing at an offset rather than appending blindly is what makes a lost reply
// or a retried chunk safe: the same bytes land in the same place, and a chunk
// that would leave a hole is refused rather than silently creating one that the
// framing would later report as corruption.
func appendBytes(path string, off int64, b []byte) error {
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer func() { _ = fh.Close() }()

	info, err := fh.Stat()
	if err != nil {
		return err
	}
	if info.Size() < off {
		return fmt.Errorf("replica: %s is %d bytes and the next chunk starts at %d; "+
			"writing it would leave a hole", filepath.Base(path), info.Size(), off)
	}
	if _, err := fh.WriteAt(b, off); err != nil {
		return err
	}
	// Durable before it counts. A follower that acknowledged bytes still in the
	// page cache would be making the promise the primary's group commit exists
	// to keep, without the barrier behind it.
	return fh.Sync()
}

// point is one record's position in the chain.
type point struct {
	seq   uint64
	chain evidence.Hash
}

// frame reads the records this follower has not framed yet, checks each one
// against the running chain, and queues it.
//
// **Incremental, and that is not an optimisation.** The first version of this
// reset its state and re-framed every segment on every pass — which is exactly
// the defect an earlier change removed from `Projector.read`, brought back in a
// new package. A follower is called on a ticker over a log that only grows;
// re-framing it each time makes the cost of following proportional to the
// history rather than to the news.
//
// The cursor is a segment id and a byte offset, for the same reason the copy
// cursor is: the writer creates the next segment before rotating into it, so a
// filename is not progress.
func (f *Follower) frame() error {
	ids, err := segment.ScanDir(f.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, id := range ids {
		if id < f.framedSeg {
			continue
		}
		insp, err := segment.Inspect(segment.Path(f.dir, id))
		if err != nil {
			return fmt.Errorf("replica: inspecting %s: %w", segment.FileName(id), err)
		}
		var floor int64
		if id == f.framedSeg {
			floor = f.framedOff
		}
		for i, rec := range insp.Records {
			// Skipped by offset *before* decoding. Deciding to skip after
			// decoding is the shape that made the fold re-read 90% of what it
			// read (docs/bench/README.md).
			if insp.Offsets[i] < floor {
				continue
			}
			if err := f.absorbRecord(rec); err != nil {
				return err
			}
			f.framedSeg, f.framedOff = id, insp.Offsets[i]+1
		}
		// A sealed segment will not grow, so framing may move past it. An open
		// one must be revisited from where its records ran out.
		if insp.Sealed() {
			f.framedSeg, f.framedOff = id+1, 0
		}
		f.boundaries[id] = verify.Anchor{Chain: f.framedChain, Seq: f.framedSeq, Known: f.framedSeq > 0}
	}
	return nil
}

// absorbRecord checks one record against the running chain and queues it as
// framed-but-not-yet-acknowledged.
//
// It stops at the first record that does not continue the chain and reports
// divergence rather than skipping. A follower that skipped would build a
// directory whose sequence numbers jump — which the verifier would call damage,
// correctly, long after the cause had gone.
func (f *Follower) absorbRecord(rec segment.Record) error {
	h, err := evidence.DecodeHeader(rec.Header)
	if err != nil {
		return fmt.Errorf("replica: decoding a record header: %w", err)
	}
	if f.framedSeq != 0 && h.Seq != f.framedSeq+1 {
		return fmt.Errorf("%w: expected sequence %d, found %d", ErrDiverged, f.framedSeq+1, h.Seq)
	}
	if f.framedSeq != 0 && rec.Prev != f.framedChain {
		return fmt.Errorf("%w: record %d records a predecessor this copy does not have",
			ErrDiverged, h.Seq)
	}
	if len(rec.Payload) > 0 {
		if got := evidence.HashPayload(rec.Payload); got != h.PayloadHash {
			return fmt.Errorf("%w: record %d's payload does not match its hash", ErrDiverged, h.Seq)
		}
	}
	if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
		return fmt.Errorf("%w: record %d's chain hash does not check out", ErrDiverged, h.Seq)
	}
	f.framedSeq, f.framedChain = h.Seq, rec.Chain
	f.framed++
	f.pending = append(f.pending, point{seq: h.Seq, chain: rec.Chain})
	return nil
}

// report sets the acknowledged prefix to the lower of what this copy has framed
// and what the primary says it has.
//
// The bound is the whole point and it is not a safety margin: a record can be
// whole and correctly chained on disk and still be one a crash will erase,
// because the writer's buffer flushes on byte boundaries rather than record
// boundaries. Acknowledging it would promise something the primary has not.
//
// Framed records above the primary's head stay queued rather than being
// discarded or rescanned — holding them is the normal state of a follower
// reading a live log, and they become reportable the moment the primary's head
// catches up to them.
func (f *Follower) report(head Head) error {
	if head.Seq > 0 && head.Chain == (evidence.Hash{}) {
		// Fail closed on an unchained head. A source that can state a sequence
		// can state the chain at it — LocalSource always does — so a head
		// arriving without one means a transport dropped the field, and the
		// divergence check below would silently degrade to comparing sequence
		// numbers. That is the naive-RPC mistake, and it must not be
		// survivable.
		return fmt.Errorf("replica: the primary stated sequence %d with no chain hash; "+
			"a head without a chain cannot be checked for divergence", head.Seq)
	}
	for len(f.pending) > 0 && f.pending[0].seq <= head.Seq {
		f.reported = f.pending[0]
		f.pending = f.pending[1:]
	}
	if f.reported.seq == head.Seq && head.Seq > 0 && f.reported.chain != head.Chain {
		return fmt.Errorf("%w: at sequence %d the primary's chain differs from this copy's",
			ErrDiverged, head.Seq)
	}
	f.seq, f.chain = f.reported.seq, f.reported.chain
	return nil
}

// resetFraming discards framing state so the next pass rebuilds it.
//
// Called when the primary truncates, which invalidates bytes this follower may
// already have framed. It is a full re-frame and it is deliberately the *rare*
// path: a truncation is a crash-recovery event on the primary, not something
// that happens on a ticker, so paying O(log) for it keeps the common path O(new)
// without needing to unwind framing record by record.
func (f *Follower) resetFraming() {
	f.framedSeg, f.framedOff = 0, 0
	f.framedSeq, f.framedChain = 0, evidence.Hash{}
	f.pending = nil
	f.reported = point{}
	f.seq, f.chain = 0, evidence.Hash{}
	f.boundaries = map[uint64]verify.Anchor{}
	f.verifiedThrough = 0
	f.anchor = verify.Anchor{}
	// Framing restarts from the beginning of the log, so trust does too: the
	// declarations that extended it will be read again.
	f.accepted = nil
	// And the listing is asked again from scratch, because a re-frame follows a
	// truncation and this is the one moment a file here may have got shorter.
	if f.scan != nil {
		f.scan.Forget()
	}
}

// verifySeals is integrity layer two: a segment's signature and Merkle root,
// checked the moment it gains a footer.
//
// It is a *range* rather than a whole-directory sweep, anchored at the chain
// position this follower had already established, because the alternative is
// re-reading the entire log every time a 16 MiB segment fills. That is the same
// call `pkg/evidence/continuous` makes for the same reason, and its weakness is
// the same one: it says the new segments are sound and continue from the anchor,
// and says nothing about whether the older ones still hold the bytes they held.
// Layer three — a periodic full sweep — is what covers that, and a replica
// directory is an ordinary log, so `continuous` runs against it unchanged.
//
// With no trust root configured this does nothing and `Status` says so. A
// follower that silently skipped signature checking while reporting a verified
// head would be the hollow-control failure in its purest form.
func (f *Follower) verifySeals() error {
	if len(f.trust) == 0 {
		return nil
	}
	ids, err := f.scan.Complete()
	if err != nil {
		return err
	}
	// The highest sealed segment. Everything below it that is not yet verified
	// forms one range; the open segment at the tail has no footer and is not
	// this layer's business.
	var through uint64
	var found bool
	for _, id := range ids {
		// Same skip, same reason: this loop wants the highest sealed segment at
		// or above what it has already verified, and it was asking about every
		// segment below that too — a second footer read per file per poll, on
		// top of the one setResumePoint was doing.
		if id < f.verifiedThrough {
			continue
		}
		sealed, err := segment.IsSealed(segment.Path(f.dir, id))
		if err != nil {
			return err
		}
		if sealed && id >= f.verifiedThrough {
			through, found = id, true
		}
	}
	if !found || (f.verifiedThrough > 0 && through <= f.verifiedThrough) {
		return nil
	}

	from := f.verifiedThrough
	if from > 0 {
		from++
	}
	roots, origin := f.roots()
	rep, err := verify.Range(f.dir, from, through, f.anchorFor(from), verify.Options{
		Keys: roots, KeysOrigin: origin, Version: f.verifierVersion,
		// The same scanner, so one poll lists the directory twice and stats it
		// once rather than twice.
		Scan: func(string) ([]uint64, error) { return f.scan.Complete() },
	})
	if err != nil {
		return fmt.Errorf("replica: verifying sealed segments %d..%d: %w", from, through, err)
	}
	if !rep.OK {
		// Which of the two this is, asked of the findings rather than assumed.
		// By the time a range reaches verification its records have already
		// been framed — sequence continuity, chain hashes and payload hashes,
		// all checked on the way in — so bytes that got this far and then fail
		// only on the sealing key are one log whose writer this copy cannot
		// vouch for, which is a different sentence from "two logs". Anything
		// else critical in the range, and it is the alarm it always was.
		if unreachable, key := onlyUnknownKey(rep); unreachable {
			return fmt.Errorf("%w: sealed segments %d..%d are signed by key %s.\n\n"+
				"The records are intact and continue this copy's chain, so what is wrong is "+
				"the signature and not the bytes. Two things look like this and this copy "+
				"cannot tell them apart:\n"+
				"  - the usual one: the writer's key was never declared in the log while the "+
				"previous writer was healthy (janus-keys rotate -standby-keys, before the "+
				"failover, which is what makes one root enough afterwards), or this follower "+
				"was started with -keys that does not reach the log's own root;\n"+
				"  - the serious one: these segments were sealed by a key that is not this "+
				"log's writer.\n"+
				"Find out which %s is before doing anything else. If it is the writer's, "+
				"add it to this follower's -keys: the log could not introduce it, so it has "+
				"to arrive out of band, and declaring the next standby before the next "+
				"failover is what stops that happening again. If it is not, do not copy "+
				"this directory -- re-seeding takes the same segments and is refused the "+
				"same way",
				ErrUntrustedWriter, from, through, key, key)
		}
		return fmt.Errorf("%w: sealed segments %d..%d do not verify: %s",
			ErrDiverged, from, through, firstCritical(rep))
	}
	f.verifiedThrough = through
	f.anchor = f.boundaries[through]
	// Carried at the same point the cursor advances, and for the same reason: a
	// range that did not verify may hold a declaration this follower has not
	// earned the right to trust.
	if rep.TrustedKeys != nil {
		f.accepted = rep.TrustedKeys
	}
	return nil
}

// roots is what the next range verifies under.
//
// The set the last range ended with, if there was one, and the configured roots
// otherwise. A replacement rather than a union: key revocation is
// forward-only, so a root that revoked itself must not come back because the
// caller still holds it in a config file.
func (f *Follower) roots() (keys.PublicKeySet, string) {
	if len(f.accepted) > 0 {
		return f.accepted, "carried from an earlier pass"
	}
	return f.trust, ""
}

// anchorFor is the chain position immediately before segment id.
//
// An unknown anchor means "this range starts the log", which is true for the
// first segment and a lie for any other — so a missing boundary returns the
// zero Anchor with Known false only when there is genuinely nothing before it.
func (f *Follower) anchorFor(from uint64) verify.Anchor {
	if from == 0 {
		return verify.Anchor{}
	}
	if a, ok := f.boundaries[from-1]; ok {
		return a
	}
	return f.anchor
}

// firstCritical names the finding that mattered, so an error message says what
// is wrong rather than that something is.
// onlyUnknownKey reports whether every critical finding in the report is an
// unreachable signing key, and names one of the keys if so.
//
// Every, not any: a range that is both unreachable *and* broken somewhere else
// is a range this follower has no business softening the language about.
func onlyUnknownKey(rep *verify.Report) (bool, string) {
	var key string
	for _, fnd := range rep.Findings {
		if fnd.Severity != verify.Critical {
			continue
		}
		if fnd.Code != "UNKNOWN_SIGNING_KEY" {
			return false, ""
		}
		if key == "" {
			key = unknownKeyID(fnd.Message)
		}
	}
	return key != "", key
}

// unknownKeyID pulls the key id out of the finding's message, which is where
// the verifier puts it. An unrecognised shape degrades to the whole message
// rather than to nothing: the point is to tell an operator which key, and a
// slightly long line does that where an empty one does not.
func unknownKeyID(msg string) string {
	const prefix = "footer is signed by key "
	rest, ok := strings.CutPrefix(msg, prefix)
	if !ok {
		return msg
	}
	id, _, _ := strings.Cut(rest, ",")
	return id
}

func firstCritical(rep *verify.Report) string {
	for _, fnd := range rep.Findings {
		if fnd.Severity == verify.Critical {
			return fnd.Code + ": " + fnd.Message
		}
	}
	return "no critical finding was recorded, which is itself surprising"
}
