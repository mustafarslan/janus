package segment

import (
	"bufio"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mustafarslan/janus/pkg/evidence/merkle"
)

// SyncMode selects the durability barrier used by Sync.
type SyncMode int

const (
	// SyncModeFull is the default: the strongest barrier the platform offers
	// (F_FULLFSYNC on darwin, fsync on linux). Required for the
	// evidence-before-effect guarantee on real deployments.
	SyncModeFull SyncMode = iota
	// SyncModeData uses fsync/fdatasync without forcing the device cache.
	SyncModeData
	// SyncModeNone skips the barrier entirely. Benchmark and test use only —
	// it voids the durability guarantee and must never be used in a
	// deployment that gates effects on evidence.
	SyncModeNone
)

func (m SyncMode) String() string {
	switch m {
	case SyncModeFull:
		return "full"
	case SyncModeData:
		return "data"
	case SyncModeNone:
		return "none"
	default:
		return fmt.Sprintf("SyncMode(%d)", int(m))
	}
}

// ParseSyncMode maps a flag value onto a SyncMode.
func ParseSyncMode(s string) (SyncMode, error) {
	switch s {
	case "full":
		return SyncModeFull, nil
	case "data":
		return SyncModeData, nil
	case "none":
		return SyncModeNone, nil
	default:
		return SyncModeFull, fmt.Errorf("unknown sync mode %q (want full|data|none)", s)
	}
}

// Signer signs a segment footer. Phase 0 uses an on-disk Ed25519 key; the
// interface is what a KMS or HSM custodian implements later.
type Signer interface {
	KeyID() string
	Sign(message []byte) ([]byte, error)
	Public() ed25519.PublicKey
}

// WriterOptions configures a segment writer.
type WriterOptions struct {
	// SyncMode selects the durability barrier. Defaults to SyncModeFull.
	SyncMode SyncMode
	// BufferBytes sizes the userspace write buffer. Defaults to 1 MiB.
	BufferBytes int
	// Open creates the backing file. Defaults to OpenReal; the fault-injection
	// harness substitutes a file that fails on demand.
	Open OpenFunc
}

// Writer appends records to one segment file. It is not safe for concurrent
// use: the Appender owns a Writer from a single goroutine, which is also what
// keeps the hash chain strictly ordered.
type Writer struct {
	path   string
	file   File
	buf    *bufio.Writer
	header FileHeader
	opts   WriterOptions

	leaves    [][merkle.Size]byte
	firstSeq  uint64
	lastSeq   uint64
	firstPrev [HashSize]byte
	lastChain [HashSize]byte
	bytes     int64
	sealed    bool
}

// Create opens a new segment file. It fails if the file already exists, so a
// segment id is never silently reused.
func Create(dir string, segmentID uint64, opts WriterOptions) (*Writer, error) {
	if opts.BufferBytes <= 0 {
		opts.BufferBytes = 1 << 20
	}
	if opts.Open == nil {
		opts.Open = OpenReal
	}
	path := filepath.Join(dir, FileName(segmentID))
	f, err := opts.Open(path)
	if err != nil {
		return nil, err
	}
	h := FileHeader{Version: Version, HashAlg: HashAlgBLAKE3, SigAlg: SigAlgEd25519, SegmentID: segmentID}
	w := &Writer{
		path:   path,
		file:   f,
		buf:    bufio.NewWriterSize(f, opts.BufferBytes),
		header: h,
		opts:   opts,
	}
	hdr := encodeFileHeader(h)
	if _, err := w.buf.Write(hdr); err != nil {
		_ = f.Close()
		return nil, err
	}
	w.bytes = int64(len(hdr))
	// Make the file's existence durable before any record claims to live in
	// it: a record acked as durable must be findable after a crash.
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := w.Sync(); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := syncDir(dir); err != nil {
		_ = f.Close()
		return nil, err
	}
	return w, nil
}

// ErrSealed is returned when a sealed segment is written to again.
var ErrSealed = errors.New("segment: already sealed")

// AppendRecord buffers one record. It does not make it durable; the caller
// batches records and then calls Flush and Sync once per group commit.
func (w *Writer) AppendRecord(seq uint64, r Record) error {
	if w.sealed {
		return ErrSealed
	}
	// Refuse what this package's own reader would refuse. Without this the
	// writer will happily frame a record longer than MaxRecordLen, and the
	// reader then reports `implausible record length` on the first one -- so a
	// segment written correctly by this code is reported as corrupt, and an
	// operator cannot tell that from tampering. The whole rest of the segment
	// goes with it, because the reader cannot resynchronise past a frame it
	// does not believe.
	if n := EncodedLen(r); n > MaxRecordLen {
		return fmt.Errorf("%w: %d bytes, limit %d. A record this size can be written and "+
			"not read back, so it is refused here rather than becoming a segment that "+
			"fails verification", ErrRecordTooLarge, n, MaxRecordLen)
	}
	enc := encodeEventRecord(r)
	if _, err := w.buf.Write(enc); err != nil {
		return err
	}
	w.bytes += int64(len(enc))
	w.leaves = append(w.leaves, merkle.HashLeaf(r.Chain[:]))
	if len(w.leaves) == 1 {
		w.firstSeq = seq
		w.firstPrev = r.Prev
	}
	w.lastSeq = seq
	w.lastChain = r.Chain
	return nil
}

// Flush pushes buffered bytes into the kernel. Not a durability barrier.
func (w *Writer) Flush() error { return w.buf.Flush() }

// Sync issues the configured durability barrier.
func (w *Writer) Sync() error {
	switch w.opts.SyncMode {
	case SyncModeNone:
		return nil
	case SyncModeData:
		return w.file.SyncData()
	default:
		return w.file.Sync()
	}
}

// Count returns the number of records written to this segment.
func (w *Writer) Count() int { return len(w.leaves) }

// Bytes returns the segment's current size on disk, buffered bytes included.
func (w *Writer) Bytes() int64 { return w.bytes }

// Path returns the segment file path.
func (w *Writer) Path() string { return w.path }

// SegmentID returns this segment's id.
func (w *Writer) SegmentID() uint64 { return w.header.SegmentID }

// MerkleRoot returns the root over the records written so far.
func (w *Writer) MerkleRoot() [merkle.Size]byte { return merkle.Root(w.leaves) }

// Leaves returns the segment's leaf hashes, for building inclusion proofs.
// The returned slice aliases the writer's state and must not be modified.
func (w *Writer) Leaves() [][merkle.Size]byte { return w.leaves }

// Seal writes the signed footer and makes it durable. A sealed segment is
// immutable and independently verifiable.
func (w *Writer) Seal(signer Signer) (Footer, error) {
	if w.sealed {
		return Footer{}, ErrSealed
	}
	f := Footer{
		Count:      uint32(len(w.leaves)),
		FirstSeq:   w.firstSeq,
		LastSeq:    w.lastSeq,
		FirstPrev:  w.firstPrev,
		LastChain:  w.lastChain,
		MerkleRoot: merkle.Root(w.leaves),
		KeyID:      signer.KeyID(),
	}
	sig, err := signer.Sign(SigPreimage(w.header, f))
	if err != nil {
		return Footer{}, fmt.Errorf("sign footer: %w", err)
	}
	f.Sig = sig

	enc := encodeFooterRecord(f)
	if _, err := w.buf.Write(enc); err != nil {
		return Footer{}, err
	}
	w.bytes += int64(len(enc))
	if err := w.Flush(); err != nil {
		return Footer{}, err
	}
	// Seal always takes the strong barrier regardless of SyncMode: an unsigned
	// or half-written footer is the one state that makes a segment unverifiable.
	if err := w.file.Sync(); err != nil {
		return Footer{}, err
	}
	w.sealed = true
	return f, nil
}

// Sealed reports whether the footer has been written.
func (w *Writer) Sealed() bool { return w.sealed }

// Close flushes and closes the underlying file. It does not seal.
func (w *Writer) Close() error {
	if err := w.buf.Flush(); err != nil {
		_ = w.file.Close()
		return err
	}
	return w.file.Close()
}

// syncDir fsyncs a directory so that newly created file names are durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil {
		// Some filesystems reject fsync on directories; the name durability
		// gap is acceptable there and not worth failing the write path over.
		if errors.Is(err, os.ErrInvalid) {
			return nil
		}
		return err
	}
	return nil
}
