// Package segment implements the Janus evidence segment file format: an
// append-only, length-framed sequence of hash-chained records terminated by a
// signed footer carrying the segment's Merkle root.
//
// This package is deliberately ignorant of what an event *means*. It stores
// opaque records — an already-canonicalized header blob, the previous and
// current chain hashes, and an optional inline payload — so that the evidence
// envelope (pkg/evidence) and the offline verifier can layer on top of one
// format without an import cycle.
//
// Signing is per segment rather than per event: the footer signs the Merkle
// root, and any single event's authenticity is then provable by an inclusion
// proof against that root. This keeps Ed25519 off the per-event critical path
// while still making every event individually provable.
package segment

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// File layout constants.
const (
	// Magic identifies a Janus segment file.
	Magic = "JANUSSEG"
	// EndMagic trails a sealed segment's footer. Its absence means the segment
	// is still open (or the writer died before sealing).
	EndMagic = "JANUSEND"

	// Version is the format version written by this package.
	Version uint16 = 1

	// HeaderSize is the fixed size of the segment file header.
	HeaderSize = 32

	// HashSize is the length of every hash stored in a segment.
	HashSize = 32

	// MaxRecordLen bounds a single framed record. A length field larger than
	// this is treated as corruption rather than an allocation request.
	//
	// It bounds the WRITE side as well, and that is not symmetry for its own
	// sake. It was read-only until a gosec G115 finding pointed at the `uint32`
	// conversions below and the check that followed found `AppendRecord` would
	// encode any size it was given: a 64 MiB payload produced a segment whose
	// very first record its own reader called `implausible record length`, and
	// a log written faithfully by this code reported as corrupt is
	// indistinguishable from one somebody tampered with. See EncodedLen.
	MaxRecordLen = 64 << 20
)

// Algorithm identifiers. Regulated deployments need a FIPS build (SHA-256 /
// ECDSA-P256), so the algorithms are named in the file
// rather than assumed by the reader.
const (
	HashAlgBLAKE3 uint8 = 1
	SigAlgEd25519 uint8 = 1
)

// Record types.
const (
	recTypeEvent  uint8 = 1
	recTypeFooter uint8 = 2
)

// sigContext domain-separates the footer signature so a signature over one
// kind of Janus structure can never be replayed as another.
const sigContext = "JANUS/segment-footer/1\x00"

// Errors returned when parsing a segment.
var (
	// ErrBadMagic means the file is not a Janus segment.
	ErrBadMagic = errors.New("segment: bad magic")
	// ErrUnsupportedVersion means the file was written by a newer format.
	ErrUnsupportedVersion = errors.New("segment: unsupported format version")
	// ErrCorrupt means a record could not be parsed and the damage is not a
	// plain truncated tail.
	ErrCorrupt = errors.New("segment: corrupt record")
	// ErrTornTail means the final record is incomplete, which is what a crash
	// mid-append looks like. Recovery truncates to the last intact record.
	ErrTornTail = errors.New("segment: torn tail")
	// ErrNotSealed means a footer was expected but the segment is still open.
	ErrNotSealed = errors.New("segment: not sealed")

	// ErrRecordTooLarge means a record would not fit the frame this format can
	// describe, and is refused at the point of writing rather than discovered
	// at the point of reading. The two limits are the same number on purpose:
	// anything this package will write, it will read back.
	ErrRecordTooLarge = errors.New("segment: record too large")
)

// Record is one stored evidence record. Header holds the canonical encoding of
// the event envelope; the segment layer treats it as opaque bytes.
type Record struct {
	Header  []byte
	Prev    [HashSize]byte
	Chain   [HashSize]byte
	Payload []byte
}

// FileHeader is the fixed-size prelude of a segment file.
type FileHeader struct {
	Version   uint16
	HashAlg   uint8
	SigAlg    uint8
	SegmentID uint64
}

// Footer terminates a sealed segment. Everything in it is covered by Sig,
// including Count — so the signature binds the Merkle root to an exact leaf
// count and a contiguous sequence range.
type Footer struct {
	Count      uint32
	FirstSeq   uint64
	LastSeq    uint64
	FirstPrev  [HashSize]byte
	LastChain  [HashSize]byte
	MerkleRoot [HashSize]byte
	KeyID      string
	Sig        []byte
}

// encodeFileHeader renders the fixed segment header.
func encodeFileHeader(h FileHeader) []byte {
	buf := make([]byte, HeaderSize)
	copy(buf[0:8], Magic)
	binary.LittleEndian.PutUint16(buf[8:10], h.Version)
	buf[10] = h.HashAlg
	buf[11] = h.SigAlg
	binary.LittleEndian.PutUint64(buf[12:20], h.SegmentID)
	// buf[20:32] reserved, must be zero.
	return buf
}

// decodeFileHeader parses the fixed segment header.
func decodeFileHeader(buf []byte) (FileHeader, error) {
	var h FileHeader
	if len(buf) < HeaderSize {
		return h, ErrTornTail
	}
	if string(buf[0:8]) != Magic {
		return h, ErrBadMagic
	}
	h.Version = binary.LittleEndian.Uint16(buf[8:10])
	if h.Version != Version {
		return h, fmt.Errorf("%w: %d", ErrUnsupportedVersion, h.Version)
	}
	h.HashAlg = buf[10]
	h.SigAlg = buf[11]
	h.SegmentID = binary.LittleEndian.Uint64(buf[12:20])
	// Reserved bytes must be zero. Without this check they would be the one
	// region of the file no hash or signature covers, which would leave a place
	// to hide data and would falsify invariant I2 ("any single-byte mutation of
	// any segment is detected").
	for i, b := range buf[20:HeaderSize] {
		if b != 0 {
			return h, fmt.Errorf("%w: reserved header byte %d is 0x%02x, want 0", ErrCorrupt, 20+i, b)
		}
	}
	return h, nil
}

// EncodedLen is the number of bytes encodeEventRecord would produce for r,
// including the u32 length prefix.
//
// Exported so a caller can refuse an oversized record *before* handing it to
// the writer. That matters because a failed AppendRecord is a write-path
// failure and sticky (ErrWritePathFailed): one caller with an outsized payload
// would otherwise stop the whole log rather than get an error back.
func EncodedLen(r Record) int {
	return 4 + eventBodyLen(r)
}

func eventBodyLen(r Record) int {
	return 1 + 4 + len(r.Header) + HashSize + HashSize + 4 + len(r.Payload)
}

// encodeEventRecord renders a framed event record: a u32 length followed by the
// body. The length prefix is what makes a torn tail detectable.
//
// The caller has already established that bodyLen fits; see AppendRecord. The
// uint32 conversions below are safe only because of that, and were not before
// it existed — above 4 GiB the length prefix wraps and stops being implausible,
// which turns a refusal into a reader resynchronising onto payload bytes.
func encodeEventRecord(r Record) []byte {
	bodyLen := eventBodyLen(r)
	buf := make([]byte, 4+bodyLen)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(bodyLen))
	b := buf[4:]
	b[0] = recTypeEvent
	n := 1
	binary.LittleEndian.PutUint32(b[n:n+4], uint32(len(r.Header)))
	n += 4
	n += copy(b[n:], r.Header)
	n += copy(b[n:], r.Prev[:])
	n += copy(b[n:], r.Chain[:])
	binary.LittleEndian.PutUint32(b[n:n+4], uint32(len(r.Payload)))
	n += 4
	copy(b[n:], r.Payload)
	return buf
}

// decodeEventRecord parses an event record body (the bytes after the length
// prefix and the type byte).
func decodeEventRecord(b []byte) (Record, error) {
	var r Record
	n := 0
	need := func(k int) bool { return len(b)-n >= k }

	if !need(4) {
		return r, ErrCorrupt
	}
	hdrLen := int(binary.LittleEndian.Uint32(b[n : n+4]))
	n += 4
	if hdrLen < 0 || hdrLen > MaxRecordLen || !need(hdrLen) {
		return r, ErrCorrupt
	}
	r.Header = append([]byte(nil), b[n:n+hdrLen]...)
	n += hdrLen

	if !need(2 * HashSize) {
		return r, ErrCorrupt
	}
	copy(r.Prev[:], b[n:n+HashSize])
	n += HashSize
	copy(r.Chain[:], b[n:n+HashSize])
	n += HashSize

	if !need(4) {
		return r, ErrCorrupt
	}
	payLen := int(binary.LittleEndian.Uint32(b[n : n+4]))
	n += 4
	if payLen < 0 || payLen > MaxRecordLen || !need(payLen) {
		return r, ErrCorrupt
	}
	if payLen > 0 {
		r.Payload = append([]byte(nil), b[n:n+payLen]...)
		n += payLen
	}
	if n != len(b) {
		return r, fmt.Errorf("%w: %d trailing bytes in event record", ErrCorrupt, len(b)-n)
	}
	return r, nil
}

// encodeFooterRecord renders the framed, sealed footer plus the trailing magic.
func encodeFooterRecord(f Footer) []byte {
	bodyLen := 1 + 4 + 8 + 8 + 3*HashSize + 2 + len(f.KeyID) + 2 + len(f.Sig)
	buf := make([]byte, 4+bodyLen+len(EndMagic))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(bodyLen))
	b := buf[4:]
	b[0] = recTypeFooter
	n := 1
	binary.LittleEndian.PutUint32(b[n:n+4], f.Count)
	n += 4
	binary.LittleEndian.PutUint64(b[n:n+8], f.FirstSeq)
	n += 8
	binary.LittleEndian.PutUint64(b[n:n+8], f.LastSeq)
	n += 8
	n += copy(b[n:], f.FirstPrev[:])
	n += copy(b[n:], f.LastChain[:])
	n += copy(b[n:], f.MerkleRoot[:])
	binary.LittleEndian.PutUint16(b[n:n+2], uint16(len(f.KeyID)))
	n += 2
	n += copy(b[n:], f.KeyID)
	binary.LittleEndian.PutUint16(b[n:n+2], uint16(len(f.Sig)))
	n += 2
	n += copy(b[n:], f.Sig)
	copy(b[n:], EndMagic)
	return buf
}

// decodeFooterRecord parses a footer record body.
func decodeFooterRecord(b []byte) (Footer, error) {
	var f Footer
	n := 0
	need := func(k int) bool { return len(b)-n >= k }

	if !need(4 + 8 + 8 + 3*HashSize + 2) {
		return f, ErrCorrupt
	}
	f.Count = binary.LittleEndian.Uint32(b[n : n+4])
	n += 4
	f.FirstSeq = binary.LittleEndian.Uint64(b[n : n+8])
	n += 8
	f.LastSeq = binary.LittleEndian.Uint64(b[n : n+8])
	n += 8
	copy(f.FirstPrev[:], b[n:n+HashSize])
	n += HashSize
	copy(f.LastChain[:], b[n:n+HashSize])
	n += HashSize
	copy(f.MerkleRoot[:], b[n:n+HashSize])
	n += HashSize

	keyIDLen := int(binary.LittleEndian.Uint16(b[n : n+2]))
	n += 2
	if !need(keyIDLen + 2) {
		return f, ErrCorrupt
	}
	f.KeyID = string(b[n : n+keyIDLen])
	n += keyIDLen
	sigLen := int(binary.LittleEndian.Uint16(b[n : n+2]))
	n += 2
	if !need(sigLen) {
		return f, ErrCorrupt
	}
	f.Sig = append([]byte(nil), b[n:n+sigLen]...)
	n += sigLen
	if n != len(b) {
		return f, fmt.Errorf("%w: %d trailing bytes in footer", ErrCorrupt, len(b)-n)
	}
	return f, nil
}

// SigPreimage returns the exact bytes a segment footer signature covers.
// Both the writer and any independent verifier must derive it identically, so
// it is defined once here.
//
// The whole file header is included rather than a selection of its fields, so
// that adding a field to the header cannot silently fall outside the signature.
func SigPreimage(h FileHeader, f Footer) []byte {
	buf := make([]byte, 0, len(sigContext)+HeaderSize+4+8+8+3*HashSize)
	buf = append(buf, sigContext...)
	buf = append(buf, encodeFileHeader(h)...)
	buf = binary.LittleEndian.AppendUint32(buf, f.Count)
	buf = binary.LittleEndian.AppendUint64(buf, f.FirstSeq)
	buf = binary.LittleEndian.AppendUint64(buf, f.LastSeq)
	buf = append(buf, f.FirstPrev[:]...)
	buf = append(buf, f.LastChain[:]...)
	buf = append(buf, f.MerkleRoot[:]...)
	return buf
}

// FileName returns the canonical file name for a segment id. Zero-padded hex
// keeps lexical order equal to numeric order, so a directory listing is a
// valid replay order.
func FileName(segmentID uint64) string {
	return fmt.Sprintf("%016x.jseg", segmentID)
}
