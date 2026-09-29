package segment

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Reader streams records out of one segment file.
//
// It distinguishes two kinds of damage, because they call for opposite
// responses. A torn tail — a short or missing final record with no footer — is
// what a crash mid-append looks like; recovery truncates to LastGoodOffset and
// carries on. Anything else is corruption or tampering and must never be
// silently repaired.
type Reader struct {
	f      *os.File
	br     *bufio.Reader
	hdr    FileHeader
	off    int64
	footer *Footer
	done   bool
}

// Open opens a segment file and parses its header.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(f, 1<<20)
	raw := make([]byte, HeaderSize)
	if _, err := io.ReadFull(br, raw); err != nil {
		_ = f.Close()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("%w: file shorter than segment header", ErrTornTail)
		}
		return nil, err
	}
	hdr, err := decodeFileHeader(raw)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Reader{f: f, br: br, hdr: hdr, off: HeaderSize}, nil
}

// FileHeader returns the parsed segment header.
func (r *Reader) FileHeader() FileHeader { return r.hdr }

// LastGoodOffset returns the byte offset just past the last record that parsed
// cleanly. Crash recovery truncates the file here.
func (r *Reader) LastGoodOffset() int64 { return r.off }

// Footer returns the segment footer once the reader has consumed it.
func (r *Reader) Footer() (Footer, bool) {
	if r.footer == nil {
		return Footer{}, false
	}
	return *r.footer, true
}

// Next returns the next event record. It reports ok=false once the records are
// exhausted, whether the segment ended with a footer or simply ran out.
func (r *Reader) Next() (Record, bool, error) {
	if r.done {
		return Record{}, false, nil
	}
	var lenBuf [4]byte
	n, err := io.ReadFull(r.br, lenBuf[:])
	switch {
	case errors.Is(err, io.EOF) && n == 0:
		// Clean end of an unsealed segment.
		r.done = true
		return Record{}, false, nil
	case err != nil:
		r.done = true
		return Record{}, false, fmt.Errorf("%w: %d-byte length prefix at offset %d", ErrTornTail, n, r.off)
	}

	recLen := int(binary.LittleEndian.Uint32(lenBuf[:]))
	if recLen == 0 || recLen > MaxRecordLen {
		r.done = true
		return Record{}, false, fmt.Errorf("%w: implausible record length %d at offset %d", ErrCorrupt, recLen, r.off)
	}

	body := make([]byte, recLen)
	if n, err := io.ReadFull(r.br, body); err != nil {
		r.done = true
		return Record{}, false, fmt.Errorf("%w: record at offset %d wants %d bytes, got %d", ErrTornTail, r.off, recLen, n)
	}

	switch body[0] {
	case recTypeEvent:
		rec, err := decodeEventRecord(body[1:])
		if err != nil {
			r.done = true
			return Record{}, false, fmt.Errorf("record at offset %d: %w", r.off, err)
		}
		r.off += int64(4 + recLen)
		return rec, true, nil

	case recTypeFooter:
		f, err := decodeFooterRecord(body[1:])
		if err != nil {
			r.done = true
			return Record{}, false, fmt.Errorf("footer at offset %d: %w", r.off, err)
		}
		var end [len(EndMagic)]byte
		if _, err := io.ReadFull(r.br, end[:]); err != nil {
			r.done = true
			return Record{}, false, fmt.Errorf("%w: footer at offset %d missing end magic", ErrTornTail, r.off)
		}
		if string(end[:]) != EndMagic {
			r.done = true
			return Record{}, false, fmt.Errorf("%w: bad end magic after footer at offset %d", ErrCorrupt, r.off)
		}
		// Bytes after a sealed footer mean somebody tried to extend an
		// immutable segment.
		if _, err := r.br.ReadByte(); err == nil {
			r.done = true
			return Record{}, false, fmt.Errorf("%w: data appended after sealed footer", ErrCorrupt)
		} else if !errors.Is(err, io.EOF) {
			r.done = true
			return Record{}, false, err
		}
		r.off += int64(4 + recLen + len(EndMagic))
		r.footer = &f
		r.done = true
		return Record{}, false, nil

	default:
		r.done = true
		return Record{}, false, fmt.Errorf("%w: unknown record type %d at offset %d", ErrCorrupt, body[0], r.off)
	}
}

// Close releases the underlying file.
func (r *Reader) Close() error { return r.f.Close() }

// ReadAll loads every record of a segment plus its footer, if sealed. On a torn
// tail it returns the records it did parse alongside the error, so recovery can
// use them.
func ReadAll(path string) ([]Record, *Footer, error) {
	rd, err := Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rd.Close() }()

	var recs []Record
	for {
		rec, ok, err := rd.Next()
		if err != nil {
			return recs, nil, err
		}
		if !ok {
			break
		}
		recs = append(recs, rec)
	}
	f, sealed := rd.Footer()
	if !sealed {
		return recs, nil, nil
	}
	return recs, &f, nil
}

// ext is the segment file extension.
const ext = ".jseg"

// ScanDir returns the segment ids present in dir, ascending. Because ids are
// zero-padded hex, this is also a valid replay order.
func ScanDir(dir string) ([]uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ids []uint64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ext) {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSuffix(e.Name(), ext), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("unexpected segment file name %q: %w", e.Name(), err)
		}
		ids = append(ids, id)
	}
	// os.ReadDir already sorts by name, which for this naming equals numeric
	// order, but do not rely on that coupling.
	for i := 1; i < len(ids); i++ {
		if ids[i-1] > ids[i] {
			return nil, fmt.Errorf("segment ids out of order in %s", dir)
		}
	}
	return ids, nil
}

// ScanComplete lists the segments in a directory that are readable as
// segments, skipping any file too short to hold a header.
//
// This is what a *reader* wants, and it is deliberately different from what
// recovery wants. Segments are created ahead of time so that a rotation does
// not stall the write path, so at any instant the newest file in a
// live log may be part-way through being created — and a crash can leave one
// that way permanently. Such a file is not a damaged segment; it is a segment
// that does not exist yet. No record can ever have been acknowledged on its
// authority, so there is nothing in it for a reader to miss.
//
// Recovery keeps using ScanDir, because it has the opposite need: it must see
// these files in order to delete them, and it must know the highest id on disk
// so the next segment it creates does not collide with one.
//
// Skipping is safe against tampering as well as against timing. Truncating a
// real segment to below header size would hide it here, but a removed segment
// is caught by the chain rather than by the file listing: the following
// segment's recorded predecessor hash would no longer match, and the sequence
// numbers would jump. That is the check that has to hold anyway, since an
// attacker could just as easily delete the file outright.
func ScanComplete(dir string) ([]uint64, error) {
	ids, err := ScanDir(dir)
	if err != nil {
		return nil, err
	}
	out := ids[:0:0]
	for _, id := range ids {
		incomplete, err := IsIncomplete(Path(dir, id))
		if err != nil {
			return nil, err
		}
		if !incomplete {
			out = append(out, id)
		}
	}
	return out, nil
}

// Path returns the full path of a segment id inside dir.
func Path(dir string, segmentID uint64) string {
	return filepath.Join(dir, FileName(segmentID))
}
