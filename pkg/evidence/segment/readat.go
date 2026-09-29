package segment

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// ReadRecordsAt reads named records out of a segment without walking it.
//
// A reader that already knows where a record is should not pay to frame and
// decode every record before it. That cost is not theoretical: at 16,000
// records in one segment, walking the whole thing to find one saga's eight
// events measured 13.5 ms, of which 10.5 ms was decoding headers that were then
// thrown away.
//
// The offsets come from a locator built by whoever wrote the records, and are
// verified structurally on the way back: a length prefix that is implausible,
// a record type that is not an event, or a decode failure is an error rather
// than a shrug. What this cannot check is that the *right* records were asked
// for — an index that omits an event yields a short history that looks valid.
// That is the locator's problem, and `pkg/evidence`'s equivalence test against
// a full scan is what holds it to account.
//
// The file is opened once and read with ReadAt, so the offsets need not be
// sorted and no state carries between them.
func ReadRecordsAt(path string, offsets []int64) ([]Record, error) {
	if len(offsets) == 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	out := make([]Record, 0, len(offsets))
	var lenBuf [4]byte
	for _, off := range offsets {
		if off < int64(HeaderSize) {
			return nil, fmt.Errorf("%w: offset %d is inside the segment header", ErrCorrupt, off)
		}
		if _, err := f.ReadAt(lenBuf[:], off); err != nil {
			return nil, fmt.Errorf("read the length prefix at offset %d in %s: %w", off, path, err)
		}
		recLen := int(binary.LittleEndian.Uint32(lenBuf[:]))
		if recLen == 0 || recLen > MaxRecordLen {
			return nil, fmt.Errorf("%w: implausible record length %d at offset %d in %s",
				ErrCorrupt, recLen, off, path)
		}
		body := make([]byte, recLen)
		if _, err := f.ReadAt(body, off+4); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				// The locator pointed past the end of what is on disk. That is
				// not a torn tail to read around: an offset only exists because
				// something claimed to have written the record there.
				return nil, fmt.Errorf("%w: record at offset %d in %s wants %d bytes and the "+
					"file ends first", ErrCorrupt, off, path, recLen)
			}
			return nil, fmt.Errorf("read the record at offset %d in %s: %w", off, path, err)
		}
		if body[0] != recTypeEvent {
			return nil, fmt.Errorf("%w: offset %d in %s is record type %d, not an event",
				ErrCorrupt, off, path, body[0])
		}
		rec, err := decodeEventRecord(body[1:])
		if err != nil {
			return nil, fmt.Errorf("record at offset %d in %s: %w", off, path, err)
		}
		out = append(out, rec)
	}
	return out, nil
}
