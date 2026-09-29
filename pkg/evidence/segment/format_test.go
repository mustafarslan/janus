package segment

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestASegmentFromANewerFormatIsRefused fills the one cell of the
// format compatibility table that had nothing in it.
//
// `decodeFileHeader` has refused an unsupported segment format version since
// Phase 1, and this package had no test files at all — so the oldest of the
// five version gates was the only one nobody had ever watched fail. The check
// is four lines and it is the outermost of them: a file this build cannot parse
// must not reach the code that decodes records out of it.
func TestASegmentFromANewerFormatIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName(1))

	// A real segment, written by the writer rather than assembled here, so the
	// only thing wrong with it is the version.
	w, err := Create(dir, 1, WriterOptions{SyncMode: SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(path); err != nil {
		t.Fatalf("the unmodified segment does not inspect, so this test would prove "+
			"nothing about the version: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint16(raw[8:10], Version+1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Inspect(path)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("a segment written under format version %d was read by a build that "+
			"understands %d, with err=%v: the file layout is what every other reader "+
			"assumes, so guessing at it is guessing at record boundaries",
			Version+1, Version, err)
	}
}

// TestTheWriterRefusesWhatItsOwnReaderWouldRefuse.
//
// MaxRecordLen bounded the read side in three places and the write side in
// none — found by following a gosec G115 finding on the `uint32(bodyLen)`
// conversion rather than by the conversion being wrong. The consequence was
// worse than a truncated field: AppendRecord framed a 64 MiB record happily,
// and the reader then called the segment's *first* record `implausible record
// length`. A log this code had written faithfully verified as corrupt, and
// nothing distinguishes that from a log somebody changed. The rest of the
// segment went with it, because a reader cannot resynchronise past a frame it
// does not believe.
func TestTheWriterRefusesWhatItsOwnReaderWouldRefuse(t *testing.T) {
	dir := t.TempDir()
	w, err := Create(dir, 0, WriterOptions{SyncMode: SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })

	oversize := Record{Header: []byte("h"), Payload: make([]byte, MaxRecordLen)}
	if n := EncodedLen(oversize); n <= MaxRecordLen {
		t.Fatalf("the fixture is not actually oversized: %d bytes", n)
	}
	err = w.AppendRecord(1, oversize)
	if err == nil {
		t.Fatal("the writer framed a record longer than MaxRecordLen. Its own reader " +
			"refuses those, so this segment verifies as corrupt — and a log that reports " +
			"as corrupt because of how it was written cannot be told apart from one that " +
			"reports as corrupt because somebody changed it")
	}
	if !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	// And the limit is a limit rather than a ban: the largest record that fits
	// must still fit. An off-by-one here loses data at the boundary instead of
	// at 64 MiB, which is the version of this bug nobody would notice.
	fits := Record{Header: []byte("h")}
	fits.Payload = make([]byte, MaxRecordLen-EncodedLen(fits))
	if n := EncodedLen(fits); n != MaxRecordLen {
		t.Fatalf("fixture is %d bytes, want exactly %d", n, MaxRecordLen)
	}
	if err := w.AppendRecord(1, fits); err != nil {
		t.Fatalf("a record of exactly MaxRecordLen was refused: %v", err)
	}
}
