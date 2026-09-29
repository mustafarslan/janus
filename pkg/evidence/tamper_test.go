package evidence_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// TestEverySingleByteMutationIsDetected is invariant I2 taken literally: "any
// single-byte mutation of any segment is detected by the verifier".
//
// It flips one bit in each byte of a real segment in turn and requires the
// verifier to reject every result. This is the test that would fail if any
// region of the format were left uncovered by a hash or a signature — which is
// exactly what happened with the reserved header bytes before they were
// required to be zero.
func TestEverySingleByteMutationIsDetected(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, nil)
	appendN(t, a, 3, "sg_i2")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	path := segment.Path(dir, 1)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(original) < 200 {
		t.Fatalf("segment is suspiciously small (%d bytes); the test may not be exercising the format", len(original))
	}

	work := t.TempDir()
	target := filepath.Join(work, segment.FileName(1))
	opts := verify.Options{Keys: keySet(signer), Version: "test"}

	for off := range original {
		mutated := slices.Clone(original)
		mutated[off] ^= 0x01
		if err := os.WriteFile(target, mutated, 0o600); err != nil {
			t.Fatal(err)
		}
		rep, err := verify.SegmentDir(work, opts)
		if err != nil {
			// An unreadable segment is a detection, not a miss.
			continue
		}
		if rep.OK {
			t.Fatalf("flipping the low bit of byte %d (of %d) produced a segment that still verified:\n%s",
				off, len(original), rep.Text())
		}
	}
}

// TestReorderingRecordsIsDetected covers the other half of tamper-evidence:
// keeping every byte but changing the order they appear in.
func TestReorderingRecordsIsDetected(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, nil)
	appendN(t, a, 4, "sg_reorder")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// Rebuild the segment with two records transposed, re-deriving nothing:
	// this is the "insider with write access to the log file" case.
	path := segment.Path(dir, 1)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bounds := recordBounds(t, path)
	if len(bounds) < 4 {
		t.Fatalf("expected at least 4 records, found %d", len(bounds))
	}

	swapped := make([]byte, 0, len(raw))
	swapped = append(swapped, raw[:bounds[0].start]...)
	order := []int{1, 0, 2, 3}
	for _, i := range order {
		swapped = append(swapped, raw[bounds[i].start:bounds[i].end]...)
	}
	swapped = append(swapped, raw[bounds[len(bounds)-1].end:]...)

	work := t.TempDir()
	if err := os.WriteFile(filepath.Join(work, segment.FileName(1)), swapped, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := verify.SegmentDir(work, verify.Options{Keys: keySet(signer), Version: "test"})
	if err != nil {
		return // unreadable is a detection
	}
	if rep.OK {
		t.Fatalf("transposing two records went undetected:\n%s", rep.Text())
	}
}

type span struct{ start, end int }

// recordBounds returns the byte range of each event record in a segment.
func recordBounds(t *testing.T, path string) []span {
	t.Helper()
	rd, err := segment.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	var out []span
	prev := int(rd.LastGoodOffset())
	for {
		_, ok, err := rd.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		cur := int(rd.LastGoodOffset())
		out = append(out, span{start: prev, end: cur})
		prev = cur
	}
	return out
}
