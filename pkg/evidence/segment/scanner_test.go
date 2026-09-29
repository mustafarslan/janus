package segment_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// TestAScannerSeesASegmentThatFillsIn is the property that makes caching only
// the positive answers correct.
//
// A follower writes into its mirror's newest file progressively, so a file below
// header size is the ordinary state of a log being written into — not a
// permanent one. Caching "incomplete" would hide that file from every later
// pass, and the follower would stop at the segment before it forever.
func TestAScannerSeesASegmentThatFillsIn(t *testing.T) {
	dir := t.TempDir()
	write := func(id int, n int) {
		p := filepath.Join(dir, fmt.Sprintf("%016x.jseg", id))
		if err := os.WriteFile(p, make([]byte, n), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write(0, segment.HeaderSize+8)
	write(1, 4) // created, not yet written into

	s := segment.NewScanner(dir)
	got, err := s.Complete()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []uint64{0}) {
		t.Fatalf("first pass saw %v, want [0]", got)
	}

	write(1, segment.HeaderSize+8)
	got, err = s.Complete()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []uint64{0, 1}) {
		t.Fatalf("after segment 1 filled in the scanner saw %v, want [0 1]", got)
	}
}

// TestAScannerAgreesWithScanComplete, on every shape that matters: a growing
// directory, a partial tail, and a file appearing between passes.
func TestAScannerAgreesWithScanComplete(t *testing.T) {
	dir := t.TempDir()
	s := segment.NewScanner(dir)
	check := func(step string) {
		t.Helper()
		want, err := segment.ScanComplete(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Complete()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%s: scanner saw %v, ScanComplete saw %v", step, got, want)
		}
	}
	check("empty")
	for i := range 6 {
		p := filepath.Join(dir, fmt.Sprintf("%016x.jseg", i))
		if err := os.WriteFile(p, make([]byte, segment.HeaderSize+8), 0o640); err != nil {
			t.Fatal(err)
		}
		check(fmt.Sprintf("after segment %d", i))
	}
	// A placeholder at the tail, the state a rotation and a crash both leave.
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%016x.jseg", 6)),
		make([]byte, 3), 0o640); err != nil {
		t.Fatal(err)
	}
	check("with a placeholder at the tail")

	// And the returned slice is the caller's to keep: mutating it must not
	// reach the next answer.
	got, err := s.Complete()
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		got[i] = 999
	}
	check("after a caller mutated a previous result")
}

// TestForgetMakesAScannerAskAgain: the escape hatch is not decoration, a
// follower that re-frames from the start of its mirror uses it.
func TestForgetMakesAScannerAskAgain(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, fmt.Sprintf("%016x.jseg", 0))
	if err := os.WriteFile(p, make([]byte, segment.HeaderSize+8), 0o640); err != nil {
		t.Fatal(err)
	}
	s := segment.NewScanner(dir)
	if got, err := s.Complete(); err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	// Truncated behind the scanner's back. Cached, it still reports the
	// segment; asked again, it does not.
	if err := os.Truncate(p, 2); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Complete(); err != nil || len(got) != 1 {
		t.Fatalf("a cached answer should survive: got %v, %v", got, err)
	}
	s.Forget()
	if got, err := s.Complete(); err != nil || len(got) != 0 {
		t.Fatalf("after Forget the scanner should re-stat: got %v, %v", got, err)
	}
}
