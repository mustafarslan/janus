package evidence_test

import (
	"os"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// A reader can see a segment that is still being created.
//
// Segments are prepared ahead of time so that a rotation does not stall the
// write path, so the newest file in a live log may be part-way
// through existing, and a crash can leave one that way for good. Every reader
// has to treat that as "no segment here" rather than as damage — the saga
// chaos suite found this the hard way, with a healthy log becoming permanently
// unreadable because a SIGKILL landed inside that window.
func TestVerifyToleratesASegmentThatIsNotASegmentYet(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, nil)
	appendN(t, a, 5, "sg")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	next := segment.Path(dir, ids[len(ids)-1]+1)

	for _, size := range []int{0, 1, segment.HeaderSize - 1} {
		if err := os.WriteFile(next, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
		rep := verifyDir(t, dir, signer)
		if !rep.OK {
			t.Fatalf("a %d-byte placeholder made a healthy log fail verification:\n%s",
				size, rep.Text())
		}
	}
	if err := os.Remove(next); err != nil {
		t.Fatal(err)
	}
}

// The safety claim behind skipping those files: a real segment truncated to
// below header size is still caught, because a missing segment is detected by
// the chain rather than by the directory listing.
//
// This matters because the skip is otherwise indistinguishable from an
// attacker's best move. If hiding a segment were as simple as truncating it to
// ten bytes, the allowance above would be a hole rather than a convenience.
func TestTruncatingARealSegmentIsStillCaught(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, func(o *evidence.Options) { o.SegmentTargetBytes = 512 })
	appendN(t, a, 40, "sg")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) < 3 {
		t.Fatalf("need at least three segments to remove a middle one, got %d", len(ids))
	}

	// Truncate a segment in the middle to below header size — the shape a
	// reader is told to ignore.
	victim := segment.Path(dir, ids[1])
	if err := os.WriteFile(victim, make([]byte, 8), 0o600); err != nil {
		t.Fatal(err)
	}

	rep := verifyDir(t, dir, signer)
	if rep.OK {
		t.Fatalf("a segment truncated out of existence was not noticed:\n%s", rep.Text())
	}
	t.Logf("caught as:\n%s", rep.Text())
}
