package evidence_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// tornLog builds the situation this is all about: a log whose last record is
// only partly on disk, with an appender that has acknowledged it.
//
// It is constructed rather than raced for, because a test that depends on
// winning a race only fails on the machines that lose it. The construction is
// faithful to the mechanism: `segment.Writer` flushes on a bufio buffer
// boundary rather than a record boundary, so a reader mid-flush sees exactly
// this — every earlier record whole, the last one cut off part-way, and no
// footer because the segment is still open.
//
// It returns the directory, the acknowledged head (which includes the partial
// record, since the appender published it), and the sequence the log actually
// reads to.
func tornLog(t *testing.T, whole int) (dir string, head, readable uint64) {
	t.Helper()
	dir = t.TempDir()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })

	appendOne := func() uint64 {
		ref, err := app.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      "sg_walk",
			Participant: evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1", Principal: "pr_1"},
			Payload:     []byte("x"),
		})
		if err != nil {
			t.Fatal(err)
		}
		return ref.Seq
	}

	for range whole {
		readable = appendOne()
	}

	// The last *id* is not the last segment holding records: an open appender
	// creates the next one ahead of a rotation, so `ScanComplete`
	// reports an empty placeholder. Truncating that one grows it with zero
	// padding, which produces a torn tail in a file with no records in it — a
	// fixture that looks like it works and tests nothing.
	path := lastSegmentWithRecords(t, dir)
	whole_, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// One more, acknowledged, then cut it back to a few bytes past where the
	// complete records end. Those few bytes are the partial record.
	head = appendOne()
	if err := os.Truncate(path, whole_.Size()+3); err != nil {
		t.Fatal(err)
	}
	return dir, head, readable
}

// lastSegmentWithRecords is the file the newest record is actually in.
func lastSegmentWithRecords(t *testing.T, dir string) string {
	t.Helper()
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(ids) - 1; i >= 0; i-- {
		path := segment.Path(dir, ids[i])
		insp, err := segment.Inspect(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(insp.Records) > 0 {
			return path
		}
	}
	t.Fatal("no segment in the directory holds any records")
	return ""
}

func count(t *testing.T, dir string, opts ...evidence.ReadOption) (int, error) {
	t.Helper()
	n := 0
	err := evidence.Walk(dir, func(evidence.EventHeader, segment.Record) error {
		n++
		return nil
	}, opts...)
	return n, err
}

// A reader with no appender to ask keeps refusing, because it has no basis for
// deciding that a tear is the ordinary kind.
//
// This is the behaviour every reader once had, and it is still the
// right answer offline: `janus-verify` and an auditor working on a copied
// directory cannot distinguish a crash from a write in progress, and should not
// pretend to.
func TestAnOfflineReaderStillRefusesATornTail(t *testing.T) {
	dir, _, _ := tornLog(t, 4)

	if _, err := count(t, dir); !errors.Is(err, segment.ErrTornTail) {
		t.Fatalf("an offline read of a torn log did not refuse with the sentinel: %v", err)
	}
}

// A reader that names the acknowledged head reads the log a writer is in the
// middle of, which is the case that made `janus-latency` die at concurrency 8.
func TestNamingTheHeadReadsPastALiveTear(t *testing.T) {
	dir, head, readable := tornLog(t, 4)
	if head == readable {
		t.Fatal("the fixture did not actually tear the last record")
	}

	// `readable` is the head a reader would have obtained *before* the partial
	// record was appended, which is the ordering AsOf requires: read the head,
	// then walk. Anything appended after the question was asked is not part of
	// the answer to it.
	n, err := count(t, dir, evidence.AsOf(readable))
	if err != nil {
		t.Fatalf("a live read of a healthy log being written was refused: %v", err)
	}
	if n != 4 {
		t.Fatalf("read %d records past the tear, want the 4 complete ones", n)
	}
}

// The tolerance is bounded by what was acknowledged. A tear that swallowed a
// record somebody was promised is damage, and saying so is the whole reason the
// caller has to name a sequence rather than just asking for leniency.
func TestATearBelowTheAcknowledgedHeadIsStillRefused(t *testing.T) {
	dir, head, _ := tornLog(t, 4)

	_, err := count(t, dir, evidence.AsOf(head))
	if !errors.Is(err, segment.ErrTornTail) {
		t.Fatalf("a tear hiding an acknowledged record was accepted: %v", err)
	}
}

// A gap is refused however the read is configured. Sequences are contiguous, so
// unreadable records in the middle were acknowledged — that is damage, and
// naming a head must not be a way to wave it through.
func TestAGapIsRefusedEvenWithAHead(t *testing.T) {
	dir := t.TempDir()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// A tiny segment target so the log rotates and there is a middle to make a
	// hole in.
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 6 {
		if _, err := app.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      "sg_walk",
			Participant: evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1", Principal: "pr_1"},
			Payload:     []byte("x"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	head := app.Stats().LastSeq
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	ids, err := segment.ScanComplete(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) < 3 {
		t.Fatalf("the log made %d segments, need at least 3 to have a middle", len(ids))
	}
	// Empty a segment that is not the last one, so the walk sees a jump in the
	// sequence rather than a short tail.
	if err := os.Truncate(segment.Path(dir, ids[1]), int64(segment.HeaderSize)); err != nil {
		t.Fatal(err)
	}

	if _, err := count(t, dir, evidence.AsOf(head)); !errors.Is(err, evidence.ErrGap) {
		t.Fatalf("a hole in the middle of the log was not reported as a gap: %v", err)
	}
}
