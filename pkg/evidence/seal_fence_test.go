package evidence_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// TestAWriterThatLostTheLeaseDoesNotSeal is the fence reaching the write path.
//
// The lease itself is tested against a real object store in pkg/evidence/fence.
// What this covers is the join: that a refusal at BeforeSeal stops a segment
// becoming signed history, and that the failure is **sticky** — a writer that
// has been fenced out does not get to carry on appending once the next seal has
// been refused.
//
// No object store here on purpose. The question is what the appender does when
// told no, and a test that needed MinIO to ask it would be skipped on the
// machine of anyone running `go test ./...`.
func TestAWriterThatLostTheLeaseDoesNotSeal(t *testing.T) {
	signer := mustSigner(t)
	lost := errors.New("the writer lease was lost")
	// Atomic: BeforeSeal runs on the background seal goroutine, so a plain bool
	// here is a data race and the race detector says so. Worth keeping in view
	// beyond this test -- whatever a deployment passes as BeforeSeal is called
	// from that goroutine too.
	var refuse atomic.Bool

	a, dir := newAppender(t, signer, func(o *evidence.Options) {
		// Small, so the drill rotates rather than relying on Close to seal.
		o.SegmentTargetBytes = 2048
		o.BeforeSeal = func() error {
			if refuse.Load() {
				return lost
			}
			return nil
		}
	})

	// While the lease is held, sealing works and segments accumulate.
	appendN(t, a, 40, "sg_leased")
	if got := countSegments(t, dir); got < 2 {
		t.Fatalf("expected the log to have rotated at least once so a seal actually "+
			"happened; found %d segment(s)", got)
	}

	// The lease is lost. The next seal must refuse.
	refuse.Store(true)

	// Closed on the way out, and it is not tidiness. Without it the appender's
	// background goroutines are still running when t.TempDir()'s RemoveAll
	// fires, and a seal landing in that window fails the test with `directory
	// not empty` — which reads as an unrelated flake rather than as this test
	// having left a writer running. It was the only test in the package doing
	// so, because the sticky failure it provokes makes Close look unnecessary.
	t.Cleanup(func() { _ = a.Close() })

	var appendErr error
	for i := range 400 {
		_, err := a.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      "sg_fenced",
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_test", ManifestVersion: "1.0.0", Principal: "pr_test", Kind: "AGENT"},
			Payload:     []byte(`{"outcome":"OK"}`),
		})
		if err != nil {
			appendErr = err
			break
		}
	}

	if appendErr == nil {
		t.Fatal("the writer went on appending indefinitely after losing its lease; a fence " +
			"that does not stop the write path is not a fence")
	}
	if !errors.Is(appendErr, evidence.ErrWritePathFailed) {
		t.Fatalf("the refusal did not fail the write path, so the failure is not sticky "+
			"and the writer would resume: %v", appendErr)
	}
	if !errors.Is(appendErr, lost) {
		t.Fatalf("the write path failed for a reason that does not name the lease, which "+
			"would send an operator after the wrong problem: %v", appendErr)
	}

	// Sticky: a later append does not recover.
	if _, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindStepResult, SagaID: "sg_after", StepID: "st_after",
		Participant: evidence.ParticipantRef{ID: "ag_test", ManifestVersion: "1.0.0", Principal: "pr_test", Kind: "AGENT"},
		Payload:     []byte(`{}`),
	}); !errors.Is(err, evidence.ErrWritePathFailed) {
		t.Fatalf("the write path recovered after a lease loss: %v", err)
	}
}

// TestWhatTheFenceDoesNotPrevent states the cost in a test rather than only in
// a comment, because it is the thing most likely to be misread as a guarantee.
//
// The lease is checked at seal, not at append. A writer that has lost it can
// still have written records into its open segment — those records exist, and
// the fence's claim is only that they never become *sealed* history.
func TestWhatTheFenceDoesNotPrevent(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, func(o *evidence.Options) {
		o.SegmentTargetBytes = 1 << 20 // large: no rotation, so no seal is attempted
		o.BeforeSeal = func() error {
			return errors.New("the writer lease was lost")
		}
	})

	// Every one of these succeeds, with the lease already lost, because none of
	// them triggers a seal.
	appendN(t, a, 20, "sg_unsealed")

	raw, err := os.ReadFile(segment.Path(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("expected records on disk")
	}
	// And this is the boundary: the segment is not sealed, so a verifier sees
	// an open tail rather than history somebody signed.
	rd, err := segment.Open(segment.Path(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	for {
		if _, ok, err := rd.Next(); err != nil || !ok {
			break
		}
	}
	if _, sealed := rd.Footer(); sealed {
		t.Fatal("the segment was sealed despite the lease being lost")
	}
}

func countSegments(t *testing.T, dir string) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.jseg"))
	if err != nil {
		t.Fatal(err)
	}
	return len(matches)
}
