package evidence_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// TestLiveLogVerifiesWithOpenTail covers the shape a running writer leaves on
// disk. Background sealing plus segment pre-creation mean the end of a live log
// has more than one open segment — the one taking records and the empty one
// waiting behind it — so "allow an open tail" has to mean the trailing run of
// unsealed segments, not just the final file.
func TestLiveLogVerifiesWithOpenTail(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, func(o *evidence.Options) { o.SegmentTargetBytes = 512 })

	appendN(t, a, 30, "sg_live")

	// A live log does not have an open segment at every instant. Immediately
	// after a rotation the previous segment is sealed and the next one has not
	// been created yet, so a directory listing taken in that window shows
	// nothing but sealed segments. Sampling once and demanding an open tail
	// therefore fails on whichever machine happens to look at the wrong
	// moment — which is how this test failed on Linux CI while passing
	// everywhere else.
	//
	// Waiting for the state under test is not weakening the assertion. The
	// claim is that verify tolerates an open tail, and there has to be one
	// before that claim can be tested at all; an open tail always arrives,
	// because the writer is still running.
	var rep *verify.Report
	deadline := time.Now().Add(10 * time.Second)
	for {
		var err error
		rep, err = verify.SegmentDir(dir, verify.Options{
			Keys:              keySet(signer),
			AllowUnsealedTail: true,
			Version:           "test",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !rep.OK {
			t.Fatalf("a live log did not verify with an open tail:\n%s", rep.Text())
		}

		// How many segments are open is timing-dependent — one or two,
		// depending on whether the next pre-created segment has landed — so
		// only the presence of one is asserted. TestOpenTailAllowanceCoversARun
		// pins the semantics on a state built by hand.
		open := 0
		for _, s := range rep.Segments {
			if !s.Sealed {
				open++
			}
		}
		if open > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no segment was ever open while the writer was running, so this test " +
				"never exercised the open-tail path")
		}
		// Keep the writer working, so a rotation boundary is passed rather
		// than waited out.
		appendN(t, a, 1, "sg_live")
	}

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	// After a clean close nothing is left open, and the empty prepared segment
	// is gone rather than signed.
	rep = verifyDir(t, dir, signer)
	if !rep.OK {
		t.Fatalf("log did not verify after close:\n%s", rep.Text())
	}
	for _, s := range rep.Segments {
		if !s.Sealed {
			t.Fatalf("segment %d is still open after a clean close", s.SegmentID)
		}
		if s.Records == 0 {
			t.Fatalf("segment %d was sealed with no records; empty segments should be removed", s.SegmentID)
		}
	}
}

// TestOpenTailAllowanceCoversARun builds the tail state by hand so the
// semantics are pinned without racing a live writer: several unsealed segments
// in a row at the end are acceptable when the caller says the log is open, and
// unacceptable when it does not.
func TestOpenTailAllowanceCoversARun(t *testing.T) {
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
	next := ids[len(ids)-1] + 1
	for i := range uint64(2) {
		w, err := segment.Create(dir, next+i, segment.WriterOptions{SyncMode: segment.SyncModeNone})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}

	rep, err := verify.SegmentDir(dir, verify.Options{
		Keys: keySet(signer), AllowUnsealedTail: true, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a run of unsealed segments at the tail was rejected:\n%s", rep.Text())
	}

	strict := verifyDir(t, dir, signer)
	if strict.OK {
		t.Fatal("unsealed segments were accepted without AllowUnsealedTail")
	}
	if !hasFinding(strict, "SEGMENT_UNSEALED") {
		t.Fatalf("expected SEGMENT_UNSEALED without the allowance, got:\n%s", strict.Text())
	}
}

// TestUnsealedSegmentBeforeSealedOnesIsStillRejected: the open-tail allowance
// must not become a blanket excuse. A seal that went missing in the middle of
// the log is exactly what recovery is supposed to repair, so seeing one means
// something is wrong.
func TestUnsealedSegmentBeforeSealedOnesIsStillRejected(t *testing.T) {
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
		t.Fatalf("need at least three segments, got %d", len(ids))
	}
	unseal(t, segment.Path(dir, ids[0]))

	rep, err := verify.SegmentDir(dir, verify.Options{
		Keys: keySet(signer), AllowUnsealedTail: true, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatalf("an unsealed segment with sealed segments after it was accepted:\n%s", rep.Text())
	}
	if !hasFinding(rep, "SEGMENT_UNSEALED") {
		t.Fatalf("expected SEGMENT_UNSEALED, got:\n%s", rep.Text())
	}
}

// TestRecoverySealsUnsealedSegmentInTheMiddle is the crash case background
// sealing introduces: seals run concurrently, so a process can die after the
// seal of segment N+1 lands but before N's does.
func TestRecoverySealsUnsealedSegmentInTheMiddle(t *testing.T) {
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
		t.Fatalf("need at least three segments, got %d", len(ids))
	}
	orphan := ids[len(ids)-2]
	unseal(t, segment.Path(dir, orphan))

	b, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	appendN(t, b, 3, "sg_after")
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	rep := verifyDir(t, dir, signer)
	if !rep.OK {
		t.Fatalf("log did not verify after recovery:\n%s", rep.Text())
	}
	if !hasKind(t, dir, evidence.KindRecovery) {
		t.Fatal("recovery sealed a segment it did not write without recording the custody break")
	}
}

// TestRecoveryRemovesEmptyPreparedSegment: a segment created ahead of time but
// never written to holds no evidence, so it should be deleted rather than
// signed. Signing it would put an empty, meaningless artefact in the audit
// trail for every unclean stop.
func TestRecoveryRemovesEmptyPreparedSegment(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, nil)
	appendN(t, a, 3, "sg")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	orphanID := ids[len(ids)-1] + 1
	w, err := segment.Create(dir, orphanID, segment.WriterOptions{SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(segment.Path(dir, orphanID)); err != nil {
		t.Fatalf("setup: empty segment should exist: %v", err)
	}

	b, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(segment.Path(dir, orphanID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty prepared segment %d was not removed (err=%v)", orphanID, err)
	}
	// The id must not be handed out again, even though its file is gone.
	after, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range after {
		if id == orphanID {
			t.Fatalf("segment id %d was reused after its empty file was removed", orphanID)
		}
	}
	if rep := verifyDir(t, dir, signer); !rep.OK {
		t.Fatalf("log did not verify after removing the empty segment:\n%s", rep.Text())
	}
}

// TestIsSealedMatchesFullInspection: recovery classifies segments with a cheap
// trailing-magic read instead of parsing them, so the shortcut has to agree
// with the real thing.
func TestIsSealedMatchesFullInspection(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, func(o *evidence.Options) { o.SegmentTargetBytes = 512 })
	appendN(t, a, 30, "sg")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	// Leave one unsealed so both answers are exercised.
	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	unseal(t, segment.Path(dir, ids[len(ids)-1]))

	for _, id := range ids {
		path := segment.Path(dir, id)
		cheap, err := segment.IsSealed(path)
		if err != nil {
			t.Fatal(err)
		}
		insp, err := segment.Inspect(path)
		if err != nil {
			t.Fatal(err)
		}
		if cheap != insp.Sealed() {
			t.Fatalf("segment %d: IsSealed says %v, full inspection says %v", id, cheap, insp.Sealed())
		}
	}
}

func TestIsSealedOnTruncatedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, segment.FileName(1))
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	sealed, err := segment.IsSealed(path)
	if err != nil {
		t.Fatalf("IsSealed should classify a stub file, not fail: %v", err)
	}
	if sealed {
		t.Fatal("a five-byte file was reported as sealed")
	}
}

// TestSealFailureStopsTheWritePath: sealing now happens off the writer
// goroutine, so its failure arrives asynchronously. It still has to stop the
// world — an unsigned segment is evidence nobody can authenticate.
func TestSealFailureStopsTheWritePath(t *testing.T) {
	signer := failingSigner{inner: mustSigner(t)}
	a, _ := newAppender(t, signer, func(o *evidence.Options) { o.SegmentTargetBytes = 512 })

	var lastErr error
	// Append until the background seal failure propagates. The bound is
	// generous; what matters is that it stops, not exactly when.
	for range 500 {
		_, lastErr = a.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			Participant: evidence.ParticipantRef{ID: "ag"},
			Payload:     []byte(`{"padding":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		})
		if lastErr != nil {
			break
		}
	}
	if lastErr == nil {
		t.Fatal("appends kept succeeding after a background seal failed")
	}
	if !errors.Is(lastErr, evidence.ErrWritePathFailed) {
		t.Fatalf("got %v, want it to wrap ErrWritePathFailed", lastErr)
	}
	_ = a.Close()
}
