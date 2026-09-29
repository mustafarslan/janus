package evidence_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

func mustSigner(t *testing.T) *keys.Signer {
	t.Helper()
	s, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func keySet(s *keys.Signer) keys.PublicKeySet {
	return keys.PublicKeySet{s.KeyID(): s.Public()}
}

// newAppender opens an appender in a fresh directory. Tests use SyncModeNone
// because they are exercising correctness, not durability; the durability
// barrier itself is measured by cmd/janus-bench.
func newAppender(t *testing.T, signer segment.Signer, mutate func(*evidence.Options)) (*evidence.Appender, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	opts := evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone}
	if mutate != nil {
		mutate(&opts)
	}
	a, err := evidence.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	return a, opts.Dir
}

func appendN(t *testing.T, a *evidence.Appender, n int, sagaID string) []evidence.Ref {
	t.Helper()
	refs := make([]evidence.Ref, 0, n)
	for i := range n {
		ref, err := a.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      sagaID,
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_test", ManifestVersion: "1.0.0", Principal: "pr_test", Kind: "AGENT"},
			Payload:     fmt.Appendf(nil, `{"step":%d,"outcome":"OK"}`, i),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		refs = append(refs, ref)
	}
	return refs
}

func verifyDir(t *testing.T, dir string, signer *keys.Signer) *verify.Report {
	t.Helper()
	rep, err := verify.SegmentDir(dir, verify.Options{Keys: keySet(signer), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestAppendThenVerify(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, nil)

	refs := appendN(t, a, 10, "sg_0001")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	for i, ref := range refs {
		if want := uint64(i + 1); ref.Seq != want {
			t.Fatalf("event %d got seq %d, want %d", i, ref.Seq, want)
		}
		if ref.EventID == "" {
			t.Fatalf("event %d has no id", i)
		}
	}

	rep := verifyDir(t, dir, signer)
	if !rep.OK {
		t.Fatalf("verification failed:\n%s", rep.Text())
	}
	if rep.Events != 10 {
		t.Fatalf("verifier counted %d events, want 10", rep.Events)
	}
	if rep.LastSeq != 10 {
		t.Fatalf("head sequence is %d, want 10", rep.LastSeq)
	}
	for _, s := range rep.Segments {
		if !s.Sealed || !s.SignatureOK || !s.ChainOK {
			t.Fatalf("segment %d not fully verified: %+v", s.SegmentID, s)
		}
	}
}

func TestCloseSealsAndRotationChainsAcrossSegments(t *testing.T) {
	signer := mustSigner(t)
	// A tiny segment target forces rotation every batch, so the chain has to
	// survive segment boundaries.
	a, dir := newAppender(t, signer, func(o *evidence.Options) { o.SegmentTargetBytes = 512 })

	appendN(t, a, 40, "sg_rotate")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	rep := verifyDir(t, dir, signer)
	if !rep.OK {
		t.Fatalf("verification failed:\n%s", rep.Text())
	}
	if len(rep.Segments) < 2 {
		t.Fatalf("expected rotation to produce several segments, got %d", len(rep.Segments))
	}
	if rep.Events != 40 {
		t.Fatalf("counted %d events across segments, want 40", rep.Events)
	}
}

// TestConcurrentAppendsAreTotallyOrdered exercises the group-commit path: many
// producers, one chain, no gaps and no duplicates.
func TestConcurrentAppendsAreTotallyOrdered(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, nil)

	const writers, perWriter = 8, 250
	var mu sync.Mutex
	seen := map[uint64]bool{}

	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWriter {
				ref, err := a.Append(context.Background(), evidence.Request{
					Kind:        evidence.KindStepResult,
					SagaID:      fmt.Sprintf("sg_%02d", w),
					Participant: evidence.ParticipantRef{ID: "ag_test"},
					Payload:     fmt.Appendf(nil, `{"w":%d,"i":%d}`, w, i),
				})
				if err != nil {
					t.Errorf("writer %d append %d: %v", w, i, err)
					return
				}
				mu.Lock()
				if seen[ref.Seq] {
					t.Errorf("sequence %d handed out twice", ref.Seq)
				}
				seen[ref.Seq] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	total := writers * perWriter
	if len(seen) != total {
		t.Fatalf("got %d distinct sequence numbers, want %d", len(seen), total)
	}
	for i := 1; i <= total; i++ {
		if !seen[uint64(i)] {
			t.Fatalf("sequence %d was never assigned", i)
		}
	}

	rep := verifyDir(t, dir, signer)
	if !rep.OK {
		t.Fatalf("verification failed:\n%s", rep.Text())
	}
	if rep.Events != total {
		t.Fatalf("verifier counted %d events, want %d", rep.Events, total)
	}
}

// unseal truncates a sealed segment back to the end of its last event record,
// leaving it in the state a writer that died before sealing would leave it.
func unseal(t *testing.T, path string) int64 {
	t.Helper()
	rd, err := segment.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var lastRecordEnd int64
	for {
		_, ok, err := rd.Next()
		if err != nil {
			rd.Close()
			t.Fatal(err)
		}
		if !ok {
			break
		}
		lastRecordEnd = rd.LastGoodOffset()
	}
	rd.Close()
	if err := segment.Truncate(path, lastRecordEnd); err != nil {
		t.Fatal(err)
	}
	return lastRecordEnd
}

func appendRaw(t *testing.T, path string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
}

// TestRecoveryFromTornTail is the crash case: the process died between writing
// a record and making it durable. Recovery must discard the partial record,
// seal the orphaned segment, and say so in the log.
func TestRecoveryFromTornTail(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, nil)
	appendN(t, a, 5, "sg_crash")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	path := segment.Path(dir, 1)
	unseal(t, path)
	// A half-written record: a length prefix promising more than follows.
	appendRaw(t, path, []byte{0x40, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef})

	b, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
	appendN(t, b, 2, "sg_after_crash")
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	rep := verifyDir(t, dir, signer)
	if !rep.OK {
		t.Fatalf("log did not verify after recovery:\n%s", rep.Text())
	}
	// 5 before the crash, 1 recovery event, 2 after.
	if rep.Events != 8 {
		t.Fatalf("counted %d events after recovery, want 8:\n%s", rep.Events, rep.Text())
	}

	if !hasKind(t, dir, evidence.KindRecovery) {
		t.Fatal("recovery did not record a RECOVERY event; the custody break is invisible in the log")
	}
}

// TestRecoveryIsSilentAfterCleanShutdown checks the opposite case: a clean close
// leaves nothing to confess, so no RECOVERY event should appear.
func TestRecoveryIsSilentAfterCleanShutdown(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, nil)
	appendN(t, a, 3, "sg_clean")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, b, 3, "sg_clean_2")
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	if hasKind(t, dir, evidence.KindRecovery) {
		t.Fatal("a clean restart recorded a RECOVERY event")
	}
	rep := verifyDir(t, dir, signer)
	if !rep.OK || rep.Events != 6 {
		t.Fatalf("want 6 events and a clean verify, got %d:\n%s", rep.Events, rep.Text())
	}
}

// TestRecoveryRefusesBrokenChain: starting a fresh chain on top of a damaged one
// would hide the damage, so the appender must refuse to open at all.
func TestRecoveryRefusesBrokenChain(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, nil)
	appendN(t, a, 4, "sg_damaged")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	path := segment.Path(dir, 1)
	unseal(t, path)
	flipByteAt(t, path, findOffset(t, path, []byte(`"outcome":"OK"`))+3)

	if _, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone}); err == nil {
		t.Fatal("appender opened on top of a corrupted chain")
	}
}

func hasKind(t *testing.T, dir string, kind evidence.Kind) bool {
	t.Helper()
	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		insp, err := segment.Inspect(segment.Path(dir, id))
		if err != nil {
			t.Fatal(err)
		}
		for _, rec := range insp.Records {
			h, err := evidence.DecodeHeader(rec.Header)
			if err != nil {
				t.Fatal(err)
			}
			if h.Kind == kind {
				return true
			}
		}
	}
	return false
}

func findOffset(t *testing.T, path string, needle []byte) int64 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+len(needle) <= len(b); i++ {
		if string(b[i:i+len(needle)]) == string(needle) {
			return int64(i)
		}
	}
	t.Fatalf("%q not found in %s", needle, path)
	return 0
}

func flipByteAt(t *testing.T, path string, off int64) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b[off] ^= 0x01
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// failingSigner refuses to sign, which is how these tests reach the write path's
// failure handling without a filesystem fault injector.
type failingSigner struct{ inner *keys.Signer }

func (f failingSigner) KeyID() string                 { return f.inner.KeyID() }
func (f failingSigner) Public() ed25519.PublicKey     { return f.inner.Public() }
func (f failingSigner) Sign(_ []byte) ([]byte, error) { return nil, errors.New("hsm unavailable") }

// TestWritePathFailureIsSticky is the fail-closed guarantee: once the
// evidence path cannot do its job, it must stop returning successes that a
// caller could read as permission to act.
func TestWritePathFailureIsSticky(t *testing.T) {
	signer := failingSigner{inner: mustSigner(t)}
	a, _ := newAppender(t, signer, func(o *evidence.Options) { o.SegmentTargetBytes = 1 })

	// The first append is durable and correctly acknowledged; the failure only
	// occurs when the segment is sealed on rotation right after it.
	if _, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindStepResult, Participant: evidence.ParticipantRef{ID: "ag"}, Payload: []byte(`{}`),
	}); err != nil {
		t.Fatalf("first append should have succeeded: %v", err)
	}

	var lastErr error
	for range 5 {
		_, lastErr = a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, Participant: evidence.ParticipantRef{ID: "ag"}, Payload: []byte(`{}`),
		})
		if lastErr != nil {
			break
		}
	}
	if lastErr == nil {
		t.Fatal("appends kept succeeding after the write path failed")
	}
	if !errors.Is(lastErr, evidence.ErrWritePathFailed) {
		t.Fatalf("got %v, want it to wrap evidence.ErrWritePathFailed", lastErr)
	}

	// And it stays failed rather than recovering on its own.
	if _, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindStepResult, Participant: evidence.ParticipantRef{ID: "ag"}, Payload: []byte(`{}`),
	}); !errors.Is(err, evidence.ErrWritePathFailed) {
		t.Fatalf("write path recovered by itself: %v", err)
	}
	_ = a.Close()
}

func TestAppendRejectsAfterClose(t *testing.T) {
	signer := mustSigner(t)
	a, _ := newAppender(t, signer, nil)
	appendN(t, a, 1, "sg")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Append(context.Background(), evidence.Request{Kind: evidence.KindStepResult}); !errors.Is(err, evidence.ErrClosed) {
		t.Fatalf("got %v, want evidence.ErrClosed", err)
	}
}

func TestAppendRequiresKind(t *testing.T) {
	signer := mustSigner(t)
	a, _ := newAppender(t, signer, nil)
	defer a.Close()
	if _, err := a.Append(context.Background(), evidence.Request{Payload: []byte("x")}); err == nil {
		t.Fatal("expected an error for an event with no kind")
	}
}

func TestVerifyRejectsUntrustedSigningKey(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, nil)
	appendN(t, a, 3, "sg")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	stranger := mustSigner(t)
	rep, err := verify.SegmentDir(dir, verify.Options{Keys: keySet(stranger), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("verification passed with a key set that does not contain the writer's key")
	}
	if !hasFinding(rep, "UNKNOWN_SIGNING_KEY") {
		t.Fatalf("expected UNKNOWN_SIGNING_KEY, got:\n%s", rep.Text())
	}
}

func TestVerifyRejectsUnsealedSegmentByDefault(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, nil)
	appendN(t, a, 3, "sg")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	unseal(t, segment.Path(dir, 1))

	rep := verifyDir(t, dir, signer)
	if rep.OK {
		t.Fatal("an unsigned segment verified")
	}
	if !hasFinding(rep, "SEGMENT_UNSEALED") {
		t.Fatalf("expected SEGMENT_UNSEALED, got:\n%s", rep.Text())
	}

	// The same log is acceptable when the caller knows the tail is still open.
	rep, err := verify.SegmentDir(dir, verify.Options{Keys: keySet(signer), AllowUnsealedTail: true, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("an open tail should be allowed when asked for:\n%s", rep.Text())
	}
}

func TestVerifyDetectsRemovedSegment(t *testing.T) {
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
		t.Fatalf("need at least three segments for this test, got %d", len(ids))
	}
	if err := os.Remove(segment.Path(dir, ids[1])); err != nil {
		t.Fatal(err)
	}

	rep := verifyDir(t, dir, signer)
	if rep.OK {
		t.Fatalf("deleting a whole segment went undetected:\n%s", rep.Text())
	}
	if !hasFinding(rep, "CHAIN_BREAK") && !hasFinding(rep, "SEQUENCE_GAP") {
		t.Fatalf("expected a chain break or sequence gap, got:\n%s", rep.Text())
	}
}

func hasFinding(rep *verify.Report, code string) bool {
	for _, f := range rep.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// TestAnOversizedEventIsRefusedWithoutStoppingTheLog.
//
// The segment writer refuses a record larger than MaxRecordLen, because its own
// reader does. But an AppendRecord failure is a *write-path* failure and sticky
// (ErrWritePathFailed), so leaving the refusal to the writer would mean one
// caller with an outsized payload stops the log for every other caller — a
// denial of service reachable by anybody who can append.
//
// So the appender declines it per-event, and the two halves of that are
// separately worth pinning: the caller is told no, and the next append works.
func TestAnOversizedEventIsRefusedWithoutStoppingTheLog(t *testing.T) {
	signer := mustSigner(t)
	a, _ := newAppender(t, signer, nil)
	defer func() { _ = a.Close() }()

	before := appendN(t, a, 1, "sg_before")

	_, err := a.Append(context.Background(), evidence.Request{
		Kind:        evidence.KindStepResult,
		SagaID:      "sg_huge",
		StepID:      "st_huge",
		Participant: evidence.ParticipantRef{ID: "ag_test", ManifestVersion: "1.0.0", Principal: "pr_test", Kind: "AGENT"},
		Payload:     make([]byte, segment.MaxRecordLen),
	})
	if err == nil {
		t.Fatal("an event larger than the segment format can frame was accepted")
	}
	if !errors.Is(err, segment.ErrRecordTooLarge) {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	// Not sticky: this is the caller's problem, not the log's.
	if errors.Is(err, evidence.ErrWritePathFailed) {
		t.Fatal("an oversized payload failed the whole write path. Any caller able to " +
			"append could then stop the log for everybody by sending one large event")
	}

	after := appendN(t, a, 1, "sg_after")
	if after[0].Seq != before[0].Seq+1 {
		t.Fatalf("the refused event consumed a sequence: %d then %d", before[0].Seq, after[0].Seq)
	}
}

// TestNoCounterTrailsAnAcknowledgement states an
// invariant: nothing this appender reports may lag what it has already told a
// caller.
//
// It used to, and not rarely. The publish phase indexed a record, answered its
// caller, and only then took statsMu — so with group commit the whole batch was
// acknowledged before any counter moved. Measured at the time: **0 of 3,000**
// sequential appends saw a stale counter and **2,980 of 3,000** concurrent ones
// did, which is why it read as a rare race and was not one. Three CI failures
// came out of it, in two tests and against two different counters.
//
// Concurrency is not decoration here. Run this loop sequentially against the old
// ordering and it passes every time: the writer goroutine has finished the stats
// update before a single caller is rescheduled. The bug only exists when
// somebody else is in the batch.
func TestNoCounterTrailsAnAcknowledgement(t *testing.T) {
	signer := mustSigner(t)
	a, _ := newAppender(t, signer, nil)
	defer func() { _ = a.Close() }()

	const n = 2000
	var stale, phaseStale atomic.Int64
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ref, err := a.Append(context.Background(), evidence.Request{
				Kind:        evidence.KindStepResult,
				SagaID:      "sg_ack",
				StepID:      fmt.Sprintf("st_%04d", i),
				Participant: evidence.ParticipantRef{ID: "ag_test", ManifestVersion: "1.0.0", Principal: "pr_test", Kind: "AGENT"},
				Payload:     []byte(`{"outcome":"OK"}`),
			})
			if err != nil {
				t.Errorf("append: %v", err)
				return
			}
			// The head this appender advertises -- and therefore the head
			// replica.FromAppender lets a follower copy up to -- must already
			// cover the record whose Ref we are holding.
			if a.Stats().LastSeq < ref.Seq {
				stale.Add(1)
			}
			// The same for the counters, because a test reading them right
			// after its own append is a reasonable thing to write and two in
			// this repository had to be taught not to.
			if a.Phases().Appends < 1 {
				phaseStale.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := stale.Load(); got > 0 {
		t.Errorf("%d of %d callers were told their event was recorded while Stats().LastSeq "+
			"still reported a sequence below it. A follower asking in that window is told a "+
			"head that excludes an acknowledged record, and a primary that dies before the "+
			"next poll leaves it on no replica", got, n)
	}
	if got := phaseStale.Load(); got > 0 {
		t.Errorf("%d of %d callers saw Phases().Appends at zero after their own append "+
			"returned", got, n)
	}
}
