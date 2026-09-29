package continuous_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/continuous"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

func writeLog(t *testing.T, events int, segBytes int64) (string, *keys.Signer) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: segBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendTo(t, a, events)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, signer
}

func appendTo(t *testing.T, a *evidence.Appender, events int) {
	t.Helper()
	for i := range events {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      "sg_cv",
			Participant: evidence.ParticipantRef{ID: "ag"},
			Payload:     fmt.Appendf(nil, `{"i":%d,"pad":"%060d"}`, i, i),
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func newVerifier(t *testing.T, dir string, signer *keys.Signer, findings *[]verify.Finding) *continuous.Verifier {
	t.Helper()
	v, err := continuous.New(continuous.Config{
		Dir:            dir,
		Keys:           keys.PublicKeySet{signer.KeyID(): signer.Public()},
		CheckpointPath: filepath.Join(dir, "..", "checkpoint.json"),
		OnFinding: func(f verify.Finding) {
			if findings != nil {
				*findings = append(*findings, f)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestIncrementalDoesNotRereadTheWholeLog is the reason this package exists:
// verification cost has to stay flat as the log grows, or continuous
// verification stops being possible within hours.
func TestIncrementalDoesNotRereadTheWholeLog(t *testing.T) {
	dir, signer := writeLog(t, 200, 2048)
	v := newVerifier(t, dir, signer, nil)
	ctx := context.Background()

	first, err := v.Incremental(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !first.OK {
		t.Fatalf("first pass failed:\n%s", first.Text())
	}
	if first.Events == 0 {
		t.Fatal("the first pass verified nothing")
	}

	// Nothing has changed, so the second pass should have almost nothing to do.
	second, err := v.Incremental(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.Events >= first.Events {
		t.Fatalf("the second pass re-read %d events after the first read %d; "+
			"the checkpoint is not advancing", second.Events, first.Events)
	}

	cp := v.Checkpoint()
	if cp.NextSegment == 0 || cp.Seq == 0 {
		t.Fatalf("checkpoint did not advance: %+v", cp)
	}
}

// TestIncrementalPicksUpNewSegments: the pass has to see work that arrives
// after it last ran, and continue the chain across the boundary.
func TestIncrementalPicksUpNewSegments(t *testing.T) {
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir := filepath.Join(root, "evidence")

	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendTo(t, a, 100)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	v := newVerifier(t, dir, signer, nil)
	if _, err := v.Incremental(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := v.Checkpoint()

	// More work arrives.
	b, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendTo(t, b, 100)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := v.Incremental(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("verification of new segments failed:\n%s", rep.Text())
	}
	after := v.Checkpoint()
	if after.Seq <= before.Seq {
		t.Fatalf("checkpoint did not advance over new work: %d -> %d", before.Seq, after.Seq)
	}
}

// TestSweepCatchesTamperingTheIncrementalPassWouldMiss is the argument for
// having two passes at all. Editing an old segment is invisible to a verifier
// that only ever looks at new ones — which is precisely the insider attack the
// chain exists to catch.
func TestSweepCatchesTamperingTheIncrementalPassWouldMiss(t *testing.T) {
	dir, signer := writeLog(t, 300, 2048)
	var findings []verify.Finding
	v := newVerifier(t, dir, signer, &findings)
	ctx := context.Background()

	if _, err := v.Incremental(ctx); err != nil {
		t.Fatal(err)
	}
	if !v.Status().Healthy {
		t.Fatal("a clean log was reported unhealthy")
	}

	// Tamper with the first segment, long behind the checkpoint.
	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) < 3 {
		t.Fatalf("need several segments, got %d", len(ids))
	}
	tamper(t, segment.Path(dir, ids[0]))

	// The incremental pass is blind to it, by design.
	inc, err := v.Incremental(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !inc.OK {
		t.Fatal("the incremental pass unexpectedly re-read an old segment; " +
			"this test no longer proves the sweep is necessary")
	}

	// The sweep finds it. Run slices until it completes a pass.
	found := false
	for range len(ids) + 2 {
		rep, done, err := v.SweepStep(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		if rep != nil && !rep.OK {
			found = true
			break
		}
		if done {
			break
		}
	}
	if !found {
		t.Fatal("the rolling sweep did not detect tampering with an old segment")
	}
	if v.Status().Healthy {
		t.Fatal("status stayed healthy after tampering was found")
	}
	if len(findings) == 0 {
		t.Fatal("no alert fired for the tampering")
	}
}

// TestUnhealthyIsSticky: a log that was tampered with does not become
// untampered because a later pass happened to look elsewhere.
func TestUnhealthyIsSticky(t *testing.T) {
	dir, signer := writeLog(t, 200, 2048)
	v := newVerifier(t, dir, signer, nil)
	ctx := context.Background()

	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	tamper(t, segment.Path(dir, ids[0]))

	for range len(ids) + 2 {
		if _, _, err := v.SweepStep(ctx, 1); err != nil {
			t.Fatal(err)
		}
		if !v.Status().Healthy {
			break
		}
	}
	if v.Status().Healthy {
		t.Fatal("tampering was never detected")
	}
	// Further clean passes must not clear it.
	for range 3 {
		if _, err := v.Incremental(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if v.Status().Healthy {
		t.Fatal("a later clean pass reset the health status")
	}
}

// TestSweepCompletesAndRestarts: the sweep has to wrap around, or it stops
// checking history once it reaches the end.
func TestSweepCompletesAndRestarts(t *testing.T) {
	dir, signer := writeLog(t, 150, 2048)
	v := newVerifier(t, dir, signer, nil)
	ctx := context.Background()

	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	completed := 0
	for range len(ids)*2 + 4 {
		_, done, err := v.SweepStep(ctx, 2)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			completed++
		}
	}
	if completed == 0 {
		t.Fatal("the sweep never completed a pass")
	}
	if v.Status().SweepsCompleted == 0 {
		t.Fatal("completed sweeps were not counted")
	}
	if !v.Status().Healthy {
		t.Fatal("a clean log was reported unhealthy by the sweep")
	}
}

// TestSweepCompletesWhileTheLogIsStillGrowing is the case a static fixture
// cannot reach and a deployment never leaves.
//
// A pass has to cover the log as it stood when the pass began. If instead it
// runs to whatever the end happens to be at each step, the cursor catches the
// tail of a log that is still being written and then follows it: from that point
// on the sweep re-reads only the newest segments — exactly what the incremental
// pass already covers — never returns to segment 1, and never registers a
// completed pass.
//
// The symptom is silence rather than an error. Status goes on reporting a
// healthy log and a HistoryCheckedWithin of one sweep interval, while in fact
// nothing has looked at an old segment since the first pass, which is precisely
// the window an insider editing history needs.
func TestSweepCompletesWhileTheLogIsStillGrowing(t *testing.T) {
	dir, signer := writeLog(t, 120, 2048)
	v := newVerifier(t, dir, signer, nil)
	ctx := context.Background()

	completed := 0
	for range 40 {
		_, done, err := v.SweepStep(ctx, 4)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			completed++
		}

		// The log grows between steps, the way it does in a running system.
		a, err := evidence.Open(evidence.Options{
			Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 2048,
		})
		if err != nil {
			t.Fatal(err)
		}
		appendTo(t, a, 8)
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
	}

	if completed == 0 {
		t.Fatalf("the sweep never completed a pass over a growing log, so nothing " +
			"re-read an old segment: history is unverified while Status still calls the log healthy")
	}
	if v.Status().SweepsCompleted == 0 {
		t.Fatal("completed sweeps over a growing log were not counted")
	}
}

// TestCheckpointSurvivesRestart: without persistence every restart re-reads the
// whole log, which on a large one is exactly the cost this design avoids.
func TestCheckpointSurvivesRestart(t *testing.T) {
	dir, signer := writeLog(t, 200, 2048)
	v := newVerifier(t, dir, signer, nil)
	if _, err := v.Incremental(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved := v.Checkpoint()
	if saved.NextSegment == 0 {
		t.Fatal("checkpoint did not advance")
	}

	reopened := newVerifier(t, dir, signer, nil)
	got := reopened.Checkpoint()
	if got.NextSegment != saved.NextSegment || got.Seq != saved.Seq || got.Chain != saved.Chain {
		t.Fatalf("checkpoint did not survive a restart:\n saved %+v\n  got  %+v", saved, got)
	}

	rep, err := reopened.Incremental(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("verification after restart failed:\n%s", rep.Text())
	}
}

// TestDamagedCheckpointDoesNotStopTheVerifier: refusing to start because a
// cache is corrupt would turn a bad file into an outage of the very thing that
// watches for corruption.
func TestDamagedCheckpointDoesNotStopTheVerifier(t *testing.T) {
	dir, signer := writeLog(t, 100, 2048)
	path := filepath.Join(dir, "..", "checkpoint.json")
	if err := os.WriteFile(path, []byte("this is not json"), 0o640); err != nil {
		t.Fatal(err)
	}

	v := newVerifier(t, dir, signer, nil)
	rep, err := v.Incremental(context.Background())
	if err != nil {
		t.Fatalf("a damaged checkpoint stopped the verifier: %v", err)
	}
	if !rep.OK {
		t.Fatalf("verification failed after a damaged checkpoint:\n%s", rep.Text())
	}
	if v.Checkpoint().NextSegment == 0 {
		t.Fatal("the verifier did not re-establish a checkpoint")
	}
}

// TestStatusStatesItsOwnStaleness: quoting the incremental interval as the
// detection latency would overstate the guarantee, because history is only
// covered once per sweep.
func TestStatusStatesItsOwnStaleness(t *testing.T) {
	dir, signer := writeLog(t, 50, 4096)
	v, err := continuous.New(continuous.Config{
		Dir:           dir,
		Keys:          keys.PublicKeySet{signer.KeyID(): signer.Public()},
		SweepInterval: 90 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Status().HistoryCheckedWithin; got != 90*time.Minute {
		t.Fatalf("status reports history coverage of %s, want the sweep interval of 90m", got)
	}
}

func TestRequiresTrustedKeys(t *testing.T) {
	dir, _ := writeLog(t, 10, 4096)
	if _, err := continuous.New(continuous.Config{Dir: dir}); err == nil {
		t.Fatal("a verifier was built with no trusted keys, so it would only check the log against itself")
	}
	if _, err := continuous.New(continuous.Config{Keys: keys.PublicKeySet{"k": nil}}); err == nil {
		t.Fatal("a verifier was built with no directory")
	}
}

// TestRunStopsOnContextCancel guards against a background service that ignores
// shutdown.
func TestRunStopsOnContextCancel(t *testing.T) {
	dir, signer := writeLog(t, 50, 4096)
	v, err := continuous.New(continuous.Config{
		Dir:                 dir,
		Keys:                keys.PublicKeySet{signer.KeyID(): signer.Public()},
		IncrementalInterval: 10 * time.Millisecond,
		SweepTick:           10 * time.Millisecond,
		SweepInterval:       50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- v.Run(ctx) }()

	time.Sleep(120 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop when its context was cancelled")
	}

	if v.Status().IncrementalRuns < 2 {
		t.Fatalf("Run performed %d incremental passes; it does not appear to have been working",
			v.Status().IncrementalRuns)
	}
}

// tamper flips a bit in the middle of a segment file.
func tamper(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 0x01
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// rotate writes more records under a new key, optionally declaring the next one
// first. Declaring happens under the *current* signer, which is what makes the
// chain a chain.
func rotate(t *testing.T, dir string, signer *keys.Signer, declare *keys.Signer, events int) {
	t.Helper()
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	if declare != nil {
		if _, err := a.RecordWriterKey(context.Background(), evidence.WriterKeyDeclaration{
			Kind: evidence.WriterKeyTrusted, KeyID: declare.KeyID(), PublicKey: declare.Public(),
		}, evidence.ParticipantRef{ID: "sys_test", Kind: "SYSTEM"}); err != nil {
			t.Fatal(err)
		}
	}
	appendTo(t, a, events)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestTheIncrementalPassSurvivesAKeyRotation.
//
// Key declarations exist so an auditor needs one key rather than all of them: a
// WRITER_KEY declaration in a segment the old key signed introduces the new one.
// That worked end to end and not incrementally — each pass built its trust from
// the configured roots alone, so a pass starting after the declaration reported
// UNKNOWN_SIGNING_KEY on every segment the new key signed.
//
// The consequence is worse than a wrong report. `Incremental` advances the
// checkpoint only when the pass is OK, so the verifier would stop advancing
// entirely: the log stops being verified at the rotation, and the alert says it
// cannot be verified — for the one operation key declarations were built to support.
func TestTheIncrementalPassSurvivesAKeyRotation(t *testing.T) {
	dir, root := writeLog(t, 100, 2048)
	next, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// The declaration, while the root is still the writer.
	rotate(t, dir, root, next, 20)

	var findings []verify.Finding
	v := newVerifier(t, dir, root, &findings)
	if _, err := v.Incremental(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := v.Checkpoint()
	if before.NextSegment == 0 {
		t.Fatal("the first pass advanced nothing, so the second would start at the beginning")
	}

	// The rotation itself: segments signed by the declared successor.
	rotate(t, dir, next, nil, 100)

	rep, err := v.Incremental(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("the pass after a rotation failed:\n%s", rep.Text())
	}
	if after := v.Checkpoint(); after.NextSegment <= before.NextSegment {
		t.Errorf("the checkpoint stopped advancing at the rotation: %d then %d",
			before.NextSegment, after.NextSegment)
	}
	for _, f := range findings {
		if f.Severity == verify.Critical {
			t.Errorf("a routine key rotation raised a critical finding: %s %s", f.Code, f.Message)
		}
	}
	// The report has to say the key came from the log rather than from the
	// operator, or an auditor reading it concludes they had to trust two keys
	// directly when they trusted one.
	if origin := rep.SigningKeys[next.KeyID()]; origin == "supplied out of band" {
		t.Errorf("the rotated key is reported as %q; it was carried, not handed over", origin)
	}
}

// TestARotationSurvivesARestart is the half the in-memory fix does not reach.
//
// A restart resumes from the checkpoint, mid-log, with the configured roots —
// which is the same position the running verifier was in, so the same failure.
// The trust set is in the checkpoint for this reason, at the cost that whoever
// can write the checkpoint file can introduce a signer.
func TestARotationSurvivesARestart(t *testing.T) {
	dir, root := writeLog(t, 100, 2048)
	next, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	rotate(t, dir, root, next, 20)

	v := newVerifier(t, dir, root, nil)
	if _, err := v.Incremental(context.Background()); err != nil {
		t.Fatal(err)
	}
	rotate(t, dir, next, nil, 100)
	if _, err := v.Incremental(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved := v.Checkpoint()
	if len(saved.TrustedKeys) < 2 {
		t.Fatalf("the checkpoint carries %d keys; the log introduced one on top of the root",
			len(saved.TrustedKeys))
	}

	// A new process, the same checkpoint file, and only the root in its config.
	rotate(t, dir, next, nil, 100)
	reopened := newVerifier(t, dir, root, nil)
	rep, err := reopened.Incremental(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a restart after a rotation cannot verify its own log:\n%s", rep.Text())
	}
}

// TestARevokedRootDoesNotComeBack is the reason the carried set replaces the
// configured roots instead of joining them.
//
// Revocation is forward-only: a key revoked at sequence N keeps its
// earlier segments verifying and signs nothing after. If each pass started from
// `cfg.Keys` united with what it had learned, the operator's config file would
// re-trust the revoked key on every tick, and the revocation would hold for
// exactly as long as one process lived.
func TestARevokedRootDoesNotComeBack(t *testing.T) {
	dir, root := writeLog(t, 100, 2048)
	next, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// Declare the successor and revoke the root, both under the root, which is
	// the only key that can do either at this point — and then stop writing
	// under it. A revocation is forward-only, so the segment carrying it still
	// verifies; anything the root signs *after* it does not, which is the
	// property the last third of this test exercises deliberately.
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: root, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []evidence.WriterKeyDeclaration{
		{Kind: evidence.WriterKeyTrusted, KeyID: next.KeyID(), PublicKey: next.Public()},
		{Kind: evidence.WriterKeyRevoked, KeyID: root.KeyID(), PublicKey: root.Public(),
			Reason: "retired in favour of the successor declared above"},
	} {
		if _, err := a.RecordWriterKey(context.Background(), d,
			evidence.ParticipantRef{ID: "sys_test", Kind: "SYSTEM"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	// The successor takes over, as it must.
	rotate(t, dir, next, nil, 60)

	v := newVerifier(t, dir, root, nil)
	rep0, err := v.Incremental(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep0.OK {
		t.Fatalf("a clean rotation-and-revocation does not verify:\n%s", rep0.Text())
	}
	cp := v.Checkpoint()
	if _, still := cp.TrustedKeys[root.KeyID()]; still {
		t.Error("the revoked root is still in the carried set, so the next pass would " +
			"accept segments it signed after its own revocation")
	}
	if _, ok := cp.TrustedKeys[next.KeyID()]; !ok {
		t.Fatal("the successor is not in the carried set")
	}

	// And it stays out on the next pass, which is the assertion a union with
	// cfg.Keys would fail: the operator's config still holds the root, and a
	// verifier that started each pass from "my roots plus what I have learned"
	// would re-trust it every tick, making the revocation last exactly as long
	// as one process.
	//
	// The writer path cannot produce the corresponding segments to check the
	// other way round — `evidence.Open` refuses a revoked key outright, with
	// "a writer using it would produce segments that fail verification from the
	// log's own root". The risk here is the verifier widening, not the writer.
	rotate(t, dir, next, nil, 60)
	if _, err := v.Incremental(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, back := v.Checkpoint().TrustedKeys[root.KeyID()]; back {
		t.Error("the revoked root came back on the next pass")
	}
}
