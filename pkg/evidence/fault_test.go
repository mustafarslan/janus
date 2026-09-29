package evidence_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/fault"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// faultyLog opens an appender whose storage fails according to cfg.
func faultyLog(t *testing.T, cfg fault.Config, mutate func(*evidence.Options)) (*evidence.Appender, string, *keys.Signer, *fault.FS) {
	t.Helper()
	signer := mustSigner(t)
	fs := fault.New(cfg)
	dir := filepath.Join(t.TempDir(), "evidence")
	opts := evidence.Options{
		Dir:      dir,
		Signer:   signer,
		SyncMode: segment.SyncModeData,
		OpenFile: fs.Open,
	}
	if mutate != nil {
		mutate(&opts)
	}
	a, err := evidence.Open(opts)
	if err != nil {
		t.Fatalf("open with fault injection: %v", err)
	}
	return a, opts.Dir, signer, fs
}

// appendUntilFailure appends until the write path refuses, returning the
// sequence numbers that were acknowledged. Those are the events a caller was
// told it could act on, so they are exactly what must survive.
func appendUntilFailure(t *testing.T, a *evidence.Appender, limit int) ([]uint64, error) {
	t.Helper()
	var acked []uint64
	for i := range limit {
		ref, err := a.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      "sg_fault",
			StepID:      fmt.Sprintf("st_%04d", i),
			Participant: evidence.ParticipantRef{ID: "ag_fault"},
			Payload:     fmt.Appendf(nil, `{"i":%d,"pad":"%040d"}`, i, i),
		})
		if err != nil {
			return acked, err
		}
		acked = append(acked, ref.Seq)
	}
	return acked, nil
}

// assertAckedSurvive is the durability property under any fault: whatever was
// acknowledged is in the log after recovery, the chain verifies, and sequence
// numbers are contiguous. An event that was acked and then lost would mean a
// caller released a side effect on evidence that no longer exists.
func assertAckedSurvive(t *testing.T, dir string, signer *keys.Signer, acked []uint64) {
	t.Helper()

	// Recovery runs on open; it may truncate a torn tail and seal orphans.
	b, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatalf("recovery refused to open the damaged log: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("close after recovery: %v", err)
	}

	rep := verifyDir(t, dir, signer)
	if !rep.OK {
		t.Fatalf("log did not verify after recovery:\n%s", rep.Text())
	}

	present := map[uint64]bool{}
	for _, id := range mustScan(t, dir) {
		insp, err := segment.Inspect(segment.Path(dir, id))
		if err != nil {
			t.Fatal(err)
		}
		for _, rec := range insp.Records {
			h, err := evidence.DecodeHeader(rec.Header)
			if err != nil {
				t.Fatal(err)
			}
			if present[h.Seq] {
				t.Fatalf("sequence %d appears twice in the recovered log", h.Seq)
			}
			present[h.Seq] = true
		}
	}
	for _, seq := range acked {
		if !present[seq] {
			t.Fatalf("sequence %d was acknowledged to the caller but is missing after recovery", seq)
		}
	}
}

func mustScan(t *testing.T, dir string) []uint64 {
	t.Helper()
	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// TestDiskFullFailsClosed: when the disk fills mid-write, the append that could
// not be made durable must fail, the write path must stop, and everything
// already acknowledged must survive.
func TestDiskFullFailsClosed(t *testing.T) {
	a, dir, signer, fs := faultyLog(t, fault.Config{WriteBudgetBytes: 40 << 10}, nil)

	acked, err := appendUntilFailure(t, a, 5000)
	if err == nil {
		t.Fatal("the disk filled up but appends kept succeeding")
	}
	if !errors.Is(err, evidence.ErrWritePathFailed) {
		t.Fatalf("got %v, want it to wrap ErrWritePathFailed", err)
	}
	if len(acked) == 0 {
		t.Fatal("nothing was acknowledged before the failure; the test proves nothing")
	}
	_ = a.Close()

	if s := fs.Stats(); s.WriteFailures == 0 {
		t.Fatal("no write actually failed; the injector did not fire")
	}
	assertAckedSurvive(t, dir, signer, acked)
}

// TestShortWriteLeavesRecoverableTornTail is the torn-write case specifically:
// the budget is chosen so a write lands partially, leaving half a record on
// disk. Recovery must discard it rather than accept a record it cannot verify.
func TestShortWriteLeavesRecoverableTornTail(t *testing.T) {
	// A budget that is not a record boundary guarantees the cut falls mid-record.
	a, dir, signer, fs := faultyLog(t, fault.Config{WriteBudgetBytes: 20*1024 + 137}, nil)

	acked, err := appendUntilFailure(t, a, 5000)
	if err == nil {
		t.Fatal("expected the write path to fail once the budget ran out")
	}
	_ = a.Close()

	if s := fs.Stats(); s.ShortWrites == 0 {
		t.Skipf("no short write occurred (budget landed on a boundary); injector stats: %+v", s)
	}
	assertAckedSurvive(t, dir, signer, acked)
}

// TestSyncFailureFailsClosed: a barrier that refuses means durability cannot be
// claimed, so the append must fail even though the bytes reached the kernel.
func TestSyncFailureFailsClosed(t *testing.T) {
	// Let the segment be created and a few batches through, then refuse.
	a, dir, signer, fs := faultyLog(t, fault.Config{FailSyncAfter: 12}, nil)

	acked, err := appendUntilFailure(t, a, 2000)
	if err == nil {
		t.Fatal("the durability barrier failed but appends kept succeeding")
	}
	if !errors.Is(err, evidence.ErrWritePathFailed) {
		t.Fatalf("got %v, want it to wrap ErrWritePathFailed", err)
	}
	_ = a.Close()

	if s := fs.Stats(); s.SyncFailures == 0 {
		t.Fatal("no sync actually failed; the injector did not fire")
	}
	assertAckedSurvive(t, dir, signer, acked)
}

// TestDeviceDeathMidFlight models storage that stops answering entirely rather
// than filling gradually.
func TestDeviceDeathMidFlight(t *testing.T) {
	a, dir, signer, fs := faultyLog(t, fault.Config{}, nil)

	var acked []uint64
	for i := range 200 {
		ref, err := a.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      "sg_death",
			Participant: evidence.ParticipantRef{ID: "ag"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		})
		if err != nil {
			t.Fatalf("append %d failed before the device was stopped: %v", i, err)
		}
		acked = append(acked, ref.Seq)
	}

	fs.Stop()

	if _, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindStepResult, Participant: evidence.ParticipantRef{ID: "ag"}, Payload: []byte(`{}`),
	}); err == nil {
		t.Fatal("an append succeeded after the device stopped answering")
	}
	_ = a.Close()

	assertAckedSurvive(t, dir, signer, acked)
}

// TestSegmentCreationFailureFailsClosed: rotation needs a new file, and if the
// filesystem will not give one the writer must stop rather than continue
// without anywhere to put evidence.
func TestSegmentCreationFailureFailsClosed(t *testing.T) {
	a, dir, signer, _ := faultyLog(t, fault.Config{FailCreateAfter: 3},
		func(o *evidence.Options) { o.SegmentTargetBytes = 1024 })

	acked, err := appendUntilFailure(t, a, 2000)
	if err == nil {
		t.Fatal("segment creation failed but appends kept succeeding")
	}
	if !errors.Is(err, evidence.ErrWritePathFailed) {
		t.Fatalf("got %v, want it to wrap ErrWritePathFailed", err)
	}
	_ = a.Close()

	assertAckedSurvive(t, dir, signer, acked)
}

// TestNoFaultsIsANoOp guards the injector itself: with an empty config it must
// behave exactly like the real filesystem, or every test above is measuring the
// injector rather than Janus.
func TestNoFaultsIsANoOp(t *testing.T) {
	a, dir, signer, fs := faultyLog(t, fault.Config{}, func(o *evidence.Options) { o.SegmentTargetBytes = 2048 })

	acked, err := appendUntilFailure(t, a, 200)
	if err != nil {
		t.Fatalf("append failed with no faults configured: %v", err)
	}
	if len(acked) != 200 {
		t.Fatalf("acknowledged %d of 200 appends", len(acked))
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if s := fs.Stats(); s.WriteFailures != 0 || s.SyncFailures != 0 {
		t.Fatalf("injector fired with an empty config: %+v", s)
	}

	rep := verifyDir(t, dir, signer)
	if !rep.OK {
		t.Fatalf("log written through the injector did not verify:\n%s", rep.Text())
	}
}
