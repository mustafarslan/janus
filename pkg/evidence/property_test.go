package evidence_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/fault"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// Property tests generate a random history and assert the invariants that must
// hold no matter what happened. This is the highest-leverage
// investment for a system like this, because the failure modes that matter are
// the ones nobody thought to write a case for.
//
// Every run prints its seed, and the seed can be pinned with JANUS_SEED, so a
// failure found in CI is reproduced locally by copying one number.

// seedFor returns the seed for a property run, honouring JANUS_SEED.
func seedFor(t *testing.T) uint64 {
	t.Helper()
	if s := os.Getenv("JANUS_SEED"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("JANUS_SEED=%q is not a number: %v", s, err)
		}
		return v
	}
	return uint64(time.Now().UnixNano())
}

// scenario is one randomly generated configuration.
type scenario struct {
	Seed           uint64
	SegmentBytes   int64
	MaxBatchEvents int
	Payload        int
	Producers      int
	Events         int
	SyncMode       segment.SyncMode
	Fault          fault.Config
	FaultKind      string
}

func (s scenario) String() string {
	return fmt.Sprintf("seed=%d segBytes=%d maxBatch=%d payload=%d producers=%d events=%d sync=%s fault=%s%+v",
		s.Seed, s.SegmentBytes, s.MaxBatchEvents, s.Payload, s.Producers, s.Events, s.SyncMode, s.FaultKind, s.Fault)
}

func generateScenario(rng *rand.Rand, seed uint64) scenario {
	s := scenario{
		Seed: seed,
		// Small segments so rotation, background sealing, and pre-creation are
		// exercised many times in a short run.
		SegmentBytes:   int64(256 + rng.IntN(8192)),
		MaxBatchEvents: 1 + rng.IntN(64),
		Payload:        rng.IntN(512),
		Producers:      1 + rng.IntN(8),
		Events:         50 + rng.IntN(400),
		SyncMode:       segment.SyncModeNone,
	}

	switch rng.IntN(4) {
	case 0:
		s.FaultKind = "none"
	case 1:
		s.FaultKind = "disk-full"
		s.Fault.WriteBudgetBytes = int64(2048 + rng.IntN(64*1024))
	case 2:
		s.FaultKind = "sync-failure"
		s.Fault.FailSyncAfter = 3 + rng.IntN(60)
	case 3:
		s.FaultKind = "create-failure"
		s.Fault.FailCreateAfter = 2 + rng.IntN(12)
	}
	return s
}

// runScenario plays the scenario out and returns the sequence numbers that were
// acknowledged to callers.
func runScenario(t *testing.T, sc scenario, dir string, signer *keys.Signer) []uint64 {
	t.Helper()

	fs := fault.New(sc.Fault)
	a, err := evidence.Open(evidence.Options{
		Dir:                dir,
		Signer:             signer,
		SyncMode:           sc.SyncMode,
		SegmentTargetBytes: sc.SegmentBytes,
		MaxBatchEvents:     sc.MaxBatchEvents,
		OpenFile:           fs.Open,
	})
	if err != nil {
		// Only a create fault can legitimately prevent opening at all.
		if sc.Fault.FailCreateAfter > 0 {
			return nil
		}
		t.Fatalf("%s: open: %v", sc, err)
	}

	body := make([]byte, sc.Payload)
	for i := range body {
		body[i] = byte('a' + i%26)
	}

	type result struct{ seqs []uint64 }
	results := make([]result, sc.Producers)
	done := make(chan int, sc.Producers)

	per := sc.Events / sc.Producers
	for p := range sc.Producers {
		go func(p int) {
			for range per {
				ref, err := a.Append(context.Background(), evidence.Request{
					Kind:        evidence.KindStepResult,
					SagaID:      fmt.Sprintf("sg_%02d", p),
					Participant: evidence.ParticipantRef{ID: "ag_prop"},
					Payload:     body,
				})
				if err != nil {
					break // the write path failed; that is allowed, losing data is not
				}
				results[p].seqs = append(results[p].seqs, ref.Seq)
			}
			done <- p
		}(p)
	}
	for range sc.Producers {
		<-done
	}
	_ = a.Close()

	var acked []uint64
	for _, r := range results {
		acked = append(acked, r.seqs...)
	}
	return acked
}

// TestPropertyRecoveryHoldsUnderRandomHistories is the core property loop.
func TestPropertyRecoveryHoldsUnderRandomHistories(t *testing.T) {
	base := seedFor(t)
	t.Logf("property base seed %d (rerun with JANUS_SEED=%d)", base, base)

	rounds := 40
	if testing.Short() {
		rounds = 8
	}

	for i := range rounds {
		seed := base + uint64(i)
		rng := rand.New(rand.NewPCG(seed, 0x9E3779B97F4A7C15))
		sc := generateScenario(rng, seed)

		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			signer := mustSigner(t)
			dir := filepath.Join(t.TempDir(), "evidence")

			acked := runScenario(t, sc, dir, signer)

			ids, err := segment.ScanDir(dir)
			if err != nil || len(ids) == 0 {
				// A create fault can stop the log before it exists at all.
				if sc.Fault.FailCreateAfter > 0 && len(acked) == 0 {
					return
				}
				t.Fatalf("%s: no segments on disk (err %v) but %d events were acknowledged", sc, err, len(acked))
			}

			checkInvariants(t, sc, dir, signer, acked)
		})
	}
}

// regressionSeeds are scenarios that once found a real bug. Keeping them pinned
// is the point of seeded generation: a failure that took a random search to find
// should never need finding twice.
var regressionSeeds = []struct {
	seed uint64
	bug  string
}{
	{
		seed: 1785055665200799001,
		bug: "recovery refused to truncate a torn tail because a pre-created " +
			"placeholder sat after it, so the segment was no longer the last file",
	},
	{
		seed: 1785055665200799007,
		bug: "the disk filled while a segment was being created, leaving a file " +
			"too short to hold a header, which recovery treated as corruption",
	},
	{
		seed: 1785055836525780020,
		bug: "a torn footer left by the background sealer sat in a segment that " +
			"had fully-written segments after it, which a position-based rule rejected",
	},
}

func TestPropertyRegressionSeeds(t *testing.T) {
	for _, rc := range regressionSeeds {
		t.Run(fmt.Sprintf("seed_%d", rc.seed), func(t *testing.T) {
			t.Logf("regression: %s", rc.bug)
			rng := rand.New(rand.NewPCG(rc.seed, 0x9E3779B97F4A7C15))
			sc := generateScenario(rng, rc.seed)

			signer := mustSigner(t)
			dir := filepath.Join(t.TempDir(), "evidence")
			acked := runScenario(t, sc, dir, signer)

			if ids, err := segment.ScanDir(dir); err != nil || len(ids) == 0 {
				if sc.Fault.FailCreateAfter > 0 && len(acked) == 0 {
					return
				}
				t.Fatalf("%s: no segments on disk (err %v)", sc, err)
			}
			checkInvariants(t, sc, dir, signer, acked)
		})
	}
}

// checkInvariants asserts everything that must be true of a log after whatever
// happened to it.
func checkInvariants(t *testing.T, sc scenario, dir string, signer *keys.Signer, acked []uint64) {
	t.Helper()

	// Recovery must succeed. Refusing to open is only correct when the chain is
	// genuinely broken, which no scenario here should produce.
	b, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatalf("%s: recovery refused to open: %v", sc, err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("%s: close after recovery: %v", sc, err)
	}

	// I2: the whole log verifies, signatures and all.
	rep, err := verify.SegmentDir(dir, verify.Options{Keys: keySet(signer), Version: "property"})
	if err != nil {
		t.Fatalf("%s: verify: %v", sc, err)
	}
	if !rep.OK {
		t.Fatalf("%s: log did not verify after recovery:\n%s", sc, rep.Text())
	}

	// Sequence numbers are unique and contiguous from 1: a gap would mean a
	// record vanished from the middle, a duplicate that two events share an
	// identity.
	seen := map[uint64]bool{}
	var maxSeq uint64
	for _, id := range mustScan(t, dir) {
		insp, err := segment.Inspect(segment.Path(dir, id))
		if err != nil {
			t.Fatalf("%s: inspect segment %d: %v", sc, id, err)
		}
		for _, rec := range insp.Records {
			h, err := evidence.DecodeHeader(rec.Header)
			if err != nil {
				t.Fatalf("%s: decode header: %v", sc, err)
			}
			if seen[h.Seq] {
				t.Fatalf("%s: sequence %d appears twice", sc, h.Seq)
			}
			seen[h.Seq] = true
			maxSeq = max(maxSeq, h.Seq)
		}
	}
	for i := uint64(1); i <= maxSeq; i++ {
		if !seen[i] {
			t.Fatalf("%s: sequence %d is missing from a log whose head is %d", sc, i, maxSeq)
		}
	}

	// The durability property: nothing acknowledged may be lost.
	for _, seq := range acked {
		if !seen[seq] {
			t.Fatalf("%s: sequence %d was acknowledged to a caller but is not in the recovered log", sc, seq)
		}
	}
}

// TestPropertyRepeatedRecoveryIsIdempotent: opening and closing a log over and
// over must not change it or grow it without bound. Recovery that repairs
// something on every pass would mean it never actually converges.
func TestPropertyRepeatedRecoveryIsIdempotent(t *testing.T) {
	signer := mustSigner(t)
	a, dir := newAppender(t, signer, func(o *evidence.Options) { o.SegmentTargetBytes = 1024 })
	appendN(t, a, 60, "sg_idem")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	head := ""
	for round := range 5 {
		b, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
		if err != nil {
			t.Fatalf("round %d: open: %v", round, err)
		}
		if err := b.Close(); err != nil {
			t.Fatalf("round %d: close: %v", round, err)
		}

		rep := verifyDir(t, dir, signer)
		if !rep.OK {
			t.Fatalf("round %d: log did not verify:\n%s", round, rep.Text())
		}
		if round == 0 {
			head = rep.HeadChain
			continue
		}
		if rep.HeadChain != head {
			t.Fatalf("round %d: a clean open/close changed the head chain from %s to %s", round, head, rep.HeadChain)
		}
		if hasKind(t, dir, evidence.KindRecovery) {
			t.Fatalf("round %d: a clean restart recorded a RECOVERY event", round)
		}
	}
}
