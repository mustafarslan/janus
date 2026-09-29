package evidence_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/fault"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// settle blocks until no barrier has been taken for a quiet interval, so a
// count started afterwards sees only what the test itself causes.
func settle(t *testing.T, fs *fault.FS) {
	t.Helper()
	last := fs.Stats().Syncs
	for range 200 {
		time.Sleep(10 * time.Millisecond)
		now := fs.Stats().Syncs
		if now == last {
			return
		}
		last = now
	}
	t.Fatal("the log never stopped taking durability barriers on its own")
}

// pairRequests is two ordinary records, the second citing the first by an event
// id the caller chose. It is the shape AppendPair exists for.
func pairRequests(t *testing.T) (evidence.Request, evidence.Request) {
	t.Helper()
	const id = "0199b0c0-0000-7000-8000-00000000beef"
	return evidence.Request{
			Kind:        evidence.KindDPR,
			EventID:     id,
			SagaID:      "sg_pair",
			StepID:      "st",
			Participant: evidence.ParticipantRef{ID: "ag_pair"},
			Payload:     []byte(`{"why":"the checks that were run"}`),
		}, evidence.Request{
			Kind:        evidence.KindGateVerdict,
			SagaID:      "sg_pair",
			StepID:      "st",
			Participant: evidence.ParticipantRef{ID: "ag_pair"},
			Payload:     fmt.Appendf(nil, `{"dpr_ref":%q}`, id),
		}
}

// The claim the shared barrier rests on: a pair with no decision between them pays one
// durability barrier, not two.
//
// The barrier is what the entry measured and what a saga pays nine of, so the
// count of syncs is the number under test — not the elapsed time, which would
// make this a benchmark that passes on a fast disk.
func TestAPairPaysOneBarrier(t *testing.T) {
	a, _, _, fs := faultyLog(t, fault.Config{}, nil)
	defer a.Close()

	first, second := pairRequests(t)

	// One append before anything is counted. Opening a log prepares the *next*
	// segment on a background goroutine, and that Create carries a barrier of
	// its own; a count started at Open would race it. Nothing after the first
	// acknowledged append creates a segment until this one fills, which at
	// these payload sizes it never does.
	warm := first
	warm.EventID = ""
	if _, err := a.Append(context.Background(), warm); err != nil {
		t.Fatalf("warm-up append: %v", err)
	}

	// Then wait for that background Create to land. It is the only barrier in
	// this log that this test does not cause, and it is off the writer's
	// goroutine, so the count is read until it holds still rather than assumed
	// to have settled.
	settle(t, fs)

	const pairs = 20
	before := fs.Stats().Syncs
	for i := range pairs {
		f, s := first, second
		f.EventID = fmt.Sprintf("0199b0c0-0000-7000-8000-%012d", i)
		s.Payload = fmt.Appendf(nil, `{"dpr_ref":%q}`, f.EventID)
		if _, _, err := a.AppendPair(context.Background(), f, s); err != nil {
			t.Fatalf("AppendPair %d: %v", i, err)
		}
	}
	if got := fs.Stats().Syncs - before; got != pairs {
		t.Fatalf("%d pairs took %d durability barriers, want %d", pairs, got, pairs)
	}

	// The same records submitted one at a time take two barriers each, which is
	// what makes the number above a result rather than a property of this disk.
	before = fs.Stats().Syncs
	for i := range pairs {
		f, s := first, second
		f.EventID = ""
		s.Payload = fmt.Appendf(nil, `{"dpr_ref":"separate %d"}`, i)
		if _, err := a.Append(context.Background(), f); err != nil {
			t.Fatalf("Append first %d: %v", i, err)
		}
		if _, err := a.Append(context.Background(), s); err != nil {
			t.Fatalf("Append second %d: %v", i, err)
		}
	}
	if got := fs.Stats().Syncs - before; got != 2*pairs {
		t.Fatalf("%d separate pairs took %d barriers, want %d", pairs, got, 2*pairs)
	}
}

// Both records land, in the order they were submitted, with the chain running
// through them. One barrier must not become one record.
func TestAPairIsTwoRecordsInOrder(t *testing.T) {
	a, dir, signer, _ := faultyLog(t, fault.Config{}, nil)
	first, second := pairRequests(t)

	dprRef, verdictRef, err := a.AppendPair(context.Background(), first, second)
	if err != nil {
		t.Fatalf("AppendPair: %v", err)
	}
	if dprRef.EventID != first.EventID {
		t.Fatalf("the DPR got event id %q, want the caller's %q", dprRef.EventID, first.EventID)
	}
	if verdictRef.Seq != dprRef.Seq+1 {
		t.Fatalf("the verdict is seq %d and the DPR seq %d; the pair is out of order",
			verdictRef.Seq, dprRef.Seq)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	verifyDir(t, dir, signer)
}

// If either record is refused, both are — and the one that was not at fault
// does not reach the log.
//
// The case that makes this more than tidiness is a refused *first* record. The
// second cites it by event id, so writing the second alone would put a verdict
// in the log whose DprRef points at a record that was never written: a dangling
// reference in an audit trail, and one that verifies, because nothing in the
// chain checks that a cited id exists. Refusing the unit is what stops it.
func TestARefusedPartnerRefusesThePair(t *testing.T) {
	a, dir, signer, _ := faultyLog(t, fault.Config{}, nil)

	first, second := pairRequests(t)
	// Over the segment format's ceiling, so the writer declines this one record
	// on its own terms rather than failing the whole write path.
	first.Payload = []byte(strings.Repeat("x", segment.MaxRecordLen+1))

	dprRef, verdictRef, err := a.AppendPair(context.Background(), first, second)
	if !errors.Is(err, segment.ErrRecordTooLarge) {
		t.Fatalf("AppendPair with an oversized first record: err = %v, want ErrRecordTooLarge", err)
	}
	if dprRef != (evidence.Ref{}) || verdictRef != (evidence.Ref{}) {
		t.Fatalf("a refused pair handed back refs: %+v %+v", dprRef, verdictRef)
	}

	// The appender is still usable: a per-record refusal is not a write-path
	// failure, and refusing a unit must not have made it one.
	ok := second
	ok.Kind, ok.Payload = evidence.KindStepResult, []byte(`{"unrelated":true}`)
	if _, err := a.Append(context.Background(), ok); err != nil {
		t.Fatalf("the appender is unusable after a refused pair: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The verdict that cited the refused DPR is not in the log.
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
			if h.Kind == evidence.KindGateVerdict {
				t.Fatalf("seq %d is a gate verdict citing a DPR that was refused; "+
					"its DprRef points at a record that does not exist", h.Seq)
			}
		}
	}
	verifyDir(t, dir, signer)
}

// The unit is indivisible, and this is what shows it rather than assuming it.
//
// With MaxBatchEvents at one, the writer may put exactly one *unit* in a batch.
// Two records submitted separately are two units and cannot share a barrier, by
// the appender's own cap. A pair is one unit and still does — which is the
// difference between two records that coalesced because the queue happened to
// have both of them and two records that were promised they would.
//
// That distinction is not academic. At Linger zero, two submissions made
// back-to-back without waiting almost always land in one batch anyway: the
// writer picks the first up and fill drains the second before syncing. The
// latency is the same. What is not the same is the guarantee — nothing stops
// the writer from taking the first and starting a barrier before the second
// arrives, and a caller that acted on the first Ref would then have acted on a
// decision whose verdict was not yet on the record.
func TestAPairIsOneUnitEvenWhenABatchHoldsOne(t *testing.T) {
	a, _, _, fs := faultyLog(t, fault.Config{}, func(o *evidence.Options) {
		o.MaxBatchEvents = 1
	})
	defer a.Close()

	first, second := pairRequests(t)
	warm := first
	warm.EventID = ""
	if _, err := a.Append(context.Background(), warm); err != nil {
		t.Fatalf("warm-up append: %v", err)
	}
	settle(t, fs)

	before := fs.Stats().Syncs
	if _, _, err := a.AppendPair(context.Background(), first, second); err != nil {
		t.Fatalf("AppendPair: %v", err)
	}
	if got := fs.Stats().Syncs - before; got != 1 {
		t.Fatalf("a pair took %d barriers with MaxBatchEvents at 1, want 1", got)
	}
	if got := a.Stats().Batches; got == 0 {
		t.Fatal("no batches recorded")
	}
}

// The chaos scenario for a shared barrier: the disk gives out partway through
// writing a pair, so the cut lands between the two records that share a barrier.
//
// What this proves is narrower than "both or neither", and the difference is
// worth stating because the entry originally asked for the wrong thing. A
// shared barrier changes when callers are told, not what the platter holds
// mid-batch: the first record's bytes can be on disk with the second's missing
// or half-written, exactly as they could when the two were separate appends and
// the machine died between them. What the pair guarantees is that neither
// caller was told yes. So the property under test is the one that has always
// held — whatever was acknowledged survives, the chain verifies, and the
// recovered log is one a saga can resume from — now asserted with the cut
// falling inside a unit.
func TestAPairTornByAFullDisk(t *testing.T) {
	// A cut inside the pair rather than before it: the budget admits a few
	// records comfortably and then runs out partway through one.
	for _, budget := range []int64{700, 900, 1100, 1300} {
		t.Run(fmt.Sprintf("budget %d", budget), func(t *testing.T) {
			a, dir, signer, _ := faultyLog(t, fault.Config{WriteBudgetBytes: budget}, nil)

			var acked []uint64
			first, second := pairRequests(t)
			for i := range 8 {
				f, s := first, second
				f.EventID = fmt.Sprintf("0199b0c0-0000-7000-8000-%012d", i)
				s.Payload = fmt.Appendf(nil, `{"dpr_ref":%q}`, f.EventID)
				dprRef, verdictRef, err := a.AppendPair(context.Background(), f, s)
				if err != nil {
					break
				}
				acked = append(acked, dprRef.Seq, verdictRef.Seq)
			}
			if len(acked) == 16 {
				t.Skipf("budget %d was never reached; nothing was torn", budget)
			}
			_ = a.Close()

			assertAckedSurvive(t, dir, signer, acked)

			// And an acknowledged pair is never half present. This is the part
			// the barrier does buy: a caller that was told yes was told it
			// about both records, so both are in the recovered log.
			if len(acked)%2 != 0 {
				t.Fatalf("%d acknowledged records: a pair was acknowledged by halves", len(acked))
			}
		})
	}
}
