package evidence_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/replica"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// promotable writes a log under one key and returns the directory, that key, and
// a standby key.
func promotable(t *testing.T, declareStandby bool) (dir string, primary, standby *keys.Signer) {
	t.Helper()
	primary = mustSigner(t)
	standby = mustSigner(t)
	dir = filepath.Join(t.TempDir(), "evidence")

	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: primary, SyncMode: segment.SyncModeNone,
		SegmentTargetBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 30 {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg_tenure",
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_primary"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if declareStandby {
		// While the primary is healthy: the whole point.
		if _, err := a.RecordWriterKey(context.Background(), evidence.WriterKeyDeclaration{
			Kind: evidence.WriterKeyTrusted, KeyID: standby.KeyID(), PublicKey: standby.Public(),
		}, evidence.ParticipantRef{ID: "sys_orchd", Kind: "SYSTEM"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, primary, standby
}

// promoteTo opens a directory under a new key and records a tenure, the way
// `janus-replicad promote` does.
func promoteTo(t *testing.T, dir string, signer *keys.Signer, acked uint64) evidence.Tenure {
	t.Helper()
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatalf("opening as a writer: %v", err)
	}
	defer func() { _ = a.Close() }()

	st := a.Stats()
	chain := st.LastChain
	tenure := evidence.Tenure{
		InheritedSeq: st.LastSeq, InheritedChain: fmt.Sprintf("blake3:%x", chain[:]),
		AcknowledgedSeq: acked, KeyID: signer.KeyID(),
		Node: "region-b", Operator: "op_alice", Reason: "region A lost",
	}
	if _, err := a.RecordTenure(context.Background(), tenure,
		evidence.ParticipantRef{ID: "sys_replicad", Kind: "SYSTEM"}); err != nil {
		t.Fatalf("recording the tenure: %v", err)
	}
	// Something after the tenure, so the promoted writer has actually written
	// segments of its own for the verifier to check.
	for i := range 20 {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg_after",
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_promoted"},
			Payload:     fmt.Appendf(nil, `{"after":%d}`, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return tenure
}

// TestAPromotedTenureVerifiesFromTheOriginalRoot is the test that makes the
// enrolment-while-healthy rule a demonstrated constraint rather than an assertion.
//
// Writer trust extends *forward*: a key is introduced in a segment
// the current key signed, so an auditor who holds one root can follow the log
// forward without being handed anything else. At failover the old region is gone,
// so a standby key first declared by the *promoted* writer would dangle from no
// in-chain declaration.
//
// This runs both arrangements against the same verifier with the same single
// root. Declared in advance: the whole log verifies. Declared at promotion: every
// segment the promoted writer signed reports UNKNOWN_SIGNING_KEY — and an auditor
// would need a second root handed to them at exactly the moment a withheld key
// and a corrupt segment are hardest to tell apart.
func TestAPromotedTenureVerifiesFromTheOriginalRoot(t *testing.T) {
	t.Run("declared while the primary was healthy", func(t *testing.T) {
		dir, primary, standby := promotable(t, true)
		promoteTo(t, dir, standby, 30)

		rep, err := verify.SegmentDir(dir, verify.Options{
			// One root: the original primary's key, as an auditor holds it.
			Keys: keys.PublicKeySet{primary.KeyID(): primary.Public()}, Version: "test",
			AllowUnsealedTail: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !rep.OK {
			for _, f := range rep.Findings {
				t.Errorf("finding: %s %s — %s", f.Severity, f.Code, f.Message)
			}
			t.Fatal("a log promoted onto a key declared in advance does not verify from " +
				"the original root")
		}
	})

	t.Run("declared only at promotion", func(t *testing.T) {
		dir, primary, standby := promotable(t, false)
		promoteTo(t, dir, standby, 30)

		rep, err := verify.SegmentDir(dir, verify.Options{
			Keys: keys.PublicKeySet{primary.KeyID(): primary.Public()}, Version: "test",
			AllowUnsealedTail: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if rep.OK {
			t.Fatal("a key introduced only by the promoted writer verified from the " +
				"original root; if that were so, enrolling the standby in advance would " +
				"buy nothing and the enrolment rule would be ceremony")
		}
		var unknownKey bool
		for _, f := range rep.Findings {
			if f.Code == "UNKNOWN_SIGNING_KEY" {
				unknownKey = true
			}
		}
		if !unknownKey {
			t.Errorf("the verifier refused for some other reason than the unreachable key; " +
				"findings above")
			for _, f := range rep.Findings {
				t.Logf("  %s %s — %s", f.Severity, f.Code, f.Message)
			}
		}
	})
}

// TestATenureRecordsWhatItAdopted is about the span nobody was told about.
//
// A follower legitimately holds records the primary never acknowledged: the
// writer's buffer flushes on byte boundaries, so a record can be whole on disk
// and uncovered by a barrier. Promotion adopts them, because recovery keeps every
// complete record — which is exactly what a restarted primary does.
//
// No effect was released on their authority, so a reader who takes "in the log"
// to mean "was acted upon" is wrong about precisely this span. Recording both
// heads is what stops that being invisible.
//
// What this test actually exercises, stated plainly: the arithmetic and the
// round-trip through the log, with a *simulated* stale acknowledged head. The
// fixture's records were all acknowledged — producing genuinely unacknowledged
// complete records needs a kill between a write and its barrier, which is the
// failover drill's job and not a unit test's.
func TestATenureRecordsWhatItAdopted(t *testing.T) {
	dir, _, standby := promotable(t, true)

	// The previous writer had acknowledged less than the directory holds.
	const stated = 20
	tenure := promoteTo(t, dir, standby, stated)

	if tenure.InheritedSeq <= stated {
		t.Fatalf("the fixture inherited sequence %d and claims %d acknowledged, so there "+
			"is no adopted span to record", tenure.InheritedSeq, stated)
	}
	if got, want := tenure.Adopted(), tenure.InheritedSeq-stated; got != want {
		t.Errorf("the tenure reports %d adopted records, want %d", got, want)
	}

	// And it is readable back out of the log, which is where an auditor looks.
	var found bool
	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		if h.Kind != evidence.KindWriterTenure {
			return nil
		}
		got, err := evidence.DecodeTenure(rec.Payload)
		if err != nil {
			return err
		}
		found = true
		if got.AcknowledgedSeq != stated {
			t.Errorf("the recorded tenure says %d acknowledged, want %d",
				got.AcknowledgedSeq, stated)
		}
		if got.Operator == "" {
			t.Error("the recorded tenure names no operator")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("no tenure is in the log")
	}
}

// TestADirectoryAWriterOwnsRefusesToBecomeAFollower is the physical safety, and
// it has to be enforced from something durable rather than from a flag.
//
// A follower copies with WriteAt at offsets the *primary* names. Aimed at a
// promoted directory as its own target, it would overwrite the promoted history
// on disk — before any divergence check could look, because the check reads what
// is on disk after the write. There is no in-memory state that survives a
// restart to prevent it. The tenure is the durable statement that this directory
// is a writer now.
//
// The name matters, and the first one ("RefusesToBeFollowed") was read as the
// opposite claim for long enough to be written down: that a
// promoted log cannot be *replicated*. It can, and
// TestAPromotedLogCanStillBeReplicated is that. What is refused is a directory
// a writer owns going back to being a follower.
//
// The check is the writer marker, not the tenure. The tenure was wrong for this
// because it is replicated, which is what
// TestAFollowerRestartsOnALogThatHasFailedOver pins from the other side.
func TestADirectoryAWriterOwnsRefusesToBecomeAFollower(t *testing.T) {
	dir, _, standby := promotable(t, true)
	promoteTo(t, dir, standby, 30)

	_, err := replica.New(replica.Options{
		Dir:    dir,
		Source: replica.NewLocalSource(dir, func() replica.Head { return replica.Head{} }),
	})
	if err == nil {
		t.Fatal("a follower opened a promoted directory; the next pass would have " +
			"overwritten the promoted history with the old primary's bytes")
	}
	if !errors.Is(err, replica.ErrPromoted) {
		t.Fatalf("got %v, want it to wrap ErrPromoted", err)
	}
}

// TestATenureThatMisdescribesItsOwnLogIsCritical is the in-log half of fork
// detection, and it is worth being precise about what it can and cannot do.
//
// It cannot see a fork. Two promotions from the same point live in two different
// directories, and a verifier reading one of them has nothing to compare
// against — cross-log attribution needs both, which is the drill's job. What it
// catches is a tenure that misdescribes its own log: a forged history assembled
// to look continuous has to claim a predecessor, and this checks the claim
// against the record that is actually there.
func TestATenureThatMisdescribesItsOwnLogIsCritical(t *testing.T) {
	dir, primary, standby := promotable(t, true)

	// A tenure claiming to continue from somewhere it does not.
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: standby, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	st := a.Stats()
	chain := st.LastChain
	if _, err := a.RecordTenure(context.Background(), evidence.Tenure{
		// Off by one: the record before this one is st.LastSeq.
		InheritedSeq:   st.LastSeq + 7,
		InheritedChain: fmt.Sprintf("blake3:%x", chain[:]),
		KeyID:          standby.KeyID(), Operator: "op_mallory",
	}, evidence.ParticipantRef{ID: "sys_replicad", Kind: "SYSTEM"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.SegmentDir(dir, verify.Options{
		Keys: keys.PublicKeySet{primary.KeyID(): primary.Public()}, Version: "test",
		AllowUnsealedTail: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("a tenure claiming a predecessor the log does not have verified clean")
	}
	var found bool
	for _, f := range rep.Findings {
		if f.Code == "DIVERGENT_TENURE" {
			found = true
		}
	}
	if !found {
		t.Error("the verifier refused for some other reason than the tenure's claim:")
		for _, f := range rep.Findings {
			t.Logf("  %s %s — %s", f.Severity, f.Code, f.Message)
		}
	}
}

// TestCompareLogsFindsWhereTwoWritersParted is the cross-log half of fork
// detection, and it needs two directories because that is what a fork is.
//
// A verifier reading one log cannot see this and never could: it has nothing to
// compare against. What the comparison gives somebody is the sequence to start
// reading from and the tenure on each side — not an answer about which log is
// right, which is a decision about released effects rather than a computation.
func TestCompareLogsFindsWhereTwoWritersParted(t *testing.T) {
	// One history, copied, and then continued differently by two writers — which
	// is exactly what a promoted replica and a surviving primary produce.
	dir, primary, standby := promotable(t, true)
	other := filepath.Join(t.TempDir(), "replica")
	if err := copyDir(t, dir, other); err != nil {
		t.Fatal(err)
	}

	// The original primary keeps going, unaware it has been replaced.
	kept, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: primary, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, err := kept.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg_primary_carried_on",
			StepID:      fmt.Sprintf("st_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_primary"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := kept.Close(); err != nil {
		t.Fatal(err)
	}

	// And the replica is promoted and writes its own continuation.
	promoteTo(t, other, standby, 30)

	fork, err := evidence.CompareLogs(dir, other)
	if err != nil {
		t.Fatal(err)
	}
	if !fork.Diverged() {
		t.Fatal("two logs that were continued by different writers compare as identical")
	}
	if fork.CommonSeq == 0 {
		t.Error("no shared prefix was found, so these read as unrelated logs rather " +
			"than as a fork")
	}
	if fork.LeftNext != fork.RightNext {
		t.Errorf("the two sides diverge at %d and %d; a fork from a common prefix "+
			"should part at the same sequence", fork.LeftNext, fork.RightNext)
	}
	// The attribution: one side records a promotion and the other does not,
	// which is the ordinary failover shape and is what an operator needs told.
	if fork.RightTenure == nil {
		t.Error("the promoted side's tenure was not found, so the comparison cannot " +
			"say who took over")
	}
	if fork.LeftTenure != nil {
		t.Error("the surviving primary reports a tenure it never recorded")
	}
	t.Logf("\n%s", fork.Describe("primary", "promoted-replica"))
}

// TestCompareLogsDoesNotCallALaggingReplicaAFork is the negative that keeps the
// comparison useful.
//
// A replica that is simply behind shares a prefix and stops. Calling that a fork
// would make the tool cry wolf on the ordinary state of every follower and every
// backup ever taken, and a fork detector nobody believes is worse than none.
func TestCompareLogsDoesNotCallALaggingReplicaAFork(t *testing.T) {
	dir, primary, _ := promotable(t, true)
	behind := filepath.Join(t.TempDir(), "behind")
	if err := copyDir(t, dir, behind); err != nil {
		t.Fatal(err)
	}

	// The primary writes on; the copy does not. This has to actually happen —
	// a version of this test that reopened the log and appended nothing was
	// comparing two identical directories and would have passed against a
	// comparison that called every short log a fork.
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: primary, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 12 {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind: evidence.KindStepResult, SagaID: "sg_tenure",
			StepID:      fmt.Sprintf("st_on_%03d", i),
			Participant: evidence.ParticipantRef{ID: "ag_primary"},
			Payload:     fmt.Appendf(nil, `{"on":%d}`, i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	fork, err := evidence.CompareLogs(dir, behind)
	if err != nil {
		t.Fatal(err)
	}
	// Prove the setup produced the situation the test is named for, rather than
	// two identical directories that would agree trivially.
	if fork.LeftHead <= fork.RightHead {
		t.Fatalf("the primary did not get ahead of the copy: %d vs %d; this test is "+
			"not exercising a lagging replica", fork.LeftHead, fork.RightHead)
	}
	if fork.Diverged() {
		t.Errorf("a copy that is merely behind was called a fork: left diverges at %d, "+
			"right at %d\n%s", fork.LeftNext, fork.RightNext,
			fork.Describe("primary", "behind"))
	}
	// The shared prefix is the whole of the shorter log, which is what "behind"
	// means and what distinguishes it from a divergence.
	if fork.CommonSeq != fork.RightHead {
		t.Errorf("the shared prefix stops at %d but the copy runs to %d; a lagging "+
			"replica should agree all the way to its own head",
			fork.CommonSeq, fork.RightHead)
	}

	// The sentence an operator actually reads, on the ordinary day. This is the
	// common case — every follower and every backup is behind — and it is the
	// branch a fork-focused test would leave unexecuted, so a swapped name or a
	// wrong count would reach a runbook unnoticed.
	side, by := fork.Behind()
	if side != "right" {
		t.Errorf("Behind() named %q as the short side; the copy is on the right", side)
	}
	if want := fork.LeftHead - fork.CommonSeq; by != want {
		t.Errorf("Behind() says %d record(s) behind, want %d", by, want)
	}
	desc := fork.Describe("primary", "behind")
	for _, want := range []string{
		"primary has 12 record(s) beyond that and behind has none",
		"is not a fork",
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("the lagging description does not say %q:\n%s", want, desc)
		}
	}
}

// copyDir copies an evidence directory, the way an operator taking a snapshot
// would.
func copyDir(t *testing.T, from, to string) error {
	t.Helper()
	if err := os.MkdirAll(to, 0o750); err != nil {
		return err
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		blob, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), blob, 0o640); err != nil {
			return err
		}
	}
	return nil
}

// TestAPromotedLogCanStillBeReplicated is the claim an earlier note got
// backwards, and it is the one that decides whether a failover leaves the
// deployment with a replica.
//
// If a promoted log could not be followed, then after the first failover the new
// primary would have no replica and the RPO = 0 target would hold exactly once. It
// can be followed, and — this is the part worth pinning — a follower holding
// only the *pre-failover* root verifies segments the promoted writer sealed,
// because the primary declared the standby in-log while it was healthy.
// One key out of band, across a change of writer.
func TestAPromotedLogCanStillBeReplicated(t *testing.T) {
	dir, primary, standby := promotable(t, true)
	promoteTo(t, dir, standby, 30)

	a, err := evidence.Open(evidence.Options{Dir: dir, Signer: standby})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	// The promoted writer's own segments are signed by the standby key, or this
	// test would pass without exercising anything.
	if !sealedBy(t, dir, standby.KeyID()) {
		t.Fatal("no sealed segment carries the promoted writer's key, so nothing here " +
			"tests trust crossing the promotion")
	}

	fresh := filepath.Join(t.TempDir(), "follower")
	f, err := replica.New(replica.Options{
		Dir: fresh, Source: replica.FromAppender(dir, a),
		Keys: keys.PublicKeySet{primary.KeyID(): primary.Public()},
	})
	if err != nil {
		t.Fatalf("a fresh follower could not open against a promoted primary: %v", err)
	}
	if err := f.Follow(t.Context()); err != nil {
		t.Fatalf("following a promoted primary: %v", err)
	}
	st := f.Status()
	if st.Seq != a.Stats().LastSeq {
		t.Errorf("the follower reached seq %d, the promoted primary is at %d",
			st.Seq, a.Stats().LastSeq)
	}
	if !st.SignaturesChecked || st.SignaturesCheckedThrough == 0 {
		t.Errorf("signatures were not checked: %+v", st)
	}
}

// TestAnUndeclaredPromotionIsRefused is the other half, and the reason the drill
// declares the standby while the primary is healthy.
//
// Trust extends forward only. A key first seen on the promoted writer's own
// segments dangles from nothing, and a follower says so rather than copying it.
func TestAnUndeclaredPromotionIsRefused(t *testing.T) {
	dir, primary, standby := promotable(t, false)
	promoteTo(t, dir, standby, 30)

	a, err := evidence.Open(evidence.Options{Dir: dir, Signer: standby})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	fresh := filepath.Join(t.TempDir(), "follower")
	f, err := replica.New(replica.Options{
		Dir: fresh, Source: replica.FromAppender(dir, a),
		Keys: keys.PublicKeySet{primary.KeyID(): primary.Public()},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = f.Follow(t.Context())
	if err == nil {
		t.Fatal("a follower copied a promotion whose key nothing in the log introduced")
	}

	// Refused as what it is. This used to come back as ErrDiverged — "the
	// primary's log diverges from this copy" — which is the split-brain alarm,
	// raised for an operator who forgot -standby-keys. The bytes here are one
	// log: they framed cleanly, they continue the chain, and the only thing
	// wrong is that nothing this follower trusts introduced the key that sealed
	// them.
	if !errors.Is(err, replica.ErrUntrustedWriter) {
		t.Fatalf("refused as %v, want ErrUntrustedWriter", err)
	}
	if errors.Is(err, replica.ErrDiverged) {
		t.Fatalf("an undeclared promotion still reads as a fork: %v", err)
	}
	if !strings.Contains(err.Error(), standby.KeyID()) {
		t.Fatalf("the refusal does not name the key an operator has to declare: %v", err)
	}
	if !strings.Contains(err.Error(), "-standby-keys") {
		t.Fatalf("the refusal does not name the flag that would have prevented it: %v", err)
	}
}

// sealedBy reports whether any sealed segment in dir carries this key id.
func sealedBy(t *testing.T, dir, keyID string) bool {
	t.Helper()
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		insp, err := segment.Inspect(segment.Path(dir, id))
		if err != nil {
			continue
		}
		if insp.Footer != nil && insp.Footer.KeyID == keyID {
			return true
		}
	}
	return false
}

// TestAFollowerRunningAcrossAFailoverDoesNotCryDivergence is the defect the
// replication half of writer fencing was hiding, and the one an operator would meet
// first.
//
// A fresh follower verifies segments 0..N in one range, so the WRITER_KEY
// declaration introducing the promoted writer is inside the range that needs it.
// A follower that was *already running* is not: it verified through the segment
// before the promotion, so its next range starts after the declaration, and each
// range built its trust from the configured roots alone.
//
// The result was ErrDiverged — "the primary's log diverges from this copy" — for
// a routine failover. That is the alarm that means split-brain, raised for a key
// rotation, and restarting the follower made it go away, which is the worst
// possible diagnostic signal. The follower now carries the trust forward instead.
func TestAFollowerRunningAcrossAFailoverDoesNotCryDivergence(t *testing.T) {
	dir, primary, standby := promotable(t, true)

	a, err := evidence.Open(evidence.Options{Dir: dir, Signer: primary})
	if err != nil {
		t.Fatal(err)
	}
	// One source over the directory, serving whichever writer currently owns
	// it. A real failover repoints the follower at the standby's copy, which
	// holds the same bytes; what this reproduces is the part that matters —
	// the follower's own cursor is past the declaration when the writer
	// changes.
	live := a
	mirror := filepath.Join(t.TempDir(), "follower")
	f, err := replica.New(replica.Options{
		Dir: mirror,
		Source: replica.NewLocalSource(dir, func() replica.Head {
			st := live.Stats()
			return replica.Head{Seq: st.LastSeq, Chain: st.LastChain}
		}),
		Keys: keys.PublicKeySet{primary.KeyID(): primary.Public()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Follow(t.Context()); err != nil {
		t.Fatalf("following the healthy primary: %v", err)
	}
	// The premise: this follower has already verified past the declaration, so
	// the next range cannot see it. Without this the test would pass on a
	// follower that simply re-read the whole log.
	before := f.Status()
	if before.SignaturesCheckedThrough == 0 {
		t.Fatal("the follower verified no sealed segment before the failover, so its next " +
			"range would start at the beginning and the declaration would be in it")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	promoteTo(t, dir, standby, 30)
	b, err := evidence.Open(evidence.Options{Dir: dir, Signer: standby})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if !sealedBy(t, dir, standby.KeyID()) {
		t.Fatal("the promoted writer sealed nothing, so the next pass verifies no new key")
	}

	// The same follower object, still running, now pulling from the promoted
	// primary. `janus-replicad follow` reconnecting is exactly this.
	live = b
	if err := f.Follow(t.Context()); err != nil {
		t.Fatalf("a running follower across a failover: %v", err)
	}
	after := f.Status()
	if after.SignaturesCheckedThrough <= before.SignaturesCheckedThrough {
		t.Errorf("the follower verified nothing new: through %d before, %d after",
			before.SignaturesCheckedThrough, after.SignaturesCheckedThrough)
	}
	if after.Seq != b.Stats().LastSeq {
		t.Errorf("the follower is at seq %d and the promoted primary at %d",
			after.Seq, b.Stats().LastSeq)
	}
}

// TestAFollowerRestartsOnALogThatHasFailedOver is the deployment-facing half of
// the writer marker, and it is the one an operator meets first.
//
// A follower of a promoted log copies the promotion's tenure, because a faithful
// copy copies everything. While the refusal was written against the tenure, that
// made every replica of a failed-over log unfollowable — so `janus-replicad`
// dying for any ordinary reason (a deploy, an OOM, a host reboot) could not come
// back, and the error told the operator to re-seed into an empty directory,
// which at 100M events is a 30 GB copy, for a directory nobody had ever
// promoted.
func TestAFollowerRestartsOnALogThatHasFailedOver(t *testing.T) {
	dir, primary, standby := promotable(t, true)
	promoteTo(t, dir, standby, 30)

	a, err := evidence.Open(evidence.Options{Dir: dir, Signer: standby})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })

	mirror := filepath.Join(t.TempDir(), "follower")
	open := func() (*replica.Follower, error) {
		return replica.New(replica.Options{
			Dir: mirror, Source: replica.FromAppender(dir, a),
			Keys: keys.PublicKeySet{primary.KeyID(): primary.Public()},
		})
	}
	f, err := open()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Follow(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The premise: this mirror now holds the promotion's tenure. Without it the
	// test would pass against any directory at all.
	if n, err := evidence.TenureCount(mirror); err != nil || n == 0 {
		t.Fatalf("the mirror holds %d tenures (err %v); it has not copied the promotion", n, err)
	}
	// And no writer marker, because a follower is not an appender.
	if owned, err := evidence.HasWriterMark(mirror); err != nil || owned {
		t.Fatalf("the mirror is marked as a writer's (owned=%v, err=%v)", owned, err)
	}

	g, err := open()
	if err != nil {
		t.Fatalf("a follower could not restart on a log that had failed over: %v", err)
	}
	if err := g.Follow(t.Context()); err != nil {
		t.Fatalf("the restarted follower could not follow: %v", err)
	}
	if g.Status().Seq != a.Stats().LastSeq {
		t.Errorf("the restarted follower is at %d, the primary at %d",
			g.Status().Seq, a.Stats().LastSeq)
	}
}

// TestASecondFailoverPromotesTheReplicaAndDerivesTheNextEpoch is the other half.
//
// `janus-replicad promote` refused any directory holding a tenure, so after one
// failover no replica could be promoted and the deployment could fail over
// exactly once. The epoch derivation uses the same count and is *correct* on it:
// an epoch counts the log's promotions, so a replica of a once-promoted log
// derives 2. One call, two questions, conflated until they disagreed.
func TestASecondFailoverPromotesTheReplicaAndDerivesTheNextEpoch(t *testing.T) {
	dir, primary, standby := promotable(t, true)
	promoteTo(t, dir, standby, 30)

	// The promoted writer declares the standby for the failover *after* this
	// one, while it is healthy — one hop further along the key-declaration chain than any
	// other test here goes — and then goes on writing, so the declaration's
	// segment is sealed by the key that made it. A declaration sealed by the
	// key it introduces is refused, correctly, and that is a property of the
	// chain rather than of this test.
	second := mustSigner(t)
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: standby, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.RecordWriterKey(t.Context(), evidence.WriterKeyDeclaration{
		Kind: evidence.WriterKeyTrusted, KeyID: second.KeyID(), PublicKey: second.Public(),
	}, evidence.ParticipantRef{ID: "sys_orchd", Kind: "SYSTEM"}); err != nil {
		t.Fatal(err)
	}
	appendN(t, a, 40, "sg_promoted")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	// Reopened only to serve the follower a head.
	a, err = evidence.Open(evidence.Options{
		Dir: dir, Signer: standby, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}

	mirror := filepath.Join(t.TempDir(), "follower")
	f, err := replica.New(replica.Options{
		Dir: mirror, Source: replica.FromAppender(dir, a),
		Keys: keys.PublicKeySet{primary.KeyID(): primary.Public()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Follow(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// What `promote` asks, and what it must answer.
	owned, err := evidence.HasWriterMark(mirror)
	if err != nil {
		t.Fatal(err)
	}
	if owned {
		t.Fatal("promote would refuse this replica: it reads as a writer's directory")
	}
	tenures, err := evidence.TenureCount(mirror)
	if err != nil {
		t.Fatal(err)
	}
	if epoch := tenures + 1; epoch != 2 {
		t.Fatalf("the second promotion would derive epoch %d, want 2", epoch)
	}

	// The promotion itself, and then the claim that makes two failovers worth
	// having: the twice-promoted log verifies from the ORIGINAL root alone.
	promoteTo(t, mirror, second, 30)
	if owned, err := evidence.HasWriterMark(mirror); err != nil || !owned {
		t.Fatalf("promoting did not make this a writer's directory (owned=%v, err=%v)", owned, err)
	}
	rep, err := verify.SegmentDir(mirror, verify.Options{
		Keys:              keys.PublicKeySet{primary.KeyID(): primary.Public()},
		AllowUnsealedTail: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a log two promotions from its root does not verify from it: %+v", rep.Findings)
	}
	if got := rep.SigningKeys[second.KeyID()]; !strings.HasPrefix(got, "introduced at seq ") {
		t.Errorf("the second promotion's key reads as %q, not as something the log introduced", got)
	}
}
