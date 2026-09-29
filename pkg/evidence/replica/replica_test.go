package replica_test

import (
	"context"
	"encoding/hex"
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

// primary opens a writable evidence directory and a source over it.
func primary(t *testing.T, mutate func(*evidence.Options)) (*evidence.Appender, string, *replica.LocalSource, *keys.Signer) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "primary")
	opts := evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone}
	if mutate != nil {
		mutate(&opts)
	}
	app, err := evidence.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	return app, dir, replica.FromAppender(dir, app), signer
}

func follower(t *testing.T, src replica.Source) (*replica.Follower, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "replica")
	f, err := replica.New(replica.Options{Dir: dir, Source: src})
	if err != nil {
		t.Fatal(err)
	}
	return f, dir
}

func appendN(t *testing.T, app *evidence.Appender, n int) {
	t.Helper()
	for i := range n {
		if _, err := app.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      fmt.Sprintf("sg_%04d", i/4),
			StepID:      fmt.Sprintf("st_%04d", i),
			Participant: evidence.ParticipantRef{ID: "ag_primary"},
			Payload:     fmt.Appendf(nil, `{"i":%d}`, i),
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

// TestAFollowerMirrorsTheBytesExactly is rule one.
//
// Byte identity is not an optimisation. A sealed segment's footer signs the
// bytes as written, so a follower that re-appended through an Appender would
// produce a directory that is internally consistent and *not the same log* —
// different rotation points, invalid footers. Comparing files byte for byte is
// therefore the assertion, rather than comparing replayed states, which would
// pass for a re-appending follower.
func TestAFollowerMirrorsTheBytesExactly(t *testing.T) {
	app, pdir, src, _ := primary(t, nil)
	appendN(t, app, 200)

	f, rdir := follower(t, src)
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}

	ids, err := segment.ScanDir(pdir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) == 0 {
		t.Fatal("the primary wrote no segments, so there is nothing to mirror")
	}
	for _, id := range ids {
		want, err := os.ReadFile(segment.Path(pdir, id))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(segment.Path(rdir, id))
		if err != nil {
			t.Fatalf("segment %s was not mirrored: %v", segment.FileName(id), err)
		}
		if string(got) != string(want) {
			t.Errorf("segment %s differs: %d bytes on the primary, %d on the replica",
				segment.FileName(id), len(want), len(got))
		}
	}
}

// TestAFollowerDoesNotAcknowledgePastThePrimarysHead is rule two, and it is the
// rule most likely to be got wrong by an implementation that looks correct.
//
// The source here serves complete, correctly chained records while reporting a
// head below them — which is not a contrived situation but the ordinary one: the
// writer's buffer flushes on byte boundaries, so a record can be whole on disk
// and not yet covered by a barrier. A follower that trusted its own framing
// would acknowledge a record a crash will erase.
func TestAFollowerDoesNotAcknowledgePastThePrimarysHead(t *testing.T) {
	app, pdir, _, _ := primary(t, nil)
	appendN(t, app, 40)

	const stated = 12
	// A real chain at that sequence, not a zero one. A head with no chain is
	// refused outright now (it is how a transport that dropped the field would
	// present itself), so supplying the true value is also what makes this test
	// exercise the divergence comparison rather than skip past it.
	held := &heldHead{LocalSource: replica.NewLocalSource(pdir, func() replica.Head {
		return replica.Head{Seq: stated, Chain: chainAt(t, pdir, stated)}
	})}

	f, _ := follower(t, held)
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.Status().Seq; got != stated {
		t.Errorf("acknowledged sequence %d, want %d: the follower reported records the "+
			"primary has not acknowledged, which a crash on the primary would erase", got, stated)
	}
}

// heldHead is a source whose head is under this test's control.
type heldHead struct{ *replica.LocalSource }

// TestAFollowerTruncatesToThePrimaryAfterATornWrite is the torn-tail case.
//
// The primary crashes mid-record and recovery truncates below what the follower
// already copied. The follower must cut back rather than keep bytes the primary
// has disowned — and it is safe to do so precisely because rule two means it
// never told anyone about them.
func TestAFollowerTruncatesToThePrimaryAfterATornWrite(t *testing.T) {
	app, pdir, src, _ := primary(t, nil)
	appendN(t, app, 40)

	f, rdir := follower(t, src)
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Cut the primary's newest segment, as recovery would after a crash between
	// a write and its barrier.
	ids, err := segment.ScanDir(pdir)
	if err != nil {
		t.Fatal(err)
	}
	// The *largest* segment, not the last: the writer creates the next segment
	// ahead of a rotation, so the highest id may be an empty placeholder with
	// nothing to truncate.
	var last string
	var size int64
	for _, id := range ids {
		info, err := os.Stat(segment.Path(pdir, id))
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > size {
			last, size = segment.Path(pdir, id), info.Size()
		}
	}
	shorter := size - 200
	if shorter <= 0 {
		t.Fatalf("the largest segment is %d bytes, too small to truncate meaningfully", size)
	}
	if err := os.Truncate(last, shorter); err != nil {
		t.Fatal(err)
	}

	if err := f.Follow(context.Background()); err != nil {
		t.Fatalf("following after the primary truncated: %v", err)
	}

	rinfo, err := os.Stat(filepath.Join(rdir, filepath.Base(last)))
	if err != nil {
		t.Fatal(err)
	}
	if rinfo.Size() != shorter {
		t.Errorf("the replica's copy is %d bytes and the primary's is %d: the follower "+
			"kept bytes the primary disowned", rinfo.Size(), shorter)
	}
}

// TestAFollowerResumesPastRecordsNotFilenames is rule three, and it is Phase
// 6a's projector bug re-armed in a harder place.
//
// The writer creates the next segment file *before* it rotates into it,
// so a follower that treated "the highest segment id I have" as
// progress would skip the segment still being filled. This forces a rotation
// between two passes and asserts the records written before it are present.
func TestAFollowerResumesPastRecordsNotFilenames(t *testing.T) {
	// A small segment so rotation happens inside this test rather than after it.
	app, pdir, src, _ := primary(t, func(o *evidence.Options) { o.SegmentTargetBytes = 8 << 10 })

	appendN(t, app, 20)
	f, rdir := follower(t, src)
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := f.Status().Seq

	appendN(t, app, 200) // enough to rotate at least once
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}

	pids, err := segment.ScanDir(pdir)
	if err != nil {
		t.Fatal(err)
	}
	if len(pids) < 2 {
		t.Fatalf("no rotation happened (%d segments), so this test proves nothing", len(pids))
	}
	if f.Status().Seq <= first {
		t.Fatalf("the follower did not advance past sequence %d", first)
	}
	// One Follow, compared directly against the primary's head. This test spent
	// one commit following twice, because the head the source advertised trailed
	// what the primary had acknowledged: appendN returned inside that
	// window and the first Follow asked for the head inside it too. The appender
	// publishes before it replies now, so a head read after an append that
	// returned covers that append.
	if got, want := f.Status().Seq, app.Stats().LastSeq; got != want {
		t.Errorf("the follower reached sequence %d and the primary is at %d: records "+
			"written before the rotation were skipped", got, want)
	}
	for _, id := range pids {
		if _, err := os.Stat(segment.Path(rdir, id)); err != nil {
			t.Errorf("segment %s is missing from the replica", segment.FileName(id))
		}
	}
}

// TestAFollowerRefusesADivergentChain is the check that makes "integrity-checked"
// mean something on receipt rather than only at seal time.
//
// A single flipped byte inside a record must stop the follower, not be copied
// and discovered later by a background verifier — by which time the replica has
// been reporting a head derived from it.
func TestAFollowerRefusesADivergentChain(t *testing.T) {
	app, pdir, _, _ := primary(t, nil)
	appendN(t, app, 40)
	head := app.Stats()

	f, _ := follower(t, &corrupting{
		LocalSource: replica.NewLocalSource(pdir, func() replica.Head {
			return replica.Head{Seq: head.LastSeq, Chain: head.LastChain}
		}),
	})
	err := f.Follow(context.Background())
	if err == nil {
		t.Fatal("the follower accepted a corrupted chunk")
	}
	if !errors.Is(err, replica.ErrDiverged) {
		t.Fatalf("got %v, want it to wrap ErrDiverged", err)
	}
	// And not the other one: bytes that do not continue the chain are the case
	// ErrDiverged is for, and the signing-key split must not have swallowed it.
	if errors.Is(err, replica.ErrUntrustedWriter) {
		t.Fatalf("a corrupted chunk was reported as a signing-key problem: %v", err)
	}
}

// corrupting flips a byte in the middle of every chunk after the header.
type corrupting struct{ *replica.LocalSource }

func (c *corrupting) Read(ctx context.Context, id uint64, off int64, max int) (replica.Chunk, error) {
	chunk, err := c.LocalSource.Read(ctx, id, off, max)
	if err != nil || len(chunk.Bytes) < 600 {
		return chunk, err
	}
	chunk.Bytes[len(chunk.Bytes)/2] ^= 0xFF
	return chunk, nil
}

// TestAReplicaVerifiesAsALogInItsOwnRight is the claim replication exists to
// make, and it is not implied by the byte comparison above.
//
// A directory that matches the primary byte for byte would still be worthless if
// the primary's own footers only verified in place. This runs the *offline*
// verifier — the one an auditor runs — against the replica alone, with the
// primary's public key as the root, and requires the head this follower reports
// to be the head the verifier computes. A replica that could not be verified
// without the primary present would not be a replica, it would be a cache.
func TestAReplicaVerifiesAsALogInItsOwnRight(t *testing.T) {
	app, _, src, signer := primary(t, nil)
	appendN(t, app, 120)

	// Close the primary before following. An open segment carries no footer, so
	// a replica of a live log is *correctly* unsealed at its tail and the
	// offline verifier is right to say so — that is the four-layer point in the
	// package comment, not a defect. What is being asserted here is the sealed
	// case: what an auditor is handed.
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	f, rdir := follower(t, src)
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.SegmentDir(rdir, verify.Options{
		Keys:            keys.PublicKeySet{signer.KeyID(): signer.Public()},
		Version:         "replica-test",
		ExpectHeadChain: "blake3:" + hex.EncodeToString(chainOf(f)),
	})
	if err != nil {
		t.Fatalf("verifying the replica: %v", err)
	}
	if !rep.OK {
		for _, fnd := range rep.Findings {
			t.Errorf("finding: %s %s — %s", fnd.Severity, fnd.Code, fnd.Message)
		}
		t.Fatal("the replica does not verify on its own")
	}
}

// TestAFollowerCopiesSegmentsAndNothingElse guards the shred-safety claim.
//
// Replication is safe against crypto-shredding only because the follower
// copies the segment directory and *not* the keyring beside it: the replica
// holds ciphertext and no key, so destroying a data subject's key on the primary
// leaves the replica's copy exactly as unreadable.
//
// That is a structural property, so the honest test is a structural one. It
// cannot prove a future change will not copy keys; it can fail the moment one
// does, which is what makes the claim in the package comment load-bearing rather
// than decorative.
func TestAFollowerCopiesSegmentsAndNothingElse(t *testing.T) {
	app, _, src, _ := primary(t, nil)
	appendN(t, app, 40)

	f, rdir := follower(t, src)
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(rdir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("the replica directory is empty, so this proves nothing")
	}
	for _, e := range entries {
		if e.IsDir() {
			t.Errorf("the replica contains a directory %q; a follower copies segment "+
				"files and nothing else, which is what keeps a shred a shred", e.Name())
			continue
		}
		if filepath.Ext(e.Name()) != ".jseg" {
			t.Errorf("the replica contains %q, which is not a segment file", e.Name())
		}
	}
}

// chainOf is the follower's head chain as bytes, for comparison with the
// verifier's own rendering of it.
func chainOf(f *replica.Follower) []byte {
	c := f.Status().Chain
	return c[:]
}

// TestAFollowerChecksSignaturesWhenASegmentSeals is integrity layer two, and the
// reason it is a separate test from the chain check is that the two catch
// different attackers.
//
// The chain check catches bytes that do not continue the log. It does *not*
// catch a whole segment re-signed by somebody else's key, because such a segment
// chains perfectly — it is internally consistent and simply not ours. Only the
// footer signature, checked against a trust root, separates the two.
//
// The follower must catch it on receipt. Leaving it to a background sweep means
// the replica reports a verified head derived from a segment nothing has
// authenticated, for however long the sweep interval is.
//
// It is refused as ErrUntrustedWriter rather than ErrDiverged, and the reason is
// this test's own premise: such a segment "chains perfectly". The bytes are not
// the problem, the signature is — and an operator who forgot -standby-keys
// before a failover produces bytes of exactly this shape. The follower cannot
// tell the two apart, so the refusal names both and stops either way.
func TestAFollowerChecksSignaturesWhenASegmentSeals(t *testing.T) {
	app, _, src, writer := primary(t, func(o *evidence.Options) { o.SegmentTargetBytes = 8 << 10 })
	stranger, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, app, 300)
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	// A trust root that did not sign this log: every sealed segment is sound and
	// signed by the wrong key, which is exactly the shape a re-signed segment has.
	dir := filepath.Join(t.TempDir(), "replica")
	f, err := replica.New(replica.Options{
		Dir: dir, Source: src, VerifierVersion: "replica-test",
		Keys: keys.PublicKeySet{stranger.KeyID(): stranger.Public()},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = f.Follow(context.Background())
	if err == nil {
		t.Fatal("the follower accepted sealed segments signed by a key it does not trust")
	}
	if !errors.Is(err, replica.ErrUntrustedWriter) {
		t.Fatalf("got %v, want it to wrap ErrUntrustedWriter", err)
	}
	// Both causes named, because the bytes do not say which one this is.
	// The key named is the one that *sealed* the segments, not the root this
	// follower was handed: an operator has to go and find out what that key is.
	for _, want := range []string{writer.KeyID(), "-standby-keys", "not this log's writer", "-keys", "do not copy"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

// TestAFollowerWithNoTrustRootSaysSoRatherThanClaimingVerified is the negative
// that keeps the previous test honest.
//
// Signature checking is optional — a deployment may not have distributed the
// root yet — but "not checked" must never render as "checked and fine". Status
// carries the distinction so an operator reading it cannot conflate them.
func TestAFollowerWithNoTrustRootSaysSoRatherThanClaimingVerified(t *testing.T) {
	app, _, src, _ := primary(t, nil)
	appendN(t, app, 40)

	f, _ := follower(t, src)
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := f.Status()
	if st.SignaturesChecked {
		t.Error("a follower with no trust root reports signatures as checked")
	}
	if st.Seq == 0 {
		t.Error("the follower copied nothing, so this proves nothing about the flag")
	}
}

// chainAt reads the chain hash at one sequence out of a log.
func chainAt(t *testing.T, dir string, seq uint64) evidence.Hash {
	t.Helper()
	var out evidence.Hash
	var found bool
	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		if h.Seq == seq {
			out, found = rec.Chain, true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("no record at sequence %d", seq)
	}
	return out
}

// TestAFollowerRefusesAHeadWithNoChain is the fail-closed half of rule two.
//
// A source that can state a sequence can state the chain at it. A head arriving
// without one means a transport dropped the field — the naive-RPC
// mistake — and accepting it would quietly degrade
// the divergence check to comparing sequence numbers, which any forged log can
// satisfy.
func TestAFollowerRefusesAHeadWithNoChain(t *testing.T) {
	app, pdir, _, _ := primary(t, nil)
	appendN(t, app, 20)

	f, _ := follower(t, &heldHead{LocalSource: replica.NewLocalSource(pdir, func() replica.Head {
		return replica.Head{Seq: 10}
	})})
	if err := f.Follow(context.Background()); err == nil {
		t.Fatal("a head stating a sequence with no chain hash was accepted")
	}
}

// TestFollowingCostsNewsNotHistory is the check that keeps the framing
// incremental.
//
// The first version of this follower reset its state and re-framed every segment
// on every pass — which is precisely the defect an earlier change removed
// from `Projector.read`, reintroduced in a new package. It passed every other test in this file,
// because re-reading produces the right answer; only its cost was wrong.
//
// So the cost is asserted directly. A pass that brings no new records must
// decode none, and a pass that brings five must decode five.
func TestFollowingCostsNewsNotHistory(t *testing.T) {
	app, _, src, _ := primary(t, nil)
	appendN(t, app, 300)

	f, _ := follower(t, src)
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := f.Status().RecordsFramed
	if after == 0 {
		t.Fatal("nothing was framed, so this proves nothing")
	}

	// A pass with nothing new.
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.Status().RecordsFramed; got != after {
		t.Errorf("an idle pass framed %d records, having already framed %d: the "+
			"follower is re-reading its own directory every tick", got-after, after)
	}

	// A pass with five new ones.
	appendN(t, app, 5)
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.Status().RecordsFramed; got != after+5 {
		t.Errorf("after five new records the follower had framed %d, want %d",
			got, after+5)
	}
}

// TestAnIdlePollDoesNotReExamineSealedSegments is the cost of re-listing,
// pinned as a property rather than as a benchmark.
//
// Two loops in `Follow` walked the mirror from segment 0 on every pass, asking
// `segment.IsSealed` — an open, a stat, a read and a close — of every file:
// `setResumePoint` looking for the first unsealed segment, and `verifySeals`
// looking for the highest sealed one. At 3,078 segments an idle poll cost 86 ms
// and the directory listing was 6 of them. On the default 300 ms interval that
// is a follower spending a quarter of its life asking about files that cannot
// have changed.
//
// They cannot have changed because this follower only ever copies into segments
// at or above its own cursor, so nothing below it can be truncated back open
// behind the loop. The observable form of "does not look" is that damage below
// the cursor does not move it: a sealed segment emptied out is not noticed by a
// poll, and is not the poll's job — the chain is what catches a tampered
// history, in `janus-verify` and in the continuous verifier's sweep.
func TestAnIdlePollDoesNotReExamineSealedSegments(t *testing.T) {
	app, pdir, _, signer := primary(t, func(o *evidence.Options) {
		o.SegmentTargetBytes = 1024
	})
	appendN(t, app, 200)

	mdir := filepath.Join(t.TempDir(), "replica")
	f, err := replica.New(replica.Options{
		Dir: mdir, Source: replica.FromAppender(pdir, app),
		Keys: keys.PublicKeySet{signer.KeyID(): signer.Public()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Follow(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := f.Status()
	if before.SignaturesCheckedThrough < 2 {
		t.Fatalf("the mirror has too few sealed segments to test with: %+v", before)
	}

	// A sealed segment well below the cursor, emptied. A loop that walks from
	// zero finds it unsealed and winds the resume point back onto it.
	ids, err := segment.ScanDir(mdir)
	if err != nil || len(ids) < 3 {
		t.Fatalf("the mirror holds %v (err %v); too few segments to damage one below the cursor", ids, err)
	}
	if err := os.Truncate(segment.Path(mdir, ids[0]), 0); err != nil {
		t.Fatal(err)
	}

	if err := f.Follow(context.Background()); err != nil {
		t.Fatalf("an idle poll failed after a segment below the cursor was damaged: %v", err)
	}
	after := f.Status()
	if after.Segment < before.Segment ||
		(after.Segment == before.Segment && after.Offset < before.Offset) {
		t.Errorf("the poll wound the cursor back onto a segment it had passed: "+
			"%d:%d then %d:%d — it is re-examining sealed segments on every pass",
			before.Segment, before.Offset, after.Segment, after.Offset)
	}
	if after.Seq != before.Seq {
		t.Errorf("the acknowledged sequence moved from %d to %d", before.Seq, after.Seq)
	}
}
