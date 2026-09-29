package orchd_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence/replica"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/orchd"
)

// TestAReplicaConvergesOverTheWire is the whole of 6g's second half in one
// check: the follower's rules, unchanged, with gRPC underneath instead of a
// function call.
//
// The assertion is byte identity rather than "the follower reported a
// sequence". A transport that dropped the last chunk of a segment, or that
// silently truncated a response at a frame boundary, would still let the
// follower report a plausible head — and would produce a replica that cannot be
// promoted. Comparing files is what catches that.
func TestAReplicaConvergesOverTheWire(t *testing.T) {
	s, pdir := newServer(t)
	conn := clientConn(t, s)
	ctx := context.Background()

	// Real work through the daemon, so the log has the shape a deployment's
	// does rather than a shape written to be easy to copy.
	beginGatedPlan(t, s, ctx)

	src := orchd.NewRemoteSource(conn)
	rdir := filepath.Join(t.TempDir(), "replica")
	f, err := replica.New(replica.Options{Dir: rdir, Source: src})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Follow(ctx); err != nil {
		t.Fatalf("following over the wire: %v", err)
	}

	if f.Status().Seq == 0 {
		t.Fatal("the follower acknowledged nothing, so nothing here is proven")
	}
	if got, want := f.Status().Seq, headSeq(t, s, ctx); got != want {
		t.Errorf("the follower reached sequence %d and the primary is at %d", got, want)
	}
	assertSameBytes(t, pdir, rdir)
}

// TestAReplicaOverTheWireKeepsUpWithNewRecords is the second pass, which is
// where a transport with a broken cursor shows up.
//
// The first pass copies everything and looks correct for any implementation
// that reads from zero. Only a pass that has to resume — into a segment the
// writer is still filling — exercises the offset the client sends and the slice
// the server returns for it.
func TestAReplicaOverTheWireKeepsUpWithNewRecords(t *testing.T) {
	s, pdir := newServer(t)
	conn := clientConn(t, s)
	ctx := context.Background()

	beginGatedPlan(t, s, ctx)

	src := orchd.NewRemoteSource(conn)
	rdir := filepath.Join(t.TempDir(), "replica")
	f, err := replica.New(replica.Options{Dir: rdir, Source: src})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Follow(ctx); err != nil {
		t.Fatal(err)
	}
	first := f.Status()

	// More history, into the segment the follower is already part-way through.
	if _, err := s.RevokeCredential(ctx, &janusv1.RevokeCredentialRequest{
		CredentialId: "cred_replication", Reason: "so the log grows",
	}); err != nil {
		t.Fatal(err)
	}

	if err := f.Follow(ctx); err != nil {
		t.Fatalf("following after the primary appended: %v", err)
	}
	second := f.Status()

	if second.Seq <= first.Seq {
		t.Errorf("the follower stayed at sequence %d after the primary appended; "+
			"the resume offset is not reaching the server", first.Seq)
	}
	if got, want := second.Seq, headSeq(t, s, ctx); got != want {
		t.Errorf("the follower reached sequence %d and the primary is at %d", got, want)
	}
	// Following costs news, not history: the second pass must not re-frame what
	// the first already did.
	if second.RecordsFramed <= first.RecordsFramed {
		t.Error("the second pass framed nothing, so it copied nothing")
	}
	assertSameBytes(t, pdir, rdir)
}

// TestTheReplicationSurfaceIsReadOnly is a boundary check rather than a
// behaviour one.
//
// A follower asks for bytes and is told what has been acknowledged. It must not
// be able to reach anything that changes the primary through the same calls —
// which is easy to hold now and easy to lose the moment somebody adds a
// convenience field. The check is that a read with a nonsense offset is refused
// rather than interpreted.
func TestTheReplicationSurfaceIsReadOnly(t *testing.T) {
	s, _ := newServer(t)
	ctx := context.Background()

	if _, err := s.ReplicationRead(ctx, &janusv1.ReplicationReadRequest{
		SegmentId: 0, Offset: -1,
	}); err == nil {
		t.Error("a negative offset was accepted")
	}
	// Reading a segment that does not exist is not an error: a follower asking
	// about a segment the primary has since sealed and rotated past would
	// otherwise fail rather than move on.
	if _, err := s.ReplicationRead(ctx, &janusv1.ReplicationReadRequest{
		SegmentId: 999999, Offset: 0,
	}); err != nil {
		t.Errorf("reading an absent segment should answer empty, not fail: %v", err)
	}
}

// TestAWireHeadCarriesItsChain guards the fail-closed rule from the other side.
//
// The follower refuses a head that states a sequence with no chain hash,
// because that is how a dropped field presents itself. This asserts the primary
// never produces one — so the refusal stays a guard against a broken transport
// rather than something the real one trips over.
func TestAWireHeadCarriesItsChain(t *testing.T) {
	s, _ := newServer(t)
	ctx := context.Background()
	beginGatedPlan(t, s, ctx)

	resp, err := s.ReplicationHead(ctx, &janusv1.ReplicationHeadRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetSeq() == 0 {
		t.Fatal("the primary reports no head, so this proves nothing")
	}
	if len(resp.GetChain()) != 32 {
		t.Errorf("the head carries a %d-byte chain hash, want 32: a follower cannot "+
			"check a head it cannot compare", len(resp.GetChain()))
	}
}

// headSeq reads the primary's acknowledged sequence through the same call a
// follower uses.
func headSeq(t *testing.T, s *orchd.Server, ctx context.Context) uint64 {
	t.Helper()
	resp, err := s.ReplicationHead(ctx, &janusv1.ReplicationHeadRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return resp.GetSeq()
}

// assertSameBytes requires the two directories to hold identical segments.
func assertSameBytes(t *testing.T, pdir, rdir string) {
	t.Helper()
	ids, err := segment.ScanDir(pdir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) == 0 {
		t.Fatal("the primary wrote no segments")
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
