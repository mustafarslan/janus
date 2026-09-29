package evidence_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/keys/remote"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
)

// signerDaemon starts a signing daemon and returns its socket and a function
// that stops it — which is how the interesting half of these tests is written.
func signerDaemon(t *testing.T, signer *keys.Signer) (socket string, stop func()) {
	t.Helper()
	// Short path: a unix socket address is capped near 104 bytes on darwin and
	// t.TempDir()'s /var/folders/... prefix can exhaust it.
	dir, err := os.MkdirTemp("", "jsig")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	socket = filepath.Join(dir, "s")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- remote.Serve(ln, signer) }()

	var once bool
	stop = func() {
		if once {
			return
		}
		once = true
		_ = ln.Close()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
		_ = os.Remove(socket)
	}
	t.Cleanup(stop)
	return socket, stop
}

// TestALogSignedByADaemonVerifiesAndHoldsNoKey is the whole arrangement end to
// end: the appender writes and seals segments whose signatures came from
// another process, and an auditor holding only the public key verifies them.
//
// The assertion worth reading is the last one. No private key is anywhere under
// the evidence directory, because nothing ever put one there and the protocol
// has no operation that would return one.
func TestALogSignedByADaemonVerifiesAndHoldsNoKey(t *testing.T) {
	held := mustSigner(t)
	socket, _ := signerDaemon(t, held)

	client, err := remote.Dial(remote.Options{Socket: socket})
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: client, SyncMode: segment.SyncModeNone,
		// Small enough that a handful of events rotates a segment, so the seal
		// path — the only place a signature is taken — actually runs.
		SegmentTargetBytes: 512,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, a, 12, "sg_1")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := verify.SegmentDir(dir, verify.Options{
		Keys: keys.PublicKeySet{client.KeyID(): client.Public()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a log signed by the daemon did not verify: %+v", rep.Findings)
	}
	if len(rep.Segments) < 2 {
		t.Fatalf("only %d segment(s); the seal path may not have run", len(rep.Segments))
	}
	for _, s := range rep.Segments {
		if s.Sealed && !s.SignatureOK {
			t.Fatalf("segment %d sealed without a valid signature", s.SegmentID)
		}
	}

	// Nothing under the evidence directory is a key file. The appender never
	// had one to write, and the on-disk custody path would have created
	// <dir>/../keys/writer.key by default.
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "keys")); !os.IsNotExist(err) {
		t.Fatalf("a key directory exists next to a log signed by a daemon: %v", err)
	}
}

// TestTheLogStopsWhenTheSignerGoesAway is fail-closed at the seal.
//
// The alternative it rules out is the dangerous one: a segment closed without a
// footer, or with a footer nobody signed, sitting in a log that otherwise looks
// complete. Evidence that cannot be signed must not become evidence at all,
// so the write path goes sticky and every later append is refused.
func TestTheLogStopsWhenTheSignerGoesAway(t *testing.T) {
	held := mustSigner(t)
	socket, stop := signerDaemon(t, held)

	client, err := remote.Dial(remote.Options{Socket: socket})
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: client, SyncMode: segment.SyncModeNone,
		SegmentTargetBytes: 512,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, a, 6, "sg_1")

	stop()

	// Sealing happens off the writer goroutine, so the failure lands
	// on a later append rather than on the one that triggered the rotation.
	var last error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, last = a.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      "sg_1",
			Participant: evidence.ParticipantRef{ID: "ag_test", Principal: "pr_test", Kind: "AGENT"},
			Payload:     []byte(`{"filler":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`),
		})
		if last != nil {
			break
		}
	}
	if !errors.Is(last, evidence.ErrWritePathFailed) {
		t.Fatalf("the log kept accepting events after its signer went away: %v", last)
	}
	_ = a.Close()

	// And nothing was sealed badly. Every sealed segment still verifies under
	// the key the daemon held; the one that could not be signed is simply not
	// sealed, which recovery will finish when a signer is available again.
	rep, err := verify.SegmentDir(dir, verify.Options{
		Keys:              keys.PublicKeySet{held.KeyID(): held.Public()},
		AllowUnsealedTail: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range rep.Segments {
		if s.Sealed && !s.SignatureOK {
			t.Fatalf("segment %d was sealed with a signature that does not verify", s.SegmentID)
		}
	}
}

// TestOpeningALogNobodyCanSignIsRefused is the same rule at startup.
//
// Recovery *writes*: it seals the segments a dead writer left open, and that
// takes a signature. A process that opened such a directory with no signer
// reachable would have to either leave the tail unsealed and carry on — a log
// with a hole in the middle of its signature coverage — or seal it later under
// whatever key turned up. It refuses instead.
func TestOpeningALogNobodyCanSignIsRefused(t *testing.T) {
	held := mustSigner(t)
	socket, stop := signerDaemon(t, held)
	client, err := remote.Dial(remote.Options{Socket: socket})
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: client, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, a, 3, "sg_1")

	// A copy taken while the writer is live has the same shape a machine that
	// lost power leaves behind: records in a segment with no footer.
	crashed := filepath.Join(t.TempDir(), "crashed")
	copyTree(t, dir, crashed)
	_ = a.Close()

	stop()

	if _, err := evidence.Open(evidence.Options{
		Dir: crashed, Signer: client, SyncMode: segment.SyncModeNone,
	}); !errors.Is(err, remote.ErrUnavailable) {
		t.Fatalf("a log with an unsealed tail opened with no signer reachable: %v", err)
	}
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	if err := os.MkdirAll(to, 0o750); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// The writer lock is a file in the directory and copying it would carry
		// a lock nobody holds into the copy.
		if e.Name() == ".janus-writer.lock" {
			continue
		}
		blob, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), blob, 0o640); err != nil {
			t.Fatal(err)
		}
	}
}

// TestALogSpanningARotationNeedsBothKeys states the property a deployment
// rotating its writer key depends on, and the one it is easiest to get wrong.
//
// Segments signed under the retired key keep verifying forever — a rotation is
// not a repudiation, and a log whose old segments stopped verifying every time
// a key was replaced would make rotation something operators avoid. So the
// trust set is cumulative: an auditor needs every key the log was ever written
// under, and being handed only the current one produces a failure rather than a
// partial pass.
//
// Nothing new was built for this. Verification already keys the footer check by
// key id, so a set holding both works; the test is here because "you must keep
// the old public key" is the kind of operational fact that is only discovered
// when somebody has thrown it away.
func TestALogSpanningARotationNeedsBothKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	first, second := mustSigner(t), mustSigner(t)

	for _, signer := range []*keys.Signer{first, second} {
		a, err := evidence.Open(evidence.Options{
			Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
			SegmentTargetBytes: 512,
		})
		if err != nil {
			t.Fatal(err)
		}
		appendN(t, a, 8, "sg_1")
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
	}

	both := keys.PublicKeySet{
		first.KeyID(): first.Public(), second.KeyID(): second.Public(),
	}
	rep, err := verify.SegmentDir(dir, verify.Options{Keys: both})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("a rotated log did not verify with both keys: %+v", rep.Findings)
	}

	current := keys.PublicKeySet{second.KeyID(): second.Public()}
	rep, err = verify.SegmentDir(dir, verify.Options{Keys: current})
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK {
		t.Fatal("a log written under two keys verified against only the newer one")
	}
	if !hasCritical(rep, "UNKNOWN_SIGNING_KEY") {
		t.Fatalf("no UNKNOWN_SIGNING_KEY finding: %+v", rep.Findings)
	}
}
