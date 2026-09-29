package evidence_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// The interlock these tests protect is not "two goroutines" — the appender
// already serialises those — but two *processes* on one directory. Each would
// compute the next sequence number from its own start-up scan, so both would
// issue the same numbers over different payloads and chain each other's records
// into two histories in one directory.

func TestASecondWriterIsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	first := openLocked(t, dir)

	_, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: mustSigner(t), SyncMode: segment.SyncModeNone,
	})
	if err == nil {
		t.Fatal("a second writer opened a directory another writer holds; both would issue the " +
			"same sequence numbers over different payloads")
	}
	if !errors.Is(err, evidence.ErrLocked) {
		t.Fatalf("want ErrLocked so an operator knows to look for the other writer, got %v", err)
	}

	// And the directory is usable again once the first writer lets go.
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: mustSigner(t), SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatalf("the directory stayed locked after its writer closed: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestTheLockDiesWithTheProcessThatHeldIt is the property that makes an OS lock
// the right mechanism rather than a pid file. `make soak` SIGKILLs a writer
// thousands of times and requires the successor to take the same directory
// immediately; a lock that needed unwinding by the dying process would deadlock
// that on the first kill.
func TestTheLockDiesWithTheProcessThatHeldIt(t *testing.T) {
	if os.Getenv("JANUS_LOCK_CHILD") != "" {
		holdAndBlock(t)
		return
	}
	dir := filepath.Join(t.TempDir(), "evidence")

	cmd := exec.Command(os.Args[0], "-test.run=TestTheLockDiesWithTheProcessThatHeldIt", "-test.v")
	cmd.Env = append(os.Environ(), "JANUS_LOCK_CHILD=1", "JANUS_LOCK_DIR="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Wait() }()

	// Wait for the child to say it holds the lock, rather than sleeping.
	buf := make([]byte, 512)
	for {
		n, err := stdout.Read(buf)
		if err != nil {
			t.Fatalf("the child never reported holding the lock: %v", err)
		}
		if n > 0 && strings.Contains(string(buf[:n]), "LOCK HELD") {
			break
		}
	}

	if _, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: mustSigner(t), SyncMode: segment.SyncModeNone,
	}); !errors.Is(err, evidence.ErrLocked) {
		t.Fatalf("the child holds the lock but a second writer was admitted: %v", err)
	}

	// SIGKILL: no unwinding, no defer, nothing the dying process does.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()

	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: mustSigner(t), SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatalf("the lock outlived the process that held it, so a killed writer would strand "+
			"its directory: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
}

// holdAndBlock is the child half: take the lock, announce it, and wait to be
// killed.
func holdAndBlock(t *testing.T) {
	dir := os.Getenv("JANUS_LOCK_DIR")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: mustSigner(t), SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatalf("child could not open %s: %v", dir, err)
	}
	if _, err := app.Append(context.Background(), evidence.Request{
		Kind:        evidence.KindControl,
		Participant: evidence.ParticipantRef{ID: "child", Kind: "SYSTEM"},
		Payload:     []byte(`{"child":true}`),
	}); err != nil {
		t.Fatal(err)
	}
	os.Stdout.WriteString("LOCK HELD\n")
	select {} // killed by the parent
}

// TestTheLockFileIsNotMistakenForEvidence. It lives in the segment directory,
// so every reader walks past it.
func TestTheLockFileIsNotMistakenForEvidence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	app := openLocked(t, dir)
	if _, err := app.Append(context.Background(), evidence.Request{
		Kind:        evidence.KindControl,
		Participant: evidence.ParticipantRef{ID: "test", Kind: "SYSTEM"},
		Payload:     []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Name() == ".janus-writer.lock" {
			found = true
		}
	}
	if !found {
		t.Fatal("no lock file was left behind; removing it on release races a writer that has " +
			"already opened it")
	}

	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatalf("the lock file broke the segment scan: %v", err)
	}
	if len(ids) == 0 {
		t.Fatal("no segments found")
	}
}

func openLocked(t *testing.T, dir string) *evidence.Appender {
	t.Helper()
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: mustSigner(t), SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	return app
}
