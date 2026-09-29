package remote_test

import (
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/keys/remote"
)

// socketPath returns a short temporary path.
//
// Not t.TempDir(): a unix socket address is capped at about 104 bytes on
// darwin, and the /var/folders/... paths the test framework hands out can push
// a socket name past it. The failure is `bind: invalid argument`, which reads
// like a bug in the listener rather than a path length.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "jsig")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}

// serve starts a signing daemon in-process and returns its socket.
func serve(t *testing.T, signer *keys.Signer) string {
	t.Helper()
	path := socketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- remote.Serve(ln, signer) }()
	t.Cleanup(func() {
		_ = ln.Close()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return path
}

func mustSigner(t *testing.T) *keys.Signer {
	t.Helper()
	s, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignaturesFromTheDaemonVerifyUnderItsKey(t *testing.T) {
	signer := mustSigner(t)
	c, err := remote.Dial(remote.Options{Socket: serve(t, signer)})
	if err != nil {
		t.Fatal(err)
	}
	if c.KeyID() != signer.KeyID() {
		t.Fatalf("client reports key %s, daemon holds %s", c.KeyID(), signer.KeyID())
	}

	message := []byte("JANUS/segment-footer/1\x00some footer bytes")
	sig, err := c.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(signer.Public(), message, sig) {
		t.Fatal("the daemon's signature does not verify under its own public key")
	}
	// And the client's cached public key is the daemon's, so a trust set built
	// from the client is the one that verifies the log.
	if !ed25519.Verify(c.Public(), message, sig) {
		t.Fatal("the client cached a public key that does not match the signer")
	}
}

// TestTheProtocolHasNoWayToAskForTheKey is the claim this package makes, and it
// is a claim about the protocol rather than about the daemon's discretion.
//
// The test cannot prove a negative about every possible request, and does not
// try. What it establishes is that the obvious ways of asking are not
// special-cased into working, and that an unknown command is answered without
// telling the caller what else might be understood.
func TestTheProtocolHasNoWayToAskForTheKey(t *testing.T) {
	signer := mustSigner(t)
	path := serve(t, signer)

	for _, cmd := range []string{"PRIVKEY", "KEY", "EXPORT", "GET", "SIGN", "sign", ""} {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		_ = conn.Close()
		answer := string(buf[:n])

		if len(answer) < 3 || answer[:3] != "ERR" {
			t.Fatalf("command %q was answered %q, want an error", cmd, answer)
		}
		// Nothing that could be key material: an Ed25519 private key is 64
		// bytes, so 128 hex characters. The error lines are far shorter than
		// that, and this fails loudly if one ever stops being.
		if len(answer) > 64 {
			t.Fatalf("command %q was answered %d bytes, which is enough to carry a key: %q",
				cmd, len(answer), answer)
		}
	}
}

// TestDialRefusesADaemonThatMisreportsItsKeyId covers a daemon — or something
// standing in for one — that answers PUBKEY with an id belonging to a key it
// does not hold. Believing it would put footers in the log pointing at the
// wrong entry in the trust set, and they would fail verification in an
// auditor's hands rather than here.
func TestDialRefusesADaemonThatMisreportsItsKeyId(t *testing.T) {
	path := socketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	honest := mustSigner(t)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 128)
		_, _ = conn.Read(buf)
		// A real public key, under somebody else's id.
		_, _ = conn.Write([]byte("OK ed25519-0000000000000000 " +
			hexOf(honest.Public()) + "\n"))
	}()

	if _, err := remote.Dial(remote.Options{Socket: path}); !errors.Is(err, remote.ErrUnavailable) {
		t.Fatalf("a daemon misreporting its key id was accepted: %v", err)
	}
}

// TestDialRefusesAnAbsentSigner is the startup half of fail-closed. A lazy
// client would let a process open an evidence directory, accept work, and only
// discover at the first seal that nothing can sign it.
func TestDialRefusesAnAbsentSigner(t *testing.T) {
	if _, err := remote.Dial(remote.Options{Socket: socketPath(t)}); !errors.Is(err, remote.ErrUnavailable) {
		t.Fatalf("dialling a socket nobody is listening on succeeded: %v", err)
	}
	if _, err := remote.Dial(remote.Options{}); !errors.Is(err, remote.ErrUnavailable) {
		t.Fatalf("dialling with no socket configured succeeded: %v", err)
	}
}

// TestSignFailsOnceTheDaemonIsGone is the running half. What matters is not the
// error itself but what the appender does with it — see the evidence tests,
// where this becomes a log that stops rather than a segment sealed unsigned.
func TestSignFailsOnceTheDaemonIsGone(t *testing.T) {
	signer := mustSigner(t)
	path := socketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- remote.Serve(ln, signer) }()

	c, err := remote.Dial(remote.Options{Socket: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sign([]byte("before")); err != nil {
		t.Fatal(err)
	}

	_ = ln.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(path)

	if _, err := c.Sign([]byte("after")); !errors.Is(err, remote.ErrUnavailable) {
		t.Fatalf("signing succeeded after the daemon stopped: %v", err)
	}
}

// TestAnUnverifiableSignatureIsRefused covers a daemon that answers with bytes
// that are not a signature over what was asked.
//
// Returning it would put a footer in the log that fails in an auditor's hands
// months later, with no way to tell whether the segment was tampered with or
// merely signed badly. Refusing here turns an unanswerable question into a
// refused write.
func TestAnUnverifiableSignatureIsRefused(t *testing.T) {
	path := socketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	honest := mustSigner(t)
	other := mustSigner(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 4096)
				n, _ := conn.Read(buf)
				if n >= 6 && string(buf[:6]) == "PUBKEY" {
					_, _ = conn.Write([]byte("OK " + honest.KeyID() + " " + hexOf(honest.Public()) + "\n"))
					return
				}
				// A real signature, over the right bytes, from the wrong key.
				sig, _ := other.Sign([]byte("whatever was asked"))
				_, _ = conn.Write([]byte("OK " + hexOf(sig) + "\n"))
			}()
		}
	}()

	c, err := remote.Dial(remote.Options{Socket: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sign([]byte("a footer")); !errors.Is(err, remote.ErrUnavailable) {
		t.Fatalf("a signature that does not verify was accepted: %v", err)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}
