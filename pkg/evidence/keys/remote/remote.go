// Package remote is writer-key custody outside the process that writes the log.
//
// Phase 0 put the writer's Ed25519 private key in a file next to the evidence
// directory. That is the simplest thing that works, and it has a property worth
// stating plainly rather than leaving to be discovered: anyone who can read
// that file can sign segments. Not just future ones — they can rewrite a sealed
// segment, recompute its Merkle root, sign the new footer, and hand an auditor
// a log that verifies perfectly and is not what happened. On-disk custody makes
// the tamper-evidence exactly as strong as the host.
//
// This package moves the key out of that process. The appender talks to a
// signing daemon over a unix socket and asks it for two things:
//
//	PUBKEY            -> the key id and public key, for the trust set
//	SIGN <hex bytes>  -> a signature
//
// **There is no third operation.** The protocol has no way to ask for a private
// key, so "the appender never holds the key material" is true by construction
// rather than by a test that goes looking for it. That is the only kind of
// claim of this shape worth making.
//
// # What this buys, and what it does not
//
// A signing daemon on the same host is not an HSM, and shipping it as one would
// be the failure this project keeps refusing: a control that reads as present
// and is hollow. What the seam actually gives you:
//
//   - The key is never in the appender's address space and never on the disk
//     that holds the evidence. Run the daemon under its own uid with the key
//     file 0600 and a compromise of the appender — short of root — cannot take
//     it.
//
//   - Forgery needs an online oracle. An attacker who steals a key file forges
//     silently, offline, for as long as the key lives. An attacker who has to
//     ask a daemon forges only while they hold that access, and every request
//     is something the daemon can log independently of Janus.
//
//   - The daemon is replaceable. A PKCS#11 bridge, a cloud-KMS client, or a
//     tenant's own signing service speaks the same two operations, and Janus
//     does not change. That is where per-tenant BYOK actually arrives: the
//     operator running the daemon need not be the party that holds the key.
//
// What it does not buy: an attacker who owns the host can still ask the oracle
// to sign a rewritten segment. Moving custody removes durable, silent, offline
// key theft. It does not make a compromised host honest, and no signing
// arrangement does.
package remote

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/keys"
)

// Protocol constants. The wire format is one line per message, hex-encoded, so
// a transcript is readable in a packet capture or a log and a malformed frame
// cannot be mistaken for a short one.
const (
	cmdPubkey = "PUBKEY"
	cmdSign   = "SIGN"
	respOK    = "OK"
	respErr   = "ERR"
	// maxLine bounds a request. A signature is over a 32-byte digest-sized
	// preimage in practice, but the segment footer preimage is longer; 64 KiB
	// is far more than either and small enough that a hostile client cannot
	// make the daemon allocate.
	maxLine = 64 << 10
)

// ErrUnavailable wraps every failure to reach or use the signer.
//
// It is deliberately one error rather than a taxonomy. Every one of them means
// the same thing to the write path: this segment cannot be signed, so it must
// not be sealed, so the log stops. A caller that wanted to treat
// "connection refused" differently from "daemon said no" would be looking for
// a reason to continue.
var ErrUnavailable = errors.New("remote signer unavailable")

// Client is a segment.Signer whose private key lives in another process.
type Client struct {
	addr    string
	timeout time.Duration

	// The key id and public key are fetched once at Dial and cached. They are
	// not secrets, they do not change for the life of a connection, and
	// fetching them per signature would put a round trip in front of every
	// seal for a value that cannot have moved.
	keyID string
	pub   ed25519.PublicKey

	// mu serialises requests. The protocol is a synchronous request/response
	// with no correlation ids, so two concurrent callers on one connection
	// would read each other's answers. Sealing is already serialised behind
	// the writer goroutine; this is here so that stays true if it stops being.
	mu sync.Mutex
}

// Options configures a Client.
type Options struct {
	// Socket is the unix socket the signing daemon listens on.
	Socket string
	// Timeout bounds one request. Defaults to five seconds.
	//
	// It exists because the alternative is worse than a slow seal: a signer
	// that accepts a connection and never answers would park the writer
	// goroutine forever, and an evidence log that has stopped without saying
	// so is the one failure mode fail-closed is supposed to prevent being
	// silent.
	Timeout time.Duration
}

// Dial connects to a signing daemon and learns which key it holds.
//
// Connecting eagerly is deliberate. A lazy client would let a process open an
// evidence directory, accept work, and only discover at the first seal that
// nothing can sign it — by which point there are events in an open segment and
// the operator's mistake has become a recovery problem. This fails at startup,
// where a wrong socket path is still just a wrong socket path.
func Dial(opts Options) (*Client, error) {
	if opts.Socket == "" {
		return nil, fmt.Errorf("%w: no socket configured", ErrUnavailable)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	c := &Client{addr: opts.Socket, timeout: opts.Timeout}

	fields, err := c.roundTrip(cmdPubkey)
	if err != nil {
		return nil, err
	}
	if len(fields) != 2 {
		return nil, fmt.Errorf("%w: PUBKEY answered %d field(s), want 2", ErrUnavailable, len(fields))
	}
	pub, err := hex.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("%w: public key is not hex: %w", ErrUnavailable, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key is %d bytes, want %d",
			ErrUnavailable, len(pub), ed25519.PublicKeySize)
	}
	// The id is derived from the key rather than believed. A daemon that
	// reported an id belonging to a key it does not hold would put footers in
	// the log pointing at the wrong entry in the trust set, and they would fail
	// verification later rather than here — which is the wrong place to find
	// out.
	if want := keys.KeyIDFor(pub); fields[0] != want {
		return nil, fmt.Errorf("%w: daemon reports key id %s for a key whose id is %s",
			ErrUnavailable, fields[0], want)
	}
	c.keyID = fields[0]
	c.pub = pub
	return c, nil
}

// KeyID returns the id of the key the daemon holds.
func (c *Client) KeyID() string { return c.keyID }

// Public returns the public half, for building a trust set.
func (c *Client) Public() ed25519.PublicKey { return c.pub }

// Sign asks the daemon for a signature over message.
//
// The result is verified against the public key learned at Dial before it is
// returned. That check is not paranoia about the daemon: a signature that does
// not verify is a signature that will fail in an auditor's hands months later,
// with the log sealed around it and no way to tell whether the segment was
// tampered with or merely signed badly. Catching it here turns an unanswerable
// question into a refused write.
func (c *Client) Sign(message []byte) ([]byte, error) {
	fields, err := c.roundTrip(cmdSign + " " + hex.EncodeToString(message))
	if err != nil {
		return nil, err
	}
	if len(fields) != 1 {
		return nil, fmt.Errorf("%w: SIGN answered %d field(s), want 1", ErrUnavailable, len(fields))
	}
	sig, err := hex.DecodeString(fields[0])
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not hex: %w", ErrUnavailable, err)
	}
	if !ed25519.Verify(c.pub, message, sig) {
		return nil, fmt.Errorf("%w: the daemon returned a signature that does not verify under key %s",
			ErrUnavailable, c.keyID)
	}
	return sig, nil
}

// roundTrip opens a connection, sends one command, and reads one answer.
//
// A connection per request rather than a pooled one. Signing happens once per
// sealed segment — every sixteen megabytes of evidence by default — so the cost
// of a unix-socket connect is not measurable here, and a fresh connection
// cannot inherit a half-read response from a previous timeout.
func (c *Client) roundTrip(cmd string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := net.DialTimeout("unix", c.addr, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	if _, err := io.WriteString(conn, cmd+"\n"); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	line, err := bufio.NewReaderSize(conn, maxLine).ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return nil, fmt.Errorf("%w: empty answer", ErrUnavailable)
	}
	if fields[0] != respOK {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, strings.Join(fields[1:], " "))
	}
	return fields[1:], nil
}

// Serve runs the signing daemon's accept loop until ln is closed.
//
// It lives here, next to the client, because a protocol whose two ends are
// written in different places drifts. It is exported so a test can run a signer
// in-process and so cmd/janus-signer is a flag parser and nothing more.
func Serve(ln net.Listener, signer *keys.Signer) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			// A closed listener is how this loop is meant to end.
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handle(conn, signer)
	}
}

// handle answers one connection.
//
// One command per connection, matching the client. A daemon that stayed open
// for further commands would have to decide what to do with a client that
// connects and says nothing, and the answer would be a timeout — which is what
// closing after one exchange achieves without the state.
func handle(conn net.Conn, signer *keys.Signer) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	line, err := bufio.NewReaderSize(conn, maxLine).ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		reply(conn, respErr, "empty command")
		return
	}

	switch fields[0] {
	case cmdPubkey:
		reply(conn, respOK, signer.KeyID(), hex.EncodeToString(signer.Public()))
	case cmdSign:
		if len(fields) != 2 {
			reply(conn, respErr, "SIGN takes one hex argument")
			return
		}
		message, err := hex.DecodeString(fields[1])
		if err != nil {
			reply(conn, respErr, "argument is not hex")
			return
		}
		sig, err := signer.Sign(message)
		if err != nil {
			reply(conn, respErr, "signing failed")
			return
		}
		reply(conn, respOK, hex.EncodeToString(sig))
	default:
		// Deliberately not an echo of what was asked. This daemon holds a
		// private key and answers whoever reaches its socket; it does not need
		// to help an unknown caller discover what else it might understand.
		reply(conn, respErr, "unknown command")
	}
}

func reply(conn net.Conn, fields ...string) {
	_, _ = io.WriteString(conn, strings.Join(fields, " ")+"\n")
}
