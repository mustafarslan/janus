// Package crypto implements crypto-shredding: the mechanism that lets Janus
// satisfy an erasure request without breaking an immutable audit trail.
//
// The conflict is real and not resolvable by policy. GDPR Art. 17 and its
// equivalents give a data subject the right to have their personal data erased.
// EU AI Act Art. 12, MiFID II, and SEC 17a-4 require the same records to be
// kept, unaltered, for years. A hash chain makes the second requirement
// structural: removing bytes from the middle of it destroys every link after
// them.
//
// Crypto-shredding resolves it by changing what "erase" removes. Personal-data
// payloads are stored encrypted under a key held per data subject. Erasure
// destroys the key, not the record. The ciphertext stays exactly where it was,
// so the chain still verifies and the log still shows that something happened at
// that point — while the content itself becomes unrecoverable by anyone,
// including the operator.
//
// # What the chain commits to
//
// The chain commits to the hash of the *ciphertext*, not of the plaintext.
//
// This is the decision that makes shredding complete rather than approximate. A
// hash of plaintext would survive erasure as a permanent, verifiable fingerprint
// of the erased content: anyone holding a guess could confirm it by hashing,
// which for low-entropy personal data — an account number, a date of birth, a
// name — is a practical attack rather than a theoretical one. A hash of
// ciphertext leaks nothing once the key is gone, because the ciphertext is
// indistinguishable from random without it.
//
// The cost is that after shredding, nobody can prove what the plaintext was.
// That is not a side effect to be minimised; it is the definition of erasure.
// What survives is proof that a record existed, when, by whom, and that it has
// not been altered since — which is what the retention regimes actually require.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// KeySize is the length of a data encryption key.
const KeySize = 32

// Overhead is the number of bytes encryption adds: a version byte, the nonce,
// and the GCM tag.
const Overhead = 1 + nonceSize + gcmTagSize

// formatVersion prefixes every ciphertext so the envelope layout can change
// without old records becoming unreadable.
const formatVersion byte = 1

const (
	nonceSize  = 12
	gcmTagSize = 16
)

// Errors returned by this package.
var (
	// ErrKeyDestroyed means the key for this subject has been shredded. The
	// ciphertext is intact and the chain still verifies; the content is gone
	// permanently and no amount of privilege brings it back.
	ErrKeyDestroyed = errors.New("crypto: key destroyed by erasure, content is unrecoverable")
	// ErrNoKey means no key exists for the subject and none was created.
	ErrNoKey = errors.New("crypto: no key for subject")
	// ErrCiphertextMalformed means the stored bytes are not a Janus envelope.
	ErrCiphertextMalformed = errors.New("crypto: malformed ciphertext")
	// ErrWrongContext means the ciphertext decrypted under a different binding
	// than the one supplied — the record has been moved.
	ErrWrongContext = errors.New("crypto: ciphertext does not belong to this event")
)

// Context binds a ciphertext to the event it belongs to.
//
// It becomes the AEAD's additional authenticated data, so a ciphertext lifted
// from one event and pasted into another fails to decrypt rather than silently
// decrypting into the wrong place. Without this, an attacker who could edit the
// hot tier could move a customer's encrypted decision onto a different saga and
// the chain would happily attest to the result.
type Context struct {
	Subject string
	SagaID  string
	StepID  string
	Kind    string
}

// aad renders the binding in a form with unambiguous field boundaries, so that
// two different contexts can never produce the same bytes.
func (c Context) aad() []byte {
	var out []byte
	out = append(out, "JANUS/aead/1\x00"...)
	for _, field := range []string{c.Subject, c.SagaID, c.StepID, c.Kind} {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	return out
}

// Sealer encrypts and decrypts payloads under per-subject keys.
type Sealer struct {
	ring KeyRing
}

// NewSealer returns a sealer over a key ring.
func NewSealer(ring KeyRing) *Sealer { return &Sealer{ring: ring} }

// Seal encrypts a payload for a data subject, creating the subject's key if it
// does not exist yet.
func (s *Sealer) Seal(plaintext []byte, ctx Context) ([]byte, error) {
	if ctx.Subject == "" {
		return nil, errors.New("crypto: sealing requires a data subject")
	}
	key, err := s.ring.EnsureKey(ctx.Subject)
	if err != nil {
		return nil, err
	}
	defer zero(key)

	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: read nonce: %w", err)
	}

	out := make([]byte, 0, 1+nonceSize+len(plaintext)+gcmTagSize)
	out = append(out, formatVersion)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, ctx.aad()), nil
}

// Open decrypts a payload. It returns ErrKeyDestroyed once the subject has been
// shredded, which callers should surface rather than treat as corruption: the
// record is intact and the content is deliberately gone.
func (s *Sealer) Open(ciphertext []byte, ctx Context) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, fmt.Errorf("%w: %d bytes is shorter than the envelope overhead", ErrCiphertextMalformed, len(ciphertext))
	}
	if ciphertext[0] != formatVersion {
		return nil, fmt.Errorf("%w: unknown format version %d", ErrCiphertextMalformed, ciphertext[0])
	}

	key, err := s.ring.Key(ctx.Subject)
	if err != nil {
		return nil, err
	}
	defer zero(key)

	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[1 : 1+nonceSize]
	body := ciphertext[1+nonceSize:]

	plaintext, err := aead.Open(nil, nonce, body, ctx.aad())
	if err != nil {
		// GCM cannot distinguish a wrong key from a wrong binding from a
		// corrupted byte, but the binding is the case a caller can act on, so
		// say so and let the message carry the ambiguity.
		return nil, fmt.Errorf("%w (or the key is wrong, or the bytes are damaged)", ErrWrongContext)
	}
	return plaintext, nil
}

// IsEncrypted reports whether a stored payload is a Janus crypto envelope.
func IsEncrypted(payload []byte) bool {
	return len(payload) >= Overhead && payload[0] == formatVersion
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new GCM: %w", err)
	}
	return aead, nil
}

// zero overwrites key material once it is no longer needed. It is a small
// hardening measure, not a guarantee: Go can copy a slice during garbage
// collection, so this reduces the window rather than closing it.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
