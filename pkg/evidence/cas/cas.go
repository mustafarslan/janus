// Package cas is the content-addressed store for evidence payloads that are too
// large to sit inside the hash chain.
//
// Prompts, retrieved documents, model contexts, and tool results can run to
// megabytes. Putting them in the segment file would make the chain expensive to
// read and impossible to prune, so the envelope carries only a digest and a
// reference and the bytes live here.
//
// Addressing by content rather than by name is what keeps that safe. A
// reference names a digest, so a blob cannot be swapped for different bytes
// without the reference no longer matching — the store has no way to lie about
// what it holds, and no separate integrity mechanism is needed. It also makes
// writes idempotent, which matters when a step is retried.
//
// This package deliberately has no delete-by-name. Erasure works by destroying
// the key a blob was encrypted under (crypto-shredding, Phase 1c), not by
// removing bytes an audit trail still refers to.
package cas

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/zeebo/blake3"
)

// Scheme prefixes every reference.
const Scheme = "cas://"

// Algorithm names the digest a reference uses. Only BLAKE3 exists today; the
// name is in the reference so a FIPS build's SHA-256 refs are distinguishable
// rather than silently incompatible.
const Algorithm = "blake3"

// DigestSize is the length of a digest in bytes.
const DigestSize = 32

// Digest is a content address.
type Digest [DigestSize]byte

// Sum returns the digest of b.
//
// The domain separation here matters: a CAS digest must not collide with a
// payload or chain digest over the same bytes, or a value computed for one
// purpose could be presented as evidence of another.
func Sum(b []byte) Digest {
	h := blake3.New()
	_, _ = h.Write([]byte(casDomain))
	_, _ = h.Write(b)
	var d Digest
	copy(d[:], h.Sum(nil))
	return d
}

// SumReader streams r and returns its digest along with the bytes read.
func SumReader(r io.Reader) (Digest, []byte, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return Digest{}, nil, err
	}
	return Sum(body), body, nil
}

const casDomain = "JANUS/cas/1\x00"

// String renders the digest as "blake3:<hex>".
func (d Digest) String() string { return Algorithm + ":" + hex.EncodeToString(d[:]) }

// Ref renders the full reference stored in an event envelope.
func (d Digest) Ref() string { return Scheme + d.String() }

// Errors returned by this package.
var (
	// ErrNotFound means the store has no blob with that digest.
	ErrNotFound = errors.New("cas: blob not found")
	// ErrDigestMismatch means the bytes returned do not hash to the digest that
	// was asked for. It is the store being caught in a lie, and is never
	// recoverable by retrying.
	ErrDigestMismatch = errors.New("cas: content does not match its digest")
	// ErrBadRef means a reference could not be parsed.
	ErrBadRef = errors.New("cas: malformed reference")
)

// ParseRef parses "cas://blake3:<hex>" into a digest.
func ParseRef(ref string) (Digest, error) {
	var d Digest
	rest, ok := strings.CutPrefix(ref, Scheme)
	if !ok {
		return d, fmt.Errorf("%w: %q does not start with %q", ErrBadRef, ref, Scheme)
	}
	alg, hexDigest, ok := strings.Cut(rest, ":")
	if !ok {
		return d, fmt.Errorf("%w: %q has no algorithm prefix", ErrBadRef, ref)
	}
	if alg != Algorithm {
		return d, fmt.Errorf("%w: unsupported digest algorithm %q", ErrBadRef, alg)
	}
	raw, err := hex.DecodeString(hexDigest)
	if err != nil {
		return d, fmt.Errorf("%w: %w", ErrBadRef, err)
	}
	if len(raw) != DigestSize {
		return d, fmt.Errorf("%w: digest is %d bytes, want %d", ErrBadRef, len(raw), DigestSize)
	}
	copy(d[:], raw)
	return d, nil
}

// Store holds content-addressed blobs.
//
// Put is idempotent by construction: the same bytes always produce the same
// address, so storing them twice is storing them once.
type Store interface {
	// Put stores b and returns its digest.
	Put(ctx context.Context, b []byte) (Digest, error)
	// Get returns the blob, verifying it hashes to d before handing it back.
	Get(ctx context.Context, d Digest) ([]byte, error)
	// Has reports whether the blob is present, without fetching it.
	Has(ctx context.Context, d Digest) (bool, error)
	// Describe names the backing store, for reports and error messages.
	Describe() string
}

// Located is implemented by a store that declares which jurisdiction the bytes
// it holds rest in.
//
// It is a separate, optional interface rather than a method on Store because
// most stores cannot answer it. A directory on local disk is wherever the
// machine is; an S3 endpoint is wherever the operator says it is. Janus cannot
// determine the answer and does not pretend to — what it can do is refuse to
// write a jurisdictionally pinned tenant's payloads to a store that has not
// been declared to be in that jurisdiction.
//
// That is a smaller claim than "the data is in Germany" and it is the honest
// one. It converts "nobody checked" into "somebody stated it, in configuration,
// and it matched" — which is a lie an operator has to have written down, rather
// than an omission nobody can point at.
type Located interface {
	// Jurisdiction returns the region code the store's operator declared, or
	// the empty string when none was declared.
	Jurisdiction() string
}

// JurisdictionOf reads a store's declared jurisdiction, or "" if it declares
// none or cannot.
func JurisdictionOf(s Store) string {
	if l, ok := s.(Located); ok {
		return l.Jurisdiction()
	}
	return ""
}

// GetByRef resolves a reference and fetches the blob.
func GetByRef(ctx context.Context, s Store, ref string) ([]byte, error) {
	d, err := ParseRef(ref)
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, d)
}

// Verify checks fetched bytes against the digest they were requested under.
// Every backend runs this before returning, so a corrupted or substituted blob
// is caught at the point of use rather than propagating into a decision.
//
// Exported because a backend does not have to live in this package — the S3 one
// does not, precisely so that the offline verifier does not link an S3 client.
// A store implemented elsewhere that
// skipped this would be a store that hands back whatever the network said.
func Verify(d Digest, body []byte) error {
	if got := Sum(body); got != d {
		return fmt.Errorf("%w: asked for %s, got %s", ErrDigestMismatch, d, got)
	}
	return nil
}
