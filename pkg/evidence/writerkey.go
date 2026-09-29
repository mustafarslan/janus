package evidence

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// Which key signs this log, recorded in the log.
//
// # The problem
//
// A segment's footer names the key that signed it, and verification looks that
// key up in a set the auditor supplies. Rotating the writer key therefore means
// the auditor has to be handed *every* key the log was ever written under, out
// of band, with no way to tell whether they were given all of them.
//
// That is not a theoretical gap. Withhold the key that signed the segments you
// would rather not be read, and the recipient sees UNKNOWN_SIGNING_KEY on
// exactly those segments and a clean pass on the rest — which reads like a
// corrupted archive, not like a withheld one. The two failures are
// indistinguishable from the outside, and only one of them is somebody's fault.
//
// # What this changes
//
// A WRITER_KEY event introduces the next key, in a segment signed by the
// current one. Verification starts from the root the auditor was handed and
// extends the set forward as it walks. So an auditor needs **one** public key,
// and a rotation removed from the log breaks the chain hash — the key cannot be
// withheld, only destroyed along with the evidence that mentions it.
//
// # What it does not establish
//
// This is a certificate chain, and it is worth saying so plainly rather than
// letting it read as tamper-proofing. An attacker holding the current key can
// introduce another one — but they hold the current key, so they can already
// sign whatever they like. What the chain buys is narrower and real: an auditor
// who trusts one key out of band can follow the log forward without being
// handed anything else, and can tell a *withheld* key from a *corrupt* segment.
//
// Two ordering rules make it work, and both are the sort of thing that looks
// like an implementation detail and is the whole property:
//
//   - A declaration extends trust only if the segment carrying it verified
//     under the set as it stood. Otherwise a forged segment could introduce the
//     key that signs it.
//   - It extends trust only *after* that segment's own footer is checked, so a
//     segment cannot introduce the key it was signed with.
//
// And revocation is not retroactive. A key revoked at sequence N keeps its
// earlier segments verifying and signs nothing after; the alternative makes
// every rotation invalidate the history written under the previous key, which
// is how operators learn not to rotate.

// WriterKeyKind distinguishes a declaration from a withdrawal.
type WriterKeyKind string

const (
	// WriterKeyTrusted introduces a key. The segment carrying it must be signed
	// by a key that is already trusted — which for the first one means the root
	// an auditor is handed out of band.
	WriterKeyTrusted WriterKeyKind = "TRUSTED"
	// WriterKeyRevoked withdraws one, from this point forward.
	WriterKeyRevoked WriterKeyKind = "REVOKED"
)

// WriterKeyDeclaration is the payload of a WRITER_KEY event.
//
// CBOR rather than protobuf, and the only payload in this system that is. The
// verifier has to read it, and the verifier is the one artifact an auditor
// compiles themselves: linking the protobuf runtime into it takes the
// binary from 7 MB to 16 MB for one event type.
type WriterKeyDeclaration struct {
	Kind WriterKeyKind `json:"kind" cbor:"1,keyasint"`
	// KeyID is derived from the public key rather than believed. It is carried
	// so a revocation can name a key without repeating its bytes.
	KeyID string `json:"key_id" cbor:"2,keyasint"`
	// PublicKey is the raw 32 bytes of an Ed25519 key. Required for TRUSTED,
	// omitted for REVOKED.
	PublicKey []byte `json:"public_key,omitempty" cbor:"3,keyasint,omitempty"`
	// Reason is why. For a revocation it is the whole content of the event: a
	// key withdrawn without a reason tells a later reader nothing about whether
	// it was compromised or merely retired.
	Reason string `json:"reason,omitempty" cbor:"4,keyasint,omitempty"`
}

// ErrWriterKey means a declaration is malformed or contradicts the log.
var ErrWriterKey = errors.New("evidence: writer key declaration")

// Validate checks a declaration is usable before it is recorded or applied.
func (d WriterKeyDeclaration) Validate() error {
	switch d.Kind {
	case WriterKeyTrusted:
		if len(d.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: a trusted key is %d bytes, want %d",
				ErrWriterKey, len(d.PublicKey), ed25519.PublicKeySize)
		}
		// Derived, never believed — the same rule the remote signer client
		// applies to a daemon reporting its own id. A declaration naming one key
		// and carrying another would put footers in the log pointing at the
		// wrong entry, and they would fail in an auditor's hands rather than
		// here.
		if want := keys.KeyIDFor(d.PublicKey); d.KeyID != want {
			return fmt.Errorf("%w: declares key id %s for a key whose id is %s",
				ErrWriterKey, d.KeyID, want)
		}
	case WriterKeyRevoked:
		if d.KeyID == "" {
			return fmt.Errorf("%w: a revocation names no key", ErrWriterKey)
		}
		if d.Reason == "" {
			return fmt.Errorf("%w: a revocation needs a reason; without one a later reader "+
				"cannot tell a compromised key from a retired one", ErrWriterKey)
		}
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrWriterKey, d.Kind)
	}
	return nil
}

// Encode renders a declaration for an event payload.
func (d WriterKeyDeclaration) Encode() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return cbor.Marshal(d)
}

// DecodeWriterKey parses a WRITER_KEY payload.
func DecodeWriterKey(payload []byte) (WriterKeyDeclaration, error) {
	var d WriterKeyDeclaration
	if err := cbor.Unmarshal(payload, &d); err != nil {
		return d, fmt.Errorf("%w: unreadable: %w", ErrWriterKey, err)
	}
	if err := d.Validate(); err != nil {
		return d, err
	}
	return d, nil
}

// WriterTrust is the set of keys a log's segments may be signed by, as it
// stands at some point in the walk.
type WriterTrust struct {
	trusted map[string]ed25519.PublicKey
	// origin records where each key came from, so a report can say which key
	// the reader supplied and which the log introduced. An auditor being told
	// "these three keys were used" wants to know that they only had to trust
	// one of them.
	origin map[string]string
}

// NewWriterTrust starts from the roots an auditor was handed out of band.
func NewWriterTrust(roots keys.PublicKeySet) *WriterTrust {
	return NewWriterTrustFrom(roots, "supplied out of band")
}

// NewWriterTrustFrom is NewWriterTrust with the roots' provenance named.
//
// A verification that resumes where the last one stopped starts from the set
// that one *ended* with, which contains keys the log introduced rather than
// keys anybody was handed. Reporting those as "supplied out of band"
// would tell an auditor they had to trust several keys directly when they
// trusted one — which is the exact confusion key declarations exist to remove — so the
// caller says where its roots came from and the report repeats it.
func NewWriterTrustFrom(roots keys.PublicKeySet, origin string) *WriterTrust {
	w := &WriterTrust{
		trusted: make(map[string]ed25519.PublicKey, len(roots)),
		origin:  make(map[string]string, len(roots)),
	}
	for id, pub := range roots {
		w.trusted[id] = pub
		w.origin[id] = origin
	}
	return w
}

// Key returns the public key for an id, if it is currently trusted.
func (w *WriterTrust) Key(keyID string) (ed25519.PublicKey, bool) {
	pub, ok := w.trusted[keyID]
	return pub, ok
}

// Origin says where a key came from, for a report.
func (w *WriterTrust) Origin(keyID string) string { return w.origin[keyID] }

// Keys returns every key currently trusted: the roots the caller supplied plus
// the ones the log introduced and did not revoke.
//
// It exists so that a check made *outside* the segment walk — a bundle's
// manifest signature is the one that matters — can accept the same keys the
// walk accepted. Handing such a check only the caller's roots would report a
// signature made by a legitimately rotated key as untrusted, which is
// forward-extending trust working everywhere except the one place a reader is
// most likely to look.
//
// A copy, so that a caller holding it cannot widen what the walk will accept.
func (w *WriterTrust) Keys() keys.PublicKeySet {
	out := make(keys.PublicKeySet, len(w.trusted))
	for id, pub := range w.trusted {
		out[id] = pub
	}
	return out
}

// Apply extends or narrows the set from one declaration.
//
// The caller decides *when* to call this, and that decision is the security
// property rather than this function's: a declaration must only be applied
// after the segment carrying it has verified, and after that segment's own
// footer has been checked. See the package comment.
func (w *WriterTrust) Apply(d WriterKeyDeclaration, seq uint64) {
	switch d.Kind {
	case WriterKeyTrusted:
		if _, known := w.trusted[d.KeyID]; !known {
			w.origin[d.KeyID] = fmt.Sprintf("introduced at seq %d", seq)
		}
		w.trusted[d.KeyID] = ed25519.PublicKey(d.PublicKey)
	case WriterKeyRevoked:
		delete(w.trusted, d.KeyID)
		// The origin is kept. A report that said nothing about a revoked key
		// would leave a reader wondering why the segments it signed passed.
		w.origin[d.KeyID] = w.origin[d.KeyID] + ", revoked at seq " + fmt.Sprint(seq)
	}
}

// RecordWriterKey appends a declaration.
//
// It is on the Appender rather than a separate recorder because the declaration
// has to land in a segment signed by the key that is being rotated *away* from,
// and this Appender is the thing holding that key.
func (a *Appender) RecordWriterKey(ctx context.Context, d WriterKeyDeclaration,
	by ParticipantRef) (Ref, error) {

	payload, err := d.Encode()
	if err != nil {
		return Ref{}, err
	}
	return a.Append(ctx, Request{
		Kind:        KindWriterKey,
		Participant: by,
		Payload:     payload,
		Labels:      map[string]string{"writer_key": d.KeyID, "declaration": string(d.Kind)},
	})
}

// TrustedWriterKeys folds a directory for the keys it has declared and not
// withdrawn.
//
// It exists so a caller can tell a new declaration from a repeat — a daemon
// restarted with the same standby key must record nothing, because a second
// identical declaration is a rotation that did not happen and a log full of them
// makes the real ones harder to find.
//
// Read from the log rather than remembered, because the process that made the
// first declaration is often not the one asking.
func TrustedWriterKeys(dir string, _ ...ReadOption) (map[string]struct{}, error) {
	trusted := map[string]struct{}{}
	err := walkDeclarations(dir, func(d WriterKeyDeclaration, _ uint64) {
		switch d.Kind {
		case WriterKeyTrusted:
			trusted[d.KeyID] = struct{}{}
		case WriterKeyRevoked:
			delete(trusted, d.KeyID)
		}
	})
	if err != nil {
		return nil, err
	}
	return trusted, nil
}

// RevokedWriterKeys folds a directory for the keys it has withdrawn.
//
// Used at Open, so a daemon started on a key the log has revoked refuses rather
// than signing segments nothing will accept. That refusal is cheap and the
// alternative is expensive: a log that keeps growing under a key an auditor
// will reject, discovered at the audit.
func RevokedWriterKeys(dir string) (map[string]string, error) {
	revoked := map[string]string{}
	err := walkDeclarations(dir, func(d WriterKeyDeclaration, _ uint64) {
		switch d.Kind {
		case WriterKeyTrusted:
			delete(revoked, d.KeyID)
		case WriterKeyRevoked:
			revoked[d.KeyID] = d.Reason
		}
	})
	return revoked, err
}

// walkDeclarations visits every WRITER_KEY declaration in a directory, in
// sequence order.
//
// It does not verify anything. That is deliberate and it is why this is not the
// function verification uses: extending trust from an unverified declaration is
// exactly the mistake the ordering rules exist to prevent. What it is for is the
// narrower question a writer asks about itself — "has my own key been revoked" —
// where the log is one this process is about to take the lock on.
func walkDeclarations(dir string, visit func(WriterKeyDeclaration, uint64)) error {
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		return err
	}
	for _, id := range ids {
		insp, err := segment.Inspect(segment.Path(dir, id))
		if err != nil {
			return fmt.Errorf("inspect segment %d: %w", id, err)
		}
		for i, rec := range insp.Records {
			h, err := DecodeHeader(rec.Header)
			if err != nil {
				return fmt.Errorf("segment %d record %d: %w", id, i, err)
			}
			if h.Kind != KindWriterKey || len(rec.Payload) == 0 {
				continue
			}
			d, err := DecodeWriterKey(rec.Payload)
			if err != nil {
				return fmt.Errorf("segment %d seq %d: %w", id, h.Seq, err)
			}
			visit(d, h.Seq)
		}
	}
	return nil
}

// refuseRevokedSigner stops a writer using a key the log has withdrawn.
//
// A revocation is not retroactive — the segments the key already signed keep
// verifying — but it does mean the key signs nothing more. A daemon that
// carried on would produce a growing tail that fails from the root, and would
// produce it silently.
func refuseRevokedSigner(dir, keyID string) error {
	revoked, err := RevokedWriterKeys(dir)
	if err != nil {
		// A directory that cannot be read for declarations is a directory
		// recovery is about to fail on anyway; let that produce the error, with
		// its own better message.
		return nil //nolint:nilerr // recovery reports this more precisely
	}
	if reason, ok := revoked[keyID]; ok {
		return fmt.Errorf("%w: this log has revoked key %s (%s); a writer using it would "+
			"produce segments that fail verification from the log's own root",
			ErrWriterKey, keyID, reason)
	}
	return nil
}
