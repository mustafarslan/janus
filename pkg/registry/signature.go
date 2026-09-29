package registry

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/template"
)

// Manifest signatures, and why the trust does not come from the manifest.
//
// A manifest declares public keys in its identity section. Those keys are for
// the participant's own messages; they cannot establish that the manifest is
// genuine, because a document that names the key that signed it authenticates
// nothing — anybody can generate a key, sign a manifest, and name it.
//
// So the verifying side supplies the keys it trusts for each principal out of
// band. That is the same shape janus-verify uses for writer keys, and for the
// same reason: the artifact and the trust in it must not travel together, or
// the signature is decoration.
//
// What a signature buys, concretely: the registry knows a manifest came from
// the legal entity answerable for the participant, and an auditor re-reading
// the log years later can check the same thing without asking the registry.

// signatureDomain separates a manifest signature from every other Ed25519
// signature in the system, so a segment footer signature can never be replayed
// as a manifest signature or the reverse.
const signatureDomain = "JANUS/manifest-sig/1\x00"

// TrustStore says which keys may speak for which principal.
//
// It is keyed by principal rather than being a flat key set on purpose. A key
// trusted to register manifests for one legal entity is not thereby trusted to
// register them for another, and a flat set would silently grant exactly that.
type TrustStore map[string]keys.PublicKeySet

// Trust adds a public key as authorised to sign manifests for a principal.
func (t TrustStore) Trust(principal string, pub ed25519.PublicKey) {
	set, ok := t[principal]
	if !ok {
		set = keys.PublicKeySet{}
		t[principal] = set
	}
	set[keys.KeyIDFor(pub)] = pub
}

// Knows reports whether the store holds any key for a principal.
func (t TrustStore) Knows(principal string) bool { return len(t[principal]) > 0 }

// ErrSignature means a manifest signature does not hold up.
var ErrSignature = errors.New("registry: manifest signature")

// ErrUntrusted means no key is trusted for the principal that signed.
//
// It is separate from ErrSignature because the two mean different things to
// whoever has to act: a bad signature is an attack or a corruption, while an
// unknown principal is usually a trust store that has not been told about a new
// legal entity yet. Collapsing them would train an operator to treat the first
// as routine.
var ErrUntrusted = errors.New("registry: no trusted key for principal")

// Sign produces a signature over the manifest's canonical bytes.
func Sign(m *Manifest, signer *keys.Signer) (*janusv1.ManifestSignature, error) {
	canonical, err := m.Canonical()
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(signedBytes(canonical))
	if err != nil {
		return nil, fmt.Errorf("registry: sign manifest: %w", err)
	}
	return &janusv1.ManifestSignature{
		KeyId:     signer.KeyID(),
		Signature: sig,
		Principal: m.Identity.Principal,
	}, nil
}

// Verify checks a signature over canonical manifest bytes against the trust
// store.
//
// The principal comes from the manifest rather than from the signature record:
// a signature that names its own principal could claim to speak for whichever
// entity the store happens to trust.
func Verify(canonical []byte, principal string, sig *janusv1.ManifestSignature, trust TrustStore) error {
	if sig == nil || len(sig.GetSignature()) == 0 {
		return fmt.Errorf("%w: manifest for principal %q carries no signature", ErrSignature, principal)
	}
	set := trust[principal]
	if len(set) == 0 {
		return fmt.Errorf("%w: %q", ErrUntrusted, principal)
	}
	pub, ok := set[sig.GetKeyId()]
	if !ok {
		return fmt.Errorf("%w: key %s is not trusted for principal %q", ErrSignature,
			sig.GetKeyId(), principal)
	}
	// The key id is derived from the key material, so this cannot be satisfied
	// by claiming a trusted id while carrying different bytes — but checking it
	// here means a store built by hand rather than through Trust cannot smuggle
	// a mismatch in either.
	if keys.KeyIDFor(pub) != sig.GetKeyId() {
		return fmt.Errorf("%w: trusted key %s does not match its own key id", ErrSignature,
			sig.GetKeyId())
	}
	if !ed25519.Verify(pub, signedBytes(canonical), sig.GetSignature()) {
		return fmt.Errorf("%w: does not verify for principal %q under key %s", ErrSignature,
			principal, sig.GetKeyId())
	}
	return nil
}

func signedBytes(canonical []byte) []byte {
	out := make([]byte, 0, len(signatureDomain)+len(canonical))
	out = append(out, signatureDomain...)
	return append(out, canonical...)
}

// SignTemplate produces a signature over a template's canonical bytes.
//
// The same construction as Sign, over a different document, and deliberately not
// a shared "sign these bytes" helper: the signature is checked against the
// principal the *document* declares, and a helper taking loose bytes would let a
// caller sign one document and claim the principal of another.
func SignTemplate(t *template.Template, signer *keys.Signer) (*janusv1.ManifestSignature, error) {
	canonical, err := template.Encode(t)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(signedBytes(canonical))
	if err != nil {
		return nil, fmt.Errorf("registry: sign template: %w", err)
	}
	return &janusv1.ManifestSignature{
		KeyId:     signer.KeyID(),
		Signature: sig,
		Principal: t.Principal,
	}, nil
}
