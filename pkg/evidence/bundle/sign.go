package bundle

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// Signing the manifest, and why it is a separate file.
//
// The manifest's own comment says it is unsigned, and that authenticity comes
// from the segment footers it lists. That is true of a bundle of *sealed*
// segments and false of a backup, which must include the open tail or accept an
// RPO of one whole segment — and an unsealed segment carries no footer, so
// nothing in the artifact authenticates it. The manifest is also what names the
// head chain and the digest of every file; an attacker who can rewrite it can
// drop a segment and adjust the counts to match.
//
// The signature goes in a file beside the manifest rather than a field inside
// it. A field would mean canonicalising JSON to verify — the manifest would have
// to be re-serialised byte-identically by every reader, forever — and it would
// change the format under every bundle already written. Signing the manifest
// file's exact bytes has neither problem: old bundles stay valid old bundles,
// and a *backup* is distinguished from a bundle by requiring the signature.

// SignatureName is the file holding the manifest's signature.
const SignatureName = "janus-bundle.sig"

// Signature authenticates a manifest file's exact bytes.
type Signature struct {
	// KeyID names the writer key that signed. It is the same key that signs
	// segment footers, so a verifier that trusts the log's root already trusts
	// this without being given anything new.
	KeyID string `json:"key_id"`
	// Algorithm is always ed25519 today, and is written down so that a future
	// one is a value rather than a silent reinterpretation of these bytes.
	Algorithm string `json:"algorithm"`
	// Signature is over the manifest file's bytes exactly as they are on disk.
	Signature string `json:"signature"`
}

// ErrUnsigned means a bundle carries no manifest signature.
var ErrUnsigned = errors.New("bundle: the manifest is not signed")

// ErrBadSignature means the manifest's signature does not check out.
var ErrBadSignature = errors.New("bundle: the manifest's signature does not verify")

// SignManifest signs the manifest in a bundle directory.
func SignManifest(dir string, signer segment.Signer) error {
	blob, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return err
	}
	raw, err := signer.Sign(blob)
	if err != nil {
		return fmt.Errorf("bundle: signing the manifest: %w", err)
	}
	sig := Signature{
		KeyID:     signer.KeyID(),
		Algorithm: "ed25519",
		Signature: hex.EncodeToString(raw),
	}
	out, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, SignatureName), append(out, '\n'), 0o640)
}

// VerifyManifestSignature checks a bundle's manifest against trusted roots.
//
// It returns ErrUnsigned when there is no signature file. That is deliberately
// distinguishable from a bad one: "nobody signed this" and "somebody signed this
// and it does not check out" call for different responses, and a caller that
// collapsed them would treat a missing control as a failed one — or worse, the
// other way round.
//
// The keys are the caller's trusted roots, never the manifest's own `Keys`
// field. A signature checked against a key the artifact carries proves the
// artifact is internally consistent, which is what an attacker who rewrote both
// would also produce.
func VerifyManifestSignature(dir string, trusted keys.PublicKeySet) error {
	blob, err := os.ReadFile(filepath.Join(dir, SignatureName))
	if errors.Is(err, os.ErrNotExist) {
		return ErrUnsigned
	}
	if err != nil {
		return err
	}
	var sig Signature
	if err := json.Unmarshal(blob, &sig); err != nil {
		return fmt.Errorf("bundle: reading %s: %w", SignatureName, err)
	}
	if sig.Algorithm != "ed25519" {
		return fmt.Errorf("%w: signed with %q, which this build cannot check",
			ErrBadSignature, sig.Algorithm)
	}
	pub, ok := trusted[sig.KeyID]
	if !ok {
		return fmt.Errorf("%w: signed by %s, which is not among the trusted keys",
			ErrBadSignature, sig.KeyID)
	}
	raw, err := hex.DecodeString(sig.Signature)
	if err != nil {
		return fmt.Errorf("%w: the signature is not hex: %w", ErrBadSignature, err)
	}
	manifest, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, manifest, raw) {
		return fmt.Errorf("%w: the manifest has been altered since it was signed", ErrBadSignature)
	}
	return nil
}
