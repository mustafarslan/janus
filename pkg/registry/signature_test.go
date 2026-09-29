package registry_test

import (
	"errors"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/registry"
)

func TestASignatureOverAManifestVerifies(t *testing.T) {
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	m := wireManifest()
	sig, err := registry.Sign(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}

	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	if err := registry.Verify(canonical, "pr_bank", sig, trust); err != nil {
		t.Fatalf("an honestly signed manifest did not verify: %v", err)
	}
}

// TestEditingOneByteBreaksTheSignature. The manifest is what a saga pins and
// what the gates read; a signature that survived an edit would be decoration.
func TestEditingOneByteBreaksTheSignature(t *testing.T) {
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	m := wireManifest()
	sig, err := registry.Sign(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())

	mutated := append([]byte(nil), canonical...)
	mutated[len(mutated)/2] ^= 0x01
	if err := registry.Verify(mutated, "pr_bank", sig, trust); err == nil {
		t.Fatal("a manifest with a flipped bit verified under the original signature")
	}
}

// TestAKeyTrustedForOnePrincipalCannotSpeakForAnother. A flat key set would
// grant exactly this by accident: whoever may register manifests for the
// payments team could register them for the trading desk.
func TestAKeyTrustedForOnePrincipalCannotSpeakForAnother(t *testing.T) {
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	m := wireManifest()
	m.Identity.Principal = "pr_trading"
	sig, err := registry.Sign(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}

	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	err = registry.Verify(canonical, "pr_trading", sig, trust)
	if !errors.Is(err, registry.ErrUntrusted) {
		t.Fatalf("a key trusted for one principal signed for another: %v", err)
	}
}

// TestAnUnknownPrincipalIsDistinctFromABadSignature. Collapsing the two would
// train an operator to treat a forgery as routine, because the routine case —
// a legal entity the trust store has not been told about — looks the same.
func TestAnUnknownPrincipalIsDistinctFromABadSignature(t *testing.T) {
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	other, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	m := wireManifest()
	canonical, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := registry.Sign(m, other)
	if err != nil {
		t.Fatal(err)
	}

	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	err = registry.Verify(canonical, "pr_bank", sig, trust)
	if errors.Is(err, registry.ErrUntrusted) {
		t.Fatalf("a signature by an untrusted key was reported as an unknown principal: %v", err)
	}
	if !errors.Is(err, registry.ErrSignature) {
		t.Fatalf("want a signature error, got %v", err)
	}
}

// TestAnUnsignedManifestIsRefusedWhenTheRegistryVerifies.
func TestAnUnsignedManifestIsRefusedWhenTheRegistryVerifies(t *testing.T) {
	r, _, _ := newRecorder(t)
	if _, err := r.Register(t.Context(), wireManifest(), nil); err == nil {
		t.Fatal("an unsigned manifest was registered by a registry holding a trust store")
	}
}
