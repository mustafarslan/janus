// Package keys provides the Phase 0 writer key custody: an Ed25519 key pair on
// disk, with a key id derived from the public key.
//
// This is deliberately the simplest thing that satisfies the segment Signer
// interface. Production custody is KMS/HSM with short-lived keys;
// nothing outside this package assumes where the private key lives.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zeebo/blake3"
)

// KeyIDFor derives a stable, collision-resistant id from a public key. Binding
// the id to the key material means a bundle cannot claim a trusted key id while
// carrying different bytes.
func KeyIDFor(pub ed25519.PublicKey) string {
	sum := blake3.Sum256(pub)
	return "ed25519-" + hex.EncodeToString(sum[:8])
}

// Signer is an Ed25519 signing key held in memory.
type Signer struct {
	priv  ed25519.PrivateKey
	keyID string
}

// Generate creates a fresh key pair.
func Generate() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{priv: priv, keyID: KeyIDFor(pub)}, nil
}

// KeyID returns the derived key id.
func (s *Signer) KeyID() string { return s.keyID }

// Public returns the public key.
func (s *Signer) Public() ed25519.PublicKey { return s.priv.Public().(ed25519.PublicKey) }

// Sign signs message. Ed25519 signing cannot fail for a valid key, but the
// error is kept in the signature so a KMS-backed implementation fits the same
// interface.
func (s *Signer) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}

// keyFile is the on-disk representation of a writer key.
type keyFile struct {
	KeyID string `json:"key_id"`
	Alg   string `json:"alg"`
	Seed  string `json:"seed_hex"`
}

// ErrKeyMismatch means the stored key id does not match the stored key.
var ErrKeyMismatch = errors.New("keys: key id does not match key material")

// Save writes the key to path with owner-only permissions.
func (s *Signer) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(keyFile{
		KeyID: s.keyID,
		Alg:   "ed25519",
		Seed:  hex.EncodeToString(s.priv.Seed()),
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(blob, '\n'), 0o600)
}

// Load reads a key written by Save.
func Load(path string) (*Signer, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(blob, &kf); err != nil {
		return nil, fmt.Errorf("parse key file %s: %w", path, err)
	}
	if kf.Alg != "ed25519" {
		return nil, fmt.Errorf("unsupported key algorithm %q", kf.Alg)
	}
	seed, err := hex.DecodeString(kf.Seed)
	if err != nil {
		return nil, fmt.Errorf("parse key seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("key seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	s := &Signer{priv: priv, keyID: KeyIDFor(priv.Public().(ed25519.PublicKey))}
	if kf.KeyID != "" && kf.KeyID != s.keyID {
		return nil, fmt.Errorf("%w: file says %s, key derives %s", ErrKeyMismatch, kf.KeyID, s.keyID)
	}
	return s, nil
}

// LoadOrCreate loads the key at path, generating and persisting one if absent.
func LoadOrCreate(path string) (*Signer, error) {
	s, err := Load(path)
	if err == nil {
		return s, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s, err = Generate()
	if err != nil {
		return nil, err
	}
	if err := s.Save(path); err != nil {
		return nil, err
	}
	return s, nil
}

// PublicKeySet maps key ids to public keys. A verifier is given one of these
// and trusts nothing outside it.
type PublicKeySet map[string]ed25519.PublicKey

// MarshalJSON renders the set as key id -> hex public key.
func (s PublicKeySet) MarshalJSON() ([]byte, error) {
	m := make(map[string]string, len(s))
	for id, pub := range s {
		m[id] = hex.EncodeToString(pub)
	}
	return json.Marshal(m)
}

// UnmarshalJSON parses the key id -> hex public key form, rejecting any entry
// whose id does not match its key material.
func (s *PublicKeySet) UnmarshalJSON(b []byte) error {
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	out := make(PublicKeySet, len(m))
	for id, hexKey := range m {
		raw, err := hex.DecodeString(hexKey)
		if err != nil {
			return fmt.Errorf("public key %s: %w", id, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("public key %s is %d bytes, want %d", id, len(raw), ed25519.PublicKeySize)
		}
		pub := ed25519.PublicKey(raw)
		if got := KeyIDFor(pub); got != id {
			return fmt.Errorf("%w: entry %s holds key %s", ErrKeyMismatch, id, got)
		}
		out[id] = pub
	}
	*s = out
	return nil
}
