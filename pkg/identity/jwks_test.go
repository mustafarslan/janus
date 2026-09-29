package identity_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/identity"
)

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func jwksOf(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	blob, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

// TestParseJWKSReadsTheThreeAlgorithmsThisBuildVerifies keeps the parser and the
// verifier from drifting apart.
//
// A key this build cannot verify with is worse than an absent one: it is trusted
// in the log, selected by a token's `kid`, and then refused at the last moment
// with a message about algorithms rather than about trust.
func TestParseJWKSReadsTheThreeAlgorithmsThisBuildVerifies(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := coords(t, &ecKey.PublicKey)

	set, err := identity.ParseJWKS(jwksOf(t,
		map[string]any{"kty": "RSA", "kid": "r1",
			"n": b64(rsaKey.N.Bytes()),
			"e": b64(big.NewInt(int64(rsaKey.E)).Bytes())},
		map[string]any{"kty": "EC", "crv": "P-256", "kid": "e1", "x": b64(x), "y": b64(y)},
		map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": "o1", "x": b64(edPub)},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 3 {
		t.Fatalf("parsed %d keys, want 3", len(set))
	}
	want := map[string]string{"r1": "RS256", "e1": "ES256", "o1": "EdDSA"}
	for _, k := range set {
		if want[k.KeyID] != k.Algorithm {
			t.Errorf("key %s inferred alg %q, want %q", k.KeyID, k.Algorithm, want[k.KeyID])
		}
	}
	// The keys must round-trip to what the log stores, or a fold will hand back
	// something that does not match what was configured.
	for _, k := range set {
		if _, err := identity.EncodePublicKey(k.Key); err != nil {
			t.Errorf("key %s does not encode: %v", k.KeyID, err)
		}
	}
}

// TestAKeyWithNoIDIsSkipped: a token names its key by `kid`, so a key without
// one could never be selected. Recording it would put something in the log that
// nothing can reach and that an operator would count as trusted.
func TestAKeyWithNoIDIsSkipped(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := coords(t, &key.PublicKey)

	_, err = identity.ParseJWKS(jwksOf(t,
		map[string]any{"kty": "EC", "crv": "P-256", "x": b64(x), "y": b64(y)}))
	if err == nil {
		t.Fatal("a JWKS whose only key has no kid was accepted")
	}
	if !strings.Contains(err.Error(), "could never be selected") {
		t.Errorf("the refusal does not explain why: %v", err)
	}
}

// TestAJWKSWithNothingUsableIsRefusedNotEmpty. Returning an empty set with no
// error would let a daemon start reporting success having trusted nothing, which
// is the state in which no issuer can be trusted.
func TestAJWKSWithNothingUsableIsRefusedNotEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  map[string]any
	}{
		{"unsupported key type", map[string]any{"kty": "oct", "kid": "k", "k": "AAAA"}},
		{"unsupported curve", map[string]any{"kty": "EC", "crv": "P-521", "kid": "k",
			"x": b64([]byte("x")), "y": b64([]byte("y"))}},
		{"encryption key", map[string]any{"kty": "RSA", "use": "enc", "kid": "k",
			"n": b64([]byte("n")), "e": b64([]byte{1, 0, 1})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := identity.ParseJWKS(jwksOf(t, tc.key))
			if err == nil {
				t.Fatalf("accepted, returning %d key(s); a daemon would report success "+
					"having trusted nothing", len(set))
			}
			if !strings.Contains(err.Error(), "no key this build can verify with") {
				t.Errorf("unexpected refusal: %v", err)
			}
		})
	}
}

// TestAPointNotOnTheCurveIsRefused. A malformed EC key would be recorded and
// then fail every verification, and the failure would read as a trust problem
// rather than as a bad configuration file.
func TestAPointNotOnTheCurveIsRefused(t *testing.T) {
	_, err := identity.ParseJWKS(jwksOf(t, map[string]any{
		"kty": "EC", "crv": "P-256", "kid": "bad",
		"x": b64(make([]byte, 32)), "y": b64(make([]byte, 32)),
	}))
	if err == nil {
		t.Fatal("a point that is not on P-256 was accepted as a key")
	}
}

// TestAnEmptyKeySetIsRefused: a file with an empty "keys" array trusts nothing
// and would read to an operator as though it had worked.
func TestAnEmptyKeySetIsRefused(t *testing.T) {
	if _, err := identity.ParseJWKS([]byte(`{"keys":[]}`)); err == nil {
		t.Fatal("an empty JWKS was accepted")
	}
}

// TestAStatedAlgorithmThatDisagreesWithTheKeyIsRefused. The issuer knows what it
// signs with; a document claiming RS256 on an EC key is not one to guess about.
func TestAStatedAlgorithmThatDisagreesWithTheKeyIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := coords(t, &key.PublicKey)
	if _, err := identity.ParseJWKS(jwksOf(t, map[string]any{
		"kty": "EC", "crv": "P-256", "kid": "e1", "alg": "RS256",
		"x": b64(x), "y": b64(y),
	})); err == nil {
		t.Fatal("an EC key claiming RS256 was accepted")
	}
}

// coords returns a P-256 public key's x and y, taken from the key's own SEC 1
// encoding rather than from its deprecated coordinate fields.
func coords(t *testing.T, pub *ecdsa.PublicKey) (x, y []byte) {
	t.Helper()
	raw, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 65 || raw[0] != 4 {
		t.Fatalf("unexpected P-256 encoding: %d bytes starting %#x", len(raw), raw[0])
	}
	return raw[1:33], raw[33:]
}
