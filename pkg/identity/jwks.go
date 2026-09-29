package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// Reading an issuer's published signing keys.
//
// # Why JWKS rather than PEM
//
// An operator trusting an OIDC issuer starts from the document that issuer
// publishes at `/.well-known/jwks.json`. Accepting that document directly means
// they copy a file; accepting PEM would mean they convert each key by hand and
// then type the key id and algorithm in beside it.
//
// That hand-entry is the thing worth removing. A mistyped `kid` does not fail
// loudly: verification reports `issuer %q has no trusted key %q`, which is
// exactly what a compromised or rotated key looks like. An operator would be
// debugging a typo while reading a message about trust. The JWKS carries the
// `kid` and the key together, so they cannot disagree.
//
// # What is deliberately not here
//
// **No fetching.** This parses bytes; it does not go and get them. A
// deployment must be able to run air-gapped with no mandatory external SaaS, and a
// daemon that reached out to an issuer's JWKS endpoint at start-up would put an
// outbound network dependency in the identity path. The operator brings the
// file, as they already bring writer keys.
//
// **No `use`/`key_ops` filtering beyond signature keys.** A JWKS may carry
// encryption keys; those are skipped rather than refused, because a document
// containing one is normal and rejecting the whole file would be unhelpful.

// IssuerKey is one signing key of one issuer, ready to record.
type IssuerKey struct {
	// KeyID is the JWKS `kid`, and is what a token's header names.
	KeyID string
	// Algorithm is the JWS algorithm this key signs with, in the form
	// verifySignature expects.
	Algorithm string
	// Key is the parsed public key.
	Key crypto.PublicKey
}

// jwk is one entry of a JWKS document.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	// RSA
	N string `json:"n"`
	E string `json:"e"`
	// EC and OKP
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ParseJWKS reads an issuer's published key set.
//
// It returns only keys this build can actually verify with. A key of some other
// type is skipped and named in the error only if *nothing* usable was found —
// a document holding one RSA key and one unsupported one should not be refused,
// but a document holding nothing usable must not look like success.
func ParseJWKS(blob []byte) ([]IssuerKey, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(blob, &doc); err != nil {
		return nil, fmt.Errorf("identity: parsing the JWKS: %w", err)
	}
	if len(doc.Keys) == 0 {
		return nil, fmt.Errorf("identity: the JWKS contains no keys; a file with an empty " +
			"\"keys\" array would trust nothing and read as though it had")
	}

	var out []IssuerKey
	var skipped []string
	for i, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			skipped = append(skipped, fmt.Sprintf("key %d (use=%q, not a signing key)", i, k.Use))
			continue
		}
		key, alg, err := k.parse()
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("key %d (%v)", i, err))
			continue
		}
		if k.Kid == "" {
			// A token names its key by `kid`. One with no id could never be
			// selected, so recording it would add a key nothing can reach.
			skipped = append(skipped, fmt.Sprintf("key %d (no \"kid\": a token names its "+
				"key by id, so this one could never be selected)", i))
			continue
		}
		out = append(out, IssuerKey{KeyID: k.Kid, Algorithm: alg, Key: key})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("identity: the JWKS contains no key this build can verify "+
			"with: %v. Supported: RSA (RS256), EC P-256 (ES256), Ed25519 (EdDSA)", skipped)
	}
	return out, nil
}

// parse turns one JWK into a key and the algorithm it signs with.
//
// The algorithm comes from `alg` when the issuer states it, and is otherwise
// derived from the key type. `alg` is optional in the JWKS spec and plenty of
// providers omit it, so refusing without it would reject real documents; but a
// stated `alg` wins, because the issuer knows what it signs with and this does
// not.
func (k jwk) parse() (crypto.PublicKey, string, error) {
	switch k.Kty {
	case "RSA":
		n, err := decodeBigInt(k.N)
		if err != nil {
			return nil, "", fmt.Errorf("RSA modulus: %w", err)
		}
		e, err := decodeBigInt(k.E)
		if err != nil {
			return nil, "", fmt.Errorf("RSA exponent: %w", err)
		}
		if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > 1<<31 {
			return nil, "", fmt.Errorf("RSA exponent is out of range")
		}
		alg := k.Alg
		if alg == "" {
			alg = "RS256"
		}
		if alg != "RS256" {
			return nil, "", fmt.Errorf("RSA key states alg %q; this build verifies RS256", alg)
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, alg, nil

	case "EC":
		if k.Crv != "P-256" {
			return nil, "", fmt.Errorf("EC curve %q; this build verifies P-256", k.Crv)
		}
		x, err := decodeCoordinate(k.X)
		if err != nil {
			return nil, "", fmt.Errorf("EC x: %w", err)
		}
		y, err := decodeCoordinate(k.Y)
		if err != nil {
			return nil, "", fmt.Errorf("EC y: %w", err)
		}
		// Assembled as an uncompressed SEC 1 point and parsed, rather than by
		// setting X and Y directly. ParseUncompressedPublicKey rejects a point
		// that is not on the curve, which matters: a point that is not on P-256
		// is not a key, and recording one would put something in the log that
		// can never verify anything — surfacing later as an unexplained refusal
		// rather than as a bad configuration file. Setting the coordinates by
		// hand skips that check and is deprecated for exactly this reason.
		sec1 := append([]byte{4}, append(x, y...)...)
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), sec1)
		if err != nil {
			return nil, "", fmt.Errorf("EC point: %w", err)
		}
		alg := k.Alg
		if alg == "" {
			alg = "ES256"
		}
		if alg != "ES256" {
			return nil, "", fmt.Errorf("EC key states alg %q; this build verifies ES256", alg)
		}
		return pub, alg, nil

	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, "", fmt.Errorf("OKP curve %q; this build verifies Ed25519", k.Crv)
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, "", fmt.Errorf("Ed25519 x: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("Ed25519 key is %d bytes, want %d",
				len(raw), ed25519.PublicKeySize)
		}
		alg := k.Alg
		if alg == "" {
			alg = "EdDSA"
		}
		// verifySignature upper-cases before comparing, so both spellings that
		// appear in the wild are accepted here rather than one being a silent
		// refusal much later.
		if alg != "EdDSA" && alg != "EDDSA" {
			return nil, "", fmt.Errorf("OKP key states alg %q; this build verifies EdDSA", alg)
		}
		return ed25519.PublicKey(raw), alg, nil

	case "":
		return nil, "", fmt.Errorf("no \"kty\"")
	default:
		return nil, "", fmt.Errorf("key type %q", k.Kty)
	}
}

// decodeCoordinate reads one EC coordinate, left-padded to the curve's field
// size. A provider may omit leading zero bytes, and a short coordinate would
// otherwise assemble into a point at the wrong offset.
func decodeCoordinate(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	const p256Bytes = 32
	if len(raw) > p256Bytes {
		return nil, fmt.Errorf("%d bytes, want at most %d for P-256", len(raw), p256Bytes)
	}
	out := make([]byte, p256Bytes)
	copy(out[p256Bytes-len(raw):], raw)
	return out, nil
}

func decodeBigInt(s string) (*big.Int, error) {
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}
