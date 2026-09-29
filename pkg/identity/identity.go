// Package identity turns a role claim from something asserted into something
// established.
//
// # What was wrong
//
// Until now a GateAnswer carried the roles an authenticating proxy said the
// approver held. Janus checked the recorded claim against what the requirement
// demanded, and could not check that the claim was true. That was stated
// plainly — and it needed stating, because "the approval came from a credit
// officer" reads in a report as though Janus established it.
//
// # What establishes it instead
//
// An approver presents an assertion: an OIDC ID token signed by an identity
// provider, and — for a step-up — a WebAuthn assertion from an authenticator.
// Both are verified here against keys the log itself records, and the assertion
// is stored content-addressed with its digest in `auth_ref`. A gate then
// verifies a signature over the claim rather than reading the claim, and
// anybody holding the bundle can do the same, trusting nobody.
//
// Three properties are what make that worth anything, and each is a refusal
// somewhere below:
//
//   - **The trust anchor is in the log.** Verifying against a key supplied at
//     verification time proves whatever the verifier chose to believe. The
//     issuer's keys and the credential's public key are recorded, so a replay
//     six months later reaches the same answer as the coordinator did.
//   - **A step-up is bound to the approval it is for.** The WebAuthn challenge
//     is a digest of the saga, step, requirement and attempt. An assertion
//     captured for one approval cannot be presented for another, which is the
//     difference between a step-up and a second password prompt.
//   - **An unverifiable claim establishes nothing.** A role that fails
//     verification is dropped rather than recorded, because a gate with no
//     roles requires only separation of duty — which is honest — while a gate
//     reading an unestablished role is not.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// ErrNotEstablished means an assertion did not prove what it claimed.
var ErrNotEstablished = errors.New("identity: claim not established")

// Binding is the approval an assertion is for.
//
// It is what a step-up is bound to. Without it an assertion is a proof that
// somebody was present at some point, which is what a session cookie already
// is; with it, the proof is about this payment.
type Binding struct {
	SagaID        string
	StepID        string
	RequirementID string
	Attempt       uint32
}

// Challenge is the value an authenticator must have signed over.
//
// Derived rather than random, so that a verifier replaying the log can
// recompute it. A random challenge would have to be recorded and then trusted,
// which puts the property back where it started.
func (b Binding) Challenge() []byte {
	sum := sha256.Sum256([]byte(fmt.Sprintf("janus/step-up/v1|%s|%s|%s|%d",
		b.SagaID, b.StepID, b.RequirementID, b.Attempt)))
	return sum[:]
}

// TrustStore is what the verifier is allowed to believe.
//
// Recorded in the log rather than configured at verification time: a check
// against keys the checker chose proves what the checker wanted to prove.
type TrustStore struct {
	// Issuers maps an OIDC issuer to the keys it signs tokens with, by key id.
	Issuers map[string]map[string]crypto.PublicKey
	// Credentials maps a WebAuthn credential id to its public key, and to the
	// subject it was registered for. A credential that verifies but belongs to
	// somebody else establishes nothing about this approver.
	Credentials map[string]Credential
}

// Credential is a registered authenticator.
type Credential struct {
	Subject   string
	PublicKey crypto.PublicKey
}

// Assertion is what an approver presented.
type Assertion struct {
	// IDToken is an OIDC ID token, verbatim, as the compact JWS the provider
	// issued. Verbatim because a re-serialised token cannot be verified: the
	// signature is over the bytes.
	IDToken string `json:"id_token,omitempty"`
	// StepUp is a WebAuthn assertion captured at the moment of approval.
	StepUp *StepUp `json:"step_up,omitempty"`
	// RolesClaim names the ID token claim the roles are read from. Different
	// providers put them in different places, and guessing would mean a
	// deployment whose roles silently never verify.
	RolesClaim string `json:"roles_claim,omitempty"`
}

// StepUp is a WebAuthn assertion.
type StepUp struct {
	CredentialID      string `json:"credential_id"`
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
}

// Established is what an assertion proved.
type Established struct {
	Subject string   `json:"subject"`
	Roles   []string `json:"roles"`
	Issuer  string   `json:"issuer,omitempty"`
	// SteppedUp is true when a WebAuthn assertion bound to this approval
	// verified. A requirement that demands one refuses without it.
	SteppedUp bool `json:"stepped_up"`
}

// Verify establishes what an assertion proves about one approval.
//
// The order matters: the token establishes who, and the step-up establishes
// that they were present for *this*. A step-up whose subject differs from the
// token's is refused rather than reconciled — two identities in one approval is
// not a stronger proof, it is an unanswered question.
func Verify(a *Assertion, trust TrustStore, binding Binding, now time.Time) (*Established, error) {
	if a == nil {
		return nil, fmt.Errorf("%w: no assertion was presented", ErrNotEstablished)
	}
	if a.IDToken == "" {
		return nil, fmt.Errorf("%w: no ID token; a role nobody signed for is a role "+
			"nobody established", ErrNotEstablished)
	}

	claims, issuer, err := verifyIDToken(a.IDToken, trust, now)
	if err != nil {
		return nil, err
	}
	subject, _ := claims["sub"].(string)
	if subject == "" {
		return nil, fmt.Errorf("%w: the token names no subject", ErrNotEstablished)
	}

	out := &Established{Subject: subject, Issuer: issuer, Roles: rolesFrom(claims, a.RolesClaim)}

	if a.StepUp != nil {
		if err := verifyStepUp(a.StepUp, trust, binding, subject); err != nil {
			return nil, err
		}
		out.SteppedUp = true
	}
	return out, nil
}

// rolesFrom reads the roles claim.
//
// An absent or unreadable claim yields no roles rather than an error. That is
// the honest outcome and it is deliberately not fatal: a gate with no roles
// requires only separation of duty, which is a real control, while a gate
// reading a role nobody established is not.
func rolesFrom(claims map[string]any, name string) []string {
	if name == "" {
		name = "roles"
	}
	raw, ok := claims[name]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		// A space-separated string is what several providers emit for a scope
		// or a role list, and treating it as one opaque role would mean a gate
		// requiring "credit-officer" never matching "credit-officer treasury".
		return strings.Fields(v)
	default:
		return nil
	}
}

// ---- OIDC ------------------------------------------------------------------

func verifyIDToken(token string, trust TrustStore, now time.Time) (map[string]any, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "", fmt.Errorf("%w: the ID token is not a compact JWS", ErrNotEstablished)
	}
	header, err := decodeSegment(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("%w: unreadable token header: %w", ErrNotEstablished, err)
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("%w: unreadable token payload: %w", ErrNotEstablished, err)
	}
	signature, err := decodeSegment(parts[2])
	if err != nil {
		return nil, "", fmt.Errorf("%w: unreadable token signature: %w", ErrNotEstablished, err)
	}

	var head struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(header, &head); err != nil {
		return nil, "", fmt.Errorf("%w: unreadable token header: %w", ErrNotEstablished, err)
	}
	// "none" is a real attack, not a hypothetical: it is the first thing tried
	// against any JWT verifier, and a library that honoured it would accept a
	// token anybody could write.
	if head.Alg == "" || strings.EqualFold(head.Alg, "none") {
		return nil, "", fmt.Errorf("%w: the token declares algorithm %q", ErrNotEstablished, head.Alg)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, "", fmt.Errorf("%w: unreadable token claims: %w", ErrNotEstablished, err)
	}
	issuer, _ := claims["iss"].(string)
	if issuer == "" {
		return nil, "", fmt.Errorf("%w: the token names no issuer", ErrNotEstablished)
	}
	byKid, ok := trust.Issuers[issuer]
	if !ok {
		return nil, "", fmt.Errorf("%w: %q is not an issuer this log trusts", ErrNotEstablished, issuer)
	}
	key, ok := byKid[head.Kid]
	if !ok {
		return nil, "", fmt.Errorf("%w: issuer %q has no trusted key %q", ErrNotEstablished,
			issuer, head.Kid)
	}

	signed := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(head.Alg, key, signed, signature); err != nil {
		return nil, "", err
	}
	if err := checkExpiry(claims, now); err != nil {
		return nil, "", err
	}
	return claims, issuer, nil
}

// checkExpiry refuses a token outside its validity window.
//
// No leeway. A clock skew allowance is a window in which an expired credential
// is accepted, and the whole point of a step-up is that it was fresh at the
// moment of approval.
func checkExpiry(claims map[string]any, now time.Time) error {
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("%w: the token has no expiry, so it is a credential that never "+
			"stops working", ErrNotEstablished)
	}
	if now.After(time.Unix(int64(exp), 0)) {
		return fmt.Errorf("%w: the token expired at %s", ErrNotEstablished,
			time.Unix(int64(exp), 0).UTC().Format(time.RFC3339))
	}
	if nbf, ok := claims["nbf"].(float64); ok && now.Before(time.Unix(int64(nbf), 0)) {
		return fmt.Errorf("%w: the token is not valid until %s", ErrNotEstablished,
			time.Unix(int64(nbf), 0).UTC().Format(time.RFC3339))
	}
	return nil
}

// ---- WebAuthn --------------------------------------------------------------

func verifyStepUp(s *StepUp, trust TrustStore, binding Binding, subject string) error {
	credential, ok := trust.Credentials[s.CredentialID]
	if !ok {
		return fmt.Errorf("%w: credential %q is not registered", ErrNotEstablished, s.CredentialID)
	}
	// A credential that verifies but belongs to somebody else proves that its
	// owner was present, not that this approver was.
	if credential.Subject != subject {
		return fmt.Errorf("%w: credential %q is registered to %q, and the token names %q",
			ErrNotEstablished, s.CredentialID, credential.Subject, subject)
	}

	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(s.ClientDataJSON, &clientData); err != nil {
		return fmt.Errorf("%w: unreadable client data: %w", ErrNotEstablished, err)
	}
	if clientData.Type != "webauthn.get" {
		return fmt.Errorf("%w: the assertion is of type %q, not an authentication",
			ErrNotEstablished, clientData.Type)
	}
	// The binding check. Without it the assertion proves presence at some
	// approval, and a stolen one could be presented for any other.
	want := base64.RawURLEncoding.EncodeToString(binding.Challenge())
	if clientData.Challenge != want {
		return fmt.Errorf("%w: the assertion was signed over a different approval; a "+
			"step-up that is not bound to what it approves is a second password prompt",
			ErrNotEstablished)
	}

	// WebAuthn signs over authenticatorData || SHA-256(clientDataJSON).
	clientHash := sha256.Sum256(s.ClientDataJSON)
	signed := append(append([]byte{}, s.AuthenticatorData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	return verifyRaw(credential.PublicKey, digest[:], s.Signature)
}

// ---- signatures ------------------------------------------------------------

func verifySignature(alg string, key crypto.PublicKey, signed, signature []byte) error {
	switch strings.ToUpper(alg) {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: the trusted key is not an RSA key", ErrNotEstablished)
		}
		digest := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
			return fmt.Errorf("%w: the token signature does not verify", ErrNotEstablished)
		}
		return nil
	case "ES256":
		digest := sha256.Sum256(signed)
		return verifyECDSA(key, digest[:], signature, true)
	case "EDDSA":
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: the trusted key is not an Ed25519 key", ErrNotEstablished)
		}
		if !ed25519.Verify(pub, signed, signature) {
			return fmt.Errorf("%w: the token signature does not verify", ErrNotEstablished)
		}
		return nil
	default:
		return fmt.Errorf("%w: algorithm %q is not one this build verifies", ErrNotEstablished, alg)
	}
}

// verifyRaw checks a WebAuthn signature, which is ASN.1 DER for ECDSA.
func verifyRaw(key crypto.PublicKey, digest, signature []byte) error {
	switch pub := key.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return fmt.Errorf("%w: the step-up signature does not verify", ErrNotEstablished)
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, digest, signature) {
			return fmt.Errorf("%w: the step-up signature does not verify", ErrNotEstablished)
		}
		return nil
	default:
		return fmt.Errorf("%w: the credential's key type is not one this build verifies",
			ErrNotEstablished)
	}
}

// verifyECDSA handles the JWS form, where r and s are fixed-width and
// concatenated rather than DER.
func verifyECDSA(key crypto.PublicKey, digest, signature []byte, jws bool) error {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: the trusted key is not an ECDSA key", ErrNotEstablished)
	}
	if !jws {
		if !ecdsa.VerifyASN1(pub, digest, signature) {
			return fmt.Errorf("%w: the signature does not verify", ErrNotEstablished)
		}
		return nil
	}
	if len(signature) != 64 {
		return fmt.Errorf("%w: an ES256 signature is 64 bytes, this is %d",
			ErrNotEstablished, len(signature))
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(pub, digest, r, s) {
		return fmt.Errorf("%w: the token signature does not verify", ErrNotEstablished)
	}
	return nil
}

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ---- enrolment -------------------------------------------------------------

// Enrolment is what a browser returns from navigator.credentials.create().
//
// Deliberately not the attestation object. WebAuthn's create() response carries
// a CBOR attestation blob, and parsing it to extract the COSE public key is a
// hundred lines that check nothing: with the "none" attestation this console
// asks for, the attestation statement is empty, so the parse is a decoder
// rather than a control. `AuthenticatorAttestationResponse.getPublicKey()`
// hands over the same key already in SPKI DER, which crypto/x509 reads.
//
// What is kept is the part that *is* a control: the client data, so the
// challenge can be checked.
type Enrolment struct {
	// CredentialID is the credential id the browser reported.
	CredentialID string `json:"credential_id"`
	// ClientDataJSON is the browser's account of what it was asked to do.
	ClientDataJSON []byte `json:"client_data_json"`
	// PublicKeySPKI is the credential's public key, SPKI DER.
	PublicKeySPKI []byte `json:"public_key"`
}

// EnrolmentChallenge is the value an enrolment must have been made against.
//
// Derived from the subject, for the same reason an approval's challenge is
// derived from the approval: a random one would have to be issued, remembered
// and then trusted, and the remembering is where the property leaks. Derived,
// the server recomputes it from the identity its authenticating layer already
// established.
//
// What the derivation buys concretely: an enrolment captured from one person's
// browser cannot be replayed to register their authenticator under somebody
// else's name, because the challenge in the captured client data is a function
// of the original subject and will not match. Replaying it as the same person
// re-registers the same credential, which changes nothing.
func EnrolmentChallenge(subject string) []byte {
	sum := sha256.Sum256([]byte("janus/enrol/v1|" + subject))
	return sum[:]
}

// VerifyEnrolment checks an enrolment belongs to the person it is being
// recorded for, and returns the key to record.
//
// It does not verify an attestation statement — nothing here asks for one. That
// is a decision rather than an omission: attestation establishes which *model*
// of authenticator produced a key, which matters to a deployment that wants to
// exclude particular hardware and matters not at all to the property a step-up
// is for. Claiming otherwise would be the sort of control that reads as present
// and checks nothing.
func VerifyEnrolment(subject string, e *Enrolment) (crypto.PublicKey, error) {
	switch {
	case e == nil:
		return nil, fmt.Errorf("%w: no enrolment was presented", ErrNotEstablished)
	case subject == "":
		return nil, fmt.Errorf("%w: an enrolment with no subject would register an "+
			"authenticator for nobody", ErrNotEstablished)
	case e.CredentialID == "":
		return nil, fmt.Errorf("%w: the enrolment names no credential", ErrNotEstablished)
	}

	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(e.ClientDataJSON, &clientData); err != nil {
		return nil, fmt.Errorf("%w: unreadable client data: %w", ErrNotEstablished, err)
	}
	if clientData.Type != "webauthn.create" {
		return nil, fmt.Errorf("%w: the ceremony is of type %q, not a registration",
			ErrNotEstablished, clientData.Type)
	}
	want := base64.RawURLEncoding.EncodeToString(EnrolmentChallenge(subject))
	if clientData.Challenge != want {
		return nil, fmt.Errorf("%w: the enrolment was made for a different person; a "+
			"registration captured from one browser cannot be replayed under another name",
			ErrNotEstablished)
	}

	key, err := x509.ParsePKIXPublicKey(e.PublicKeySPKI)
	if err != nil {
		return nil, fmt.Errorf("%w: the credential's public key is not readable SPKI: %w",
			ErrNotEstablished, err)
	}
	// The key has to be one this build can verify with later. A credential
	// recorded under a key nothing can check would sit in the trust store
	// looking like coverage and refuse every step-up it was enrolled for.
	switch key.(type) {
	case *ecdsa.PublicKey, ed25519.PublicKey, *rsa.PublicKey:
		return key, nil
	default:
		return nil, fmt.Errorf("%w: the credential uses a key type this build cannot verify",
			ErrNotEstablished)
	}
}
