package identity_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/identity"
)

const (
	issuer  = "https://idp.bank.example"
	kid     = "k1"
	subject = "person:alice@bank"
)

var binding = identity.Binding{
	SagaID: "sg_1", StepID: "st_wire", RequirementID: "four-eyes", Attempt: 1,
}

// TestAnAssertionEstablishesTheRolesItIsSignedFor is the point of an assertion: the
// gate verifies a signature over the claim rather than reading the claim.
func TestAnAssertionEstablishesTheRolesItIsSignedFor(t *testing.T) {
	signer := newSigner(t)
	credential, stepUp := newStepUp(t, binding, subject)

	established, err := identity.Verify(&identity.Assertion{
		IDToken: signer.token(t, claims(time.Now().Add(time.Hour))),
		StepUp:  stepUp,
	}, trust(signer, credential), binding, time.Now())
	if err != nil {
		t.Fatalf("a signed token with a bound step-up did not establish anything: %v", err)
	}
	if established.Subject != subject {
		t.Fatalf("established subject %q, want %q", established.Subject, subject)
	}
	if len(established.Roles) != 1 || established.Roles[0] != "credit-officer" {
		t.Fatalf("established roles %v, want [credit-officer]", established.Roles)
	}
	if !established.SteppedUp {
		t.Fatal("a verified WebAuthn assertion did not register as a step-up")
	}
}

// TestAStepUpForADifferentApprovalIsRefused is the whole point of step-up.
//
// A step-up that is not bound to what it approves is a second password prompt:
// it proves somebody was present at some approval, which is what a session
// cookie already proves. Captured for one payment and presented for another, it
// must not verify.
func TestAStepUpForADifferentApprovalIsRefused(t *testing.T) {
	signer := newSigner(t)
	other := identity.Binding{
		SagaID: "sg_1", StepID: "st_wire", RequirementID: "four-eyes", Attempt: 2,
	}
	credential, stepUp := newStepUp(t, other, subject)

	_, err := identity.Verify(&identity.Assertion{
		IDToken: signer.token(t, claims(time.Now().Add(time.Hour))),
		StepUp:  stepUp,
	}, trust(signer, credential), binding, time.Now())
	if !errors.Is(err, identity.ErrNotEstablished) {
		t.Fatalf("an assertion signed over attempt 2 was accepted for attempt 1: %v", err)
	}
	if !strings.Contains(err.Error(), "second password prompt") {
		t.Fatalf("the refusal does not say why binding matters: %v", err)
	}
}

// TestACredentialRegisteredToSomebodyElseIsRefused. A credential that verifies
// but belongs to another person proves its owner was present, not this
// approver.
func TestACredentialRegisteredToSomebodyElseIsRefused(t *testing.T) {
	signer := newSigner(t)
	credential, stepUp := newStepUp(t, binding, "person:bob@bank")

	_, err := identity.Verify(&identity.Assertion{
		IDToken: signer.token(t, claims(time.Now().Add(time.Hour))),
		StepUp:  stepUp,
	}, trust(signer, credential), binding, time.Now())
	if !errors.Is(err, identity.ErrNotEstablished) {
		t.Fatalf("an authenticator registered to somebody else was accepted: %v", err)
	}
}

// TestAlgNoneIsRefused. It is the first thing tried against any JWT verifier,
// and a verifier that honoured it would accept a token anybody could write.
func TestAlgNoneIsRefused(t *testing.T) {
	signer := newSigner(t)
	header := encode(t, map[string]any{"alg": "none", "kid": kid})
	payload := encode(t, claims(time.Now().Add(time.Hour)))
	forged := header + "." + payload + "."

	_, err := identity.Verify(&identity.Assertion{IDToken: forged},
		trust(signer, identity.Credential{}), binding, time.Now())
	if !errors.Is(err, identity.ErrNotEstablished) {
		t.Fatalf("a token declaring alg=none was accepted: %v", err)
	}
}

// TestAnIssuerTheLogDoesNotTrustIsRefused. Verifying against keys the verifier
// chose proves whatever the verifier wanted to prove.
func TestAnIssuerTheLogDoesNotTrustIsRefused(t *testing.T) {
	signer := newSigner(t)
	stolen := claims(time.Now().Add(time.Hour))
	stolen["iss"] = "https://idp.attacker.example"

	_, err := identity.Verify(&identity.Assertion{IDToken: signer.token(t, stolen)},
		trust(signer, identity.Credential{}), binding, time.Now())
	if !errors.Is(err, identity.ErrNotEstablished) {
		t.Fatalf("a token from an untrusted issuer was accepted: %v", err)
	}
}

// TestAnExpiredTokenIsRefusedWithNoLeeway. A skew allowance is a window in
// which an expired credential works, and the point of a step-up is freshness.
func TestAnExpiredTokenIsRefusedWithNoLeeway(t *testing.T) {
	signer := newSigner(t)
	expired := signer.token(t, claims(time.Now().Add(-time.Second)))

	_, err := identity.Verify(&identity.Assertion{IDToken: expired},
		trust(signer, identity.Credential{}), binding, time.Now())
	if !errors.Is(err, identity.ErrNotEstablished) {
		t.Fatalf("an expired token was accepted: %v", err)
	}
}

// TestATokenWithNoExpiryIsRefused. A credential that never stops working is not
// a credential.
func TestATokenWithNoExpiryIsRefused(t *testing.T) {
	signer := newSigner(t)
	forever := claims(time.Now().Add(time.Hour))
	delete(forever, "exp")

	_, err := identity.Verify(&identity.Assertion{IDToken: signer.token(t, forever)},
		trust(signer, identity.Credential{}), binding, time.Now())
	if !errors.Is(err, identity.ErrNotEstablished) {
		t.Fatalf("a token with no expiry was accepted: %v", err)
	}
}

// TestATamperedTokenIsRefused. The claims are signed; editing them has to break
// the signature, or none of this means anything.
func TestATamperedTokenIsRefused(t *testing.T) {
	signer := newSigner(t)
	token := signer.token(t, claims(time.Now().Add(time.Hour)))

	elevated := claims(time.Now().Add(time.Hour))
	elevated["roles"] = []any{"credit-officer", "treasury-approver"}
	parts := strings.Split(token, ".")
	tampered := parts[0] + "." + encode(t, elevated) + "." + parts[2]

	_, err := identity.Verify(&identity.Assertion{IDToken: tampered},
		trust(signer, identity.Credential{}), binding, time.Now())
	if !errors.Is(err, identity.ErrNotEstablished) {
		t.Fatalf("a token whose roles were edited after signing was accepted: %v", err)
	}
}

// TestAnUnreadableRolesClaimEstablishesNoRolesRatherThanFailing.
//
// This is the rule taken literally: better to leave the role list
// empty — a gate with no roles requires only separation of duty, which is
// honest — than to record a claim nobody established.
func TestAnUnreadableRolesClaimEstablishesNoRolesRatherThanFailing(t *testing.T) {
	signer := newSigner(t)
	odd := claims(time.Now().Add(time.Hour))
	odd["roles"] = map[string]any{"credit": true}

	established, err := identity.Verify(&identity.Assertion{IDToken: signer.token(t, odd)},
		trust(signer, identity.Credential{}), binding, time.Now())
	if err != nil {
		t.Fatalf("an unreadable roles claim should establish who, not fail: %v", err)
	}
	if len(established.Roles) != 0 {
		t.Fatalf("roles %v were established from a claim nothing could read",
			established.Roles)
	}
	if established.Subject != subject {
		t.Fatal("the subject should still be established; only the roles are in doubt")
	}
}

// ---- fixtures --------------------------------------------------------------

type testSigner struct{ key *ecdsa.PrivateKey }

func newSigner(t *testing.T) *testSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{key: key}
}

// token builds a real ES256 compact JWS.
func (s *testSigner) token(t *testing.T, payload map[string]any) string {
	t.Helper()
	signed := encode(t, map[string]any{"alg": "ES256", "kid": kid}) + "." + encode(t, payload)
	digest := sha256.Sum256([]byte(signed))
	r, sig, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	sig.FillBytes(raw[32:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(raw)
}

func trust(s *testSigner, credential identity.Credential) identity.TrustStore {
	store := identity.TrustStore{
		Issuers:     map[string]map[string]crypto.PublicKey{issuer: {kid: s.key.Public()}},
		Credentials: map[string]identity.Credential{},
	}
	if credential.PublicKey != nil {
		store.Credentials["cred-1"] = credential
	}
	return store
}

func claims(expiry time.Time) map[string]any {
	return map[string]any{
		"iss": issuer, "sub": subject, "exp": float64(expiry.Unix()),
		"roles": []any{"credit-officer"},
	}
}

// newStepUp builds a WebAuthn assertion over the challenge for a binding.
func newStepUp(t *testing.T, b identity.Binding, registeredTo string) (identity.Credential, *identity.StepUp) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientData, err := json.Marshal(map[string]any{
		"type":      "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString(b.Challenge()),
		"origin":    "https://console.bank.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	authenticatorData := []byte("authenticator-data-placeholder")
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authenticatorData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return identity.Credential{Subject: registeredTo, PublicKey: key.Public()},
		&identity.StepUp{
			CredentialID: "cred-1", AuthenticatorData: authenticatorData,
			ClientDataJSON: clientData, Signature: signature,
		}
}

func encode(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
