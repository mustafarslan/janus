package orchd_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/identity"
)

// enrol registers one credential through the daemon and returns its id.
func enrol(t *testing.T, s interface {
	RegisterCredential(context.Context, *janusv1.RegisterCredentialRequest) (*janusv1.RegisterCredentialResponse, error)
}, id, subject string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterCredential(context.Background(), &janusv1.RegisterCredentialRequest{
		CredentialId: id, Subject: subject, PublicKey: spki,
	}); err != nil {
		t.Fatalf("enrolling %s: %v", id, err)
	}
}

// TestARevokedCredentialLeavesTheTrustStore is the check revocation was
// waiting for.
//
// `identity.Recorder.RevokeCredential` has been implemented since Phase 5b with
// **no caller and no test**: the fold honoured a revocation correctly and
// nothing in the system could record one, so a lost authenticator could not be
// withdrawn. This drives the whole path — enrol, revoke, re-fold — because
// testing the recorder in isolation is what the last three years of this gap
// looked like from the inside.
func TestARevokedCredentialLeavesTheTrustStore(t *testing.T) {
	s, dir := newServer(t)
	ctx := context.Background()

	enrol(t, s, "cred_lost", "alice@bank.example")
	enrol(t, s, "cred_kept", "bob@bank.example")

	before, err := identity.LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := before.Credentials["cred_lost"]; !ok {
		t.Fatal("the credential was not enrolled, so revoking it would prove nothing")
	}

	if _, err := s.RevokeCredential(ctx, &janusv1.RevokeCredentialRequest{
		CredentialId: "cred_lost", Reason: "lost laptop",
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	after, err := identity.LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Credentials["cred_lost"]; ok {
		t.Error("the revoked credential is still trusted; the revocation was recorded " +
			"and changed nothing, which is the shape of the gap this closes")
	}
	if _, ok := after.Credentials["cred_kept"]; !ok {
		t.Error("revoking one credential removed another")
	}
}

// TestARevocationNeedsAReason keeps the record actionable.
//
// A revocation with no reason is one an auditor cannot act on: "lost laptop" and
// "employee left" call for different follow-up, and the difference is not
// recoverable after the fact. The recorder already refuses; this asserts the
// daemon refuses too, rather than passing an empty string down and returning
// whatever the recorder said.
func TestARevocationNeedsAReason(t *testing.T) {
	s, _ := newServer(t)
	if _, err := s.RevokeCredential(context.Background(), &janusv1.RevokeCredentialRequest{
		CredentialId: "cred_x",
	}); err == nil {
		t.Fatal("a revocation with no reason was accepted")
	}
	if _, err := s.RevokeCredential(context.Background(), &janusv1.RevokeCredentialRequest{
		Reason: "lost laptop",
	}); err == nil {
		t.Fatal("a revocation naming no credential was accepted")
	}
}

// TestRevokingAnUnknownCredentialIsRecorded documents a deliberate choice.
//
// The daemon does not check that the credential exists. A revocation naming an
// unknown one is harmless — the fold applies it to nothing — and refusing would
// turn an operator's typo, made while an authenticator is loose, into an error
// message instead of a recorded intent. This test exists so that "we should
// validate it exists" is a decision somebody reverses on purpose rather than
// tightens by accident.
func TestRevokingAnUnknownCredentialIsRecorded(t *testing.T) {
	s, dir := newServer(t)
	if _, err := s.RevokeCredential(context.Background(), &janusv1.RevokeCredentialRequest{
		CredentialId: "cred_never_enrolled", Reason: "belt and braces",
	}); err != nil {
		t.Fatalf("revoking an unknown credential should be recorded, not refused: %v", err)
	}
	if _, err := identity.LoadTrust(dir); err != nil {
		t.Fatalf("the log no longer folds: %v", err)
	}
}
