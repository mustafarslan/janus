package orchd_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/identity"
	"github.com/mustafarslan/janus/pkg/orchd"
)

const (
	testIssuer = "https://login.bank.example"
	testKid    = "kid-2026-09"
)

// oidc is a stand-in for the identity provider: a P-256 key, the JWKS it would
// publish, and tokens it would sign.
type oidc struct{ key *ecdsa.PrivateKey }

func newOIDC(t *testing.T) *oidc {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &oidc{key: key}
}

// jwks renders the document the provider publishes, which is what an operator
// copies. Written out by hand rather than by a library, so the test exercises
// the same bytes a real provider serves.
func (o *oidc) jwks(t *testing.T, kid string) []byte {
	t.Helper()
	// x and y come from the key's own SEC 1 encoding: the raw coordinate fields
	// are deprecated, and this is also what a provider actually publishes.
	raw, err := o.key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 65 || raw[0] != 4 {
		t.Fatalf("unexpected P-256 encoding: %d bytes starting %#x", len(raw), raw[0])
	}
	b64 := base64.RawURLEncoding.EncodeToString
	blob, err := json.Marshal(map[string]any{"keys": []any{map[string]any{
		"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": kid,
		"x": b64(raw[1:33]), "y": b64(raw[33:]),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func (o *oidc) token(t *testing.T, kid, subject string, roles []string) string {
	t.Helper()
	enc := func(v any) string {
		blob, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(blob)
	}
	signed := enc(map[string]any{"alg": "ES256", "kid": kid}) + "." + enc(map[string]any{
		"iss": testIssuer, "sub": subject, "roles": roles,
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, o.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(raw)
}

// serverWithIssuer starts a daemon configured with an issuer's JWKS, the way
// `janus-orchd -issuer-jwks` does.
func serverWithIssuer(t *testing.T, dir string, jwks []byte) *orchd.Server {
	t.Helper()
	set, err := identity.ParseJWKS(jwks)
	if err != nil {
		t.Fatalf("parsing the JWKS: %v", err)
	}
	return serverWithIssuerKeys(t, dir, map[string][]identity.IssuerKey{testIssuer: set})
}

func serverWithIssuerKeys(t *testing.T, dir string, byIssuer map[string][]identity.IssuerKey) *orchd.Server {
	t.Helper()
	signer := issuerTestSigner(t, dir)
	policy, err := gate.LoadPolicyFile("../../docs/policy/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: policy,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
		IssuerKeys: byIssuer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// issuerTestSigner keeps one writer key per directory across restarts, so that
// a second Open continues the same chain rather than starting a new one.
var issuerSigners = map[string]*keys.Signer{}

func issuerTestSigner(t *testing.T, dir string) *keys.Signer {
	t.Helper()
	if s, ok := issuerSigners[dir]; ok {
		return s
	}
	s, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	issuerSigners[dir] = s
	registerManifest(t, dir, s)
	return s
}

// TestATokenVerifiesOnceItsIssuerIsTrusted is the end-to-end that no deployment
// could perform before this was built.
//
// `identity.Verify` requires an ID token; verifying one requires the issuer's
// signing key to be in the log's trust store; and `TrustIssuerKey` had no
// production caller, so nothing could put one there. Every assertion-bearing
// approval was refused with "is not an issuer this log trusts", in every
// deployment, since Phase 5b.
//
// The test drives the whole path — JWKS in, daemon start-up, fold, verify —
// because testing the recorder in isolation is precisely what the gap looked
// like from the inside for a year.
func TestATokenVerifiesOnceItsIssuerIsTrusted(t *testing.T) {
	idp := newOIDC(t)
	dir := filepath.Join(t.TempDir(), "evidence")

	// First: the state every deployment was actually in. No issuer, no verify.
	empty, err := identity.LoadTrust(dir)
	if err == nil {
		if _, refused := identity.Verify(&identity.Assertion{
			IDToken: idp.token(t, testKid, "alice@bank.example", []string{"credit-officer"}),
		}, empty, identity.Binding{}, time.Now()); refused == nil {
			t.Fatal("a token verified against a log trusting no issuer, so this test is " +
				"not establishing what trusting one buys")
		}
	}

	serverWithIssuer(t, dir, idp.jwks(t, testKid))

	trust, err := identity.LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := trust.Issuers[testIssuer][testKid]; !ok {
		t.Fatalf("the daemon started with a JWKS and the log trusts no key for %s", testIssuer)
	}

	est, err := identity.Verify(&identity.Assertion{
		IDToken:    idp.token(t, testKid, "alice@bank.example", []string{"credit-officer"}),
		RolesClaim: "roles",
	}, trust, identity.Binding{}, time.Now())
	if err != nil {
		t.Fatalf("a token signed by a trusted issuer did not establish an identity: %v", err)
	}
	if est.Subject != "alice@bank.example" {
		t.Errorf("established subject %q", est.Subject)
	}
	if len(est.Roles) != 1 || est.Roles[0] != "credit-officer" {
		t.Errorf("established roles %v; a gate requiring a role reads these", est.Roles)
	}
}

// TestRevokingAnIssuerKeyRefusesItsTokens closes the loop through the RPC.
//
// Revocation is on the wire while trusting is not, and the asymmetry is the
// decision: revoking removes authority and moves the system fail-closed, so a
// deployment that has just learned a key is compromised does not have to
// schedule a restart to stop honouring it.
func TestRevokingAnIssuerKeyRefusesItsTokens(t *testing.T) {
	idp := newOIDC(t)
	dir := filepath.Join(t.TempDir(), "evidence")
	s := serverWithIssuer(t, dir, idp.jwks(t, testKid))
	token := idp.token(t, testKid, "alice@bank.example", nil)

	trust, err := identity.LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Verify(&identity.Assertion{IDToken: token}, trust,
		identity.Binding{}, time.Now()); err != nil {
		t.Fatalf("the token did not verify before the revocation, so revoking proves "+
			"nothing: %v", err)
	}

	if _, err := s.RevokeIssuerKey(context.Background(), &janusv1.RevokeIssuerKeyRequest{
		Issuer: testIssuer, KeyId: testKid, Reason: "the provider reported it compromised",
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}

	after, err := identity.LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, still := after.Issuers[testIssuer][testKid]; still {
		t.Fatal("the key is still trusted after being revoked")
	}
	if _, err := identity.Verify(&identity.Assertion{IDToken: token}, after,
		identity.Binding{}, time.Now()); err == nil {
		t.Fatal("a token signed by a revoked issuer key still established an identity")
	}
}

// TestARevocationIsNotRetroactive keeps a rotation from rewriting history.
//
// An approval given before the revocation was valid when it was given.
// `FoldTrustUntil` is what re-verification folds, and treating a revocation as
// retroactive would invalidate every approval an issuer ever established each
// time it rotated a key.
func TestARevocationIsNotRetroactive(t *testing.T) {
	idp := newOIDC(t)
	dir := filepath.Join(t.TempDir(), "evidence")
	s := serverWithIssuer(t, dir, idp.jwks(t, testKid))

	before, err := identity.LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The sequence at which the approval was given, before anything is revoked.
	head := lastSeq(t, dir)

	if _, err := s.RevokeIssuerKey(context.Background(), &janusv1.RevokeIssuerKeyRequest{
		Issuer: testIssuer, KeyId: testKid, Reason: "routine rotation",
	}); err != nil {
		t.Fatal(err)
	}

	asItStood, err := identity.FoldTrustUntil(dir, head)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := asItStood.Issuers[testIssuer][testKid]; !ok {
		t.Error("folding the trust store as it stood before the revocation does not show " +
			"the key as trusted, so an approval given then can no longer be re-verified")
	}
	if _, ok := before.Issuers[testIssuer][testKid]; !ok {
		t.Fatal("the fixture never trusted the key")
	}
}

// TestRestartingWithTheSameJWKSRecordsNothing is the idempotency the standby
// keys have, for the same reason: a log full of identical declarations makes the
// real ones harder to find, and a restart is not a rotation.
func TestRestartingWithTheSameJWKSRecordsNothing(t *testing.T) {
	idp := newOIDC(t)
	dir := filepath.Join(t.TempDir(), "evidence")
	jwks := idp.jwks(t, testKid)

	s := serverWithIssuer(t, dir, jwks)
	first := lastSeq(t, dir)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	serverWithIssuer(t, dir, jwks)
	second := lastSeq(t, dir)
	if second != first {
		t.Errorf("restarting with the same JWKS appended %d event(s); a restart is not a "+
			"rotation and should record nothing", second-first)
	}
}

// TestAReusedKeyIDIsRefusedRatherThanOverwritten is the case worth stopping on.
//
// A different key under an id the log already trusts is either an issuer that
// rotated without changing the id, or a JWKS from somewhere else. Silently
// overwriting would replace the key every approval was checked against, without
// anything in the log saying a decision was made.
func TestAReusedKeyIDIsRefusedRatherThanOverwritten(t *testing.T) {
	first := newOIDC(t)
	dir := filepath.Join(t.TempDir(), "evidence")
	s := serverWithIssuer(t, dir, first.jwks(t, testKid))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// A different provider key, published under the SAME kid.
	other := newOIDC(t)
	set, err := identity.ParseJWKS(other.jwks(t, testKid))
	if err != nil {
		t.Fatal(err)
	}
	signer := issuerTestSigner(t, dir)
	policy, err := gate.LoadPolicyFile("../../docs/policy/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: policy,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
		IssuerKeys: map[string][]identity.IssuerKey{testIssuer: set},
	})
	if err == nil {
		_ = srv.Close()
		t.Fatal("a different key under an already-trusted id was accepted, silently " +
			"replacing the key every approval had been checked against")
	}
	if !containsAll(err.Error(), "already trusts a DIFFERENT key", "revoke-issuer") {
		t.Errorf("the refusal does not say what happened or what to do: %v", err)
	}
	_ = errors.Is(err, err)
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// lastSeq is the log's head sequence, read by walking it.
func lastSeq(t *testing.T, dir string) uint64 {
	t.Helper()
	var last uint64
	if err := evidence.Walk(dir, func(h evidence.EventHeader, _ segment.Record) error {
		last = h.Seq
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return last
}
