package console_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/console"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/cas"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/identity"
)

// The browser ceremony, tested from the server's side of it.
//
// No test here executes JavaScript, and nothing in this repository does. That
// is survivable for one reason and it is worth stating rather than implying:
// every mistake the page can make is refused by code that is tested. A wrong
// challenge, a credential belonging to somebody else, a replayed assertion, a
// missing token — each is a refusal with a test below. The failure mode of the
// script is an error on the screen, not an approval that quietly established
// nothing.
//
// What these tests do cover is the part that decides: the challenge the server
// hands out is the one the gate will check, the proof reaches the log, and it
// reaches the log in the deployment shape people actually run — a console
// delegating its appends to janus-orchd.

const (
	stepUpIssuer  = "https://issuer.bank.example"
	stepUpKid     = "k1"
	stepUpSubject = "alice"
	stepUpCredID  = "cred-console-1"
)

// ---- fixtures ---------------------------------------------------------------

type oidc struct{ key *ecdsa.PrivateKey }

func newIssuer(t *testing.T) *oidc {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &oidc{key: key}
}

func (o *oidc) token(t *testing.T, subject string, roles []string) string {
	t.Helper()
	seg := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	claims := map[string]any{
		"iss": stepUpIssuer, "sub": subject,
		"exp":   float64(time.Now().Add(time.Hour).Unix()),
		"roles": toAny(roles),
	}
	signed := seg(map[string]any{"alg": "ES256", "kid": stepUpKid}) + "." + seg(claims)
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

func toAny(v []string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

// authenticator is a WebAuthn credential that signs whatever it is given.
type authenticator struct{ key *ecdsa.PrivateKey }

func newAuthenticator(t *testing.T) *authenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{key: key}
}

// sign produces the assertion a browser would post back, over the base64url
// challenge the server issued. It signs the encoded string verbatim, exactly as
// a real authenticator does — which is what makes a mismatch here the same
// mismatch a real one would produce.
func (a *authenticator) sign(t *testing.T, challenge string) *identity.StepUp {
	t.Helper()
	clientData, err := json.Marshal(map[string]any{
		"type": "webauthn.get", "challenge": challenge,
		"origin": "https://console.bank.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	authData := []byte("authenticator-data")
	clientHash := sha256.Sum256(clientData)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return &identity.StepUp{
		CredentialID: stepUpCredID, AuthenticatorData: authData,
		ClientDataJSON: clientData, Signature: sig,
	}
}

// trustFor records the issuer key and the credential in the log, which is where
// verification reads them from. Configuring them at verification time would
// prove what the checker wanted to prove.
func trustFor(t *testing.T, dir string, o *oidc, auth *authenticator, subject string) {
	t.Helper()
	app, err := evidence.Open(evidence.Options{Dir: dir, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	rec := identity.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_identity", Kind: "SYSTEM", Principal: testPrincipal,
	})
	ctx := context.Background()
	if err := rec.TrustIssuerKey(ctx, stepUpIssuer, stepUpKid, "ES256",
		o.key.Public()); err != nil {
		t.Fatal(err)
	}
	if err := rec.RegisterCredential(ctx, stepUpCredID, subject,
		crypto.PublicKey(auth.key.Public())); err != nil {
		t.Fatal(err)
	}
}

func blobStore(t *testing.T) cas.Store {
	t.Helper()
	s, err := cas.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ---- the challenge ----------------------------------------------------------

// TestTheChallengeIsTheOneTheGateWillCheck is the property the whole ceremony
// rests on. If the page signed anything else, the assertion would verify as a
// signature and establish nothing about this approval.
func TestTheChallengeIsTheOneTheGateWillCheck(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)

	ch, err := console.Open(dir).StepUpFor(testSaga, testStep, fourEyesReq)
	if err != nil {
		t.Fatal(err)
	}
	want := base64.RawURLEncoding.EncodeToString(identity.Binding{
		SagaID: testSaga, StepID: testStep, RequirementID: fourEyesReq,
		Attempt: ch.Attempt,
	}.Challenge())
	if ch.Challenge != want {
		t.Fatalf("the console issues %q and the gate checks %q", ch.Challenge, want)
	}
	if ch.Attempt == 0 {
		t.Fatal("the challenge names attempt 0; an approval is for the attempt under decision")
	}
}

// TestAChallengeForSomethingNotWaitingIsRefused. A challenge for a decision
// already made would let a browser collect an assertion nobody can use, and the
// person would find out when their approval was rejected.
func TestAChallengeForSomethingNotWaitingIsRefused(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	c := console.Open(dir)

	for _, tc := range []struct{ name, saga, step, req string }{
		{"no such saga", "sg_missing", testStep, fourEyesReq},
		{"no such step", testSaga, "st_missing", fourEyesReq},
		{"no such requirement", testSaga, testStep, "req_missing"},
		{"a validator gate", testSaga, testStep, secondOpinion},
		{"nothing named", "", "", ""},
	} {
		if _, err := c.StepUpFor(tc.saga, tc.step, tc.req); err == nil {
			t.Fatalf("%s: a challenge was issued", tc.name)
		}
	}
}

// TestTheChallengeEndpointAnswersOverHTTP checks the wire shape the page reads,
// since a field renamed here is a ceremony that silently stops happening.
func TestTheChallengeEndpointAnswersOverHTTP(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	srv := newServer(t, console.Open(dir), console.ServerOptions{IdentityHeader: "X-User"})

	q := url.Values{"saga_id": {testSaga}, "step_id": {testStep},
		"requirement_id": {fourEyesReq}}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/stepup?"+q.Encode(), nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Attempt        uint32 `json:"attempt"`
		Challenge      string `json:"challenge"`
		RequiresStepUp bool   `json:"requires_step_up"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Challenge == "" || body.Attempt == 0 {
		t.Fatalf("the endpoint answered %s", rec.Body.String())
	}
	// The bytes must decode. A page handed a padded or hex-encoded challenge
	// would pass the wrong bytes to the authenticator and get a mismatch it
	// could not diagnose.
	if _, err := base64.RawURLEncoding.DecodeString(body.Challenge); err != nil {
		t.Fatalf("the challenge is not unpadded base64url: %v", err)
	}
}

// ---- the approval ------------------------------------------------------------

// TestAnApprovalCarriesItsProofIntoTheLog is the ceremony end to end, minus the
// browser: the server issues a challenge, an authenticator signs it, the form
// posts it back, and what lands in the log is a reference to the proof rather
// than a note about a header.
func TestAnApprovalCarriesItsProofIntoTheLog(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	issuer, auth := newIssuer(t), newAuthenticator(t)
	trustFor(t, dir, issuer, auth, stepUpSubject)

	blobs := blobStore(t)
	c := console.Open(dir).WithBlobs(blobs)
	ch, err := c.StepUpFor(testSaga, testStep, fourEyesReq)
	if err != nil {
		t.Fatal(err)
	}

	srv := newServer(t, c, console.ServerOptions{
		IdentityHeader: "X-User", IDTokenHeader: "X-Token", RolesClaim: "roles",
	})
	rec := postApproval(t, srv, ch, issuer.token(t, stepUpSubject, []string{"credit-officer"}),
		auth.sign(t, ch.Challenge))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if problem := redirectProblem(rec); problem != "" {
		t.Fatalf("the approval was refused: %s", problem)
	}

	// The answer in the log points at the assertion, and the assertion resolves
	// and still verifies — which is what an auditor does with the bundle.
	ref := recordedAuthRef(t, dir)
	if !strings.HasPrefix(ref, "cas://blake3:") {
		t.Fatalf("auth_ref is %q; the proof was not stored", ref)
	}
	stored, err := identity.GetAssertion(context.Background(), blobs, ref)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := identity.LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	established, err := identity.Verify(stored, trust, identity.Binding{
		SagaID: testSaga, StepID: testStep, RequirementID: fourEyesReq, Attempt: ch.Attempt,
	}, time.Now())
	if err != nil {
		t.Fatalf("the stored proof does not verify: %v", err)
	}
	if !established.SteppedUp {
		t.Fatal("the stored proof establishes no step-up")
	}
	if established.Subject != stepUpSubject {
		t.Fatalf("the proof establishes %q", established.Subject)
	}
}

// TestADelegatedConsoleStillCapturesTheProof is a regression test for a defect
// the step-up work found, and the reason the ceremony could not have worked without
// finding it.
//
// A console pointed at janus-orchd is the only shape that runs beside a live
// coordinator, so it is the shape a deployment uses. It handed the answer over
// *before* verifying and storing the assertion, which meant the proof was
// dropped and the proxy header recorded in its place — silently. The approval
// succeeded; the gate refused it later for a reason that named nothing about
// the console.
func TestADelegatedConsoleStillCapturesTheProof(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	issuer, auth := newIssuer(t), newAuthenticator(t)
	trustFor(t, dir, issuer, auth, stepUpSubject)

	captured := &recordingRecorder{}
	c := console.Open(dir).WithBlobs(blobStore(t)).WithRecorder(captured)
	ch, err := c.StepUpFor(testSaga, testStep, fourEyesReq)
	if err != nil {
		t.Fatal(err)
	}

	srv := newServer(t, c, console.ServerOptions{
		IdentityHeader: "X-User", IDTokenHeader: "X-Token", RolesClaim: "roles",
	})
	rec := postApproval(t, srv, ch, issuer.token(t, stepUpSubject, []string{"credit-officer"}),
		auth.sign(t, ch.Challenge))
	if problem := redirectProblem(rec); problem != "" {
		t.Fatalf("the approval was refused: %s", problem)
	}

	if captured.answer == nil {
		t.Fatal("the delegated recorder was never called")
	}
	if got := captured.answer.GetAuthRef(); !strings.HasPrefix(got, "cas://blake3:") {
		t.Fatalf("the answer handed to the daemon carries auth_ref %q; the proof was dropped "+
			"on the way and the header recorded instead", got)
	}
}

// TestAStepUpForAnotherApprovalIsRefused. This is the property that separates a
// step-up from a second password prompt, checked at the console rather than
// only in pkg/identity — because the console is where the binding is built, and
// a console that built it from the request would hand an attacker the freedom
// the derivation exists to remove.
func TestAStepUpForAnotherApprovalIsRefused(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	issuer, auth := newIssuer(t), newAuthenticator(t)
	trustFor(t, dir, issuer, auth, stepUpSubject)

	c := console.Open(dir).WithBlobs(blobStore(t))
	ch, err := c.StepUpFor(testSaga, testStep, fourEyesReq)
	if err != nil {
		t.Fatal(err)
	}
	// A perfectly good assertion, signed over a different approval's challenge.
	elsewhere := base64.RawURLEncoding.EncodeToString(identity.Binding{
		SagaID: testSaga, StepID: testStep, RequirementID: fourEyesReq,
		Attempt: ch.Attempt + 1,
	}.Challenge())

	srv := newServer(t, c, console.ServerOptions{
		IdentityHeader: "X-User", IDTokenHeader: "X-Token", RolesClaim: "roles",
	})
	rec := postApproval(t, srv, ch, issuer.token(t, stepUpSubject, []string{"credit-officer"}),
		auth.sign(t, elsewhere))
	if problem := redirectProblem(rec); problem == "" {
		t.Fatal("an assertion signed over a different approval was accepted")
	}
	if ref := recordedAuthRef(t, dir); strings.HasPrefix(ref, "cas://blake3:") {
		t.Fatalf("the refused approval was recorded anyway, with auth_ref %q", ref)
	}
}

// TestACredentialBelongingToSomebodyElseIsRefused. A credential that verifies
// but is registered to another person proves that person was present, not this
// one.
func TestACredentialBelongingToSomebodyElseIsRefused(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	issuer, auth := newIssuer(t), newAuthenticator(t)
	trustFor(t, dir, issuer, auth, "bob")

	c := console.Open(dir).WithBlobs(blobStore(t))
	ch, err := c.StepUpFor(testSaga, testStep, fourEyesReq)
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(t, c, console.ServerOptions{
		IdentityHeader: "X-User", IDTokenHeader: "X-Token", RolesClaim: "roles",
	})
	rec := postApproval(t, srv, ch, issuer.token(t, stepUpSubject, []string{"credit-officer"}),
		auth.sign(t, ch.Challenge))
	if problem := redirectProblem(rec); problem == "" {
		t.Fatal("alice approved with a credential registered to bob")
	}
}

// TestAStepUpWithNoTokenIsRefused. The assertion establishes presence; only the
// token establishes who was present, and one without the other is not an
// approval by anybody in particular.
//
// The refusal comes from pkg/identity rather than from the console — one place
// decides what an assertion must contain — and this test is here to check that
// it reaches the person through the console's surface rather than being
// swallowed on the way.
func TestAStepUpWithNoTokenIsRefused(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	issuer, auth := newIssuer(t), newAuthenticator(t)
	trustFor(t, dir, issuer, auth, stepUpSubject)

	c := console.Open(dir).WithBlobs(blobStore(t))
	ch, err := c.StepUpFor(testSaga, testStep, fourEyesReq)
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(t, c, console.ServerOptions{
		IdentityHeader: "X-User", IDTokenHeader: "X-Token", RolesClaim: "roles",
	})
	rec := postApproval(t, srv, ch, "", auth.sign(t, ch.Challenge))
	problem := redirectProblem(rec)
	if problem == "" {
		t.Fatal("a step-up with no ID token was accepted")
	}
	if !strings.Contains(problem, "no ID token") {
		t.Fatalf("the refusal does not say what is missing: %s", problem)
	}
}

// TestAnAssertionWithNowhereToGoIsRefused. A console with no blob store records
// an auth_ref pointing at nothing, which is worse than an approval that admits
// it established nothing.
func TestAnAssertionWithNowhereToGoIsRefused(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	issuer, auth := newIssuer(t), newAuthenticator(t)
	trustFor(t, dir, issuer, auth, stepUpSubject)

	c := console.Open(dir) // no WithBlobs
	ch, err := c.StepUpFor(testSaga, testStep, fourEyesReq)
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(t, c, console.ServerOptions{
		IdentityHeader: "X-User", IDTokenHeader: "X-Token", RolesClaim: "roles",
	})
	rec := postApproval(t, srv, ch, issuer.token(t, stepUpSubject, []string{"credit-officer"}),
		auth.sign(t, ch.Challenge))
	if problem := redirectProblem(rec); problem == "" {
		t.Fatal("a console with nowhere to put the proof recorded the approval anyway")
	}
}

// TestTheQueuePageOffersTheCeremonyOnlyWhereItIsWanted. Prompting for a
// security key at every approval trains people to tap through it, which is how
// a step-up becomes a formality.
func TestTheQueuePageOffersTheCeremonyOnlyWhereItIsWanted(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	srv := newServer(t, console.Open(dir), console.ServerOptions{IdentityHeader: "X-User"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/queue", nil)
	req.Header.Set("X-User", "alice")
	srv.Handler().ServeHTTP(rec, req)
	body := rec.Body.String()

	// This fixture's gate does not require a step-up, so the form must not ask
	// for one — and the script must still be served, since the page cannot know
	// which forms need it without it.
	if strings.Contains(body, `data-stepup="1"`) {
		t.Fatal("a gate that does not require a step-up offered the ceremony")
	}
	if !strings.Contains(body, "/static/stepup.js") {
		t.Fatal("the queue page does not load the ceremony script")
	}

	script := httptest.NewRecorder()
	srv.Handler().ServeHTTP(script, httptest.NewRequest("GET", "/static/stepup.js", nil))
	if script.Code != http.StatusOK {
		t.Fatalf("the script is not served: %d", script.Code)
	}
	if !strings.Contains(script.Body.String(), "navigator.credentials.get") {
		t.Fatal("the served script does not call navigator.credentials.get")
	}
}

// ---- helpers ----------------------------------------------------------------

type recordingRecorder struct{ answer *janusv1.GateAnswer }

func (r *recordingRecorder) RecordAnswer(_ context.Context, a *janusv1.GateAnswer) (
	evidence.Ref, error) {

	r.answer = a
	return evidence.Ref{Seq: 99}, nil
}

func newServer(t *testing.T, c *console.Console, opts console.ServerOptions) *console.Server {
	t.Helper()
	srv, err := console.NewServer(c, opts)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func postApproval(t *testing.T, srv *console.Server, ch *console.StepUpChallenge,
	token string, stepUp *identity.StepUp) *httptest.ResponseRecorder {

	t.Helper()
	blob, err := json.Marshal(stepUp)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{
		"saga_id": {ch.SagaID}, "step_id": {ch.StepID},
		"requirement_id": {ch.RequirementID},
		"verdict":        {"approve"}, "reason": {"checked against the invoice"},
		"step_up": {string(blob)},
	}
	req := httptest.NewRequest("POST", "/queue/answer", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-User", stepUpSubject)
	if token != "" {
		req.Header.Set("X-Token", token)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// redirectProblem returns the message the form path put in the query string, or
// "" when the answer was recorded.
func redirectProblem(rec *httptest.ResponseRecorder) string {
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		return "unparseable redirect: " + err.Error()
	}
	return u.Query().Get("problem")
}

// recordedAuthRef reads the auth_ref of the last human answer in the log.
func recordedAuthRef(t *testing.T, dir string) string {
	t.Helper()
	detail, err := console.Open(dir).Saga(testSaga)
	if err != nil {
		if errors.Is(err, console.ErrNoSaga) {
			t.Fatal(err)
		}
		t.Fatal(err)
	}
	ref := ""
	for _, st := range detail.Steps {
		for _, g := range st.Gates {
			for _, a := range g.Answers {
				if a.Human {
					ref = a.AuthRef
				}
			}
		}
	}
	return ref
}

// TestARefusalReachesThePersonWhoCausedIt is a regression test for a defect the
// ceremony work found, and it had nothing to do with the ceremony.
//
// The console put its refusal message into a redirect's query string using a
// hand-rolled escaper that covered &, # and ? — and missed the semicolon. Go's
// query parser refuses a query containing one, so `Query().Get("problem")`
// returned "" for the whole string and the page rendered no error at all.
// Almost every refusal in this package is written with a semicolon in it.
//
// The visible symptom is the worst kind: the person presses approve, nothing
// appears to happen, and the log says nothing because nothing was written.
func TestARefusalReachesThePersonWhoCausedIt(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	issuer, auth := newIssuer(t), newAuthenticator(t)
	trustFor(t, dir, issuer, auth, stepUpSubject)

	c := console.Open(dir) // no blob store, so the refusal has a semicolon in it
	ch, err := c.StepUpFor(testSaga, testStep, fourEyesReq)
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(t, c, console.ServerOptions{
		IdentityHeader: "X-User", IDTokenHeader: "X-Token", RolesClaim: "roles",
	})
	rec := postApproval(t, srv, ch, issuer.token(t, stepUpSubject, []string{"credit-officer"}),
		auth.sign(t, ch.Challenge))

	location := rec.Header().Get("Location")
	if !strings.Contains(location, "problem=") {
		t.Fatalf("no problem was reported at all: %q", location)
	}
	problem := redirectProblem(rec)
	if problem == "" {
		t.Fatalf("the refusal was swallowed on the way to the page: %q", location)
	}
	if !strings.Contains(problem, "blob store") {
		t.Fatalf("the message reached the page mangled: %q", problem)
	}

	// And the page actually renders it, which is the thing a person sees.
	page := httptest.NewRecorder()
	req := httptest.NewRequest("GET", location, nil)
	req.Header.Set("X-User", stepUpSubject)
	srv.Handler().ServeHTTP(page, req)
	if !strings.Contains(page.Body.String(), "blob store") {
		t.Fatal("the queue page rendered without the reason the approval failed")
	}
}
