package console_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/identity"
)

// Enrolling an authenticator, from the server's side.
//
// The two things worth testing are the two places an enrolment flow usually
// goes wrong: whether the subject can come from the request, and whether a
// captured registration can be replayed under another name. Both are refusals
// below, and both are proven by breaking the check.

// enrolFor builds what a browser would post back after
// navigator.credentials.create(), against the challenge for `challengeSubject`.
// Passing a different subject there is how a replay is simulated.
func enrolFor(t *testing.T, credentialID, challengeSubject string) (*identity.Enrolment,
	*ecdsa.PrivateKey) {

	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	clientData, err := json.Marshal(map[string]any{
		"type": "webauthn.create",
		"challenge": base64.RawURLEncoding.EncodeToString(
			identity.EnrolmentChallenge(challengeSubject)),
		"origin": "https://console.bank.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	return &identity.Enrolment{
		CredentialID: credentialID, ClientDataJSON: clientData, PublicKeySPKI: spki,
	}, key
}

// TestAnEnrolledCredentialCanThenSatisfyAStepUp is the whole point of the flow,
// and it is deliberately end to end: a credential enrolled through the console
// is a credential the gate's verification accepts. Anything less would be a
// registration page that writes a record nothing reads.
func TestAnEnrolledCredentialCanThenSatisfyAStepUp(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	issuer := newIssuer(t)
	trustIssuerOnly(t, dir, issuer)

	c := console.Open(dir).WithBlobs(blobStore(t))
	enrolment, key := enrolFor(t, "cred-enrolled", stepUpSubject)
	if _, err := c.Enrol(context.Background(), stepUpSubject, enrolment); err != nil {
		t.Fatalf("enrolling was refused: %v", err)
	}

	// The log now says this credential is alice's, and verification reads it
	// from there rather than from anything configured.
	trust, err := identity.LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	cred, ok := trust.Credentials["cred-enrolled"]
	if !ok {
		t.Fatal("the enrolment is not in the trust store folded out of the log")
	}
	if cred.Subject != stepUpSubject {
		t.Fatalf("the credential is recorded for %q", cred.Subject)
	}

	// And a step-up signed by it establishes the approval.
	ch, err := c.StepUpFor(testSaga, testStep, fourEyesReq)
	if err != nil {
		t.Fatal(err)
	}
	auth := &authenticator{key: key}
	stepUp := auth.sign(t, ch.Challenge)
	stepUp.CredentialID = "cred-enrolled"

	established, err := identity.Verify(&identity.Assertion{
		IDToken:    issuer.token(t, stepUpSubject, []string{"credit-officer"}),
		StepUp:     stepUp,
		RolesClaim: "roles",
	}, trust, identity.Binding{
		SagaID: testSaga, StepID: testStep, RequirementID: fourEyesReq, Attempt: ch.Attempt,
	}, timeNow())
	if err != nil {
		t.Fatalf("a credential enrolled through the console did not satisfy a step-up: %v", err)
	}
	if !established.SteppedUp {
		t.Fatal("the assertion established no step-up")
	}
}

// TestAnEnrolmentCapturedFromSomebodyElseIsRefused is what the derived
// challenge is for.
//
// The attack it stops: capture a registration from Bob's browser — a network
// log, a compromised extension, a shoulder-surfed devtools panel — and replay
// it as Alice, so that Bob's authenticator is recorded as Alice's. Alice's
// step-ups could then be produced by whoever holds Bob's key. Because the
// challenge is a function of the subject the server established, the captured
// client data names Bob's challenge and the comparison fails.
func TestAnEnrolmentCapturedFromSomebodyElseIsRefused(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	c := console.Open(dir)

	// Made for bob, presented as alice.
	enrolment, _ := enrolFor(t, "cred-bobs", "bob")
	_, err := c.Enrol(context.Background(), stepUpSubject, enrolment)
	if err == nil {
		t.Fatal("bob's registration was recorded as alice's authenticator")
	}
	if !errors.Is(err, console.ErrNotEnrollable) {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "different person") {
		t.Fatalf("the refusal does not say what happened: %v", err)
	}
}

// TestTheSubjectCannotComeFromTheRequest. A page that could name its own
// subject could enrol an authenticator under somebody else's name and then
// produce step-ups as them for as long as the credential lived.
func TestTheSubjectCannotComeFromTheRequest(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	srv := newServer(t, console.Open(dir), console.ServerOptions{IdentityHeader: "X-User"})

	enrolment, _ := enrolFor(t, "cred-x", "mallory")
	blob, err := json.Marshal(enrolment)
	if err != nil {
		t.Fatal(err)
	}
	// The form names mallory in every way a form can. The header says alice.
	form := url.Values{
		"enrolment": {string(blob)},
		"subject":   {"mallory"},
		"user":      {"mallory"},
	}
	req := httptest.NewRequest("POST", "/credentials/enrol", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-User", stepUpSubject)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	problem := redirectProblemAt(rec)
	if problem == "" {
		t.Fatal("a form naming its own subject enrolled a credential")
	}
	trust, err := identity.LoadTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := trust.Credentials["cred-x"]; ok {
		t.Fatal("the credential was recorded anyway")
	}
}

// TestAnEnrolmentFromNobodyIsRefused. The console records approvals only for an
// identity it can name, and a credential is the thing those approvals will
// later be checked against.
func TestAnEnrolmentFromNobodyIsRefused(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	enrolment, _ := enrolFor(t, "cred-nobody", "")
	if _, err := console.Open(dir).Enrol(context.Background(), "", enrolment); err == nil {
		t.Fatal("an authenticator was enrolled for nobody")
	}

	// Over HTTP, with no identity header set at all, the challenge endpoint
	// refuses rather than issuing one for the empty subject.
	srv := newServer(t, console.Open(dir), console.ServerOptions{IdentityHeader: "X-User"})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/enrol", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("the challenge endpoint answered %d to an unauthenticated request", rec.Code)
	}
}

// TestARegistrationCeremonyIsNotAnAuthentication. A `webauthn.get` assertion
// replayed at the registration endpoint would enrol a credential on the
// strength of a signature made for an entirely different purpose.
func TestARegistrationCeremonyIsNotAnAuthentication(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	enrolment, _ := enrolFor(t, "cred-wrong-type", stepUpSubject)

	var clientData map[string]any
	if err := json.Unmarshal(enrolment.ClientDataJSON, &clientData); err != nil {
		t.Fatal(err)
	}
	clientData["type"] = "webauthn.get"
	rewritten, err := json.Marshal(clientData)
	if err != nil {
		t.Fatal(err)
	}
	enrolment.ClientDataJSON = rewritten

	if _, err := console.Open(dir).Enrol(context.Background(), stepUpSubject, enrolment); err == nil {
		t.Fatal("an authentication was accepted as a registration")
	}
}

// TestAKeyThisBuildCannotVerifyIsRefusedAtRegistration. A credential recorded
// under a key nothing can check would sit in the trust store looking like
// coverage and refuse every step-up it was enrolled for — fail-closed, but for
// a reason nobody could find.
func TestAKeyThisBuildCannotVerifyIsRefusedAtRegistration(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	enrolment, _ := enrolFor(t, "cred-bad-key", stepUpSubject)
	enrolment.PublicKeySPKI = []byte("not a key")

	_, err := console.Open(dir).Enrol(context.Background(), stepUpSubject, enrolment)
	if err == nil {
		t.Fatal("a credential with an unreadable public key was recorded")
	}
	if !strings.Contains(err.Error(), "SPKI") {
		t.Fatalf("the refusal does not say what is wrong: %v", err)
	}
}

// TestADelegatedConsoleEnrolsThroughTheDaemon. Enrolment appends to the log, so
// a console beside a running coordinator cannot do it alone — and enrolment
// that only worked with the coordinator stopped would be a control unusable in
// the deployment it exists for.
func TestADelegatedConsoleEnrolsThroughTheDaemon(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	captured := &recordingCredentials{}
	c := console.Open(dir).WithRecorder(captured)

	enrolment, _ := enrolFor(t, "cred-delegated", stepUpSubject)
	if _, err := c.Enrol(context.Background(), stepUpSubject, enrolment); err != nil {
		t.Fatal(err)
	}
	if captured.credentialID != "cred-delegated" || captured.subject != stepUpSubject {
		t.Fatalf("the daemon was asked to record %q for %q",
			captured.credentialID, captured.subject)
	}
	// The key travels as SPKI, which is what the daemon parses before recording.
	if _, err := x509.ParsePKIXPublicKey(captured.key); err != nil {
		t.Fatalf("the key handed over is not readable SPKI: %v", err)
	}

	// And the verification still ran here: a bad enrolment is refused by the
	// console rather than forwarded for the daemon to worry about.
	bad, _ := enrolFor(t, "cred-bad", "bob")
	if _, err := c.Enrol(context.Background(), stepUpSubject, bad); err == nil {
		t.Fatal("a delegated console forwarded an enrolment it should have refused")
	}
	if captured.credentialID != "cred-delegated" {
		t.Fatal("the refused enrolment was forwarded anyway")
	}
}

// TestTheEnrolmentPageIsServed covers the wiring a person actually meets.
func TestTheEnrolmentPageIsServed(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	srv := newServer(t, console.Open(dir), console.ServerOptions{IdentityHeader: "X-User"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/credentials", nil)
	req.Header.Set("X-User", stepUpSubject)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`data-enrol="1"`, "/static/enrol.js", "enrol as " + stepUpSubject} {
		if !strings.Contains(body, want) {
			t.Fatalf("the page does not contain %q", want)
		}
	}

	script := httptest.NewRecorder()
	srv.Handler().ServeHTTP(script, httptest.NewRequest("GET", "/static/enrol.js", nil))
	if script.Code != http.StatusOK {
		t.Fatalf("the script is not served: %d", script.Code)
	}
	if !strings.Contains(script.Body.String(), "navigator.credentials.create") {
		t.Fatal("the served script does not call navigator.credentials.create")
	}
	// getPublicKey rather than parsing the attestation blob — a decision, and
	// one that silently reverting would make the enrolment stop working.
	if !strings.Contains(script.Body.String(), "getPublicKey") {
		t.Fatal("the script does not read the credential's public key")
	}
}

// ---- helpers ----------------------------------------------------------------

type recordingCredentials struct {
	credentialID, subject string
	key                   []byte
}

func (r *recordingCredentials) RecordAnswer(context.Context, *janusv1.GateAnswer) (
	evidence.Ref, error) {

	return evidence.Ref{}, nil
}

func (r *recordingCredentials) RegisterCredential(_ context.Context,
	credentialID, subject string, key []byte) (evidence.Ref, error) {

	r.credentialID, r.subject, r.key = credentialID, subject, key
	return evidence.Ref{Seq: 7}, nil
}

// redirectProblemAt reads the problem a redirect carries, from either page.
func redirectProblemAt(rec *httptest.ResponseRecorder) string {
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		return "unparseable redirect: " + err.Error()
	}
	return u.Query().Get("problem")
}

// trustIssuerOnly records the issuer key but no credential, so the credential
// under test is the one the console enrols.
func trustIssuerOnly(t *testing.T, dir string, o *oidc) {
	t.Helper()
	app, err := evidence.Open(evidence.Options{Dir: dir, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()
	rec := identity.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_identity", Kind: "SYSTEM", Principal: testPrincipal,
	})
	if err := rec.TrustIssuerKey(context.Background(), stepUpIssuer, stepUpKid, "ES256",
		o.key.Public()); err != nil {
		t.Fatal(err)
	}
}

func timeNow() time.Time { return time.Now() }
