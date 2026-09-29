package console

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/identity"
)

// Enrolling an authenticator.
//
// A step-up verifies a signature from a credential the log says belongs to the
// approver. Until this file, the only way a credential got into the log was
// something calling identity.Recorder.RegisterCredential directly — so a
// deployment could enforce a step-up that nobody could satisfy.
//
// Two things are worth reading closely, because both are places where an
// enrolment flow usually goes wrong:
//
// **The subject is never in the request.** It comes from whatever authenticated
// the person, the same header an approval is attributed from. A page that could
// name its own subject could enrol an authenticator under somebody else's name,
// and then produce step-ups as them for as long as the credential lived.
//
// **The challenge is derived from that subject**, so a captured registration
// cannot be replayed under a different name — the challenge in the captured
// client data is a function of the original person and will not match. Replayed
// as the same person it re-registers the same credential, which changes
// nothing.

// ErrNotEnrollable means the registration cannot be recorded.
var ErrNotEnrollable = errors.New("console: the authenticator cannot be enrolled")

// EnrolChallenge is what a browser needs to register an authenticator.
type EnrolChallenge struct {
	// Subject is who the credential will belong to, echoed back so the page can
	// show the person which identity they are enrolling under. It is not an
	// input: the server took it from the authenticating layer.
	Subject string `json:"subject"`
	// Challenge is base64url, unpadded.
	Challenge string `json:"challenge"`
}

// enrolChallenge answers "what would a registration for me have to be made
// against".
func (s *Server) enrolChallenge(w http.ResponseWriter, r *http.Request) {
	who := s.approver(r)
	if who.Subject == "" {
		writeJSON(w, nil, fmt.Errorf("%w: this console cannot say who you are, so it cannot "+
			"enrol an authenticator for you", ErrAnonymous), http.StatusForbidden)
		return
	}
	writeJSON(w, EnrolChallenge{
		Subject:   who.Subject,
		Challenge: base64.RawURLEncoding.EncodeToString(identity.EnrolmentChallenge(who.Subject)),
	}, nil, http.StatusInternalServerError)
}

// enrolForm records a registration the browser produced.
func (s *Server) enrolForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}
	who := s.approver(r)
	var enrolment identity.Enrolment
	problem := ""
	if err := json.Unmarshal([]byte(strings.TrimSpace(r.FormValue("enrolment"))), &enrolment); err != nil {
		problem = fmt.Sprintf("the registration is not readable: %v", err)
	} else if _, err := s.console.Enrol(r.Context(), who.Subject, &enrolment); err != nil {
		problem = err.Error()
	}
	if problem != "" {
		http.Redirect(w, r, "/credentials?problem="+urlEscape(problem), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/credentials?notice="+urlEscape(fmt.Sprintf(
		"enrolled %s for %s; a gate requiring a step-up will now accept a signature from it",
		enrolment.CredentialID, who.Subject)), http.StatusSeeOther)
}

// Enrol verifies a registration and records the credential.
//
// The verification happens here rather than being left to whoever appends,
// exactly as it does for an approval: the console keeps its own refusals. An
// enrolment recorded for the wrong person is not a mistake a later reader can
// detect, because the record is what a later reader consults.
func (c *Console) Enrol(ctx context.Context, subject string, e *identity.Enrolment) (
	evidence.Ref, error) {

	if strings.TrimSpace(subject) == "" {
		return evidence.Ref{}, fmt.Errorf("%w: nobody is authenticated, so there is nobody to "+
			"enrol an authenticator for", ErrAnonymous)
	}
	key, err := identity.VerifyEnrolment(subject, e)
	if err != nil {
		return evidence.Ref{}, fmt.Errorf("%w: %w", ErrNotEnrollable, err)
	}

	// Delegated first, for the same reason approvals are: one process writes an
	// evidence directory, and a console beside a live coordinator cannot append.
	if c.credentials != nil {
		ref, rerr := c.credentials.RegisterCredential(ctx, e.CredentialID, subject, e.PublicKeySPKI)
		if rerr != nil {
			return evidence.Ref{}, fmt.Errorf("console: the orchestrator refused to record the "+
				"registration: %w", rerr)
		}
		return ref, nil
	}

	app, err := evidence.Open(evidence.Options{Dir: c.dir, SyncMode: segment.SyncModeFull})
	if err != nil {
		if errors.Is(err, evidence.ErrLocked) {
			return evidence.Ref{}, fmt.Errorf("%w — a coordinator is writing this log, so the "+
				"console cannot record the registration; point it at that process with -orchd",
				err)
		}
		return evidence.Ref{}, fmt.Errorf("console: open the log to record the registration: %w", err)
	}
	defer func() { _ = app.Close() }()

	rec := identity.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_console", Kind: "SYSTEM", Principal: "pr_console",
	})
	if err := rec.RegisterCredential(ctx, e.CredentialID, subject, key); err != nil {
		return evidence.Ref{}, fmt.Errorf("console: record the registration: %w", err)
	}
	return evidence.Ref{}, nil
}

// credentials renders the enrolment page.
func (s *Server) credentialsPage(w http.ResponseWriter, r *http.Request) {
	who := s.approver(r)
	trust, err := identity.LoadTrust(s.console.Dir())
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	var mine []string
	for id, cred := range trust.Credentials {
		if cred.Subject == who.Subject {
			mine = append(mine, id)
		}
	}
	s.render(w, r, "credentials.html", page{
		Title:  "authenticators",
		Notice: r.URL.Query().Get("notice"),
		Error:  r.URL.Query().Get("problem"),
		Data:   mine,
	})
}
