package console

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
)

// The HTTP surface.
//
// Two shapes over the same read model: HTML for a person and JSON for anything
// else. They are the same handlers with a different renderer, so a screen and
// an API response cannot drift into disagreeing about what is waiting.
//
// The console authenticates nobody. It reads the approver's identity from a
// header an authenticating proxy in front of it sets, and if no such header is
// configured it is read-only — every write path answers 403 and says why.
// Taking the identity from the form instead would be one line and would make
// separation of duty meaningless, because the approver would get to choose who
// they are.

//go:embed templates/*.html
var templateFS embed.FS

// staticFS holds the one script this console serves. It is embedded rather than
// inlined into the template so that a deployment can set a Content-Security-
// Policy without an unsafe-inline exemption — a console that had to allow
// inline script to work would be weakening the page that records approvals.
//
//go:embed static/*.js
var staticFS embed.FS

// ServerOptions configures the HTTP surface.
type ServerOptions struct {
	// IdentityHeader is the request header carrying the authenticated
	// approver's identifier, set by the proxy in front of this console. Empty
	// makes the console read-only.
	IdentityHeader string
	// RolesHeader carries the roles that layer asserts for the approver, comma
	// separated. Empty means no roles are recorded — which is the honest
	// default: a gate that names roles will then refuse, and a gate that only
	// requires separation of duty will not.
	RolesHeader string
	// IDTokenHeader carries the approver's OIDC ID token, verbatim, as the
	// proxy received it. With it the console can build an assertion and verify
	// it, instead of recording what the proxy said and calling that identity.
	//
	// Why the token comes from a header and the WebAuthn assertion, below,
	// comes from the form: a form-supplied identity is an identity the approver
	// chose, which is the thing separation of duty exists to prevent. An
	// assertion is different in kind — it is signed over a challenge derived
	// from this approval, so it verifies on its own and a form is simply the
	// only place a browser can put it.
	IDTokenHeader string
	// RolesClaim names the ID token claim the roles are read from. Providers
	// disagree about where they live, and guessing would mean a deployment
	// whose roles silently never verify.
	RolesClaim string
	// Version labels the build in the footer.
	Version string
}

// Server serves the console.
type Server struct {
	console *Console
	opts    ServerOptions
	tmpl    *template.Template
}

// NewServer returns a console server.
func NewServer(c *Console, opts ServerOptions) (*Server, error) {
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"join":  strings.Join,
		"since": humanSince,
		"pct":   percent,
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("console: parse templates: %w", err)
	}
	return &Server{console: c, opts: opts, tmpl: tmpl}, nil
}

// ReadOnly reports whether this console can record an approval at all.
func (s *Server) ReadOnly() bool { return s.opts.IdentityHeader == "" }

// Handler returns the console's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", s.overview)
	mux.HandleFunc("GET /sagas/{id}", s.saga)
	mux.HandleFunc("GET /queue", s.queue)
	mux.HandleFunc("GET /quarantine", s.quarantine)
	mux.HandleFunc("GET /search", s.search)
	mux.HandleFunc("POST /queue/answer", s.answerForm)

	mux.HandleFunc("GET /credentials", s.credentialsPage)
	mux.HandleFunc("POST /credentials/enrol", s.enrolForm)

	mux.HandleFunc("GET /api/stepup", s.stepUpChallenge)
	mux.HandleFunc("GET /api/enrol", s.enrolChallenge)
	mux.Handle("GET /static/", http.FileServerFS(staticFS))

	mux.HandleFunc("GET /api/overview", s.jsonOverview)
	mux.HandleFunc("GET /api/sagas/{id}", s.jsonSaga)
	mux.HandleFunc("GET /api/queue", s.jsonQueue)
	mux.HandleFunc("GET /api/quarantine", s.jsonQuarantine)
	mux.HandleFunc("GET /api/search", s.jsonSearch)
	mux.HandleFunc("POST /api/answer", s.jsonAnswer)

	return mux
}

// ---- HTML --------------------------------------------------------------------

type page struct {
	Title    string
	Dir      string
	Version  string
	ReadOnly bool
	// Approver is who the authenticating layer says is looking, so a person can
	// see which identity an approval would be recorded under before they press
	// the button.
	Approver string
	Roles    []string
	Notice   string
	Error    string
	Data     any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, p page) {
	p.Dir = s.console.Dir()
	p.Version = s.opts.Version
	p.ReadOnly = s.ReadOnly()
	who := s.approver(r)
	p.Approver = who.Subject
	p.Roles = who.Roles

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, p); err != nil {
		// The status is already written by now, so this can only be logged into
		// the response.
		_, _ = fmt.Fprintf(w, "\n<pre>template %s: %v</pre>", name, err)
	}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, err error) {
	w.WriteHeader(status)
	s.render(w, r, "error.html", page{Title: "problem", Error: err.Error()})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	data, err := s.console.Overview()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	s.render(w, r, "overview.html", page{Title: "sagas", Data: data})
}

func (s *Server) saga(w http.ResponseWriter, r *http.Request) {
	data, err := s.console.Saga(r.PathValue("id"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ErrNoSaga) {
			status = http.StatusNotFound
		}
		s.fail(w, r, status, err)
		return
	}
	s.render(w, r, "saga.html", page{Title: data.SagaID, Data: data})
}

func (s *Server) queue(w http.ResponseWriter, r *http.Request) {
	data, err := s.console.Queue()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	s.render(w, r, "queue.html", page{
		Title:  "waiting for a person",
		Data:   data,
		Notice: r.URL.Query().Get("notice"),
		Error:  r.URL.Query().Get("problem"),
	})
}

// quarantine renders the frozen-effect work list.
//
// There is no POST beside it. Every other work list in this console has an
// action attached; this one is deliberately read-only, because releasing an
// effect from a page whose row set came from the projection is a forbidden
// release path.
func (s *Server) quarantine(w http.ResponseWriter, r *http.Request) {
	data, err := s.console.Quarantine()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	s.render(w, r, "quarantine.html", page{
		Title: "frozen, waiting for a person",
		Data:  data,
	})
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	f := filterFromQuery(r)
	data, err := s.console.Search(f)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, err)
		return
	}
	s.render(w, r, "search.html", page{Title: "evidence", Data: struct {
		Filter Filter
		Result SearchResult
	}{f, data}})
}

// answerForm records an approval submitted from the queue page.
func (s *Server) answerForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.fail(w, r, http.StatusBadRequest, err)
		return
	}
	req := AnswerRequest{
		SagaID:        r.FormValue("saga_id"),
		StepID:        r.FormValue("step_id"),
		RequirementID: r.FormValue("requirement_id"),
		Approve:       r.FormValue("verdict") == "approve",
		Reason:        r.FormValue("reason"),
		By:            s.approver(r),
	}
	assertion, aerr := s.assertionFrom(r, r.FormValue("step_up"))
	if aerr != nil {
		http.Redirect(w, r, "/queue?problem="+urlEscape(aerr.Error()), http.StatusSeeOther)
		return
	}
	req.By.Assertion = assertion

	ref, err := s.recordAnswer(r, req)
	target := "/queue?"
	if err != nil {
		http.Redirect(w, r, target+"problem="+urlEscape(err.Error()), http.StatusSeeOther)
		return
	}
	verb := "refused"
	if req.Approve {
		verb = "approved"
	}
	http.Redirect(w, r, target+"notice="+urlEscape(fmt.Sprintf(
		"%s %s/%s as %s; recorded at sequence %d — the coordinator decides the gate",
		verb, req.SagaID, req.StepID, req.By.Subject, ref.Seq)), http.StatusSeeOther)
}

// ---- JSON --------------------------------------------------------------------

func (s *Server) jsonOverview(w http.ResponseWriter, r *http.Request) {
	data, err := s.console.Overview()
	writeJSON(w, data, err, http.StatusInternalServerError)
}

func (s *Server) jsonSaga(w http.ResponseWriter, r *http.Request) {
	data, err := s.console.Saga(r.PathValue("id"))
	status := http.StatusInternalServerError
	if errors.Is(err, ErrNoSaga) {
		status = http.StatusNotFound
	}
	writeJSON(w, data, err, status)
}

func (s *Server) jsonQueue(w http.ResponseWriter, r *http.Request) {
	data, err := s.console.Queue()
	if data.Items == nil {
		data.Items = []QueueItem{}
	}
	writeJSON(w, data, err, http.StatusInternalServerError)
}

func (s *Server) jsonQuarantine(w http.ResponseWriter, r *http.Request) {
	data, err := s.console.Quarantine()
	if data.Items == nil {
		data.Items = []QuarantineItem{}
	}
	writeJSON(w, data, err, http.StatusInternalServerError)
}

func (s *Server) jsonSearch(w http.ResponseWriter, r *http.Request) {
	data, err := s.console.Search(filterFromQuery(r))
	writeJSON(w, data, err, http.StatusInternalServerError)
}

func (s *Server) jsonAnswer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SagaID        string `json:"saga_id"`
		StepID        string `json:"step_id"`
		RequirementID string `json:"requirement_id"`
		Approve       bool   `json:"approve"`
		Reason        string `json:"reason"`
		// StepUp is a WebAuthn assertion, as JSON. It is not an identity field:
		// it is signed over a challenge derived from this approval, and the
		// server recomputes that challenge rather than believing anything here.
		StepUp json.RawMessage `json:"step_up,omitempty"`
		// Deliberately no identity field. An approval that could name its own
		// approver is not an approval.
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, nil, err, http.StatusBadRequest)
		return
	}
	req := AnswerRequest{
		SagaID: body.SagaID, StepID: body.StepID, RequirementID: body.RequirementID,
		Approve: body.Approve, Reason: body.Reason, By: s.approver(r),
	}
	assertion, aerr := s.assertionFrom(r, string(body.StepUp))
	if aerr != nil {
		writeJSON(w, nil, aerr, statusFor(aerr))
		return
	}
	req.By.Assertion = assertion

	ref, err := s.recordAnswer(r, req)
	if err != nil {
		writeJSON(w, nil, err, statusFor(err))
		return
	}
	writeJSON(w, map[string]any{
		"seq":      ref.Seq,
		"event_id": ref.EventID,
		"recorded": true,
		"decided":  false,
		"note":     "the answer is recorded; the coordinator composes the verdict",
		"approver": req.By.Subject,
		"roles":    req.By.Roles,
		"auth_ref": req.By.AuthRef,
	}, nil, 0)
}

// ---- shared ------------------------------------------------------------------

// recordAnswer is the one place a write happens, so the read-only refusal
// cannot be forgotten on one of the two surfaces.
func (s *Server) recordAnswer(r *http.Request, req AnswerRequest) (evidence.Ref, error) {
	if s.ReadOnly() {
		return evidence.Ref{}, fmt.Errorf("%w: this console has no identity header configured, "+
			"so it cannot say who is approving; start it with -identity-header once an "+
			"authenticating proxy sets one", ErrAnonymous)
	}
	return s.console.Answer(r.Context(), req)
}

// approver reads the identity the layer in front of the console asserted.
//
// It reads headers and nothing else. There is no fallback to a query parameter
// or a form field, because a fallback is what an attacker uses.
func (s *Server) approver(r *http.Request) Approver {
	if s.opts.IdentityHeader == "" {
		return Approver{}
	}
	subject := strings.TrimSpace(r.Header.Get(s.opts.IdentityHeader))
	if subject == "" {
		return Approver{}
	}
	var roles []string
	if s.opts.RolesHeader != "" {
		for _, role := range strings.Split(r.Header.Get(s.opts.RolesHeader), ",") {
			if role = strings.TrimSpace(role); role != "" {
				roles = append(roles, role)
			}
		}
	}
	return Approver{
		Subject: subject,
		Roles:   roles,
		// The reference says what asserted the claim, not that it is true. An
		// auditor reading "proxy-header:X-Forwarded-User" knows exactly how
		// much the role list is worth.
		AuthRef: "proxy-header:" + s.opts.IdentityHeader,
	}
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, ErrAnonymous):
		return http.StatusForbidden
	case errors.Is(err, ErrNotAnswerable):
		return http.StatusConflict
	case errors.Is(err, ErrNoSaga):
		return http.StatusNotFound
	case errors.Is(err, evidence.ErrLocked):
		// Another process is writing the log — a coordinator, most likely.
		// That is a "come back when it lets go", not a client error.
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, data any, err error, status int) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(data)
}

func filterFromQuery(r *http.Request) Filter {
	q := r.URL.Query()
	f := Filter{
		SagaID:      q.Get("saga"),
		StepID:      q.Get("step"),
		Kind:        q.Get("kind"),
		Participant: q.Get("participant"),
		Subject:     q.Get("subject"),
		Text:        q.Get("q"),
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		f.Limit = n
	}
	if t, err := time.Parse(time.RFC3339, q.Get("from")); err == nil {
		f.From = t
	}
	if t, err := time.Parse(time.RFC3339, q.Get("until")); err == nil {
		f.Until = t
	}
	return f
}

// urlEscape puts a message safely into a redirect's query string.
//
// It was a hand-rolled replacer covering &, # and ?, and it missed the
// semicolon — which Go's query parser refuses outright, so `Query().Get` on the
// whole string returns "" and the page renders no error at all. Since almost
// every refusal in this package is written with a semicolon in it, the console
// had been swallowing its own reasons: the person pressed approve, nothing
// happened, and the log said nothing because nothing was written.
//
// url.QueryEscape handles every character rather than the four somebody thought
// of. The newline replacement stays because a message broken across lines reads
// badly in a banner, not because it would be unsafe.
func urlEscape(s string) string {
	return url.QueryEscape(strings.ReplaceAll(s, "\n", " "))
}

// humanSince renders how long something has been waiting, which is the number
// an operator actually reads on a queue.
func humanSince(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}

func percent(done, total int) int {
	if total == 0 {
		return 0
	}
	return done * 100 / total
}
