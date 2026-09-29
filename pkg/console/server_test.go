package console_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/console"
	"github.com/mustafarslan/janus/pkg/saga"
)

func serve(t *testing.T, dir string, opts console.ServerOptions) http.Handler {
	t.Helper()
	srv, err := console.NewServer(console.Open(dir), opts)
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler()
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestThePagesRender(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	h := serve(t, dir, console.ServerOptions{Version: "test"})

	for _, tc := range []struct{ path, want string }{
		{"/", testSaga},
		{"/queue", "payments.wire.large"},
		{"/quarantine", "Nothing is frozen."},
		{"/search", "chain"},
		{"/sagas/" + testSaga, "mandate:payments"},
	} {
		rec := get(t, h, tc.path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d", tc.path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("GET %s does not mention %q", tc.path, tc.want)
		}
	}

	if rec := get(t, h, "/sagas/sg_nothing"); rec.Code != http.StatusNotFound {
		t.Fatalf("a saga that does not exist returned %d", rec.Code)
	}
}

// TestTheQuarantinePageShowsAFrozenEffect renders the page over a log that has
// one, rather than only over the empty case above.
//
// It also fixes what the page must not have: a form. Releasing a frozen effect
// is a decision about whether money moves, and this page's rows can come from a
// projection's shortlist — exactly the release path that is ruled out. A POST
// arriving here later would be a real regression and would look like a feature.
func TestTheQuarantinePageShowsAFrozenEffect(t *testing.T) {
	h := serve(t, richLog(t), console.ServerOptions{Version: "test"})

	rec := get(t, h, "/quarantine")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /quarantine: %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"ef-frozen", "idem-frozen", "ledger", "COMMITTED"} {
		if !strings.Contains(body, want) {
			t.Errorf("the quarantine page does not mention %q", want)
		}
	}
	if strings.Contains(body, "<form") {
		t.Error("the quarantine page carries a form; a release taken against a list the " +
			"projection shortlisted is a forbidden release path")
	}

	// And the overview points at it, which is the other half: the page is only
	// found by somebody who knows it exists otherwise.
	if !strings.Contains(get(t, h, "/").Body.String(), `href="/quarantine"`) {
		t.Error("the overview does not link to the frozen effects it counts")
	}
}

// TestAReadOnlyConsoleRefusesToRecordAnApproval. Without an identity header
// there is nobody to attribute an approval to, and a console that filled that
// in would make separation of duty a formality.
func TestAReadOnlyConsoleRefusesToRecordAnApproval(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	h := serve(t, dir, console.ServerOptions{Version: "test"})

	rec := httptest.NewRecorder()
	body := strings.NewReader(`{"saga_id":"` + testSaga + `","step_id":"` + testStep +
		`","requirement_id":"` + fourEyesReq + `","approve":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/answer", body)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("a read-only console answered %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "identity-header") {
		t.Fatalf("the refusal does not say how to fix it: %s", rec.Body.String())
	}
	assertNoAnswers(t, dir)

	// And the queue page says so rather than showing buttons nothing will
	// honour.
	if !strings.Contains(get(t, h, "/queue").Body.String(), "read-only") {
		t.Fatal("the queue page does not say the console cannot record approvals")
	}
}

// TestIdentityIsNeverTakenFromTheRequestBody is the one that matters. An
// approver who can name themselves can name somebody else, and every four-eyes
// property rests on them not being able to.
func TestIdentityIsNeverTakenFromTheRequestBody(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	h := serve(t, dir, console.ServerOptions{
		IdentityHeader: "X-Forwarded-User", RolesHeader: "X-Forwarded-Roles", Version: "test",
	})

	// A request that supplies every identity field an attacker could think of,
	// in the body and in the query, and none in the header.
	rec := httptest.NewRecorder()
	body := strings.NewReader(`{"saga_id":"` + testSaga + `","step_id":"` + testStep +
		`","requirement_id":"` + fourEyesReq + `","approve":true,` +
		`"subject":"alice","approver":"alice","roles":["credit-officer"],"by":"alice"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/answer?subject=alice&roles=credit-officer", body)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("an approval naming its own approver was accepted with %d: %s",
			rec.Code, rec.Body.String())
	}
	assertNoAnswers(t, dir)

	// The same request with the header set is recorded, under the header's
	// identity and nobody else's.
	rec = httptest.NewRecorder()
	body = strings.NewReader(`{"saga_id":"` + testSaga + `","step_id":"` + testStep +
		`","requirement_id":"` + fourEyesReq + `","approve":true,"subject":"mallory"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/answer", body)
	req.Header.Set("X-Forwarded-User", "alice")
	req.Header.Set("X-Forwarded-Roles", "credit-officer, treasury-approver")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("an authenticated approval was refused: %d %s", rec.Code, rec.Body.String())
	}

	state, err := saga.ReplaySaga(dir, testSaga)
	if err != nil {
		t.Fatal(err)
	}
	var answers []saga.GateAnswerRecord
	for _, a := range state.Steps[testStep].Answers {
		if a.Human {
			answers = append(answers, a)
		}
	}
	if len(answers) != 1 {
		t.Fatalf("%d human answers recorded", len(answers))
	}
	if answers[0].ActorID != "alice" {
		t.Fatalf("the answer was recorded as %q; the body said mallory and the header said alice",
			answers[0].ActorID)
	}
	if len(answers[0].Roles) != 2 {
		t.Fatalf("roles recorded as %v, want the two the header asserted", answers[0].Roles)
	}
	if !strings.Contains(answers[0].AuthRef, "X-Forwarded-User") {
		t.Fatalf("the answer does not record where the claim came from: %q", answers[0].AuthRef)
	}
}

// TestTheApiSaysItRecordedRatherThanDecided. An operator integrating against
// this must not read a 200 as "the payment is approved".
func TestTheApiSaysItRecordedRatherThanDecided(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	h := serve(t, dir, console.ServerOptions{IdentityHeader: "X-User", Version: "test"})

	rec := httptest.NewRecorder()
	body := strings.NewReader(`{"saga_id":"` + testSaga + `","step_id":"` + testStep +
		`","requirement_id":"` + fourEyesReq + `","approve":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/answer", body)
	req.Header.Set("X-User", "alice")
	h.ServeHTTP(rec, req)

	var out struct {
		Recorded bool   `json:"recorded"`
		Decided  bool   `json:"decided"`
		Note     string `json:"note"`
		Seq      uint64 `json:"seq"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
	switch {
	case !out.Recorded:
		t.Fatal("the response does not say the answer was recorded")
	case out.Decided:
		t.Fatal("the response claims the gate was decided; the coordinator decides it")
	case out.Seq == 0:
		t.Fatal("the response does not cite the sequence the answer landed at")
	case !strings.Contains(out.Note, "coordinator"):
		t.Fatalf("note: %q", out.Note)
	}
}

// TestTheFormPathHasTheSameRefusals. Two surfaces over one read model is only
// safe if the write path is one piece of code.
func TestTheFormPathHasTheSameRefusals(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	h := serve(t, dir, console.ServerOptions{Version: "test"}) // read-only

	form := url.Values{
		"saga_id":        {testSaga},
		"step_id":        {testStep},
		"requirement_id": {fourEyesReq},
		"verdict":        {"approve"},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/queue/answer", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("the form post answered %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "problem=") {
		t.Fatalf("the redirect does not carry the refusal: %q", rec.Header().Get("Location"))
	}
	assertNoAnswers(t, dir)
}

func TestTheJsonApiMirrorsThePages(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)
	h := serve(t, dir, console.ServerOptions{Version: "test"})

	var overview console.Overview
	decodeInto(t, get(t, h, "/api/overview"), &overview)
	if overview.Waiting != 1 {
		t.Fatalf("api overview reports %d waiting", overview.Waiting)
	}

	var queue console.QueueBoard
	decodeInto(t, get(t, h, "/api/queue"), &queue)
	if len(queue.Items) != 1 || queue.Items[0].StepID != testStep {
		t.Fatalf("api queue: %+v", queue)
	}
	// The sequence the answer is as of is part of the answer, not decoration:
	// a client reading this API has the same right to know when the queue was
	// built as a person reading the page.
	if queue.AsOf == 0 {
		t.Error("the api queue does not say which sequence it is as of")
	}

	var detail console.SagaDetail
	decodeInto(t, get(t, h, "/api/sagas/"+testSaga), &detail)
	if detail.SagaID != testSaga {
		t.Fatalf("api saga: %+v", detail)
	}

	var search console.SearchResult
	decodeInto(t, get(t, h, "/api/search?kind=GATE_ANSWER"), &search)
	if search.Matched == 0 {
		t.Fatal("searching for the validator's answer found nothing")
	}
	if search.SignaturesChecked {
		t.Fatal("no keys were supplied, so the console must not claim signatures were checked")
	}
	if !strings.Contains(search.Integrity, "not checked") {
		t.Fatalf("the result does not say what went unchecked: %q", search.Integrity)
	}
}

// TestSearchSaysWhenItCheckedSignatures. The difference between "the chain
// holds" and "the chain holds and a trusted key signed it" is the difference
// between catching corruption and catching an insider.
func TestSearchSaysWhenItCheckedSignatures(t *testing.T) {
	dir, keySet := waitingLog(t, validatorAgrees)

	res, err := console.Open(dir).WithKeys(keySet).Search(console.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.SignaturesChecked {
		t.Fatal("keys were supplied and the result says signatures were not checked")
	}
	if !strings.Contains(res.Integrity, "signatures") {
		t.Fatalf("integrity: %q", res.Integrity)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("an honest log produced findings: %v", res.Findings)
	}
	if res.Scanned == 0 || len(res.Rows) == 0 {
		t.Fatal("the search found no events at all")
	}
}

func decodeInto(t *testing.T, rec *httptest.ResponseRecorder, out any) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("%v: %s", err, rec.Body.String())
	}
}

func assertNoAnswers(t *testing.T, dir string) {
	t.Helper()
	state, err := saga.ReplaySaga(dir, testSaga)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range state.Steps[testStep].Answers {
		if a.Human {
			t.Fatalf("a human answer reached the log: %+v", a)
		}
	}
}
