package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/a2a"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/registry"
)

const (
	principal   = "pr_bank"
	counterpart = "ag_counterparty"
)

// TestTheCardAdvertisesTheExtensionAndCarriesNoEffectClasses is the discovery
// half of the discovery surface, and the second half of that sentence is the
// part that matters.
//
// The rule is that nothing may consume the AgentCard to make a gating
// decision. The way this projection keeps that rule is structural rather than
// advisory: the effect classes are not in the document at all. A field that
// exists is a field somebody eventually reads, and the person reading this one
// would be deciding whether to hold a payment on the word of a document anybody
// can serve.
func TestTheCardAdvertisesTheExtensionAndCarriesNoEffectClasses(t *testing.T) {
	dir := newRegistry(t, registry.StateActive)
	body := get(t, discovery(t, dir), "/.well-known/agent.json", http.StatusOK)

	var card a2a.AgentCard
	if err := json.Unmarshal(body, &card); err != nil {
		t.Fatalf("the card is not readable JSON: %v", err)
	}
	if !card.Speaks(a2a.CapabilityJanusTransactions) {
		t.Fatalf("the card advertises %v; without %q a counterpart has no way to know "+
			"the saga headers will be honoured", card.Capabilities,
			a2a.CapabilityJanusTransactions)
	}
	if card.Provider.Organization != principal {
		t.Fatalf("the card names %q as the provider, want %q — who is answerable for an "+
			"agent is exactly what a counterpart is entitled to ask",
			card.Provider.Organization, principal)
	}
	if card.ManifestURL == "" || card.ManifestVersion == "" || card.ManifestAddress == "" {
		t.Fatal("the card does not say which manifest it was projected from, so a reader " +
			"cannot ask the registry about that version rather than about whatever is current")
	}

	// The structural claim, checked against the bytes rather than the struct: a
	// field that is not in the JSON cannot be read by anybody.
	for _, forbidden := range []string{"effect_class", "COMPENSABLE", "IRREVERSIBLE", "PURE"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("the card contains %q. An AgentCard is an unauthenticated document "+
				"served by whoever answers that address, and carrying the classes gates "+
				"are attached to invites exactly the gating decision a card must never inform", forbidden)
		}
	}
}

// TestAWithdrawnAgentIsNotAdvertised. A discovery document is an invitation,
// and a suspended version is one admission would refuse.
func TestAWithdrawnAgentIsNotAdvertised(t *testing.T) {
	dir := newRegistry(t, registry.StateSuspended)
	get(t, discovery(t, dir), "/.well-known/agent.json", http.StatusNotFound)

	// The manifest is still served: it is what was signed, and reading a
	// declaration is not the same as being invited to rely on it.
	get(t, discovery(t, dir), "/.well-known/janus-manifest.json", http.StatusOK)
}

// TestTheWatchResumesFromWhereAConsumerGotTo is the other half of discovery.
//
// By sequence rather than by subscription, because that is the only form that
// survives a disconnect: the consumer says where it got to and no state is held
// here on its behalf.
func TestTheWatchResumesFromWhereAConsumerGotTo(t *testing.T) {
	dir := newRegistry(t, registry.StateActive)
	handler := discovery(t, dir)

	all := watchLines(t, handler, "")
	if len(all) < 3 {
		t.Fatalf("registering, evaluating and activating is three events; the watch "+
			"reported %d", len(all))
	}

	from := all[0].Seq
	rest := watchLines(t, handler, "?after="+itoa(from))
	if len(rest) != len(all)-1 {
		t.Fatalf("resuming after seq %d returned %d events, want %d — a consumer that "+
			"reconnected would re-process what it had already seen", from, len(rest),
			len(all)-1)
	}
	if rest[0].Seq <= from {
		t.Fatalf("the first event after seq %d is seq %d", from, rest[0].Seq)
	}
	for i := 1; i < len(rest); i++ {
		if rest[i].Seq <= rest[i-1].Seq {
			t.Fatal("the watch is not in sequence order, so 'everything after N' means nothing")
		}
	}
}

// TestAForgedCardDoesNotGetYouThrough is the adversarial case.
//
// The counterpart serves a card that says everything a card can say: it is
// registered, it is active, it speaks the extension. None of it is checked,
// because none of it is checkable — an agent that wanted to be trusted would
// serve exactly this card. The registry is asked instead, it has never heard of
// this agent, and nothing is forwarded.
func TestAForgedCardDoesNotGetYouThrough(t *testing.T) {
	dir := newRegistry(t, registry.StateActive)

	var reached bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// The counterpart's own account of itself, served by the counterpart.
	forged := a2a.AgentCard{
		Name:            "ag_impostor",
		Version:         "9.9.9",
		Provider:        a2a.AgentProvider{Organization: principal},
		Capabilities:    []string{a2a.CapabilityJanusTransactions},
		ManifestVersion: "9.9.9",
	}
	if !forged.Speaks(a2a.CapabilityJanusTransactions) {
		t.Fatal("the forged card should look impeccable; that is the point of it")
	}

	proxy := newProxy(t, dir, upstream.URL, "ag_impostor", "9.9.9")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("a counterpart the registry has never heard of got %d, want 403",
			recorder.Code)
	}
	if reached {
		t.Fatal("the message reached the counterpart. The card was checked, or nothing " +
			"was — either way an agent vouched for itself and was believed")
	}
}

// TestASuspendedCounterpartIsRefused. Registered once is not registered now,
// which is why the registry is folded on every check rather than cached.
func TestASuspendedCounterpartIsRefused(t *testing.T) {
	dir := newRegistry(t, registry.StateSuspended)

	var reached bool
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	defer upstream.Close()

	proxy := newProxy(t, dir, upstream.URL, counterpart, "1.0.0")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)))

	if recorder.Code != http.StatusForbidden || reached {
		t.Fatalf("a suspended counterpart was talked to: status %d, reached %v",
			recorder.Code, reached)
	}
}

// TestTheFramingTravelsAndBothDirectionsAreRecorded.
//
// Half a conversation is not evidence of a conversation, so the reply is
// recorded before it reaches the agent that asked for it.
func TestTheFramingTravelsAndBothDirectionsAreRecorded(t *testing.T) {
	dir := newRegistry(t, registry.StateActive)

	// The counterpart deliberately does *not* echo the framing back. It used to,
	// and that made this test pass on the counterpart's cooperation rather than
	// on anything Janus does: the reply is framed because Janus knows which
	// round trip it is, not because the far side was polite.
	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()

	sessionDir := filepath.Join(t.TempDir(), "a2a-session")
	proxy, app := newProxyWithLog(t, dir, sessionDir, upstream.URL, counterpart, "1.0.0")

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ask":"quote"}`))
	request.Header.Set(a2a.HeaderSagaID, "sg_1")
	request.Header.Set(a2a.HeaderStepID, "st_ask")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("forwarding failed: %d %s", recorder.Code, recorder.Body.String())
	}
	if seen.Get(a2a.HeaderSagaID) != "sg_1" || seen.Get(a2a.HeaderStepID) != "st_ask" {
		t.Fatalf("the counterpart saw saga %q step %q; without the framing neither side "+
			"nor the log agrees on what to call this work",
			seen.Get(a2a.HeaderSagaID), seen.Get(a2a.HeaderStepID))
	}
	if got := recorder.Header().Get(a2a.HeaderSagaID); got != "sg_1" {
		t.Fatalf("the reply came back framed as %q, want sg_1", got)
	}

	// Closed before the log is read: see newProxyWithLog.
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	messages := a2aMessages(t, sessionDir)
	if len(messages) != 2 {
		t.Fatalf("the log holds %d A2A messages, want 2 — the question and the answer",
			len(messages))
	}
	if !strings.Contains(messages[0], `"ask":"quote"`) {
		t.Fatalf("the outbound message was not recorded verbatim: %s", messages[0])
	}
	if !strings.Contains(messages[1], `"result":"ok"`) {
		t.Fatalf("the counterpart's answer was not recorded verbatim: %s", messages[1])
	}
}

// ---- fixtures --------------------------------------------------------------

// newRegistry writes a registered manifest and leaves it in the given state.
func newRegistry(t *testing.T, state registry.State) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	trust := registry.TrustStore{}
	trust.Trust(principal, signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_registry", Principal: principal, Kind: "SYSTEM",
	}, registry.New(), trust)

	manifest := &registry.Manifest{
		Version:  "1.0.0",
		Identity: registry.Identity{ParticipantID: counterpart, Kind: "AGENT", Principal: principal},
		Runtime:  registry.Runtime{ModelID: "none", PromptBundleHash: "blake3:a2a"},
		Actions: []registry.Action{
			{Name: "quote.request", EffectClass: "PURE"},
			{
				Name: "settle.instruct", EffectClass: "COMPENSABLE",
				Compensation: &registry.Compensation{
					Action: "settle.recall", MaxDelaySeconds: 3600,
					ResidualEffects: "none in the sandbox",
				},
				Idempotency: &registry.Idempotency{KeyRecipe: "saga_id,step_id"},
			},
			{
				Name: "settle.recall", EffectClass: "REVERSIBLE",
				Compensation: &registry.Compensation{Action: "settle.instruct"},
				Idempotency:  &registry.Idempotency{KeyRecipe: "saga_id,step_id"},
			},
		},
		Risk: registry.Risk{
			Tier:                 2,
			RevalidationTriggers: []string{registry.TriggerModelChange, registry.TriggerActionChange},
		},
		Jurisdiction: registry.Jurisdiction{DeployableIn: []string{"EU"}, DataResidency: "EU"},
	}
	sig, err := registry.Sign(manifest, signer)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := rec.Register(ctx, manifest, sig); err != nil {
		t.Fatal(err)
	}
	doubles := registry.NewDoubles("a2a-sandbox").
		With("quote.request", registry.Double{}).
		With("settle.instruct", registry.Double{Deltas: map[string]int64{"ledger": -1}}).
		With("settle.recall", registry.Double{Deltas: map[string]int64{"ledger": 1}})
	report, err := registry.Evaluate(ctx, manifest, doubles)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Evaluate(ctx, counterpart, "1.0.0", report); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, counterpart, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if state == registry.StateSuspended {
		if err := rec.Suspend(ctx, counterpart, "1.0.0", "withdrawn for this test"); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func discovery(t *testing.T, dir string) http.Handler {
	t.Helper()
	s, err := a2a.NewServer(a2a.ServerOptions{
		Dir: dir, Participant: counterpart, Version: "1.0.0",
		BaseURL: "https://agent.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

func newProxy(t *testing.T, dir, upstream, who, version string) *a2a.Proxy {
	t.Helper()
	p, _ := newProxyWithLog(t, dir, filepath.Join(t.TempDir(), "session"), upstream, who, version)
	return p
}

// newProxyWithLog returns the proxy and the appender behind it. The appender is
// returned rather than only cleaned up because a test that reads the session
// log has to close it first: a scan of a directory the writer still holds can
// catch a half-written record and fail on a torn tail instead of on what the
// test is asserting. The same reason as runProxyRecording in pkg/mcp.
func newProxyWithLog(t *testing.T, dir, sessionDir, upstream, who, version string) (*a2a.Proxy, *evidence.Appender) {
	t.Helper()
	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{Dir: sessionDir, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })

	p, err := a2a.NewProxy(a2a.ProxyOptions{
		Upstream: target, Counterpart: who, CounterpartVersion: version,
		Verifier: a2a.NewVerifier(dir), Appender: app,
		Self: evidence.ParticipantRef{ID: "ag_a2ad", Principal: principal, Kind: "SYSTEM"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, app
}

func get(t *testing.T, h http.Handler, path string, want int) []byte {
	t.Helper()
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	if recorder.Code != want {
		t.Fatalf("GET %s returned %d, want %d: %s", path, recorder.Code, want,
			recorder.Body.String())
	}
	return recorder.Body.Bytes()
}

type line struct {
	Seq   uint64          `json:"seq"`
	Event json.RawMessage `json:"event"`
}

func watchLines(t *testing.T, h http.Handler, query string) []line {
	t.Helper()
	body := get(t, h, "/registry/watch"+query, http.StatusOK)
	var out []line
	for _, raw := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if raw == "" {
			continue
		}
		var l line
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			t.Fatalf("the watch emitted a line that is not JSON: %q", raw)
		}
		out = append(out, l)
	}
	return out
}

// a2aMessages reads back what the proxy recorded, in order, straight from the
// segments — the same way any other reader of this log would.
func a2aMessages(t *testing.T, dir string) []string {
	t.Helper()
	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatalf("reading the session log: %v", err)
	}
	var out []string
	for _, id := range ids {
		insp, err := segment.Inspect(segment.Path(dir, id))
		if err != nil {
			t.Fatal(err)
		}
		for _, rec := range insp.Records {
			header, err := evidence.DecodeHeader(rec.Header)
			if err != nil {
				t.Fatal(err)
			}
			if header.Kind == evidence.KindA2AMessage {
				out = append(out, string(rec.Payload))
			}
		}
	}
	return out
}

func itoa(n uint64) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// a2aRecords returns the header of every A2A message in a session log, so a
// test can assert which saga a record was filed under and not only what it said.
func a2aRecords(t *testing.T, dir string) []evidence.EventHeader {
	t.Helper()
	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatalf("reading the session log: %v", err)
	}
	var out []evidence.EventHeader
	for _, id := range ids {
		insp, err := segment.Inspect(segment.Path(dir, id))
		if err != nil {
			t.Fatal(err)
		}
		for _, rec := range insp.Records {
			h, err := evidence.DecodeHeader(rec.Header)
			if err != nil {
				t.Fatal(err)
			}
			if h.Kind == evidence.KindA2AMessage {
				out = append(out, h)
			}
		}
	}
	return out
}

// exchange runs one framed request through the proxy against a counterpart that
// answers with the given saga header — none at all when it is empty — and
// returns the records written plus the headers the local agent got back.
func exchange(t *testing.T, replyHeader string) ([]evidence.EventHeader, http.Header) {
	t.Helper()
	return exchangeFramed(t, "sg_1", replyHeader)
}

// exchangeFramed is the same, with the framing the *local agent* put on its
// request under the caller's control — "" for an agent that set none.
func exchangeFramed(t *testing.T, requestSaga, replyHeader string) ([]evidence.EventHeader, http.Header) {
	t.Helper()
	dir := newRegistry(t, registry.StateActive)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if replyHeader != "" {
			w.Header().Set(a2a.HeaderSagaID, replyHeader)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()

	sessionDir := filepath.Join(t.TempDir(), "a2a-session")
	proxy, app := newProxyWithLog(t, dir, sessionDir, upstream.URL, counterpart, "1.0.0")
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ask":"quote"}`))
	if requestSaga != "" {
		request.Header.Set(a2a.HeaderSagaID, requestSaga)
		request.Header.Set(a2a.HeaderStepID, "st_ask")
	}
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, request)
	if rec.Code != http.StatusOK {
		t.Fatalf("forwarding failed: %d %s", rec.Code, rec.Body.String())
	}
	// Closed before the log is read: see newProxyWithLog.
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return a2aRecords(t, sessionDir), rec.Header()
}

// A counterpart does not get to say which saga a record in this log belongs to.
//
// The inbound record used to be filed under `ContextFrom(response.Header)` — the
// counterpart's own answer to a question Janus already knows, because it is the
// same HTTP round trip. A counterpart returning a different saga id had its
// reply filed against that saga: an auditor reading the one it named would see
// an answer belonging to another conversation, and an auditor reading the real
// one would see a question with no answer.
//
// Both directions of the failure are asserted, because they are different
// defects that happened to share a line: omitting the header lost the join, and
// returning a different one moved it.
func TestACounterpartDoesNotChooseWhichSagaItsReplyBelongsTo(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
	}{
		{"omits the framing", ""},
		{"claims another saga", "sg_someone_else"},
		{"echoes ours", "sg_1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, replyHeaders := exchange(t, tc.reply)
			if len(records) != 2 {
				t.Fatalf("the log holds %d A2A message(s), want 2", len(records))
			}
			for i, r := range records {
				if r.SagaID != "sg_1" {
					t.Fatalf("record %d is filed under saga %q; both halves of one "+
						"exchange belong to the saga Janus began", i, r.SagaID)
				}
			}
			// And the agent that asked is answered in its own framing, not in
			// whatever the counterpart sent: forwarding that would hand it a
			// reply framed for work it never began.
			if got := replyHeaders.Get(a2a.HeaderSagaID); got != "sg_1" {
				t.Fatalf("the local agent was answered with framing %q, want sg_1", got)
			}
		})
	}
}

// A counterpart that claims a different saga is recorded as having claimed it.
//
// Filing the reply correctly is not the same as pretending nothing happened. A
// counterpart echoing someone else's saga id is a misconfiguration or an
// attempt, and either is worth a line — as a label, never as the key the record
// is filed under.
//
// Only on a disagreement. When the echo matches, the label would be noise on
// every message in every conversation; when the header is absent, there is no
// claim to record. Both are asserted, because a label that appears
// unconditionally says nothing.
func TestACounterpartsClaimIsRecordedWhenItDisagrees(t *testing.T) {
	records, _ := exchange(t, "sg_someone_else")
	got, ok := records[1].Labels["counterpart_claimed_saga"]
	if !ok {
		t.Fatal("a counterpart returned another agent's saga id and the log does not say so")
	}
	if got != "sg_someone_else" {
		t.Fatalf("the log records the claim as %q", got)
	}

	for _, quiet := range []string{"", "sg_1"} {
		records, _ = exchange(t, quiet)
		for i, r := range records {
			if _, present := r.Labels["counterpart_claimed_saga"]; present {
				t.Fatalf("record %d carries a disagreement label for reply framing %q; a "+
					"label on every message says nothing", i, quiet)
			}
		}
	}
}

// An unframed outbound is forwarded and recorded, not refused.
//
// This is the availability half of the framing rule and it is a decision, not an
// oversight. The proxy sits in the path of a local agent's own traffic: an
// agent that forgot the header and could not talk to anyone would have been
// stopped by its evidence layer, and an interception edge that drops its own
// side's messages is an availability decision nobody asked for. The message is
// recorded verbatim either way — what is lost is the join, not the evidence.
//
// Nor does the proxy invent a saga to fill the gap. Only the agent knows which
// saga the call belongs to, and a guess would file evidence under a saga
// nobody chose. Both halves are asserted here, because "forwarded" and "left
// unjoined" are the two ways this could have gone wrong in opposite
// directions.
func TestAnUnframedOutboundIsForwardedAndRecordedNotRefused(t *testing.T) {
	records, replyHeaders := exchangeFramed(t, "", "")
	if len(records) != 2 {
		t.Fatalf("the log holds %d A2A message(s), want 2 — an unframed message is "+
			"still recorded, both halves of it", len(records))
	}
	for i, r := range records {
		if r.SagaID != "" {
			t.Fatalf("record %d was filed under saga %q; the agent named none, and a "+
				"saga the proxy chose is evidence filed under a name nobody picked",
				i, r.SagaID)
		}
		if _, present := r.Labels["saga_id"]; present {
			t.Fatalf("record %d carries a saga_id label for a message that had no framing", i)
		}
	}
	if got := replyHeaders.Get(a2a.HeaderSagaID); got != "" {
		t.Fatalf("the agent was answered with framing %q for a call it framed with none", got)
	}
}

// A stream is refused, and nothing is sent.
//
// A2A streaming is not intercepted. What this proxy did with a stream
// was once to buffer it: `io.ReadAll` on the response returned when the
// stream ended, so a three-event stream 150 ms apart arrived after 460 ms as one
// piece, and a channel that stays open never arrived at all while this process
// held every byte of it. The bytes were recorded correctly — it is delivery that
// broke, which looks from the outside like a slow counterpart.
//
// Three things are asserted, and the second is the one that makes this a
// refusal rather than an error: the counterpart is never contacted, so nothing
// happened that a record would need to describe.
func TestAStreamIsRefusedAndNothingIsSent(t *testing.T) {
	dir := newRegistry(t, registry.StateActive)
	var reached int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reached, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	defer upstream.Close()

	sessionDir := filepath.Join(t.TempDir(), "a2a-session")
	proxy, app := newProxyWithLog(t, dir, sessionDir, upstream.URL, counterpart, "1.0.0")

	for _, accept := range []string{
		"text/event-stream",
		// A list with q-values: the same request, written the way a client
		// library writes it. A proxy that only recognised the header standing
		// alone would forward the case it means to refuse.
		"application/json;q=0.9, text/event-stream;q=1.0",
		"TEXT/EVENT-STREAM",
	} {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ask":"stream"}`))
		request.Header.Set(a2a.HeaderSagaID, "sg_1")
		request.Header.Set("Accept", accept)
		rec := httptest.NewRecorder()
		proxy.ServeHTTP(rec, request)

		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("Accept %q was answered %d, want 501: a stream this middleware cannot "+
				"record as one is forwarded, and what the caller gets back is a stream "+
				"buffered until it ends", accept, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "does not intercept A2A streaming") {
			t.Fatalf("the refusal does not say what it is refusing: %q", rec.Body.String())
		}
	}
	if n := atomic.LoadInt32(&reached); n != 0 {
		t.Fatalf("the counterpart was contacted %d time(s) by a refused stream; a refusal "+
			"that already sent the message is not a refusal", n)
	}

	// And what the refusal replaces, measured rather than argued: an upstream
	// that never closes. Without the refusal this call does not return at all —
	// io.ReadAll waits for the end of a stream that has no end — so a task
	// streaming for a minute would be answered after a minute and an open
	// channel never, with every byte held here in the meantime.
	t.Run("an endless stream would never return", func(t *testing.T) {
		release := make(chan struct{})
		endless := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			for {
				select {
				case <-release:
					return
				case <-r.Context().Done():
					return
				default:
					_, _ = w.Write([]byte("data: {}\n\n"))
					if fl, ok := w.(http.Flusher); ok {
						fl.Flush()
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
		}))
		defer endless.Close()
		defer close(release)

		p2, app2 := newProxyWithLog(t, dir, filepath.Join(t.TempDir(), "endless"),
			endless.URL, counterpart, "1.0.0")
		t.Cleanup(func() { _ = app2.Close() })

		// Refused: it returns, and fast.
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ask":"stream"}`))
		req.Header.Set(a2a.HeaderSagaID, "sg_1")
		req.Header.Set("Accept", "text/event-stream")
		done := make(chan int, 1)
		go func() {
			rec := httptest.NewRecorder()
			p2.ServeHTTP(rec, req)
			done <- rec.Code
		}()
		select {
		case code := <-done:
			if code != http.StatusNotImplemented {
				t.Fatalf("an endless stream was answered %d", code)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("the proxy did not answer an endless stream within 2s: this is the " +
				"buffering the refusal exists to replace, and it has no end to wait for")
		}

		// And the same request without the Accept header does not return,
		// which is the exposure this decision names rather than fixes.
		plain := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ask":"stream"}`))
		plain.Header.Set(a2a.HeaderSagaID, "sg_1")
		hung := make(chan struct{})
		go func() {
			p2.ServeHTTP(httptest.NewRecorder(), plain)
			close(hung)
		}()
		select {
		case <-hung:
			t.Fatal("an unannounced endless stream returned: if that is now bounded, " +
				"the named exposure is stale and the documentation should say so")
		case <-time.After(300 * time.Millisecond):
			// Still reading, as documented. Released by the deferred close.
		}
	})

	// Closed before the log is read: see newProxyWithLog.
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	if records := a2aRecords(t, sessionDir); len(records) != 0 {
		t.Fatalf("a refused stream wrote %d record(s); nothing was sent, so there is "+
			"nothing to have recorded", len(records))
	}
}

// And an ordinary request is not caught by the refusal.
//
// The check reads `Accept`, which every client sets and most set to something
// permissive. A proxy that refused `*/*` would refuse everything, and a rule
// that is never wrong in the tests it was written with is how that ships.
func TestAnOrdinaryRequestIsNotMistakenForAStream(t *testing.T) {
	for _, accept := range []string{
		"", "*/*", "application/json", "application/json, text/*;q=0.5",
	} {
		t.Run(accept, func(t *testing.T) {
			dir := newRegistry(t, registry.StateActive)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"result":"ok"}`))
			}))
			defer upstream.Close()

			proxy, _ := newProxyWithLog(t, dir, filepath.Join(t.TempDir(), "s"),
				upstream.URL, counterpart, "1.0.0")
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"ask":"q"}`))
			request.Header.Set(a2a.HeaderSagaID, "sg_1")
			if accept != "" {
				request.Header.Set("Accept", accept)
			}
			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, request)
			if rec.Code != http.StatusOK {
				t.Fatalf("Accept %q was answered %d: an ordinary A2A call was refused as a "+
					"stream, which takes the middleware out of the path of the traffic it "+
					"exists to record", accept, rec.Code)
			}
		})
	}
}
