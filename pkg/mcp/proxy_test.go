package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/evidence/verify"
	"github.com/mustafarslan/janus/pkg/mcp"
)

// session wires an agent, the proxy, and a tool server together in process,
// runs the given requests, and returns the responses plus the evidence written.
func session(t *testing.T, requests []mcp.Frame) ([]mcp.Frame, []evidence.EventHeader, mcp.Stats, string, *keys.Signer) {
	t.Helper()

	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := mcp.NewProxy(mcp.Options{
		Appender:  app,
		SessionID: "mcp_session_0001",
		Classifier: mcp.StaticClassifier{
			"echo": janusv1.EffectClass_EFFECT_CLASS_PURE,
		},
		Participant: evidence.ParticipantRef{ID: "tool_toybox", ManifestVersion: "0.1.0", Kind: "TOOL"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// agent → proxy → server → proxy → agent, over four pipes.
	agentToProxy, agentWrite := io.Pipe()
	proxyToServer, proxyServerWrite := io.Pipe()
	serverToProxy, serverWrite := io.Pipe()
	proxyToAgent, proxyAgentWrite := io.Pipe()

	serverDone := make(chan error, 1)
	go func() {
		srv := &mcp.EchoServer{ServerName: "toybox"}
		serverDone <- srv.Serve(proxyToServer, serverWrite)
	}()

	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- proxy.Run(context.Background(), agentToProxy, proxyAgentWrite, serverToProxy, proxyServerWrite)
	}()

	// The agent: send every request, then read one response each.
	go func() {
		w := mcp.NewWriter(agentWrite)
		for _, f := range requests {
			if err := w.Write(f); err != nil {
				return
			}
		}
	}()

	var responses []mcp.Frame
	reader := mcp.NewReader(proxyToAgent)
	for range requests {
		f, err := reader.Next()
		if err != nil {
			t.Fatalf("reading response %d: %v", len(responses), err)
		}
		responses = append(responses, f)
	}

	// Tear down: closing the agent's writer ends the client->server pump, which
	// closes the server's input, which ends the server and then the other pump.
	_ = agentWrite.Close()
	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("tool server did not exit")
	}
	_ = serverWrite.Close()
	select {
	case err := <-proxyDone:
		if err != nil {
			t.Fatalf("proxy: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit")
	}

	stats := proxy.Stats()
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return responses, readHeaders(t, dir), stats, dir, signer
}

func readHeaders(t *testing.T, dir string) []evidence.EventHeader {
	t.Helper()
	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
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
			out = append(out, h)
		}
	}
	return out
}

func TestProxyForwardsAndRecordsEveryMessage(t *testing.T) {
	initialize, _ := mcp.Request(1, mcp.MethodInitialize, map[string]any{"protocolVersion": "2025-06-18"})
	list, _ := mcp.Request(2, mcp.MethodToolsList, nil)
	echo, _ := mcp.ToolCall(3, "echo", map[string]any{"text": "hello janus"})
	wire, _ := mcp.ToolCall(4, "wire.send", map[string]any{"account": "DE89", "amount": 100.0})

	responses, headers, stats, _, _ := session(t, []mcp.Frame{initialize, list, echo, wire})

	if len(responses) != 4 {
		t.Fatalf("got %d responses, want 4", len(responses))
	}
	// The tool server answered normally, which is the point: it needed no
	// change and never learned it was being intercepted.
	if got := textOf(t, responses[2]); got != "hello janus" {
		t.Fatalf("echo returned %q", got)
	}

	// Eight messages crossed the boundary and eight are in the log.
	if stats.ClientToServer != 4 || stats.ServerToClient != 4 {
		t.Fatalf("proxy counted %d/%d messages, want 4/4", stats.ClientToServer, stats.ServerToClient)
	}
	if len(headers) != 8 {
		t.Fatalf("log holds %d events, want 8", len(headers))
	}
	for i, h := range headers {
		if h.Kind != evidence.KindMCPMessage {
			t.Fatalf("event %d has kind %s", i, h.Kind)
		}
		if h.SagaID != "mcp_session_0001" {
			t.Fatalf("event %d has saga id %q", i, h.SagaID)
		}
		if h.Labels["mcp.direction"] == "" {
			t.Fatalf("event %d has no direction label", i)
		}
	}
}

// TestUnregisteredToolFailsClosed is the safety default: a tool nobody declared
// is treated as irreversible until a manifest says otherwise.
func TestUnregisteredToolFailsClosed(t *testing.T) {
	echo, _ := mcp.ToolCall(1, "echo", map[string]any{"text": "hi"})
	wire, _ := mcp.ToolCall(2, "wire.send", map[string]any{"account": "DE89", "amount": 1.0})

	_, headers, stats, _, _ := session(t, []mcp.Frame{echo, wire})

	if stats.ToolCalls != 2 {
		t.Fatalf("counted %d tool calls, want 2", stats.ToolCalls)
	}
	if stats.Unclassified != 1 {
		t.Fatalf("counted %d unclassified calls, want 1 (wire.send)", stats.Unclassified)
	}

	classes := map[string]string{}
	sources := map[string]string{}
	for _, h := range headers {
		if tool := h.Labels["mcp.tool"]; tool != "" && h.Labels["mcp.direction"] == "client->server" {
			classes[tool] = h.Labels["janus.effect_class"]
			sources[tool] = h.Labels["janus.classification"]
		}
	}
	if classes["echo"] != "PURE" {
		t.Fatalf("echo was classified %q, want PURE from the manifest", classes["echo"])
	}
	if sources["echo"] != "manifest" {
		t.Fatalf("echo's classification came from %q, want manifest", sources["echo"])
	}
	if classes["wire.send"] != "IRREVERSIBLE_GATED" {
		t.Fatalf("an unregistered tool was classified %q; the default must fail closed", classes["wire.send"])
	}
	if sources["wire.send"] != "default" {
		t.Fatalf("wire.send's classification came from %q, want default", sources["wire.send"])
	}
}

// TestResponsesInheritRequestClassification: a result should be attributable to
// the effect class it was produced under without joining two records.
func TestResponsesInheritRequestClassification(t *testing.T) {
	echo, _ := mcp.ToolCall(7, "echo", map[string]any{"text": "hi"})
	_, headers, _, _, _ := session(t, []mcp.Frame{echo})

	var found bool
	for _, h := range headers {
		if h.Labels["mcp.direction"] != "server->client" {
			continue
		}
		if h.Labels["mcp.tool"] != "echo" || h.Labels["janus.effect_class"] != "PURE" {
			t.Fatalf("response labels did not inherit the request's classification: %v", h.Labels)
		}
		found = true
	}
	if !found {
		t.Fatal("no server->client event was recorded")
	}
}

// TestInterceptedSessionIsVerifiable closes the loop: the evidence a proxied
// session produces is the same kind of artifact everything else produces.
func TestInterceptedSessionIsVerifiable(t *testing.T) {
	echo, _ := mcp.ToolCall(1, "echo", map[string]any{"text": "hello"})
	_, _, _, dir, signer := session(t, []mcp.Frame{echo})

	rep, err := verify.SegmentDir(dir, verify.Options{
		Keys:    keys.PublicKeySet{signer.KeyID(): signer.Public()},
		Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("evidence from an intercepted session did not verify:\n%s", rep.Text())
	}
	if rep.Events != 2 {
		t.Fatalf("verified %d events, want 2", rep.Events)
	}
}

// TestPayloadIsStoredVerbatim: the bytes in the log must be the bytes that
// crossed the wire, or the log is a paraphrase rather than a record.
func TestPayloadIsStoredVerbatim(t *testing.T) {
	echo, _ := mcp.ToolCall(1, "echo", map[string]any{"text": "verbatim"})
	_, headers, _, dir, _ := session(t, []mcp.Frame{echo})
	_ = headers

	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	insp, err := segment.Inspect(segment.Path(dir, ids[0]))
	if err != nil {
		t.Fatal(err)
	}
	if string(insp.Records[0].Payload) != string(echo.Raw) {
		t.Fatalf("stored payload\n  %s\ndiffers from the bytes sent\n  %s",
			insp.Records[0].Payload, echo.Raw)
	}
}

func textOf(t *testing.T, f mcp.Frame) string {
	t.Helper()
	var env struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(f.Raw, &env); err != nil {
		t.Fatalf("parsing response %s: %v", f.Raw, err)
	}
	if len(env.Result.Content) == 0 {
		t.Fatalf("response has no content: %s", f.Raw)
	}
	return env.Result.Content[0].Text
}

// TestProxyStopsOnContextCancel: a pump spends nearly all its life blocked in a
// read, which no context can interrupt on its own. Before this was fixed the
// proxy ignored a shutdown signal entirely — the process hung, and because the
// evidence log is closed downstream of Run, the open segment was never sealed
// and the next start reported a custody break for a deliberate shutdown.
func TestProxyStopsOnContextCancel(t *testing.T) {
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()

	proxy, err := mcp.NewProxy(mcp.Options{Appender: app, SessionID: "s"})
	if err != nil {
		t.Fatal(err)
	}

	// Pipes that nobody ever writes to or closes, which is what an idle agent
	// and an idle tool server look like.
	agentToProxy, _ := io.Pipe()
	serverToProxy, _ := io.Pipe()
	_, proxyServerWrite := io.Pipe()
	_, proxyAgentWrite := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- proxy.Run(ctx, agentToProxy, proxyAgentWrite, serverToProxy, proxyServerWrite)
	}()

	// Let the pumps settle into their blocking reads, then ask them to stop.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy did not stop when its context was cancelled; " +
			"a signal would hang the process and leave the log unsealed")
	}
}
