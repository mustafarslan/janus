package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/mcp"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/registry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const (
	toolParticipant = "tool_toybox"
	toolPrincipal   = "pr_bank"
)

// TestTheGatewayRefusesOneCallAndReleasesAnother is the Phase 4b exit gate.
//
// One tool server, unmodified — it is the same EchoServer the Phase 0 spike
// used, and it knows nothing about any of this. Three calls go through the
// proxy in front of it:
//
//   - a PURE call, which is forwarded and evidenced exactly as before;
//   - an effectful call within the policy's limit, which becomes a saga, is
//     gated, commits, and reaches the tool server only because the outbox
//     released it;
//   - an effectful call over the limit, which never reaches the tool server at
//     all and comes back to the agent as an error it can read.
//
// The last one is the claim that matters. The agent asked; the tool server was
// never told; and the reason is in the log rather than in this proxy's memory.
func TestTheGatewayRefusesOneCallAndReleasesAnother(t *testing.T) {
	dir, srv := newOrchd(t)
	conn := dialOrchd(t, srv)
	client := orchd.NewClient(conn)

	gw, err := mcp.NewGateway(mcp.GatewayOptions{
		Client: client, SessionID: "s1", Participant: toolParticipant,
		ManifestVersion: "1.0.0", Principal: toolPrincipal, Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	serveDelivery(t, client, gw)

	responses := runProxy(t, dir, gw, []mcp.Frame{
		mustCall(t, 1, "echo", map[string]any{"text": "hello"}),
		mustCall(t, 2, "wire.send", map[string]any{
			"account": "acct-1", "amount": 12, "amount_minor": 5000,
		}),
		mustCall(t, 3, "wire.send", map[string]any{
			"account": "acct-2", "amount": 9000, "amount_minor": 900000,
		}),
	})

	if responses[0].IsErr {
		t.Fatalf("the PURE call was refused; a call that changes nothing has nothing to " +
			"gate and must pass straight through")
	}
	if responses[1].IsErr {
		t.Fatalf("the permitted effectful call was refused: %s", responses[1].Raw)
	}
	if !responses[2].IsErr {
		t.Fatal("the over-limit call was answered by the tool server; the gate that " +
			"exists to stop it did not")
	}
	if code := errorCode(t, responses[2]); code != mcp.CodeRefused {
		t.Fatalf("the refusal came back as code %d, want %d — an agent has to be able "+
			"to tell a refusal from a transport failure", code, mcp.CodeRefused)
	}

	// The claim is about the log, not about what this test observed in flight.
	state, err := outbox.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var delivered, held int
	for _, id := range state.Order {
		switch state.Effects[id].State {
		case outbox.StateDelivered:
			delivered++
		case outbox.StateHeld:
			held++
		}
	}
	if delivered != 1 {
		t.Fatalf("the log records %d delivered effects, want exactly 1 — the permitted "+
			"call and nothing else", delivered)
	}
	if held != 1 {
		t.Fatalf("the log records %d effects still held, want exactly 1 — the refused "+
			"call, captured and going nowhere", held)
	}
}

// ---- harness ---------------------------------------------------------------

func runProxy(t *testing.T, dir string, gw *mcp.Gateway, requests []mcp.Frame) []mcp.Frame {
	t.Helper()
	out, _ := runProxyRecording(t, dir, gw, requests)
	return out
}

// runProxyRecording is runProxy, and also hands back the proxy's own evidence
// directory — the second of the two logs the join is about.
func runProxyRecording(t *testing.T, dir string, gw *mcp.Gateway,
	requests []mcp.Frame) ([]mcp.Frame, string) {

	t.Helper()

	// A second appender on the same directory is refused, so the proxy's own
	// evidence goes to a directory of its own. In a deployment the proxy is a
	// client of the daemon and this is the session log beside it.
	proxyDir := filepath.Join(t.TempDir(), "mcp")
	app, err := evidence.Open(evidence.Options{
		Dir: proxyDir, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := mcp.NewProxy(mcp.Options{
		Appender:  app,
		SessionID: "mcp_session_ga",
		Classifier: mcp.StaticClassifier{
			"echo":      janusv1.EffectClass_EFFECT_CLASS_PURE,
			"wire.send": janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		},
		Participant: evidence.ParticipantRef{
			ID: toolParticipant, ManifestVersion: "1.0.0", Kind: "TOOL",
		},
		Router: gw,
	})
	if err != nil {
		t.Fatal(err)
	}

	agentToProxy, agentWrite := io.Pipe()
	proxyToServer, proxyServerWrite := io.Pipe()
	serverToProxy, serverWrite := io.Pipe()
	proxyToAgent, proxyAgentWrite := io.Pipe()

	go func() {
		srv := &mcp.EchoServer{ServerName: "toybox"}
		_ = srv.Serve(proxyToServer, serverWrite)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = proxy.Run(ctx, agentToProxy, proxyAgentWrite, serverToProxy, proxyServerWrite)
	}()
	go func() {
		w := mcp.NewWriter(agentWrite)
		for _, f := range requests {
			if err := w.Write(f); err != nil {
				return
			}
		}
	}()

	// Responses can arrive out of order: a refusal is answered by this proxy
	// immediately, while a permitted call waits for a saga to commit. So they
	// are matched by request id rather than by position.
	// Read with a deadline. Every call this proxy accepts has to be answered by
	// somebody — the tool server, or the proxy itself — and a bug that answers
	// none of them would otherwise hang this test rather than fail it. A test
	// that hangs on a regression is barely better than one that passes on it.
	byID := map[string]mcp.Frame{}
	frames := make(chan mcp.Frame, len(requests))
	go func() {
		reader := mcp.NewReader(proxyToAgent)
		for {
			f, err := reader.Next()
			if err != nil {
				return
			}
			frames <- f
		}
	}()
	for range requests {
		select {
		case f := <-frames:
			byID[mcp.IDKey(f.ID)] = f
		case <-time.After(30 * time.Second):
			t.Fatalf("only %d of %d calls were ever answered; an agent is blocked on a "+
				"synchronous call, so every one of them must come back with something",
				len(byID), len(requests))
		}
	}
	out := make([]mcp.Frame, 0, len(requests))
	for _, req := range requests {
		f, ok := byID[mcp.IDKey(req.ID)]
		if !ok {
			t.Fatalf("no response for request %s", mcp.IDKey(req.ID))
		}
		out = append(out, f)
	}
	// Closed before the caller reads it: a segment still being written has a
	// tail a reader is entitled to refuse.
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return out, proxyDir
}

// serveDelivery connects the gateway to the daemon as the deliverer for its
// tool server, which is the only path an effectful call can take to reach it.
func serveDelivery(t *testing.T, client *orchd.Client, gw *mcp.Gateway) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stream, err := client.DeliverEffects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&janusv1.DeliverEffectsRequest{
		Message: &janusv1.DeliverEffectsRequest_Register{
			Register: &janusv1.DelivererRegistration{Targets: []string{toolParticipant}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			r, derr := gw.Deliver(ctx, outbox.Effect{
				ID: msg.GetEffectId(), SagaID: msg.GetSagaId(), StepID: msg.GetStepId(),
				Target: msg.GetTarget(), Action: msg.GetAction(), IdemKey: msg.GetIdemKey(),
			})
			receipt := &janusv1.DeliveryReceipt{EffectId: msg.GetEffectId()}
			if derr != nil {
				receipt.Error, receipt.Retryable = derr.Error(), r.Retryable
			} else {
				receipt.Ref, receipt.Duplicate = r.Ref, r.Duplicate
			}
			_ = stream.Send(&janusv1.DeliverEffectsRequest{
				Message: &janusv1.DeliverEffectsRequest_Receipt{Receipt: receipt},
			})
		}
	}()
}

func newOrchd(t *testing.T) (string, *orchd.Server) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerToolManifest(t, dir, signer)

	// One rule, one threshold, decided PRE_RELEASE. The phase is not a detail:
	// gate admission refuses a plan whose irreversible step has nothing judging
	// it before release, because the effect the outbox holds is the one the
	// step produced and a check that ran earlier has not seen it.
	p := &gate.Policy{
		ID: "mcp.ga.test",
		Rules: []gate.Rule{{
			ID:    "capped-wires",
			Match: gate.Match{EffectClasses: []string{"IRREVERSIBLE_GATED"}},
			Require: []gate.Requirement{{
				ID: "wire-limit", Gate: gate.GateRiskLimit, Phase: gate.PhasePreRelease,
				RiskLimit: &gate.RiskLimitSpec{
					Thresholds: []gate.Threshold{{Fact: "amount_minor", Max: 10000}},
				},
			}},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: p,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: toolPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return dir, s
}

func registerToolManifest(t *testing.T, dir string, signer *keys.Signer) {
	t.Helper()
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	trust := registry.TrustStore{}
	trust.Trust(toolPrincipal, signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_registry", Principal: toolPrincipal, Kind: "SYSTEM",
	}, registry.New(), trust)

	m := &registry.Manifest{
		Version: "1.0.0",
		Identity: registry.Identity{
			ParticipantID: toolParticipant, Kind: "TOOL", Principal: toolPrincipal,
		},
		Runtime: registry.Runtime{ModelID: "none", PromptBundleHash: "blake3:toybox"},
		Actions: []registry.Action{
			{Name: "echo", EffectClass: "PURE"},
			{
				Name: "wire.send", EffectClass: "IRREVERSIBLE_GATED",
				Idempotency: &registry.Idempotency{KeyRecipe: "saga_id,step_id"},
			},
		},
		Risk: registry.Risk{
			Tier:                 2,
			RevalidationTriggers: []string{registry.TriggerModelChange, registry.TriggerActionChange},
		},
		Jurisdiction: registry.Jurisdiction{DeployableIn: []string{"EU"}, DataResidency: "EU"},
	}
	sig, err := registry.Sign(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := rec.Register(ctx, m, sig); err != nil {
		t.Fatal(err)
	}
	doubles := registry.NewDoubles("toybox-sandbox").
		With("echo", registry.Double{}).
		With("wire.send", registry.Double{Deltas: map[string]int64{"ledger": -1}})
	rep, err := registry.Evaluate(ctx, m, doubles)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.GetPassed() {
		t.Fatalf("the tool manifest fails its own conformance:\n%s", registry.ReportText(rep))
	}
	if err := rec.Evaluate(ctx, toolParticipant, "1.0.0", rep); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, toolParticipant, "1.0.0"); err != nil {
		t.Fatal(err)
	}
}

func dialOrchd(t *testing.T, s *orchd.Server) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	janusv1.RegisterOrchestratorServiceServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(); srv.Stop() })
	return conn
}

func mustCall(t *testing.T, id int, tool string, args any) mcp.Frame {
	t.Helper()
	f, err := mcp.ToolCall(id, tool, args)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func errorCode(t *testing.T, f mcp.Frame) int {
	t.Helper()
	var env struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(f.Raw, &env); err != nil {
		t.Fatalf("the refusal is not a readable JSON-RPC error: %v", err)
	}
	if env.Error.Message == "" {
		t.Fatal("the refusal carries no message; an agent is told it failed and not why")
	}
	return env.Error.Code
}

// TestAnAgentIsAnsweredEvenWhenTheCallCouldNotBeSent is the case that turns a
// bug into a hang instead of a failure, which is why it has its own test.
//
// A saga can commit and its effect still not go out: the target may be down, or
// — as here — nothing may be connected that can reach it. The effect is held
// and will be retried, and that is correct. What is not correct is leaving the
// agent blocked on a synchronous call waiting for a response that is never
// coming, because a committed saga was mistaken for a delivered effect.
func TestAnAgentIsAnsweredEvenWhenTheCallCouldNotBeSent(t *testing.T) {
	dir, srv := newOrchd(t)
	client := orchd.NewClient(dialOrchd(t, srv))

	gw, err := mcp.NewGateway(mcp.GatewayOptions{
		Client: client, SessionID: "s2", Participant: toolParticipant,
		ManifestVersion: "1.0.0", Principal: toolPrincipal, Timeout: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately no deliverer: nothing here can reach the tool server for an
	// effectful call, which is what a proxy sees when the process that serves
	// that target is not connected.

	responses := runProxy(t, dir, gw, []mcp.Frame{
		mustCall(t, 1, "wire.send", map[string]any{
			"account": "acct-1", "amount": 12, "amount_minor": 5000,
		}),
	})

	if !responses[0].IsErr {
		t.Fatal("the agent was told the call succeeded, but nothing was ever sent to " +
			"the tool server")
	}
	if code := errorCode(t, responses[0]); code != mcp.CodeHeld {
		t.Fatalf("the answer came back as code %d, want %d — the call is held and will "+
			"be retried, which is a different thing from having been refused",
			code, mcp.CodeHeld)
	}

	state, err := outbox.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range state.Order {
		if e := state.Effects[id]; e.State != outbox.StateHeld {
			t.Fatalf("effect %q is %s, want HELD: with nothing able to deliver it, the "+
				"effect must still be waiting", id, e.State)
		}
	}
}
