package mcp_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/mcp"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/saga"
)

// wireCall builds a tools/call frame with an arbitrary JSON-RPC id, which the
// integer-only helpers cannot: the ids that collide are strings, and the MCP
// spec permits them.
func wireCall(rawID string) mcp.Frame {
	params := `{"name":"wire.send","arguments":{"account":"a","amount":1,"amount_minor":100}}`
	raw := `{"jsonrpc":"2.0","id":` + rawID + `,"method":"tools/call","params":` + params + `}`
	return mcp.Frame{
		Raw: json.RawMessage(raw), ID: json.RawMessage(rawID),
		Method: mcp.MethodToolsCall, Params: json.RawMessage(params),
	}
}

// Two tool calls whose request ids differ only outside [A-Za-z0-9-] are two
// sagas.
//
// They used to be one. Every character outside the allowed set became `_`, so
// `"a/b"` and `"a.b"` both produced `sg_s1__a_b_` — and the log held one saga
// for two distinct requests. The second call was refused by the saga state
// machine with "step is COMMITTED and the saga is COMMITTED", which names no
// cause an agent can act on and reads as a bug in Janus rather than as a
// collision.
//
// It failed closed, which is why this is a defect and not an incident: the
// second effect never reached the tool server. What it cost was a legitimate
// call, and the unambiguity of the log.
func TestTwoRequestIdsThatDifferAreTwoSagas(t *testing.T) {
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

	responses := runProxy(t, dir, gw, []mcp.Frame{wireCall(`"a/b"`), wireCall(`"a.b"`)})
	for i, r := range responses {
		if r.IsErr {
			t.Fatalf("call %d was refused: %s", i, r.Raw)
		}
	}

	states, err := saga.ReplayAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 {
		t.Fatalf("two distinct tool calls produced %d saga(s): %v", len(states), sagaIDs(states))
	}
}

// The encoding never maps two request ids onto one, `_` included.
//
// `_` is the case an escape scheme gets wrong: left literal, `"a_b"` and
// `"a/b"` both encode to `_a_b_` and the collision is back by a different door.
// And an integer id still reads as itself, because that is the common case and
// a join nobody can read by eye is most of the problem.
func TestTheSagaIDEncodingIsInjective(t *testing.T) {
	// `"a_2fb"` against `"a/b"` is the pair that discriminates, and it is the
	// one an escape scheme gets wrong: `_` is the escape character, so an id
	// that already contains the text `_2f` encodes exactly as one containing
	// `/` unless `_` is escaped too.
	ids := []string{
		`1`, `2`, `"1"`, `"a/b"`, `"a.b"`, `"a_b"`, `"a-b"`, `"a b"`, `""`, `"é"`,
		`"a_2fb"`, `"a_5fb"`,
	}
	seen := map[string]string{}
	for _, id := range ids {
		got := mcp.SagaIDFor("s1", json.RawMessage(id))
		if prev, clash := seen[got]; clash {
			t.Fatalf("request ids %s and %s both produce %q", prev, id, got)
		}
		seen[got] = id
	}
	// The other half of "injective": the session is part of the key. A refactor
	// that dropped it would pass every assertion above.
	if mcp.SagaIDFor("s1", json.RawMessage(`1`)) == mcp.SagaIDFor("s2", json.RawMessage(`1`)) {
		t.Fatal("the same request id in two sessions produces one saga id")
	}
	if got := mcp.SagaIDFor("s1", json.RawMessage(`1`)); got != "sg_s1_1" {
		t.Fatalf("an integer request id encodes to %q; the common case has to stay "+
			"readable or the join is a computation rather than a look", got)
	}
}

// The proxy's own record carries the saga id, so the join is a field and not a
// derivation.
//
// This is the actual problem. The two logs were joined by a rule living
// in an unexported function and a sentence in the backlog — and the sentence was
// wrong for every string request id, because the label carries the raw JSON
// including its quotes. `"req-7"` in the proxy log became `sg_s1__22req-7_22`
// in the daemon's, which nobody guesses.
//
// Asked of the router rather than derived from the proxy's own session: the two
// hold separate session ids and nothing makes them equal — the fixtures here set
// them differently — so a proxy computing the key itself would stamp a saga that
// does not exist.
func TestTheProxyRecordCarriesTheSagaItsCallBecame(t *testing.T) {
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

	_, proxyDir := runProxyRecording(t, dir, gw, []mcp.Frame{wireCall(`"req-7"`)})
	headers := readHeaders(t, proxyDir)

	states, err := saga.ReplayAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 {
		t.Fatalf("one tool call produced %d saga(s)", len(states))
	}
	var want string
	for id := range states {
		want = id
	}

	var stamped int
	for _, h := range headers {
		got, ok := h.Labels["janus.saga_id"]
		if !ok {
			continue
		}
		stamped++
		if got != want {
			t.Fatalf("the proxy stamped saga %q and the daemon began %q; a join key that "+
				"names no saga is worse than no join key", got, want)
		}
	}
	// The call and its response, so a result is attributable without joining
	// two records first.
	if stamped != 2 {
		t.Fatalf("%d record(s) carry the join key, want 2 (the call and its response)", stamped)
	}
}

func sagaIDs(states map[string]saga.State) []string {
	out := make([]string, 0, len(states))
	for id := range states {
		out = append(out, id)
	}
	return out
}
