package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// Acting on the classification, not merely recording it.
//
// Phase 0 gave this proxy the ability to say what a tool call does: it resolves
// the participant's manifest and classifies each action. Until now it did
// nothing with the answer — every message was recorded and forwarded, and the
// classification was a label on the evidence.
//
// GA means the classification decides. A PURE call goes straight through and is
// evidenced as it always was. An effectful call does not go through at all
// until a saga has been admitted, gated and committed for it, and what finally
// reaches the tool server is the outbox releasing a held effect. A refusal
// comes back to the agent as a JSON-RPC error it can read.
//
// The seam is one interface so that the proxy keeps working without it. A Proxy
// with no Router is exactly the Phase 0 proxy, which is what the MCP spike and
// its tests still exercise — and it is also the honest fallback for a tool
// server nobody has registered anything about.

// Action is what the router decided about one tool call.
type Action int

const (
	// ActionForward sends the call on unchanged. This is a PURE call, or a
	// message that is not a tool call at all.
	ActionForward Action = iota
	// ActionWithhold means the call is now the router's: it does not reach the
	// tool server on this path, and the router will forward it later if the
	// saga it belongs to commits. The agent is waiting, so something must
	// eventually answer.
	ActionWithhold
	// ActionReply means answer the agent now, without the tool server being
	// asked at all. A refusal, or a gate that escalated to a person.
	ActionReply
)

// Decision is a routing outcome.
type Decision struct {
	Action Action
	// Reply is the frame to send back to the agent, for ActionReply.
	Reply Frame
}

// Router decides what happens to an intercepted tool call.
type Router interface {
	// Attach supplies the two directions the router may write in. Both are
	// serialised by the proxy: a router forwarding a released effect and a pump
	// forwarding an ordinary message must not interleave on one stream.
	Attach(toServer, toClient func(Frame) error)
	// Route decides one tool call.
	Route(ctx context.Context, f Frame, tool string, class janusv1.EffectClass) (Decision, error)
	// Observe is called for every message coming back from the tool server, so
	// a router waiting on the response to a call it forwarded can recognise it.
	// The proxy forwards the message to the agent regardless.
	Observe(f Frame)
	// SagaID names the saga this tool call becomes, so the proxy can stamp it
	// onto the message record before forwarding.
	//
	// Asked of the router rather than derived by the proxy, and that is the
	// point. Both hold a session id and nothing requires the two to be equal --
	// the gateway tests set them differently today -- so a proxy computing the
	// join key itself would stamp a saga id that does not exist. The router is
	// the half that begins the saga, so it is the half that gets to say what it
	// is called.
	//
	// Called before the record is appended, because the proxy records first and
	// acts second: a label derived from the router's answer to a call
	// it has already routed would be a label on a message that may not have
	// been recorded.
	SagaID(f Frame) string
}

// serialWriter makes a Writer safe for the two goroutines that share it.
//
// The proxy has always had one writer per direction and one goroutine per
// direction. A router breaks that: it forwards a withheld call from whatever
// goroutine the release arrived on, while the pump may be forwarding an
// unrelated message. Two interleaved writes on a stdio stream produce a frame
// neither side can parse.
type serialWriter struct {
	mu sync.Mutex
	w  *Writer
}

func (s *serialWriter) Write(f Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(f)
}

// ErrorFrame builds a JSON-RPC error response to a request.
//
// The message is written for whoever reads it next, which for an agent is a
// model and for an operator is a log line at three in the morning. It says what
// was refused and why, because "internal error" tells an agent nothing it can
// act on and tells a person nothing they can escalate.
func ErrorFrame(id json.RawMessage, code int, message string) (Frame, error) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	raw, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   any             `json:"error"`
	}{
		JSONRPC: "2.0", ID: id,
		Error: map[string]any{"code": code, "message": message},
	})
	if err != nil {
		return Frame{}, fmt.Errorf("building an error response: %w", err)
	}
	return Frame{Raw: raw, ID: id, IsResp: true, IsErr: true}, nil
}

// JSON-RPC error codes this proxy returns.
//
// Both are in the implementation-defined server range. They are distinct
// because an agent should retry neither, but a person triaging them does
// entirely different things: a refusal is a policy question and a held effect
// is a queue somebody has to work.
const (
	// CodeRefused means a gate would not let this effect through. It is final:
	// the saga that would have carried it is not going to commit.
	CodeRefused = -32001
	// CodeHeld means the call was accepted and is waiting for a decision that
	// has not been made yet — typically a person. It is not an error in the
	// sense of something having gone wrong, and it is returned as one because
	// the agent is blocked on a synchronous call and cannot be left holding it.
	CodeHeld = -32002
)
