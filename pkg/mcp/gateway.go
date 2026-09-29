package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/saga"
)

// The gateway: an effectful tool call becomes a saga, and the tool server is
// only ever reached by the outbox releasing what that saga committed.
//
// One saga per call. That is what "config-only onboarding for an unmodified
// tool server" means: the agent on the other side knows nothing about Janus,
// sends an ordinary MCP request, and everything a saga needs is derived from
// the request and from the participant's manifest. Joining a saga the agent
// already has is the `_janus` metadata convention, and it belongs
// with the JTP v0.9 draft rather than being invented here — designing those
// fields against this one caller would design the spec twice.
//
// The saga id is derived from the session and the request id rather than
// generated. An agent that retries a call whose answer it never saw is not
// starting a second payment, and a derived id is what makes the daemon's
// "already exists" the correct answer instead of a duplicate.
//
// # Why an error rather than a wait
//
// An MCP client is blocked on its call. A gate that escalates to a person may
// take hours, and there is no version of holding the connection open that ends
// well: the agent's own timeout fires, it retries, and the retry looks like a
// second intent. So a held effect answers immediately with an error that says
// what happened and names the saga. The effect is not lost — it is held, the
// person still has it in their queue, and it goes out when they approve it.

// GatewayOptions configures a Gateway.
type GatewayOptions struct {
	Client *orchd.Client
	// SessionID scopes the saga ids this gateway derives.
	SessionID string
	// Participant is the tool server being fronted: the outbox target, the
	// saga step's participant, and the thing whose manifest was resolved.
	Participant     string
	ManifestVersion string
	Principal       string
	// Timeout bounds one call's trip through the saga machinery. It is not the
	// tool server's timeout: it bounds this proxy's own work, so that an agent
	// is never blocked indefinitely by a daemon that stopped answering.
	Timeout time.Duration
}

// Gateway routes tool calls through janus-orchd.
type Gateway struct {
	opts     GatewayOptions
	toServer func(Frame) error
	toClient func(Frame) error

	mu sync.Mutex
	// held maps an effect id to the call that produced it, so the delivery can
	// forward the agent's original bytes rather than a reconstruction of them.
	// What reaches the tool server has to be what the agent sent, or the
	// evidence describes a different call from the one that happened.
	held map[string]Frame
	// compensations maps an action to the inverse its manifest declares, so a
	// compensable call's plan can name one.
	compensations map[string]string
	// sent records that an effect was actually put on the wire to the tool
	// server. A committed saga is not the same as a delivered effect — the
	// target can be down, and then the effect is held and retried — and the
	// difference decides whether anybody is going to answer the agent.
	sent map[string]bool
	// awaiting maps a request id to whoever is waiting for its response.
	awaiting map[string]chan Frame
}

// NewGateway builds a router over an orchestrator client.
func NewGateway(opts GatewayOptions) (*Gateway, error) {
	if opts.Client == nil {
		return nil, fmt.Errorf("mcp: a gateway needs an orchestrator client; without one " +
			"there is nothing to admit a call against and the honest thing is to refuse to start")
	}
	if opts.Participant == "" {
		return nil, fmt.Errorf("mcp: a gateway needs the participant id of the tool server " +
			"it fronts, because that is what the manifest and the outbox target are keyed by")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	return &Gateway{
		opts:          opts,
		held:          map[string]Frame{},
		sent:          map[string]bool{},
		compensations: map[string]string{},
		awaiting:      map[string]chan Frame{},
	}, nil
}

// Attach receives the two directions from the proxy.
func (g *Gateway) Attach(toServer, toClient func(Frame) error) {
	g.toServer, g.toClient = toServer, toClient
}

// Route decides one tool call.
func (g *Gateway) Route(ctx context.Context, f Frame, tool string,
	class janusv1.EffectClass) (Decision, error) {

	if class == janusv1.EffectClass_EFFECT_CLASS_PURE {
		// Straight through, evidenced by the pump that already recorded it.
		// A PURE call changes nothing, so there is nothing to hold and nothing
		// a gate could usefully decide about it.
		return Decision{Action: ActionForward}, nil
	}
	// A notification — a request with no id — cannot be answered, so it cannot
	// be refused either. Forwarding an effectful one would be worse: it is the
	// one shape where the agent cannot be told what happened. Refuse loudly by
	// declining to forward, and record that it was declined.
	if len(f.ID) == 0 {
		return Decision{Action: ActionWithhold}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, g.opts.Timeout)
	defer cancel()

	sagaID := g.SagaID(f)
	const stepID = "call"

	// The manifest says how this action is taken back, and the plan has to say
	// so too: gate admission refuses a COMPENSABLE step that names no inverse,
	// and it is right to — a class that promises the effect can be reversed,
	// with nothing named to reverse it, is a promise with nothing behind it.
	// The proxy is the only party that knows both, so it is the one that has to
	// carry it across.
	compensation, err := g.compensationFor(ctx, tool)
	if err != nil {
		return g.refuse(f, CodeRefused, fmt.Sprintf(
			"janus could not resolve what %s does: %v", tool, err))
	}

	if _, err := g.opts.Client.BeginSaga(ctx,
		g.plan(sagaID, stepID, tool, class, compensation)); err != nil {
		// AlreadyExists is the ordinary case for a retried call, and the saga
		// it names is the one to look at rather than a new one to start.
		if !isAlreadyExists(err) {
			return g.refuse(f, CodeRefused, fmt.Sprintf(
				"janus refused this call at admission: %v", err))
		}
	}

	prep, err := g.opts.Client.PrepareStep(ctx, sagaID, stepID, factsOf(f), nil)
	if err != nil {
		return g.refuse(f, CodeRefused, fmt.Sprintf("janus could not prepare this call: %v", err))
	}
	switch prep.GetStatus() {
	case janusv1.PrepareStatus_PREPARE_STATUS_PREPARED:
	case janusv1.PrepareStatus_PREPARE_STATUS_GATED:
		return g.refuse(f, CodeHeld, fmt.Sprintf(
			"janus is holding this call for a decision: %s (saga %s)", prep.GetReason(), sagaID))
	default:
		return g.refuse(f, CodeRefused, fmt.Sprintf(
			"janus will not run this call: %s (saga %s)", prep.GetReason(), sagaID))
	}

	// The effect is captured before the step reports, and the frame is stored
	// against it so the delivery forwards the agent's own bytes.
	effectID := sagaID + ":" + stepID
	g.remember(effectID, f)
	if _, err := g.opts.Client.HoldEffect(ctx, &janusv1.EffectHeld{
		EffectId: effectID, SagaId: sagaID, StepId: stepID,
		Target: g.opts.Participant, Action: tool,
		IdemKey:     effectID,
		EffectClass: class,
	}); err != nil {
		return g.refuse(f, CodeRefused, fmt.Sprintf("janus could not hold this call: %v", err))
	}

	// Reporting the step is what lets the saga proceed to its gates and, if
	// they pass, to commit — at which point the daemon releases the effect,
	// which is what actually calls the tool server.
	if _, err := g.opts.Client.CompleteStep(ctx, &janusv1.StepResult{
		SagaId: sagaID, StepId: stepID, Attempt: prep.GetAttempt(),
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	}); err != nil {
		return g.refuse(f, CodeRefused, fmt.Sprintf("janus could not record this call: %v", err))
	}

	state, err := g.opts.Client.GetSaga(ctx, sagaID)
	if err != nil {
		return g.refuse(f, CodeRefused, fmt.Sprintf("janus lost track of saga %s: %v", sagaID, err))
	}
	switch state.GetStatus() {
	case janusv1.SagaState_SAGA_STATE_COMMITTED:
		// The release runs synchronously inside CompleteStep, so by now the
		// effect has either been forwarded or it has not.
		//
		// Committed is not the same as delivered, and the difference is the
		// difference between an agent that gets an answer and one that waits
		// forever. A target that was down leaves the effect held and
		// retryable; the saga is still committed, the effect will still go out,
		// and the only thing that is certain is that nothing is coming back on
		// this connection. So say so.
		if !g.wasSent(effectID) {
			return g.refuse(f, CodeHeld, fmt.Sprintf(
				"janus committed saga %s but the call has not reached the tool server "+
					"yet; it stays held and will be retried", sagaID))
		}
		// Forwarded: the tool server's answer is on its way back to the agent
		// through the ordinary path. Nothing more to do.
		return Decision{Action: ActionWithhold}, nil
	case janusv1.SagaState_SAGA_STATE_GATED:
		return g.refuse(f, CodeHeld, fmt.Sprintf(
			"janus is holding this call for a decision (saga %s); it will be sent if it "+
				"is approved", sagaID))
	default:
		return g.refuse(f, CodeRefused, fmt.Sprintf(
			"janus refused this call: the saga is %s (saga %s)", state.GetStatus(), sagaID))
	}
}

// Deliver is what the outbox calls, over the delivery stream, once the saga has
// committed. This is the only path on which an effectful call reaches the tool
// server.
func (g *Gateway) Deliver(ctx context.Context, e outbox.Effect) (outbox.Receipt, error) {
	g.mu.Lock()
	f, ok := g.held[e.ID]
	g.mu.Unlock()
	if !ok {
		// The call was made by a process that is no longer here — this proxy
		// restarted while the effect was held. The agent's connection is gone
		// with it, so there is nobody to hand the answer to and nothing this
		// process can honestly do. Retryable: another proxy holding the same
		// session can complete it.
		return outbox.Receipt{Retryable: true}, fmt.Errorf(
			"effect %q was held by a proxy session that is no longer running", e.ID)
	}

	reply := g.await(IDKey(f.ID))
	defer g.forget(IDKey(f.ID))

	if err := g.toServer(f); err != nil {
		return outbox.Receipt{Retryable: true}, fmt.Errorf("forwarding to the tool server: %w", err)
	}
	// Recorded once it is on the wire rather than once it is answered: from
	// here the agent will get the tool server's response through the ordinary
	// path, and this proxy must not also answer it.
	g.markSent(e.ID)
	select {
	case resp := <-reply:
		if resp.IsErr {
			// The tool server was reached and said no. That is not a delivery
			// failure — the effect happened, in the sense that the target
			// considered it and declined — so it is reported as a
			// non-retryable receipt rather than as an error to try again.
			return outbox.Receipt{
				Ref: IDKey(f.ID), Retryable: false,
				Message: "the tool server returned an error",
			}, nil
		}
		return outbox.Receipt{Ref: IDKey(f.ID)}, nil
	case <-ctx.Done():
		return outbox.Receipt{Retryable: true}, fmt.Errorf(
			"the tool server did not answer call %s", IDKey(f.ID))
	}
}

// Observe watches the responses coming back so a delivery can tell when the
// call it forwarded has been answered.
func (g *Gateway) Observe(f Frame) {
	if !f.IsResp || len(f.ID) == 0 {
		return
	}
	g.mu.Lock()
	ch, ok := g.awaiting[IDKey(f.ID)]
	g.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- f:
	default:
	}
}

// ---- internals -------------------------------------------------------------

// SagaID names the saga a tool call becomes. It is the Router half of the join
// the proxy stamps.
func (g *Gateway) SagaID(f Frame) string {
	return SagaIDFor(g.opts.SessionID, f.ID)
}

// SagaIDFor is the saga a tool call in this session becomes.
//
// Exported because it is the join between the two logs an interception
// deployment keeps: the proxy records every message into its own evidence
// directory and the sagas live in the one `janus-orchd` owns. The rule used to be an unexported function and a sentence in a
// backlog entry, which is not a join an auditor can perform.
//
// The encoding is **injective**, and that is the whole point. It used to
// map every character outside `[A-Za-z0-9_-]` to `_`, so two distinct JSON-RPC
// request ids in one session -- `"a/b"` and `"a.b"` -- produced one saga id.
// The second call was then refused by the saga state machine with "step is
// COMMITTED and the saga is COMMITTED", which names no cause an agent can act
// on, and the log held one saga for two requests.
//
// `_` is escaped along with everything else, because it is the escape character:
// left literal, an id that already contains the text `_2f` would encode exactly
// as one containing `/`. Digits, letters and `-` pass through, so an integer id
// -- the common case -- still reads as itself: request `1` in session `s1` is
// `sg_s1_1`.
//
// **The session id is not encoded**, because it is fixed for the life of a
// gateway and is not attacker-chosen the way a request id is. Two sessions
// therefore cannot collide with each other, and within one session the request
// ids cannot collide -- which is the whole of what uniqueness requires. What it
// does cost is that a session id containing `_` (the default is
// `mcp_<suffix>`) leaves no way to see by eye where the session ends and the
// request begins. An auditor with the session in hand strips the prefix; one
// without it cannot split the string, and should call this function with a
// candidate session rather than guess.
func SagaIDFor(sessionID string, id json.RawMessage) string {
	return "sg_" + sessionID + "_" + sanitise(IDKey(id))
}

// compensationFor asks the registry what inverse the manifest declares.
//
// Cached per action for the life of this proxy session: a manifest version is
// immutable, so what version 1.0.0 says an action does cannot change
// while a session runs. What *can* change is which version is active, and that
// is not what this is reading — the pin is fixed for the session too.
func (g *Gateway) compensationFor(ctx context.Context, tool string) (string, error) {
	g.mu.Lock()
	if known, ok := g.compensations[tool]; ok {
		g.mu.Unlock()
		return known, nil
	}
	g.mu.Unlock()

	resolved, err := g.opts.Client.ResolveParticipant(ctx, g.opts.Participant,
		g.opts.ManifestVersion)
	if err != nil {
		return "", err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, action := range resolved.GetActions() {
		g.compensations[action.GetName()] = action.GetCompensationAction()
	}
	return g.compensations[tool], nil
}

func (g *Gateway) plan(sagaID, stepID, tool string, class janusv1.EffectClass,
	compensation string) *janusv1.SagaBegin {
	return &janusv1.SagaBegin{
		SagaId: sagaID,
		Mode:   "supervised",
		Intent: &janusv1.Intent{
			IntentId:   "in_" + sagaID,
			Principal:  g.opts.Principal,
			Originator: "mcp:" + g.opts.SessionID,
			MandateRef: "mandate:" + g.opts.Participant,
			Scope:      tool,
		},
		Plan: []*janusv1.PlannedStep{{
			StepId: stepID, Participant: g.opts.Participant, Action: tool,
			EffectClass: class, CompensationAction: compensation,
		}},
		ManifestPins: map[string]string{g.opts.Participant: g.opts.ManifestVersion},
	}
}

func (g *Gateway) refuse(f Frame, code int, message string) (Decision, error) {
	reply, err := ErrorFrame(f.ID, code, message)
	if err != nil {
		return Decision{}, err
	}
	return Decision{Action: ActionReply, Reply: reply}, nil
}

func (g *Gateway) remember(effectID string, f Frame) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.held[effectID] = f
}

func (g *Gateway) markSent(effectID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sent[effectID] = true
}

func (g *Gateway) wasSent(effectID string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sent[effectID]
}

func (g *Gateway) await(idKey string) chan Frame {
	ch := make(chan Frame, 1)
	g.mu.Lock()
	defer g.mu.Unlock()
	g.awaiting[idKey] = ch
	return ch
}

func (g *Gateway) forget(idKey string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.awaiting, idKey)
}

// factsOf turns a tool call's arguments into the facts its gates decide on.
//
// This is where the schema and risk-limit gates stop being theoretical: the
// amount a policy compares against is the amount in the arguments the agent
// actually sent, bound into the prepare record. An agent cannot declare one
// number to Janus and send another, because there is only one number.
//
// Only scalars are carried. A gate expression compares numbers, text and flags;
// a nested object has no comparison a policy could make of it, and flattening
// one into dotted keys would invent a naming convention the policy language
// does not have.
func factsOf(f Frame) []*janusv1.Fact {
	var params struct {
		Arguments map[string]json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(f.Params, &params); err != nil {
		return nil
	}
	out := make(map[string]saga.FactValue, len(params.Arguments))
	for k, raw := range params.Arguments {
		var asNumber json.Number
		if err := json.Unmarshal(raw, &asNumber); err == nil {
			if n, err := asNumber.Int64(); err == nil {
				out[k] = gate.Number(n)
				continue
			}
		}
		var asText string
		if err := json.Unmarshal(raw, &asText); err == nil {
			out[k] = gate.Text(asText)
			continue
		}
		var asFlag bool
		if err := json.Unmarshal(raw, &asFlag); err == nil {
			out[k] = gate.Flag(asFlag)
		}
	}
	return saga.FactsToProto(out)
}

// sanitise encodes a JSON-RPC request id into the character set a saga id may
// use, without ever mapping two ids onto one.
//
// Bytes rather than runes, so that a multi-byte character encodes to a fixed
// sequence of escapes and two different characters cannot share one. The
// previous version walked runes and replaced anything unusual with `_`, which
// is how `"a/b"` and `"a.b"` became the same saga.
func sanitise(s string) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			out = append(out, c)
		default:
			// `_` is escaped along with everything else, because it is the
			// escape character: left literal, an id that already contains the
			// text `_2f` would encode exactly as one containing `/`, and the
			// collision is back by a different door. Escaping the escape is
			// what makes the encoding injective rather than merely lossy in
			// fewer places.
			out = append(out, '_', hex[c>>4], hex[c&0x0f])
		}
	}
	return string(out)
}

func isAlreadyExists(err error) bool {
	return err != nil && containsText(err.Error(), "already exists")
}

func containsText(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
