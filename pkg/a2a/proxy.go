package a2a

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/mustafarslan/janus/pkg/evidence"
)

// The middleware: standard A2A to both sides, with three things added.
//
//  1. The counterpart is checked against the registry before anything is sent.
//  2. The Janus framing travels with the message, so both sides and the log
//     agree on which saga and step this belongs to.
//  3. What was said is on the record, verbatim, in both directions.
//
// What is deliberately *not* added is a saga. At the tool edge a call is an
// effect and janus-mcpd turns one into a gated step; here a message is a
// message, and manufacturing a transaction two agents did not agree to have
// would put a commitment in the log that neither of them made.

// ProxyOptions configures the middleware.
type ProxyOptions struct {
	// Upstream is the counterpart's A2A endpoint.
	Upstream *url.URL
	// Counterpart and CounterpartVersion are the identity being talked to, and
	// the manifest version pinned for it. Both are required: an unpinned
	// counterpart cannot be checked, and a counterpart that cannot be checked
	// is not talked to.
	Counterpart        string
	CounterpartVersion string
	// Verifier answers whether the counterpart may be talked to. It reads the
	// registry, never the counterpart's card.
	Verifier *Verifier
	// Appender records the messages. This proxy owns its own evidence
	// directory, the way janus-mcpd does, because one process writes an
	// evidence directory.
	Appender *evidence.Appender
	// Self is the identity this proxy records under.
	Self evidence.ParticipantRef
	// Client sends the forwarded request. Injectable so a test can watch what
	// went out.
	Client *http.Client
}

// Proxy is the A2A middleware.
type Proxy struct{ opts ProxyOptions }

// NewProxy builds the middleware.
func NewProxy(opts ProxyOptions) (*Proxy, error) {
	switch {
	case opts.Upstream == nil:
		return nil, fmt.Errorf("a2a: the middleware needs a counterpart endpoint")
	case opts.Counterpart == "" || opts.CounterpartVersion == "":
		return nil, fmt.Errorf("a2a: the counterpart has to be named and pinned; an agent " +
			"whose manifest version is not recorded cannot be resolved at replay time")
	case opts.Verifier == nil:
		return nil, fmt.Errorf("a2a: a verifier is required. Forwarding to a counterpart " +
			"nothing checked is the case this middleware exists to prevent")
	case opts.Appender == nil:
		return nil, fmt.Errorf("a2a: an appender is required; a message that could not be " +
			"recorded is a message that is not sent")
	}
	if opts.Client == nil {
		opts.Client = http.DefaultClient
	}
	return &Proxy{opts: opts}, nil
}

// ServeHTTP forwards one message.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// The check comes before the body is even read. A counterpart the registry
	// will not vouch for is not somebody to start a conversation with, and
	// refusing early means nothing was sent while we made up our minds.
	if _, err := p.opts.Verifier.Verify(p.opts.Counterpart, p.opts.CounterpartVersion); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// And a stream is refused here, before anything is sent, for the same
	// reason the check above happens first.
	if wantsStream(r.Header) {
		http.Error(w, streamRefusal, http.StatusNotImplemented)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading the message: "+err.Error(), http.StatusBadRequest)
		return
	}
	framing := ContextFrom(r.Header)

	// Recorded before it is forwarded, which is evidence-before-effect applied
	// at the agent boundary: a message that could not be recorded is not sent.
	if err := p.record(ctx, "outbound", framing, Context{}, body); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	outbound, err := http.NewRequestWithContext(ctx, r.Method, p.opts.Upstream.String(),
		bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	copyContentHeaders(r.Header, outbound.Header)
	framing.Apply(outbound.Header)

	response, err := p.opts.Client.Do(outbound)
	if err != nil {
		http.Error(w, "the counterpart did not answer: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()

	answer, err := io.ReadAll(response.Body)
	if err != nil {
		http.Error(w, "reading the counterpart's answer: "+err.Error(), http.StatusBadGateway)
		return
	}
	// The reply is recorded too, and before it reaches the agent that asked.
	// Half a conversation is not evidence of a conversation.
	//
	// Filed under the framing of the *request*, not under whatever the
	// counterpart put in its response headers. Janus knows which
	// round trip this is; asking the counterpart is asking a remote party to
	// choose which saga a record in this log belongs to, and it answered
	// wrongly in both directions -- omitting the header left the reply with no
	// saga at all, and returning a different one filed the reply against a saga
	// the counterpart named.
	if err := p.record(ctx, "inbound", framing, ContextFrom(response.Header), answer); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	copyContentHeaders(response.Header, w.Header())
	// The same framing back to the agent that asked, for the same reason: a
	// counterpart's headers are not authoritative about a saga, and forwarding
	// them would hand the local agent a reply framed for work it never began.
	framing.Apply(w.Header())
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(answer)
}

// record appends one message verbatim.
//
// `framing` is what this conversation is called and is always Janus's own;
// `claimed` is what the counterpart said it was called, and is recorded as a
// label rather than used, and only when the two disagree.
func (p *Proxy) record(ctx context.Context, direction string, framing, claimed Context,
	body []byte) error {

	labels := framing.Labels()
	labels["direction"] = direction
	labels["counterpart"] = p.opts.Counterpart
	// A counterpart that echoes a *different* saga id is either misconfigured
	// or trying something, and both are worth a line in the log. Recorded only
	// on a disagreement: when it matches, the label would be noise on every
	// message, and an absent header is not a claim at all.
	if claimed.SagaID != "" && claimed.SagaID != framing.SagaID {
		labels["counterpart_claimed_saga"] = claimed.SagaID
	}
	if _, err := p.opts.Appender.Append(ctx, evidence.Request{
		Kind:        evidence.KindA2AMessage,
		SagaID:      framing.SagaID,
		Participant: p.opts.Self,
		Payload:     body,
		Labels:      labels,
	}); err != nil {
		return fmt.Errorf("refusing to forward an unrecorded message: %w", err)
	}
	return nil
}

// A2A streaming is not intercepted, and a stream asked of this proxy is refused
// rather than quietly turned into something else.
//
// What happened before: `io.ReadAll` on the response buffered the whole stream
// and handed it over in one piece when it ended. A three-event stream 150 ms
// apart arrived after 460 ms, complete and no longer a stream; an A2A task that
// streams progress for a minute arrives after a minute; a channel that stays
// open never arrives at all, and this process holds every byte of it in memory
// while the conversation sits in the log with a question and no answer.
//
// None of that is a recording failure — the bytes that do arrive are recorded
// verbatim. It is a delivery failure that looks like a slow counterpart, which
// is the kind of silence worth turning into an outage somebody notices: the
// honest configuration is to refuse it — point the agent's streaming endpoint
// at nothing rather than around the middleware.
// This proxy is in a position to be that refusal, so it is.
//
// Recording a stream properly needs a framing decision — what one recorded unit
// of an A2A stream is, and what happens to a stream whose counterpart is
// suspended halfway through — and that is not built.
const streamRefusal = "a2a: this middleware does not intercept A2A streaming, and will not " +
	"forward a stream it cannot record as one. Nothing was sent. Buffering it until it ends " +
	"would turn a stream into a hang and an open channel into an unbounded read, so the " +
	"refusal is deliberate. Use request/response through " +
	"this proxy, or point the streaming endpoint at nothing so the gap is visible"

// wantsStream reports whether this request is asking for a server-sent event
// stream.
//
// Read from `Accept` rather than from anything Janus defines: A2A streaming is
// SSE over ordinary HTTP, and a client that wants events says so there. A
// substring match, because an Accept header is a list with q-values and a proxy
// that only recognised the header when it stood alone would forward the very
// case it means to refuse.
//
// **A sufficient signal, not a complete one, and the difference is checked
// rather than assumed.** The A2A specification defines its streaming operations
// as JSON-RPC methods and does not state that a client must send this header;
// what it says about the HTTP binding's headers is in a section that does not
// spell this out. So a streaming call made with a permissive `Accept` is not
// caught here, and is buffered as it was before. Catching it means reading the
// JSON-RPC method out of the body, which makes this proxy body-aware — a change
// the streaming framing decision should make deliberately rather than one this
// refusal smuggles in.
func wantsStream(h http.Header) bool {
	for _, v := range h.Values("Accept") {
		if strings.Contains(strings.ToLower(v), "text/event-stream") {
			return true
		}
	}
	return false
}

// copyContentHeaders carries the headers that describe the body and nothing
// else.
//
// Not a blanket copy. Hop-by-hop headers do not belong to the message, and an
// authorization header forwarded to a counterpart chosen by configuration is a
// credential sent somewhere its owner did not decide to send it.
func copyContentHeaders(from, to http.Header) {
	for _, name := range []string{"Content-Type", "Accept"} {
		if v := from.Get(name); v != "" {
			to.Set(name, v)
		}
	}
}
