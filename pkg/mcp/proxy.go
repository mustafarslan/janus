package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
)

// Classifier decides the effect class of a tool invocation.
//
// In the finished system this reads the participant's signed manifest from
// janus-registry: the tool server itself declares what each action does
// to the world and how it can be undone, and those claims are checked by
// conformance tests at registration. Phase 0 uses a static table so the
// interception path can be exercised before the registry exists.
type Classifier interface {
	Classify(tool string) (janusv1.EffectClass, bool)
}

// StaticClassifier maps tool names to effect classes.
type StaticClassifier map[string]janusv1.EffectClass

// Classify implements Classifier.
func (s StaticClassifier) Classify(tool string) (janusv1.EffectClass, bool) {
	c, ok := s[tool]
	return c, ok
}

// Options configures a Proxy.
type Options struct {
	// Appender receives an event for every message in both directions.
	Appender *evidence.Appender
	// Classifier resolves tool names to effect classes.
	Classifier Classifier
	// DefaultEffectClass applies to a tool the classifier does not know.
	//
	// It defaults to IRREVERSIBLE_GATED, which is the fail-closed choice: an
	// unregistered tool is assumed to change the world irreversibly until it
	// proves otherwise. Phase 0 only records this; once janus-gate exists
	// (Phase 3) the same default means an unregistered tool cannot fire at all.
	DefaultEffectClass janusv1.EffectClass
	// SessionID labels every event of this session.
	SessionID string
	// Participant identifies the tool server being fronted.
	Participant evidence.ParticipantRef
	// Labels are added to every event (tenant, jurisdiction).
	Labels map[string]string
	// Router acts on the classification. Nil is the Phase 0 behaviour —
	// everything recorded, everything forwarded — which is what the MCP spike
	// exercises and what a proxy in front of an unregistered tool server falls
	// back to.
	Router Router
}

// Proxy sits between an MCP client and an MCP server, forwarding messages
// unchanged and recording each one as evidence.
type Proxy struct {
	opts Options

	mu      sync.Mutex
	pending map[string]pendingCall
	stats   Stats
}

type pendingCall struct {
	method string
	tool   string
	class  janusv1.EffectClass
	// saga is the join key, carried onto the response the way the tool and the
	// class are: a result has to be attributable to the saga it was produced
	// under without joining two records first.
	saga string
}

// Stats counts what a session did.
type Stats struct {
	ClientToServer int
	ServerToClient int
	ToolCalls      int
	Unclassified   int
}

// NewProxy returns a proxy configured by opts.
func NewProxy(opts Options) (*Proxy, error) {
	if opts.Appender == nil {
		return nil, errors.New("mcp: Options.Appender is required")
	}
	if opts.DefaultEffectClass == janusv1.EffectClass_EFFECT_CLASS_UNSPECIFIED {
		opts.DefaultEffectClass = janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED
	}
	if opts.Classifier == nil {
		opts.Classifier = StaticClassifier{}
	}
	return &Proxy{opts: opts, pending: map[string]pendingCall{}}, nil
}

// Stats returns a snapshot of the session counters.
func (p *Proxy) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}

// Run pumps messages in both directions until either side closes.
//
// clientIn/clientOut are the agent side, serverIn/serverOut the tool server
// side. Run returns when both directions have finished.
func (p *Proxy) Run(ctx context.Context, clientIn io.Reader, clientOut io.Writer, serverIn io.Reader, serverOut io.Writer) error {
	var wg sync.WaitGroup
	errs := make([]error, 2)

	// A pump spends nearly all its life blocked inside a read, which no context
	// can interrupt. Closing the readers on cancellation is what makes those
	// reads return, and without it the proxy ignores a shutdown signal
	// entirely: the process hangs, and because the evidence log is closed
	// downstream of Run, its open segment is never sealed — so the next start
	// reports a custody break for what was a deliberate shutdown.
	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			closeIfPossible(clientIn)
			closeIfPossible(serverIn)
		case <-stopped:
		}
	}()

	// When one side stops talking, close the other side's input so the peer
	// sees end-of-stream and shuts down too. Without this half-close the tool
	// server would wait forever for a client that has already gone.
	toServer := &serialWriter{w: NewWriter(serverOut)}
	toClient := &serialWriter{w: NewWriter(clientOut)}
	if p.opts.Router != nil {
		p.opts.Router.Attach(toServer.Write, toClient.Write)
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = p.pump(ctx, "client->server", NewReader(clientIn), toServer.Write, toClient.Write)
		closeIfPossible(serverOut)
	}()
	go func() {
		defer wg.Done()
		errs[1] = p.pump(ctx, "server->client", NewReader(serverIn), toClient.Write, nil)
		closeIfPossible(clientOut)
	}()
	wg.Wait()

	return errors.Join(filterEOF(errs[0]), filterEOF(errs[1]))
}

// closeIfPossible closes a stream if it can be closed. Both the shutdown path
// and the half-close path rely on it; a stream that cannot be closed simply
// keeps blocking, which is the pre-existing behaviour rather than a regression.
func closeIfPossible(v any) {
	if c, ok := v.(io.Closer); ok {
		_ = c.Close()
	}
}

func filterEOF(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, ErrClosed) {
		return nil
	}
	return err
}

// pump forwards one direction, recording each message before passing it on.
//
// The ordering is deliberate and is the whole reason this proxy exists: the
// evidence append happens first and the forward happens only if it succeeded.
// A message that could not be recorded is not delivered, which is
// evidence-before-effect applied at the tool boundary.
func (p *Proxy) pump(ctx context.Context, direction string, r *Reader,
	forward, reply func(Frame) error) error {

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := r.Next()
		if err != nil {
			return err
		}

		labels := p.labelsFor(direction, f)
		if _, err := p.opts.Appender.Append(ctx, evidence.Request{
			Kind:        evidence.KindMCPMessage,
			SagaID:      p.opts.SessionID,
			Participant: p.opts.Participant,
			Payload:     f.Raw,
			Labels:      labels,
		}); err != nil {
			return fmt.Errorf("%s: refusing to forward an unrecorded message: %w", direction, err)
		}

		// Acting on the classification, when there is something to act with.
		// The record has already been written either way: an effect Janus
		// refused is as much a part of the evidence as one it let through, and
		// deciding first would leave the refusal itself unrecorded.
		if p.opts.Router != nil {
			if reply == nil {
				p.opts.Router.Observe(f)
			} else if tool, ok := ToolCallName(f); ok {
				d, rerr := p.opts.Router.Route(ctx, f, tool, p.classOf(tool))
				if rerr != nil {
					return fmt.Errorf("%s: routing %q: %w", direction, tool, rerr)
				}
				switch d.Action {
				case ActionWithhold:
					// The call is the router's now. Nothing reaches the tool
					// server on this path, and the agent is waiting for
					// whatever the router eventually sends it.
					continue
				case ActionReply:
					if err := reply(d.Reply); err != nil {
						return fmt.Errorf("%s: answering %q: %w", direction, tool, err)
					}
					continue
				}
			}
		}

		if err := forward(f); err != nil {
			return fmt.Errorf("%s: forward: %w", direction, err)
		}
	}
}

// classOf resolves a tool's effect class, falling back to the configured
// default — which is IRREVERSIBLE_GATED unless somebody deliberately weakened
// it. An unregistered tool is assumed to change the world irreversibly until it
// proves otherwise, and that default is the whole reason a tool server can be
// put behind this proxy without being asked to change.
func (p *Proxy) classOf(tool string) janusv1.EffectClass {
	if p.opts.Classifier != nil {
		if c, ok := p.opts.Classifier.Classify(tool); ok {
			return c
		}
	}
	return p.opts.DefaultEffectClass
}

// labelsFor builds the queryable metadata for one message. The message body is
// stored verbatim as the payload; these labels are what make "every tool call
// agent X made between T1 and T2" answerable without parsing every payload.
func (p *Proxy) labelsFor(direction string, f Frame) map[string]string {
	labels := make(map[string]string, len(p.opts.Labels)+5)
	for k, v := range p.opts.Labels {
		labels[k] = v
	}
	labels["mcp.direction"] = direction
	if f.Method != "" {
		labels["mcp.method"] = f.Method
	}
	if id := IDKey(f.ID); id != "" {
		labels["mcp.id"] = id
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if direction == "client->server" {
		p.stats.ClientToServer++
	} else {
		p.stats.ServerToClient++
	}

	switch {
	case f.Method == MethodToolsCall:
		tool, ok := ToolCallName(f)
		if !ok {
			break
		}
		class, known := p.opts.Classifier.Classify(tool)
		if !known {
			class = p.opts.DefaultEffectClass
			p.stats.Unclassified++
			labels["janus.classification"] = "default"
		} else {
			labels["janus.classification"] = "manifest"
		}
		labels["mcp.tool"] = tool
		labels["janus.effect_class"] = shortClass(class)
		p.stats.ToolCalls++
		// The join between this log and the daemon's, stamped rather than left
		// to be re-derived. Without a router
		// there is no saga, so there is nothing to name.
		saga := ""
		if p.opts.Router != nil {
			saga = p.opts.Router.SagaID(f)
		}
		if saga != "" {
			labels["janus.saga_id"] = saga
		}
		if id := IDKey(f.ID); id != "" {
			p.pending[id] = pendingCall{method: f.Method, tool: tool, class: class, saga: saga}
		}

	case f.IsResp:
		// Carry the request's classification onto its response so a result can
		// be attributed to the effect class it was produced under without
		// joining two records.
		if call, ok := p.pending[IDKey(f.ID)]; ok {
			labels["mcp.method"] = call.method
			labels["mcp.tool"] = call.tool
			labels["janus.effect_class"] = shortClass(call.class)
			if call.saga != "" {
				labels["janus.saga_id"] = call.saga
			}
			delete(p.pending, IDKey(f.ID))
		}
		if f.IsErr {
			labels["mcp.error"] = "true"
		}
	}
	return labels
}

func shortClass(c janusv1.EffectClass) string {
	const prefix = "EFFECT_CLASS_"
	n := c.String()
	if len(n) > len(prefix) {
		return n[len(prefix):]
	}
	return n
}
