// Package telemetry emits OpenTelemetry spans for saga work, following the
// GenAI semantic conventions where they fit.
//
// # Telemetry is not evidence
//
// This is the whole of the design and it is worth stating before anything else,
// because the code below looks exactly like the code that would be evidence if
// somebody decided it was.
//
// A span is a convenience for an operator watching a system run: it is sampled,
// it is dropped when a collector is down, its attributes are whatever this
// process put on them, and nothing signs it. The evidence log is none of those
// things. So when a trace and the log disagree, the log is right, and any
// question a regulator, an auditor or a court would ask has to be answerable
// from the log with the traces switched off entirely.
//
// What the spans are for is the other half of an operator's job: noticing that
// something is slow, or that a gate is escalating more often than it used to,
// without reading a log to find out. They carry the saga and step ids and the
// evidence sequence, so a span is a pointer *into* the evidence rather than a
// copy of it — which is also why nothing here carries a payload, a fact value
// or an approver's name. A trace that carried those would be a second, unsigned,
// samplable record of a decision, in a system somebody exports to a vendor.
//
// # Off unless something is listening
//
// With no tracer provider configured, OpenTelemetry's global provider is a
// no-op and every call here costs an allocation-free nothing. There is
// deliberately no flag to turn telemetry "on": it is on when an exporter is
// wired up by whoever runs the process, which is the same arrangement every
// other OTel-instrumented service has.
package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Attribute keys.
//
// The GenAI conventions are used where they mean the same thing — a step runs a
// named tool on behalf of a named agent, which is what gen_ai.tool.name and
// gen_ai.agent.id describe. Everything a saga has that GenAI has no word for
// gets a janus.* key rather than being forced into a conventional one, because
// an attribute that means something slightly different from what its name says
// is worse than an attribute nobody recognises.
const (
	AttrOperationName = "gen_ai.operation.name"
	AttrAgentID       = "gen_ai.agent.id"
	AttrToolName      = "gen_ai.tool.name"

	AttrSagaID      = "janus.saga.id"
	AttrStepID      = "janus.step.id"
	AttrEffectClass = "janus.effect_class"
	AttrAttempt     = "janus.attempt"
	// AttrEvidenceSeq is the log position this operation appended at. It is the
	// field that makes a span useful: it points at the record rather than
	// restating it.
	AttrEvidenceSeq = "janus.evidence.seq"
	AttrOutcome     = "janus.outcome"
	AttrVerdict     = "janus.gate.verdict"
)

// Operation names, in the GenAI conventions' vocabulary.
const (
	OperationInvokeAgent = "invoke_agent"
	OperationExecuteTool = "execute_tool"
)

// Recorder emits spans. The zero value is unusable; use New.
type Recorder struct{ tracer trace.Tracer }

// New returns a recorder over the global tracer provider.
//
// The global provider is a no-op until something configures one, so a process
// that wires up no exporter pays nothing for these calls.
func New(name string) *Recorder {
	return &Recorder{tracer: otel.Tracer(name)}
}

// Span is an operation in progress.
type Span struct {
	span trace.Span
}

// Start opens a span for one saga operation.
func (r *Recorder) Start(ctx context.Context, operation, name string,
	attrs ...attribute.KeyValue) (context.Context, *Span) {

	if r == nil {
		return ctx, &Span{}
	}
	ctx, span := r.tracer.Start(ctx, name, trace.WithAttributes(
		append([]attribute.KeyValue{attribute.String(AttrOperationName, operation)}, attrs...)...,
	))
	return ctx, &Span{span: span}
}

// Evidence records where this operation landed in the log.
//
// It is called after the append rather than before, because the sequence does
// not exist until the record is durable — and a span that named a sequence
// before the append succeeded would be pointing at evidence that may not be
// there.
func (s *Span) Evidence(seq uint64) {
	if s == nil || s.span == nil {
		return
	}
	s.span.SetAttributes(attribute.Int64(AttrEvidenceSeq, int64(seq)))
}

// Set adds attributes.
func (s *Span) Set(attrs ...attribute.KeyValue) {
	if s == nil || s.span == nil {
		return
	}
	s.span.SetAttributes(attrs...)
}

// End closes the span, recording an error if there was one.
//
// A refusal is not an error. A gate that declined an effect, or an admission
// that refused a plan, is the system working, and marking those spans as errors
// would train an operator to ignore the colour that means something is broken.
// Only a failure to do the work at all is recorded as an error.
func (s *Span) End(err error) {
	if s == nil || s.span == nil {
		return
	}
	if err != nil {
		s.span.RecordError(err)
		s.span.SetStatus(codes.Error, err.Error())
	}
	s.span.End()
}

// Saga is the attribute set every span about a saga carries.
func Saga(sagaID, principal string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String(AttrSagaID, sagaID),
		attribute.String(AttrAgentID, principal),
	}
}

// Step adds the attributes of one step.
func Step(stepID, action, effectClass string, attempt uint32) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String(AttrStepID, stepID),
		attribute.String(AttrToolName, action),
		attribute.String(AttrEffectClass, effectClass),
		attribute.Int(AttrAttempt, int(attempt)),
	}
}
