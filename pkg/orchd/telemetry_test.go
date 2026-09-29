package orchd_test

import (
	"context"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/telemetry"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestASpanPointsAtTheEvidenceRatherThanCopyingIt is the design of the whole
// telemetry surface, checked rather than asserted in a comment.
//
// A span is sampled, droppable, unsigned, and exported to whoever the collector
// is configured to send it to. The evidence log is none of those things. So a
// span may carry the ids and the sequence that let somebody *find* a record,
// and must not carry the record: no payloads, no fact values, no approvers'
// names. Otherwise the system grows a second account of a decision, in the one
// place where nothing signs it.
func TestASpanPointsAtTheEvidenceRatherThanCopyingIt(t *testing.T) {
	spans := captureSpans(t)

	s, _ := newServer(t)
	ctx := context.Background()
	if _, err := s.BeginSaga(ctx, &janusv1.BeginSagaRequest{Begin: quotePlan()}); err != nil {
		t.Fatal(err)
	}
	attempt := prepareStep(t, s, testSaga, "st_quote")
	if _, err := s.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: testSaga, StepId: "st_quote", Attempt: attempt,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		},
	}); err != nil {
		t.Fatal(err)
	}

	ended := spans.Ended()
	byName := map[string]sdktrace.ReadOnlySpan{}
	for _, span := range ended {
		byName[span.Name()] = span
	}
	for _, want := range []string{"janus.saga.begin", "janus.step.prepare", "janus.step.complete"} {
		if _, ok := byName[want]; !ok {
			t.Fatalf("no %q span was emitted; the operator's view of a saga has a hole "+
				"in it exactly where the work is", want)
		}
	}

	begin := byName["janus.saga.begin"]
	attrs := attributesOf(begin)
	if attrs[telemetry.AttrSagaID] != testSaga {
		t.Fatalf("the begin span names saga %q, want %q — a span that cannot be tied to "+
			"a saga is a span nobody can act on", attrs[telemetry.AttrSagaID], testSaga)
	}
	if attrs[telemetry.AttrEvidenceSeq] == "" {
		t.Fatal("the begin span carries no evidence sequence. Pointing at the record is " +
			"the whole reason a span is allowed to exist here")
	}

	// The negative half, and the one that matters. Nothing a decision was made
	// on may appear in a trace.
	for _, span := range ended {
		for key, value := range attributesOf(span) {
			for _, forbidden := range []string{"amount", "counterparty", "approved", "payload"} {
				if strings.Contains(strings.ToLower(key), forbidden) {
					t.Fatalf("span %q carries attribute %q. A fact a gate decided on, in "+
						"an unsigned record that is sampled and exported, is a second "+
						"account of that decision", span.Name(), key)
				}
				if strings.Contains(strings.ToLower(value), forbidden) {
					t.Fatalf("span %q carries %q=%q, which looks like decision content "+
						"rather than a pointer to it", span.Name(), key, value)
				}
			}
		}
	}
}

// TestARefusalIsNotASpanError. A gate declining an effect is the system
// working. Colouring it red teaches an operator to ignore the colour that means
// something is broken.
func TestARefusalIsNotASpanError(t *testing.T) {
	spans := captureSpans(t)

	s, _ := newServer(t)
	begin := quotePlan()
	// Understates the effect class, so registry admission refuses it.
	begin.Plan[0].Action = "payments.wire"
	begin.Plan[0].EffectClass = janusv1.EffectClass_EFFECT_CLASS_PURE
	if _, err := s.BeginSaga(context.Background(),
		&janusv1.BeginSagaRequest{Begin: begin}); err == nil {
		t.Fatal("the plan should have been refused")
	}

	for _, span := range spans.Ended() {
		if span.Status().Code.String() == "Error" {
			t.Fatalf("span %q was marked an error for a refusal; a refused plan is this "+
				"system doing its job", span.Name())
		}
		if got := attributesOf(span)[telemetry.AttrVerdict]; got == "" {
			t.Fatalf("span %q records no verdict, so an operator watching refusal rates "+
				"has nothing to watch", span.Name())
		}
	}
}

// captureSpans installs an in-memory exporter for the duration of one test.
//
// It has to be installed before the server is built: a recorder takes its
// tracer from the global provider when it is constructed, which is the ordinary
// OpenTelemetry arrangement and is worth knowing when a test sees no spans.
func captureSpans(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)))
	t.Cleanup(func() { otel.SetTracerProvider(previous) })
	return recorder
}

func attributesOf(span sdktrace.ReadOnlySpan) map[string]string {
	out := map[string]string{}
	for _, kv := range span.Attributes() {
		out[string(kv.Key)] = kv.Value.String()
	}
	return out
}
