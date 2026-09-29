package orchd_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/orchd"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// modelDecision is what an agent backed by a model puts forward about one step:
// which model, how it was sampled, what it said and why. Its identity fields are
// deliberately wrong — they are the daemon's to stamp, not the caller's.
func modelDecision() *janusv1.DecisionProvenanceRecord {
	return &janusv1.DecisionProvenanceRecord{
		DprId: "dpr_chosen_by_the_caller", SagaId: "sg_somebody_else", StepId: "st_elsewhere",
		DecisionKind: janusv1.DecisionProvenanceRecord_DECISION_KIND_ACT,
		Model: &janusv1.DecisionProvenanceRecord_ModelRef{
			Id: "glm-5.3", Version: "cloud", Temperature: 0.7, Seed: 17,
		},
		Output: &janusv1.DecisionProvenanceRecord_Output{
			Hash: []byte("output-hash"), CasRef: "cas:output", SchemaId: "notify.v1",
			ParseStatus: "OK",
		},
		Grounds: []*janusv1.DecisionProvenanceRecord_Ground{{
			Claim: "the counterparty is on the approved list", Source: "model",
		}},
	}
}

func completeWith(s *orchd.Server, attempt uint32, st janusv1.Outcome_Status, hash string,
	dpr *janusv1.DecisionProvenanceRecord) (*janusv1.CompleteStepResponse, error) {

	return s.CompleteStep(context.Background(), &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: notifySaga, StepId: "st_notify", Attempt: attempt,
			Outcome: &janusv1.Outcome{Status: st}, ResultHash: []byte(hash), ResultRef: "cas:result",
		},
		Provenance: dpr,
	})
}

type recorded struct {
	header  evidence.EventHeader
	payload []byte
}

func sagaRecords(t *testing.T, dir string) []recorded {
	t.Helper()
	var out []recorded
	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		if h.SagaID == notifySaga {
			out = append(out, recorded{h, rec.Payload})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAStepsResultAndItsWhyAreOnTheRecord reads both back the way
// an auditor would: the result names what the step produced, and cites the
// record of why, which is in the log immediately before it, as the
// participant's own decision, about this step.
func TestAStepsResultAndItsWhyAreOnTheRecord(t *testing.T) {
	s, dir := newGatedServer(t)
	defer func() { _ = s.Close() }()
	beginGatedPlan(t, s, context.Background())
	attempt := prepareStep(t, s, notifySaga, "st_notify")
	if _, err := completeWith(s, attempt, janusv1.Outcome_STATUS_OK, "result-hash", modelDecision()); err != nil {
		t.Fatalf("reporting a result with its provenance: %v", err)
	}
	_ = s.Close()

	recs := sagaRecords(t, dir)
	var result *janusv1.StepResult
	var at int
	for i, r := range recs {
		if r.header.Kind == evidence.KindStepResult {
			result = &janusv1.StepResult{}
			if err := proto.Unmarshal(r.payload, result); err != nil {
				t.Fatal(err)
			}
			at = i
		}
	}
	if result == nil {
		t.Fatal("no STEP_RESULT in the log")
	}
	if !bytes.Equal(result.GetResultHash(), []byte("result-hash")) || result.GetResultRef() != "cas:result" {
		t.Fatalf("the result was reported with a hash and a reference and the log holds "+
			"hash=%q ref=%q", result.GetResultHash(), result.GetResultRef())
	}
	if result.GetDprRef() == "" {
		t.Fatal("the result cites no provenance record; the why of the step is not on the record")
	}

	prev := recs[at-1]
	if prev.header.Kind != evidence.KindDPR || prev.header.EventID != result.GetDprRef() {
		t.Fatalf("the record before the result is %s %s, not the provenance record %s it cites",
			prev.header.Kind, prev.header.EventID, result.GetDprRef())
	}
	var dpr janusv1.DecisionProvenanceRecord
	if err := proto.Unmarshal(prev.payload, &dpr); err != nil {
		t.Fatal(err)
	}
	if dpr.GetSagaId() != notifySaga || dpr.GetStepId() != "st_notify" ||
		dpr.GetDprId() != result.GetDprRef() {
		t.Fatalf("the provenance record kept the identity its sender chose (%s/%s, %s); the "+
			"daemon stamps it from the result", dpr.GetSagaId(), dpr.GetStepId(), dpr.GetDprId())
	}
	if dpr.GetDecisionKind() != janusv1.DecisionProvenanceRecord_DECISION_KIND_ACT ||
		dpr.GetModel().GetId() != "glm-5.3" || dpr.GetModel().GetTemperature() != 0.7 ||
		!bytes.Equal(dpr.GetOutput().GetHash(), []byte("output-hash")) {
		t.Fatalf("the model's account did not survive: %v", &dpr)
	}
}

// TestAParticipantCannotSpeakInTheGatesVoice: VALIDATE is the record the
// coordinator writes beside a verdict, and UNSPECIFIED says nothing.
func TestAParticipantCannotSpeakInTheGatesVoice(t *testing.T) {
	for _, kind := range []janusv1.DecisionProvenanceRecord_DecisionKind{
		janusv1.DecisionProvenanceRecord_DECISION_KIND_VALIDATE,
		janusv1.DecisionProvenanceRecord_DECISION_KIND_UNSPECIFIED,
		janusv1.DecisionProvenanceRecord_DECISION_KIND_COMPENSATE,
	} {
		s, _ := newGatedServer(t)
		beginGatedPlan(t, s, context.Background())
		attempt := prepareStep(t, s, notifySaga, "st_notify")
		dpr := modelDecision()
		dpr.DecisionKind = kind
		_, err := completeWith(s, attempt, janusv1.Outcome_STATUS_OK, "h", dpr)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("a participant's result carried a %s decision record and was told %v", kind, err)
		}
		_ = s.Close()
	}
}

// TestOneAttemptHasOneAccount: a retry is accepted as already recorded, and a
// second report that says something else is refused — before this, anything
// sent after the result was in the log was told "already recorded".
func TestOneAttemptHasOneAccount(t *testing.T) {
	s, _ := newGatedServer(t)
	defer func() { _ = s.Close() }()
	beginGatedPlan(t, s, context.Background())
	attempt := prepareStep(t, s, notifySaga, "st_notify")
	if _, err := completeWith(s, attempt, janusv1.Outcome_STATUS_OK, "aaaa", modelDecision()); err != nil {
		t.Fatal(err)
	}

	resp, err := completeWith(s, attempt, janusv1.Outcome_STATUS_OK, "aaaa", modelDecision())
	if err != nil || !resp.GetAlreadyRecorded() {
		t.Fatalf("an honest retry was not accepted as already recorded: %v", err)
	}

	otherWhy := modelDecision()
	otherWhy.Grounds[0].Claim = "something else entirely"
	for name, second := range map[string]func() error{
		"another status": func() error {
			_, err := completeWith(s, attempt, janusv1.Outcome_STATUS_TERMINAL_ERROR, "aaaa", modelDecision())
			return err
		},
		"another hash": func() error {
			_, err := completeWith(s, attempt, janusv1.Outcome_STATUS_OK, "bbbb", modelDecision())
			return err
		},
		"another why": func() error {
			_, err := completeWith(s, attempt, janusv1.Outcome_STATUS_OK, "aaaa", otherWhy)
			return err
		},
		"no why": func() error {
			_, err := completeWith(s, attempt, janusv1.Outcome_STATUS_OK, "aaaa", nil)
			return err
		},
	} {
		if err := second(); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s for an attempt already on the record was told %v", name, err)
		}
	}
}

// TestACompensationRefusesWhatItCannotRecord: an undo's outcome is a status and
// nothing else, so a hash or a provenance record sent with one is refused
// rather than accepted and lost — a step result's rule, one path over.
//
// Two shapes, because the kind check would catch the first on its own: an
// undo carrying a participant's ACT record, and one carrying only a hash.
func TestACompensationRefusesWhatItCannotRecord(t *testing.T) {
	s, _ := newGatedServer(t)
	defer func() { _ = s.Close() }()
	beginGatedPlan(t, s, context.Background())
	for name, req := range map[string]*janusv1.CompleteStepRequest{
		"a decision record": {Provenance: modelDecision()},
		"a result hash":     {},
	} {
		req.Result = &janusv1.StepResult{
			SagaId: notifySaga, StepId: "st_notify~undo",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}
		if name == "a result hash" {
			req.Result.ResultHash = []byte("undo-hash")
		}
		_, err := s.CompleteStep(context.Background(), req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "compensation") {
			t.Errorf("a compensation reported with %s was told %v, not refused", name, err)
		}
	}
}
