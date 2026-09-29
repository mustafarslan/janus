package orchd_test

import (
	"context"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// A retry of an attempt was made to compare with what was
// recorded, but only on status, hash, reference and provenance. What a step
// published -- the facts a later gate reads -- and what it touched were not
// compared, and the outcome's code and message were accepted and dropped.

// fullResult is a result with every field the log keeps set.
func fullResult(attempt uint32) *janusv1.StepResult {
	return &janusv1.StepResult{
		SagaId: notifySaga, StepId: "st_notify", Attempt: attempt,
		Outcome: &janusv1.Outcome{
			Status: janusv1.Outcome_STATUS_OK, Code: "SENT", Message: "delivered to the relay",
		},
		ResultHash: []byte("aaaa"), ResultRef: "cas:result",
		Facts: []*janusv1.Fact{{Key: "balance_minor", Value: &janusv1.Fact_Number{Number: 500}}},
		Touches: []*janusv1.ResourceTouch{{
			ResourceId: "acct_1", Mode: janusv1.ResourceTouch_MODE_WRITE,
		}},
	}
}

func complete(s *orchd.Server, res *janusv1.StepResult) (*janusv1.CompleteStepResponse, error) {
	return s.CompleteStep(context.Background(), &janusv1.CompleteStepRequest{Result: res})
}

// TestOneAttemptHasOneAccountOfEverythingItReported: a second report that
// differs only in what a later gate would read, or in what the step says went
// wrong, is two accounts of one attempt.
func TestOneAttemptHasOneAccountOfEverythingItReported(t *testing.T) {
	s, _ := newGatedServer(t)
	defer func() { _ = s.Close() }()
	beginGatedPlan(t, s, context.Background())
	attempt := prepareStep(t, s, notifySaga, "st_notify")
	if _, err := complete(s, fullResult(attempt)); err != nil {
		t.Fatal(err)
	}
	if resp, err := complete(s, fullResult(attempt)); err != nil || !resp.GetAlreadyRecorded() {
		t.Fatalf("an honest retry was not accepted as already recorded: %v", err)
	}

	for name, change := range map[string]func(*janusv1.StepResult){
		"another published balance": func(r *janusv1.StepResult) {
			r.Facts[0].Value = &janusv1.Fact_Number{Number: 5_000_000}
		},
		"nothing published":        func(r *janusv1.StepResult) { r.Facts = nil },
		"another resource touched": func(r *janusv1.StepResult) { r.Touches[0].ResourceId = "acct_2" },
		"another outcome code":     func(r *janusv1.StepResult) { r.Outcome.Code = "BOUNCED" },
		"another outcome message":  func(r *janusv1.StepResult) { r.Outcome.Message = "nobody home" },
	} {
		res := fullResult(attempt)
		change(res)
		if _, err := complete(s, res); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("%s, for an attempt already on the record, was told %v -- a later gate "+
				"would read one account and the reporter believes it gave another", name, err)
		}
	}
}

// TestAnOutcomesCodeAndMessageAreRecorded: what a step says about how it went
// is on the record, not accepted on the wire and dropped.
func TestAnOutcomesCodeAndMessageAreRecorded(t *testing.T) {
	s, dir := newGatedServer(t)
	defer func() { _ = s.Close() }()
	beginGatedPlan(t, s, context.Background())
	attempt := prepareStep(t, s, notifySaga, "st_notify")
	if _, err := complete(s, fullResult(attempt)); err != nil {
		t.Fatal(err)
	}
	events, err := saga.LoadEvents(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Kind != evidence.KindStepResult {
			continue
		}
		var got janusv1.StepResult
		if err := proto.Unmarshal(e.Payload, &got); err != nil {
			t.Fatal(err)
		}
		if got.GetOutcome().GetCode() != "SENT" || got.GetOutcome().GetMessage() != "delivered to the relay" {
			t.Fatalf("the step reported code %q and message %q; the log recorded %q and %q",
				"SENT", "delivered to the relay", got.GetOutcome().GetCode(), got.GetOutcome().GetMessage())
		}
		return
	}
	t.Fatal("no result was recorded")
}

// TestAReportTheLogRefusedCanBeCorrected: a report the state machine refuses
// never reaches the log, so it is not an account of the attempt. Holding it in
// the daemon's memory as one wedges the saga: every later drive tries to record
// it again, and a comparison against it would refuse the participant's
// correction as "reported differently" from a report nobody recorded.
func TestAReportTheLogRefusedCanBeCorrected(t *testing.T) {
	s, dir := newGatedServer(t)
	defer func() { _ = s.Close() }()
	beginGatedPlan(t, s, context.Background())
	attempt := prepareStep(t, s, notifySaga, "st_notify")

	bad := fullResult(attempt)
	bad.Touches[0].ResourceId = "" // the fold refuses a touch naming no resource
	if _, err := complete(s, bad); err == nil {
		t.Fatal("a result touching a resource with no id was accepted")
	}
	// Anything else that drives the saga must not trip over the refused report
	// either: held in memory, every drive would try to record it again.
	if _, err := s.PrepareStep(context.Background(), &janusv1.PrepareStepRequest{
		SagaId: notifySaga, StepId: "st_notify",
	}); err != nil {
		t.Fatalf("after a refused report, driving the saga for another reason failed: %v", err)
	}
	if resp, err := complete(s, fullResult(attempt)); err != nil || resp.GetAlreadyRecorded() {
		t.Fatalf("the corrected report of an attempt whose first report never reached the log "+
			"was told %v (already recorded: %v); the step can never finish", err, resp.GetAlreadyRecorded())
	}
	st, err := saga.ReplaySaga(dir, notifySaga)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Steps["st_notify"].Touches; len(got) != 1 || got[0].Resource != "acct_1" {
		t.Fatalf("the recorded result is not the corrected report: touches %v", got)
	}
}

// TestACompensationReportIsItsStatusAlone: an undo's outcome is recorded as a
// status and nothing else, so a code, a message, a touch or a fact sent with
// one is refused rather than accepted and lost -- and an identical retry of it
// would otherwise be compared with a log entry that never held them.
func TestACompensationReportIsItsStatusAlone(t *testing.T) {
	s, _ := newGatedServer(t)
	defer func() { _ = s.Close() }()
	beginGatedPlan(t, s, context.Background())
	for name, change := range map[string]func(*janusv1.StepResult){
		"a code":    func(r *janusv1.StepResult) { r.Outcome.Code = "REFUNDED" },
		"a message": func(r *janusv1.StepResult) { r.Outcome.Message = "refund issued" },
		"a touch": func(r *janusv1.StepResult) {
			r.Touches = []*janusv1.ResourceTouch{{ResourceId: "acct_1", Mode: janusv1.ResourceTouch_MODE_WRITE}}
		},
		"a fact": func(r *janusv1.StepResult) {
			r.Facts = []*janusv1.Fact{{Key: "refunded_minor", Value: &janusv1.Fact_Number{Number: 1}}}
		},
	} {
		res := &janusv1.StepResult{
			SagaId: notifySaga, StepId: "st_notify~undo",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}
		change(res)
		if _, err := complete(s, res); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("a compensation reported with %s was told %v, not refused", name, err)
		}
	}
}

// TestAttemptZeroIsNotAnAttempt: attempts count from one, and a report for
// attempt zero was answered "already recorded" when nothing was.
func TestAttemptZeroIsNotAnAttempt(t *testing.T) {
	s, _ := newGatedServer(t)
	defer func() { _ = s.Close() }()
	beginGatedPlan(t, s, context.Background())
	resp, err := complete(s, fullResult(0))
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a report for attempt 0 was told %v (already recorded: %v)", err, resp.GetAlreadyRecorded())
	}
}

// TestTheOrderOfTouchesIsNotPartOfTheAccount: an honest retry that lists the
// same touches in another order is the same report.
func TestTheOrderOfTouchesIsNotPartOfTheAccount(t *testing.T) {
	s, _ := newGatedServer(t)
	defer func() { _ = s.Close() }()
	beginGatedPlan(t, s, context.Background())
	attempt := prepareStep(t, s, notifySaga, "st_notify")
	two := func(first, second string) *janusv1.StepResult {
		r := fullResult(attempt)
		r.Touches = []*janusv1.ResourceTouch{
			{ResourceId: first, Mode: janusv1.ResourceTouch_MODE_WRITE},
			{ResourceId: second, Mode: janusv1.ResourceTouch_MODE_WRITE},
		}
		return r
	}
	if _, err := complete(s, two("acct_1", "acct_2")); err != nil {
		t.Fatal(err)
	}
	if resp, err := complete(s, two("acct_2", "acct_1")); err != nil || !resp.GetAlreadyRecorded() {
		t.Fatalf("the same touches in another order were told %v", err)
	}
	if _, err := complete(s, two("acct_1", "acct_1")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("one resource touched twice in place of two was accepted as the same account: %v", err)
	}
}
