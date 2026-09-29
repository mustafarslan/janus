package gate_test

import (
	"context"
	"strings"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Audit's fourth check.
//
// The composition already refuses to *treat* an answer recorded before the
// deadline as an expiry, so a forged one cannot skip an approval. But it still
// sits in the log looking like a system decision, and an audit that could not
// tell would report nothing. This is what turns "the system said it timed out"
// into something checkable.

// timeoutPolicy gates a wire on a person, with a deadline.
func timeoutPolicy(seconds int) string {
	return `{
  "id": "test.timeout",
  "rules": [{
    "id": "wires",
    "match": {"effect_classes": ["IRREVERSIBLE_GATED"]},
    "require": [
      {"id": "approval", "gate": "HUMAN", "phase": "PRE_RELEASE",
       "timeout_seconds": ` + itoa(seconds) + `,
       "human": {"roles": ["credit-officer"], "quorum": 1}}
    ]
  }]
}`
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// writeExpiredSaga drives a wire saga to its human gate and then records an
// expiry, through the real append path so the answer's wall time is whatever the
// appender stamped rather than something a test chose.
func writeExpiredSaga(t *testing.T, timeoutSeconds int, wait time.Duration) string {
	return writeExpiredSagaGap(t, timeoutSeconds, 0, wait)
}

// writeExpiredSagaGap additionally puts a gap between the step's prepare and its
// result, which is what makes the two anchors distinguishable: with them
// milliseconds apart, anchoring a release deadline at the prepare time gives the
// same answer as anchoring it at the result, and a test cannot tell.
func writeExpiredSagaGap(t *testing.T, timeoutSeconds int, gap, wait time.Duration) string {
	t.Helper()
	app, dir := newAuditLog(t)
	ctx := context.Background()

	e := gate.NewEngine(mustPolicy(t, timeoutPolicy(timeoutSeconds)))
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1", Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in", MandateRef: "m-1"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Participant: "ag_audit", Action: "payments.wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	}
	if err := e.Admit(begin); err != nil {
		t.Fatal(err)
	}
	r := saga.NewRunner(app, auditParticipant)
	// Semantics 3: the early expiry these tests audit is one a version-3 log can
	// hold. From 4 the fold refuses a participant's answer to a person's gate
	// before its deadline outright; the audit's finding is for the
	// logs written before that.
	if _, err := r.BeginUnder(ctx, begin, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PrepareStep(ctx, &janusv1.StepPrepare{
		SagaId: "sg_1", StepId: "wire",
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(gap)
	if _, err := r.StepResult(ctx, &janusv1.StepResult{
		SagaId: "sg_1", StepId: "wire",
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	}); err != nil {
		t.Fatal(err)
	}

	// The deadline is real time, so a legitimate expiry has to wait for it.
	time.Sleep(wait)

	if _, err := r.Answer(ctx, &janusv1.GateAnswer{
		SagaId: "sg_1", StepId: "wire", RequirementId: "approval", Attempt: 1,
		Actor:   &janusv1.Actor{Participant: &janusv1.ParticipantRef{Id: "ag_orchd"}},
		Verdict: janusv1.Verdict_VERDICT_FAIL, Reason: saga.ExpiryReason,
	}); err != nil {
		t.Fatalf("recording the expiry: %v", err)
	}

	st, _ := r.State().Step("wire")
	d := gate.Decide(janusv1.GatePhase_GATE_PHASE_PRE_RELEASE, gate.Input{
		Saga: r.State(), Step: st, Declared: st.Facts,
	})
	if _, err := r.Gate(ctx, d.GateVerdict("")); err != nil {
		t.Fatalf("recording the verdict: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestAuditFlagsAnExpiryRecordedBeforeItsDeadline.
//
// A coordinator could expire a gate early to make an inconvenient approval
// unnecessary, and without this the log would show an ordinary timeout.
func TestAuditFlagsAnExpiryRecordedBeforeItsDeadline(t *testing.T) {
	// An hour's deadline, expired immediately.
	dir := writeExpiredSaga(t, 3600, 0)

	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range rep.Findings {
		if f.Kind == gate.FindingEarlyExpiry {
			found = true
			t.Logf("reported: %s", f.Detail)
			if !strings.Contains(f.Detail, "before the deadline") {
				t.Errorf("the finding does not say what is wrong: %s", f.Detail)
			}
		}
	}
	if !found {
		t.Fatalf("a gate refused on a deadline's behalf an hour early audited clean: %+v",
			rep.Findings)
	}
}

// TestAuditAcceptsAGenuineExpiry: the check must not report every timeout.
//
// A one-second deadline, actually waited out. Slow by a second and worth it: an
// audit that flagged legitimate expiries would be worse than no check, because
// it would train somebody to ignore the finding.
func TestAuditAcceptsAGenuineExpiry(t *testing.T) {
	dir := writeExpiredSaga(t, 1, 1100*time.Millisecond)

	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f.Kind == gate.FindingEarlyExpiry {
			t.Fatalf("a genuine expiry was reported as early: %s", f.Detail)
		}
	}
	// And it really did expire — the gate is refused, not still waiting, so
	// this test is about an expiry rather than about nothing.
	states, err := saga.ReplayAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := states["sg_1"].Step("wire")
	if !ok {
		t.Fatal("no step")
	}
	if st.Status != saga.StepRefused {
		t.Fatalf("the step is %s; the deadline should have refused it", st.Status)
	}
}

// TestAuditAndTheEnforcerAnchorTheDeadlineIdentically.
//
// The step takes a while to run, so its prepare and its result are far apart —
// and a release deadline anchored at the wrong one gives a different answer.
// The expiry here is recorded half a second after the result with a one-second
// deadline, so it is early measured from the result and *late* measured from the
// prepare.
//
// Anchoring both phases at the prepare time therefore makes this audit clean,
// which is the two-anchor bug: an early expiry that nobody reports. The
// symmetric mistake is worse in the other direction — every legitimate timeout
// becoming a finding — and both come from having two implementations of "when
// did this gate open".
func TestAuditAndTheEnforcerAnchorTheDeadlineIdentically(t *testing.T) {
	dir := writeExpiredSagaGap(t, 1, 1500*time.Millisecond, 500*time.Millisecond)

	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range rep.Findings {
		if f.Kind == gate.FindingEarlyExpiry {
			found = true
			t.Logf("reported: %s", f.Detail)
		}
	}
	if !found {
		t.Fatal("an expiry recorded half a second into a one-second deadline audited clean; " +
			"the audit is anchoring the deadline somewhere the enforcer does not")
	}
}
