package gate_test

import (
	"strings"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

// A human gate that nobody answers.
//
// The expiry is an *event*, not a computation: a live process notices the
// deadline has passed and records an answer, and everything afterwards — the
// composition, the audit, a re-derivation years later — reads that recorded
// answer like any other. Giving `Decide` the current time instead would make a
// verdict depend on when it was computed, and `gate.Audit` would report every
// timed-out gate as a finding.
//
// These tests are the composition half: given a recorded expiry, what does the
// gate decide. The process that records one is orchd's business.

var gateOpened = time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)

// timedState is externalState with recorded wall times, so a deadline has
// something to count from.
func timedState(t *testing.T, gates ...*janusv1.GateRequirement) saga.State {
	t.Helper()
	begin := &janusv1.SagaBegin{
		SagaId: "sg", Mode: "supervised", GatePolicyVersion: "blake3:test",
		Intent: &janusv1.Intent{IntentId: "in", Principal: initiator, MandateRef: "m-1"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Participant: "ag_1", Action: "payments.wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		GatePlan: []*janusv1.StepGates{{StepId: "wire", RuleId: "r", Require: gates}},
	}
	events := []saga.Event{
		at(event(t, 1, evidence.KindSagaBegin, begin), gateOpened.Add(-2*time.Minute)),
		at(event(t, 2, evidence.KindStepPrepare,
			&janusv1.StepPrepare{SagaId: "sg", StepId: "wire"}), gateOpened.Add(-time.Minute)),
		// The PRE_RELEASE window opens here, not at prepare: a gate that judges
		// what happened cannot start its clock before there is a result.
		at(event(t, 3, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: "wire",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}), gateOpened),
	}
	s, err := saga.Replay(events)
	if err != nil {
		t.Fatalf("the fixture saga does not replay: %v", err)
	}
	return s
}

func at(ev saga.Event, wall time.Time) saga.Event {
	ev.Wall = wall
	return ev
}

// expiry is what orchd records when a deadline passes: an answer from the
// daemon, refusing, with no human subject.
func expiry(reqID string, wall time.Time) (*janusv1.GateAnswer, time.Time) {
	return &janusv1.GateAnswer{
		SagaId: "sg", StepId: "wire", RequirementId: reqID, Attempt: 1,
		Actor:   &janusv1.Actor{Participant: &janusv1.ParticipantRef{Id: "ag_orchd"}},
		Verdict: janusv1.Verdict_VERDICT_FAIL, Reason: saga.ExpiryReason,
	}, wall
}

func withAnswerAt(t *testing.T, s saga.State, seq uint64,
	a *janusv1.GateAnswer, wall time.Time) saga.State {
	t.Helper()
	next, err := saga.Apply(s, at(event(t, seq, evidence.KindGateAnswer, a), wall))
	if err != nil {
		t.Fatalf("recording the answer: %v", err)
	}
	return next
}

func timedHuman(id string, timeout uint32, roles ...string) *janusv1.GateRequirement {
	r := human(id, 1, false, roles...)
	r.TimeoutSeconds = timeout
	return r
}

// TestAnUnansweredGateIsRefusedOnceItsDeadlineHasPassed.
func TestAnUnansweredGateIsRefusedOnceItsDeadlineHasPassed(t *testing.T) {
	req := timedHuman("approve", 3600, "credit-officer")
	s := timedState(t, req)

	// Before the expiry is recorded the gate is still waiting. Nothing about a
	// deadline changes a verdict on its own — only a recorded answer does.
	if got := decideRelease(t, s).Verdict; got != janusv1.Verdict_VERDICT_ESCALATE {
		t.Fatalf("an unanswered gate is %s before any expiry is recorded, want ESCALATE", got)
	}

	a, wall := expiry("approve", gateOpened.Add(time.Hour+time.Minute))
	s = withAnswerAt(t, s, 4, a, wall)

	d := decideRelease(t, s)
	if d.Verdict != janusv1.Verdict_VERDICT_FAIL {
		t.Fatalf("a gate nobody answered past its deadline is %s, want FAIL", d.Verdict)
	}
	if !strings.Contains(d.Reason, "deadline") && !strings.Contains(d.Reason, "1h0m0s") {
		t.Errorf("the refusal does not say a deadline caused it: %s", d.Reason)
	}
}

// TestAnExpiryRecordedTooEarlyIsNotAnExpiry is the check that makes the
// mechanism safe rather than merely auditable.
//
// Without it, anybody able to append an answer could cancel an approval on
// demand by recording something that looks like a timeout. It cannot approve
// anything, but "refuse this payment whenever I like" is a denial lever, and
// discovering it in an audit report afterwards is not the same as it not
// working.
//
// So a forged early expiry falls through to the ordinary checks and is refused
// there for what it actually is: an answer from somebody holding no roles.
func TestAnExpiryRecordedTooEarlyIsNotAnExpiry(t *testing.T) {
	req := timedHuman("approve", 3600, "credit-officer")
	s := timedState(t, req)

	// One second before the deadline.
	a, wall := expiry("approve", gateOpened.Add(time.Hour-time.Second))
	s = withAnswerAt(t, s, 4, a, wall)

	d := decideRelease(t, s)
	if strings.Contains(d.Reason, "on the deadline's behalf") {
		t.Fatal("an answer recorded before the deadline was accepted as a timeout; anybody " +
			"who can append an answer could cancel an approval on demand")
	}
	if d.Verdict != janusv1.Verdict_VERDICT_FAIL {
		t.Errorf("the forged expiry produced %s; it should be refused for what it is",
			d.Verdict)
	}
}

// TestAGateWithNoDeadlineNeverExpires: zero means wait forever, which is what
// every policy written before this field did.
func TestAGateWithNoDeadlineNeverExpires(t *testing.T) {
	s := timedState(t, timedHuman("approve", 0, "credit-officer"))
	a, wall := expiry("approve", gateOpened.Add(100*time.Hour))
	s = withAnswerAt(t, s, 4, a, wall)

	d := decideRelease(t, s)
	if strings.Contains(d.Reason, "on the deadline's behalf") {
		t.Fatal("a gate with no deadline was expired; zero means wait forever")
	}
}

// TestAHumanRefusalIsNotAnExpiry keeps the two distinguishable in the record.
//
// Both refuse the gate. What differs is who decided and why, and a log that
// could not tell them apart would report a person's decision as a clock's.
func TestAHumanRefusalIsNotAnExpiry(t *testing.T) {
	s := timedState(t, timedHuman("approve", 3600, "credit-officer"))
	s = withAnswerAt(t, s, 4,
		approval("alice", "approve", janusv1.Verdict_VERDICT_FAIL, "credit-officer"),
		gateOpened.Add(2*time.Hour))

	d := decideRelease(t, s)
	if d.Verdict != janusv1.Verdict_VERDICT_FAIL {
		t.Fatalf("a declined approval is %s, want FAIL", d.Verdict)
	}
	if strings.Contains(d.Reason, "on the deadline's behalf") {
		t.Errorf("a person's refusal was recorded as a timeout: %s", d.Reason)
	}
	if !strings.Contains(d.Reason, "alice") {
		t.Errorf("the refusal does not name who declined: %s", d.Reason)
	}
}

// TestTheAnchorIsThePhasesOwnEvent.
//
// A PRE_RELEASE gate's clock starts at the step's result, not at its prepare.
// Anchoring both phases at prepare would give a release gate a head start equal
// to however long the step took to run — which on a slow payment is the whole
// deadline.
func TestTheAnchorIsThePhasesOwnEvent(t *testing.T) {
	s := timedState(t, timedHuman("approve", 3600, "credit-officer"))
	st, ok := s.Step("wire")
	if !ok {
		t.Fatal("no step")
	}
	pre := saga.GateOpenedAt(st, janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION)
	rel := saga.GateOpenedAt(st, janusv1.GatePhase_GATE_PHASE_PRE_RELEASE)
	if !pre.Before(rel) {
		t.Fatalf("pre-execution anchors at %s and pre-release at %s; the release window "+
			"cannot open before the result exists", pre, rel)
	}
	if !rel.Equal(gateOpened) {
		t.Errorf("the release window opened at %s, want the result's wall time %s",
			rel, gateOpened)
	}
}
