package gate_test

import (
	"context"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Auditing is the second of two layers, and the tests below are about the line
// between them.
//
// The state machine enforces *structure*: a verdict must account for every
// requirement due, and a step may not run before a gate that was supposed to
// judge it. That is checked before every append, so no illegal history exists.
//
// What the state machine cannot check is whether the answers are right, because
// checking that means evaluating a policy and the state machine is the one
// component forbidden from doing so (it would stop being a pure function of the
// log). A coordinator that evaluates nothing and writes PASS produces a
// perfectly legal history. Catching that is what audit is for, and the test
// below is the one that matters: it forges exactly such a verdict, through the
// real append path, and requires the audit to find it.

var auditParticipant = evidence.ParticipantRef{
	ID: "ag_audit", ManifestVersion: "1.0.0", Principal: "pr_audit",
}

func newAuditLog(t *testing.T) (*evidence.Appender, string) {
	t.Helper()
	dir := t.TempDir()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, SyncMode: segment.SyncModeNone, SegmentTargetBytes: 1 << 20, Signer: signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	return app, dir
}

// auditPolicy gates a wire on an approval the step declares, and nothing else,
// so a forged verdict has exactly one thing to be wrong about.
const auditPolicy = `{
  "id": "test.audit",
  "rules": [{
    "id": "wires",
    "match": {"effect_classes": ["IRREVERSIBLE_GATED"]},
    "require": [
      {"id": "approval", "gate": "POLICY", "phase": "PRE_RELEASE",
       "policy": {"expr": "approved == true", "description": "payments need an approval"}}
    ]
  }]
}`

// writeSaga drives one wire saga through the real append path, with the step
// declaring the given approval, and lets the caller substitute the verdict.
func writeSaga(t *testing.T, approved bool, forge func(*janusv1.GateVerdict)) string {
	t.Helper()
	app, dir := newAuditLog(t)
	ctx := context.Background()

	e := gate.NewEngine(mustPolicy(t, auditPolicy))
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
	if _, err := r.Begin(ctx, begin); err != nil {
		t.Fatal(err)
	}
	facts := gate.FactsToProto(map[string]saga.FactValue{"approved": gate.Flag(approved)})
	if _, err := r.PrepareStep(ctx, &janusv1.StepPrepare{
		SagaId: "sg_1", StepId: "wire", Facts: facts,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.StepResult(ctx, &janusv1.StepResult{
		SagaId: "sg_1", StepId: "wire",
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	}); err != nil {
		t.Fatal(err)
	}

	st, _ := r.State().Step("wire")
	d := gate.Decide(janusv1.GatePhase_GATE_PHASE_PRE_RELEASE, gate.Input{
		Saga: r.State(), Step: st, Declared: st.Facts,
	})
	verdict := d.GateVerdict("")
	if forge != nil {
		forge(verdict)
	}
	if _, err := r.Gate(ctx, verdict); err != nil {
		t.Fatalf("recording the verdict: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// An honest log audits clean, and the audit has to have actually looked —
// a report of zero findings over zero verdicts would prove nothing.
func TestAuditAcceptsAnHonestLog(t *testing.T) {
	dir := writeSaga(t, true, nil)

	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("an honest log produced findings:\n%s", rep)
	}
	if rep.Verdicts != 1 {
		t.Fatalf("the audit re-derived %d verdicts, want 1; a clean report over nothing is not "+
			"a clean report", rep.Verdicts)
	}
}

// A refusal that was correct also has to audit clean, or every stopped payment
// would look like a finding.
func TestAuditAcceptsACorrectRefusal(t *testing.T) {
	dir := writeSaga(t, false, nil)

	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("a correct refusal produced findings:\n%s", rep)
	}
	if rep.Verdicts != 1 {
		t.Fatalf("re-derived %d verdicts, want 1", rep.Verdicts)
	}
}

// The one that matters. The step declares approved=false, the policy plainly
// refuses it, and the coordinator writes PASS anyway — naming the requirement,
// so the state machine's coverage check is satisfied and the history is legal.
// Only re-deriving the decision finds it.
func TestAuditCatchesAPassThePolicyDoesNotSupport(t *testing.T) {
	dir := writeSaga(t, false, func(v *janusv1.GateVerdict) {
		v.Verdict = janusv1.Verdict_VERDICT_PASS
		v.Reason = "approved"
		v.Decided = []string{"approval"}
	})

	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Fatal("a forged pass audited clean; the log records decisions nobody can check")
	}

	var found bool
	for _, f := range rep.Findings {
		if f.Kind != gate.FindingUnsupported {
			continue
		}
		found = true
		if f.StepID != "wire" {
			t.Errorf("the finding names step %q", f.StepID)
		}
		if f.Recorded != janusv1.Verdict_VERDICT_PASS || f.Derived != janusv1.Verdict_VERDICT_FAIL {
			t.Errorf("the finding records %s vs %s", f.Recorded, f.Derived)
		}
		if !strings.Contains(f.Detail, "payments need an approval") {
			t.Errorf("the finding does not say which check disagrees: %s", f.Detail)
		}
	}
	if !found {
		t.Fatalf("no UNSUPPORTED_VERDICT finding:\n%s", rep)
	}
}

// The reverse forgery: refusing something the policy permits. It is less
// dangerous and just as much a defect, because a system that stops payments for
// reasons its own policy does not support is one nobody can operate.
func TestAuditCatchesARefusalThePolicyDoesNotSupport(t *testing.T) {
	dir := writeSaga(t, true, func(v *janusv1.GateVerdict) {
		v.Verdict = janusv1.Verdict_VERDICT_FAIL
		v.Reason = "computer says no"
		v.Decided = []string{"approval"}
	})

	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Fatal("a refusal with nothing behind it audited clean")
	}
}

// The state machine is the first layer, and it must refuse the cheap forgeries
// outright rather than leaving them for an audit that may never run.
func TestTheStateMachineRefusesVerdictsThatDoNotAddUp(t *testing.T) {
	app, dir := newAuditLog(t)
	ctx := context.Background()
	_ = dir

	e := gate.NewEngine(mustPolicy(t, `{
	  "id": "test.two",
	  "rules": [{
	    "id": "wires",
	    "match": {"effect_classes": ["IRREVERSIBLE_GATED"]},
	    "require": [
	      {"id":"approval","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"approved == true"}},
	      {"id":"limit","gate":"RISK_LIMIT","phase":"PRE_RELEASE",
	       "risk_limit":{"thresholds":[{"fact":"amount_minor","max":100}]}}
	    ]
	  }]
	}`))
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1", Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in", MandateRef: "m-1"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Action: "payments.wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	}
	if err := e.Admit(begin); err != nil {
		t.Fatal(err)
	}

	r := saga.NewRunner(app, auditParticipant)
	if _, err := r.Begin(ctx, begin); err != nil {
		t.Fatal(err)
	}
	facts := gate.FactsToProto(map[string]saga.FactValue{
		"approved": gate.Flag(true), "amount_minor": gate.Number(50),
	})
	if _, err := r.PrepareStep(ctx, &janusv1.StepPrepare{
		SagaId: "sg_1", StepId: "wire", Facts: facts,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.StepResult(ctx, &janusv1.StepResult{
		SagaId: "sg_1", StepId: "wire",
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	}); err != nil {
		t.Fatal(err)
	}

	base := func() *janusv1.GateVerdict {
		return &janusv1.GateVerdict{
			SagaId: "sg_1", StepId: "wire",
			Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
			Verdict: janusv1.Verdict_VERDICT_PASS,
			Facts:   facts,
		}
	}

	cases := []struct {
		name string
		make func() *janusv1.GateVerdict
		hint string
	}{
		{"a pass that ran only the cheap check", func() *janusv1.GateVerdict {
			v := base()
			v.Decided = []string{"approval"}
			return v
		}, "cannot be let through on the checks somebody chose to run"},

		{"a pass that decided nothing at all", func() *janusv1.GateVerdict {
			return base()
		}, "cannot be let through"},

		{"a pass citing a requirement invented for the purpose", func() *janusv1.GateVerdict {
			v := base()
			v.Decided = []string{"approval", "limit", "vibes"}
			return v
		}, "which the saga was not admitted under"},

		{"a refusal that names nothing that refused", func() *janusv1.GateVerdict {
			v := base()
			v.Verdict = janusv1.Verdict_VERDICT_FAIL
			v.Decided = nil
			return v
		}, "without naming a requirement that refused"},

		{"a verdict rendered on facts the step never declared", func() *janusv1.GateVerdict {
			v := base()
			v.Decided = []string{"approval", "limit"}
			v.Facts = gate.FactsToProto(map[string]saga.FactValue{
				"approved": gate.Flag(true), "amount_minor": gate.Number(5),
			})
			return v
		}, "facts the step did not declare"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := r.Gate(ctx, c.make())
			if err == nil {
				t.Fatal("the state machine accepted it")
			}
			if !strings.Contains(err.Error(), c.hint) {
				t.Fatalf("the refusal does not explain itself: %v", err)
			}
		})
	}

	// And the honest version still goes through, so the checks above are
	// refusing the forgeries rather than everything.
	v := base()
	v.Decided = []string{"approval", "limit"}
	if _, err := r.Gate(ctx, v); err != nil {
		t.Fatalf("a verdict accounting for every requirement was refused: %v", err)
	}
}

// ---- audit of gates somebody outside decides ---------------------------------

// approvalPolicy gates a wire on a human approval with separation of duty, so
// the audit has a rule to check the recorded approval against.
const approvalPolicy = `{
  "id": "test.approval",
  "rules": [{
    "id": "wires",
    "match": {"effect_classes": ["IRREVERSIBLE_GATED"]},
    "require": [
      {"id": "approval", "gate": "HUMAN", "phase": "PRE_RELEASE",
       "human": {"roles": ["credit-officer"], "separation_of_duty": true}}
    ]
  }]
}`

// writeApprovedSaga drives a wire saga to the point of its human gate, records
// an approval from the named person, and lets the caller substitute the verdict.
func writeApprovedSaga(t *testing.T, approver string, forge func(*janusv1.GateVerdict)) string {
	t.Helper()
	app, dir := newAuditLog(t)
	ctx := context.Background()

	e := gate.NewEngine(mustPolicy(t, approvalPolicy))
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1", Mode: "supervised",
		// The saga is initiated on bob's authority. Whether the approver is bob
		// is the entire question separation of duty asks.
		Intent: &janusv1.Intent{IntentId: "in", Principal: "bob", MandateRef: "m-1"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Participant: "ag_audit", Action: "payments.wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	}
	if err := e.Admit(begin); err != nil {
		t.Fatal(err)
	}

	r := saga.NewRunner(app, auditParticipant)
	if _, err := r.Begin(ctx, begin); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PrepareStep(ctx, &janusv1.StepPrepare{SagaId: "sg_1", StepId: "wire"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.StepResult(ctx, &janusv1.StepResult{
		SagaId: "sg_1", StepId: "wire",
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Answer(ctx, &janusv1.GateAnswer{
		SagaId: "sg_1", StepId: "wire", RequirementId: "approval", Attempt: 1,
		Actor:   &janusv1.Actor{HumanSubject: approver},
		Verdict: janusv1.Verdict_VERDICT_PASS,
		Roles:   []string{"credit-officer"},
		AuthRef: "auth:" + approver,
	}); err != nil {
		t.Fatal(err)
	}

	st, _ := r.State().Step("wire")
	d := gate.Decide(janusv1.GatePhase_GATE_PHASE_PRE_RELEASE, gate.Input{
		Saga: r.State(), Step: st, Declared: st.Facts,
	})
	verdict := d.GateVerdict("")
	if forge != nil {
		forge(verdict)
	}
	if _, err := r.Gate(ctx, verdict); err != nil {
		t.Fatalf("recording the verdict: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A genuine four-eyes approval audits clean.
func TestAuditAcceptsAProperlySeparatedApproval(t *testing.T) {
	rep, err := gate.Audit(writeApprovedSaga(t, "alice", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("a proper approval produced findings:\n%s", rep)
	}
	if rep.Verdicts != 1 {
		t.Fatalf("re-derived %d verdicts, want 1", rep.Verdicts)
	}
}

// The one that closes the trap.
//
// A human gate implemented as "an approval exists" would re-derive to PASS here
// and agree with the forged verdict, because an approval does exist — bob's.
// The audit has to check that the recorded approval satisfies the recorded
// rule, and separation of duty is the part of that rule which needs nobody to
// be trusted: both names are in the log.
func TestAuditCatchesASelfApprovalRecordedAsAPass(t *testing.T) {
	dir := writeApprovedSaga(t, "bob", func(v *janusv1.GateVerdict) {
		v.Verdict = janusv1.Verdict_VERDICT_PASS
		v.Gate = janusv1.GateType_GATE_TYPE_COMPOSITE
		v.Reason = "approved by bob"
		v.Decided = []string{"approval"}
	})

	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Fatal("an approval by the initiator audited clean; the four-eyes rule is decorative")
	}

	var found bool
	for _, f := range rep.Findings {
		if f.Kind != gate.FindingUnsupported {
			continue
		}
		found = true
		if !strings.Contains(f.Detail, "own authority") {
			t.Errorf("the finding does not say why the approval does not count: %s", f.Detail)
		}
	}
	if !found {
		t.Fatalf("no UNSUPPORTED_VERDICT finding:\n%s", rep)
	}
}

// The same shape for the role condition. This one is weaker by construction —
// the roles are asserted by whatever authenticated the approver rather than
// established by Janus — but the assertion is on the record, so a verdict that
// ignores it is still a finding.
func TestAuditCatchesAnApprovalFromSomebodyWithoutTheRole(t *testing.T) {
	app, dir := newAuditLog(t)
	ctx := context.Background()

	e := gate.NewEngine(mustPolicy(t, approvalPolicy))
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1", Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in", Principal: "bob", MandateRef: "m-1"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Action: "payments.wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	}
	if err := e.Admit(begin); err != nil {
		t.Fatal(err)
	}
	r := saga.NewRunner(app, auditParticipant)
	for _, record := range []func() error{
		func() error { _, err := r.Begin(ctx, begin); return err },
		func() error {
			_, err := r.PrepareStep(ctx, &janusv1.StepPrepare{SagaId: "sg_1", StepId: "wire"})
			return err
		},
		func() error {
			_, err := r.StepResult(ctx, &janusv1.StepResult{
				SagaId: "sg_1", StepId: "wire",
				Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			})
			return err
		},
		func() error {
			_, err := r.Answer(ctx, &janusv1.GateAnswer{
				SagaId: "sg_1", StepId: "wire", RequirementId: "approval", Attempt: 1,
				Actor:   &janusv1.Actor{HumanSubject: "alice"},
				Verdict: janusv1.Verdict_VERDICT_PASS,
				Roles:   []string{"intern"},
			})
			return err
		},
		func() error {
			_, err := r.Gate(ctx, &janusv1.GateVerdict{
				SagaId: "sg_1", StepId: "wire",
				Gate:    janusv1.GateType_GATE_TYPE_COMPOSITE,
				Verdict: janusv1.Verdict_VERDICT_PASS,
				Reason:  "approved by alice",
				Decided: []string{"approval"},
			})
			return err
		},
	} {
		if err := record(); err != nil {
			t.Fatal(err)
		}
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK() {
		t.Fatalf("an approval from somebody holding no entitling role audited clean:\n%s", rep)
	}
}

// An escalation is not a decision, so a log that stops at one is not a log with
// a finding in it. Without this, every saga legitimately waiting on a person
// would report as a defect.
func TestAuditAcceptsALogStillWaitingOnAnApproval(t *testing.T) {
	app, dir := newAuditLog(t)
	ctx := context.Background()

	e := gate.NewEngine(mustPolicy(t, approvalPolicy))
	begin := &janusv1.SagaBegin{
		SagaId: "sg_1", Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in", Principal: "bob", MandateRef: "m-1"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Action: "payments.wire",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	}
	if err := e.Admit(begin); err != nil {
		t.Fatal(err)
	}
	r := saga.NewRunner(app, auditParticipant)
	if _, err := r.Begin(ctx, begin); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PrepareStep(ctx, &janusv1.StepPrepare{SagaId: "sg_1", StepId: "wire"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.StepResult(ctx, &janusv1.StepResult{
		SagaId: "sg_1", StepId: "wire",
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	}); err != nil {
		t.Fatal(err)
	}
	st, _ := r.State().Step("wire")
	d := gate.Decide(janusv1.GatePhase_GATE_PHASE_PRE_RELEASE, gate.Input{
		Saga: r.State(), Step: st,
	})
	if d.Verdict != janusv1.Verdict_VERDICT_ESCALATE {
		t.Fatalf("the gate decided %s with nobody having answered", d.Verdict)
	}
	if _, err := r.Gate(ctx, d.GateVerdict("")); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := gate.Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("a saga waiting on a person reported as a defect:\n%s", rep)
	}
}
