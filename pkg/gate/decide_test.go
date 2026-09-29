package gate_test

import (
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

// ---- fixtures -----------------------------------------------------------------

const preRelease = janusv1.GatePhase_GATE_PHASE_PRE_RELEASE
const preExecution = janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION

func req(id, gateType, phase string, check any) *janusv1.GateRequirement {
	r := &janusv1.GateRequirement{
		Id:    id,
		Gate:  janusv1.GateType(janusv1.GateType_value["GATE_TYPE_"+gateType]),
		Phase: janusv1.GatePhase(janusv1.GatePhase_value["GATE_PHASE_"+phase]),
	}
	switch c := check.(type) {
	case *janusv1.SchemaCheck:
		r.Check = &janusv1.GateRequirement_Schema{Schema: c}
	case *janusv1.PolicyCheck:
		r.Check = &janusv1.GateRequirement_Policy{Policy: c}
	case *janusv1.RiskLimitCheck:
		r.Check = &janusv1.GateRequirement_RiskLimit{RiskLimit: c}
	case *janusv1.FrontierCheck:
		r.Check = &janusv1.GateRequirement_Frontier{Frontier: c}
	}
	return r
}

// stateWith builds a saga projection carrying a single gated step.
func stateWith(t *testing.T, class janusv1.EffectClass, gates ...*janusv1.GateRequirement) saga.State {
	t.Helper()
	begin := &janusv1.SagaBegin{
		SagaId:            "sg",
		Mode:              "supervised",
		GatePolicyVersion: "blake3:test",
		Intent: &janusv1.Intent{
			IntentId: "in", Principal: "pr_1", MandateRef: "m-1", Scope: "payments",
			Constraints: map[string]string{"region": "EU"},
		},
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Participant: "ag_1", Action: "payments.wire", EffectClass: class,
		}},
		GatePlan: []*janusv1.StepGates{{StepId: "wire", RuleId: "r", Require: gates}},
	}
	payload, err := proto.Marshal(begin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := saga.Apply(saga.State{}, saga.Event{Seq: 1, Kind: evidence.KindSagaBegin, Payload: payload})
	if err != nil {
		t.Fatalf("the fixture saga is not admissible: %v", err)
	}
	return s
}

func decide(t *testing.T, s saga.State, phase janusv1.GatePhase,
	declared map[string]saga.FactValue) gate.Decision {
	t.Helper()
	st, ok := s.Step("wire")
	if !ok {
		t.Fatal("no step")
	}
	return gate.Decide(phase, gate.Input{Saga: s, Step: st, Declared: declared})
}

// ---- the schema gate ----------------------------------------------------------

func TestSchemaGateNamesWhatIsMissing(t *testing.T) {
	schema := &janusv1.SchemaCheck{SchemaId: "payment.v1", Fields: []*janusv1.FieldSpec{
		{Name: "amount_minor", Type: janusv1.FactType_FACT_TYPE_NUMBER},
		{Name: "currency", Type: janusv1.FactType_FACT_TYPE_TEXT},
		{Name: "memo", Type: janusv1.FactType_FACT_TYPE_TEXT, Optional: true},
	}}
	s := stateWith(t, janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		req("shape", "SCHEMA", "PRE_RELEASE", schema))

	t.Run("complete", func(t *testing.T) {
		d := decide(t, s, preRelease, map[string]saga.FactValue{
			"amount_minor": gate.Number(100), "currency": gate.Text("EUR"),
		})
		if !d.Passed() {
			t.Fatalf("a complete declaration was refused: %s", d.Reason)
		}
	})

	t.Run("missing required field", func(t *testing.T) {
		d := decide(t, s, preRelease, map[string]saga.FactValue{"currency": gate.Text("EUR")})
		if d.Passed() {
			t.Fatal("a step with no amount was let through")
		}
		// The finding an operator can act on is "no amount was declared", not
		// "a comparison could not be evaluated".
		if !strings.Contains(d.Reason, "amount_minor") {
			t.Fatalf("the reason does not name the missing field: %s", d.Reason)
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		d := decide(t, s, preRelease, map[string]saga.FactValue{
			"amount_minor": gate.Text("100"), "currency": gate.Text("EUR"),
		})
		if d.Passed() {
			t.Fatal("an amount declared as text was accepted as a number")
		}
		if !strings.Contains(d.Reason, "expected number") {
			t.Fatalf("the reason does not say what was expected: %s", d.Reason)
		}
	})

	t.Run("optional field of the wrong type is still wrong", func(t *testing.T) {
		d := decide(t, s, preRelease, map[string]saga.FactValue{
			"amount_minor": gate.Number(100), "currency": gate.Text("EUR"),
			"memo": gate.Number(7),
		})
		if d.Passed() {
			t.Fatal("optional was treated as unchecked")
		}
	})
}

// ---- the policy gate ----------------------------------------------------------

func TestPolicyGateRefusesWhatItCannotEvaluate(t *testing.T) {
	s := stateWith(t, janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		req("approval", "POLICY", "PRE_RELEASE", &janusv1.PolicyCheck{
			Expr: "approved == true", Description: "payments need an approval",
		}))

	t.Run("holds", func(t *testing.T) {
		if d := decide(t, s, preRelease, map[string]saga.FactValue{
			"approved": gate.Flag(true),
		}); !d.Passed() {
			t.Fatalf("refused an approved payment: %s", d.Reason)
		}
	})

	t.Run("does not hold", func(t *testing.T) {
		d := decide(t, s, preRelease, map[string]saga.FactValue{"approved": gate.Flag(false)})
		if d.Passed() {
			t.Fatal("released an unapproved payment")
		}
		if !strings.Contains(d.Reason, "payments need an approval") {
			t.Fatalf("the reason is not the one a human wrote: %s", d.Reason)
		}
	})

	// The fact is simply absent. This is the case that decides whether the
	// system fails open or closed, and it is not hypothetical: a renamed field
	// in a participant's manifest produces exactly this.
	t.Run("fact absent", func(t *testing.T) {
		d := decide(t, s, preRelease, nil)
		if d.Passed() {
			t.Fatal("a step that declared nothing at all was let through")
		}
		if d.Verdict != janusv1.Verdict_VERDICT_FAIL {
			t.Fatalf("verdict is %s, want FAIL", d.Verdict)
		}
	})
}

// A gate may read the saga's authority as well as the step's arguments, which
// is what "why is this allowed" resolves to.
func TestPolicyGateCanReadTheIntentChain(t *testing.T) {
	s := stateWith(t, janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		req("mandate", "POLICY", "PRE_RELEASE", &janusv1.PolicyCheck{
			Expr: `intent.mandate_ref != "" and intent.constraint.region in ["EU", "TR"]`,
		}))
	if d := decide(t, s, preRelease, nil); !d.Passed() {
		t.Fatalf("a saga with a mandate and an EU constraint was refused: %s", d.Reason)
	}
}

// A step may not declare a fact in a namespace Janus derives, or it could tell
// a gate it was a different step.
func TestStepsCannotShadowDerivedFacts(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId: "sg", Mode: "supervised",
		Plan: []*janusv1.PlannedStep{{
			StepId: "s1", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
		}},
	}
	payload, err := proto.Marshal(begin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := saga.Apply(saga.State{}, saga.Event{Seq: 1, Kind: evidence.KindSagaBegin, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}

	prepare := &janusv1.StepPrepare{SagaId: "sg", StepId: "s1", Facts: []*janusv1.Fact{
		{Key: "step.effect_class", Value: &janusv1.Fact_Text{Text: "PURE"}},
	}}
	payload, err = proto.Marshal(prepare)
	if err != nil {
		t.Fatal(err)
	}
	_, err = saga.Apply(s, saga.Event{Seq: 2, Kind: evidence.KindStepPrepare, Payload: payload})
	if err == nil {
		t.Fatal("a step declared a fact in the reserved step. namespace")
	}
	if !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("the error does not say why: %v", err)
	}
}

// ---- the risk limit gate ------------------------------------------------------

func TestRiskLimitCapsMagnitudeAndBlastRadius(t *testing.T) {
	limit := &janusv1.RiskLimitCheck{
		Thresholds:      []*janusv1.RiskLimitCheck_Threshold{{Fact: "amount_minor", Max: 1000000}},
		MaxGatedEffects: 3,
		MaxResources:    2,
	}
	s := stateWith(t, janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		req("limit", "RISK_LIMIT", "PRE_RELEASE", limit))

	t.Run("at the limit", func(t *testing.T) {
		if d := decide(t, s, preRelease, map[string]saga.FactValue{
			"amount_minor": gate.Number(1000000),
		}); !d.Passed() {
			t.Fatalf("the threshold is inclusive: %s", d.Reason)
		}
	})

	t.Run("over the limit", func(t *testing.T) {
		d := decide(t, s, preRelease, map[string]saga.FactValue{"amount_minor": gate.Number(1000001)})
		if d.Passed() {
			t.Fatal("an amount over the limit was permitted")
		}
		if !strings.Contains(d.Reason, "1000001") || !strings.Contains(d.Reason, "1000000") {
			t.Fatalf("the reason states neither the amount nor the limit: %s", d.Reason)
		}
	})

	// A limit that cannot be applied is not a limit that passed.
	t.Run("the capped fact is absent", func(t *testing.T) {
		if d := decide(t, s, preRelease, nil); d.Passed() {
			t.Fatal("a step that declared no amount slipped past an amount limit")
		}
	})

	t.Run("the capped fact is not a number", func(t *testing.T) {
		if d := decide(t, s, preRelease, map[string]saga.FactValue{
			"amount_minor": gate.Text("lots"),
		}); d.Passed() {
			t.Fatal("a text amount slipped past a numeric limit")
		}
	})
}

func TestRiskLimitCapsIrreversibleStepsPerSaga(t *testing.T) {
	// Four irreversible steps under a cap of three. Each one is individually
	// within every amount threshold; the plan as a whole is not acceptable.
	var plan []*janusv1.PlannedStep
	var gates []*janusv1.StepGates
	limit := req("blast", "RISK_LIMIT", "PRE_RELEASE", &janusv1.RiskLimitCheck{MaxGatedEffects: 3})
	for _, id := range []string{"w1", "w2", "w3", "w4"} {
		plan = append(plan, &janusv1.PlannedStep{
			StepId: id, EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		})
		gates = append(gates, &janusv1.StepGates{
			StepId: id, RuleId: "r",
			Require: []*janusv1.GateRequirement{proto.Clone(limit).(*janusv1.GateRequirement)},
		})
	}
	begin := &janusv1.SagaBegin{
		SagaId: "sg", Mode: "supervised", GatePolicyVersion: "blake3:test",
		Plan: plan, GatePlan: gates,
	}
	payload, err := proto.Marshal(begin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := saga.Apply(saga.State{}, saga.Event{Seq: 1, Kind: evidence.KindSagaBegin, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}

	st, _ := s.Step("w1")
	d := gate.Decide(preRelease, gate.Input{Saga: s, Step: st})
	if d.Passed() {
		t.Fatal("a plan holding four irreversible steps passed a cap of three")
	}
	if !strings.Contains(d.Reason, "cannot be taken back") {
		t.Fatalf("the reason does not explain the cap: %s", d.Reason)
	}
}

// ---- the frontier gate --------------------------------------------------------

// A frontier check with no cross-saga view has not found the resource clear —
// it has not looked. Passing would make the safety property depend on whether
// the caller remembered to supply an index.
func TestFrontierGateRefusesWithoutAnIndex(t *testing.T) {
	s := stateWith(t, janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		req("frontier", "FRONTIER", "PRE_RELEASE", &janusv1.FrontierCheck{}))
	st, _ := s.Step("wire")

	d := gate.Decide(preRelease, gate.Input{Saga: s, Step: st}) // no Index
	if d.Verdict != janusv1.Verdict_VERDICT_FAIL {
		t.Fatalf("verdict is %s, want FAIL when nothing answered the question", d.Verdict)
	}
	if !strings.Contains(d.Reason, "no cross-saga index") {
		t.Fatalf("the reason does not say the check could not be run: %s", d.Reason)
	}
}

// ---- composition --------------------------------------------------------------

// Every requirement must pass. There is no quorum: a payment that fails the
// limit is not made acceptable by passing the schema check.
func TestCompositionRequiresUnanimity(t *testing.T) {
	s := stateWith(t, janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		req("shape", "SCHEMA", "PRE_RELEASE", &janusv1.SchemaCheck{
			SchemaId: "s", Fields: []*janusv1.FieldSpec{
				{Name: "amount_minor", Type: janusv1.FactType_FACT_TYPE_NUMBER},
			}}),
		req("limit", "RISK_LIMIT", "PRE_RELEASE", &janusv1.RiskLimitCheck{
			Thresholds: []*janusv1.RiskLimitCheck_Threshold{{Fact: "amount_minor", Max: 100}},
		}))

	d := decide(t, s, preRelease, map[string]saga.FactValue{"amount_minor": gate.Number(5000)})
	if d.Passed() {
		t.Fatal("passing the schema check excused failing the limit")
	}
	if d.Gate != janusv1.GateType_GATE_TYPE_RISK_LIMIT {
		t.Fatalf("the verdict blames %s rather than the check that refused", d.Gate)
	}
}

// The schema check runs first whatever order the policy lists it in, so the
// recorded reason is the useful one rather than a failed comparison against a
// value that was never there.
func TestSchemaIsDecidedBeforeChecksThatReadTheValues(t *testing.T) {
	s := stateWith(t, janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		req("limit", "RISK_LIMIT", "PRE_RELEASE", &janusv1.RiskLimitCheck{
			Thresholds: []*janusv1.RiskLimitCheck_Threshold{{Fact: "amount_minor", Max: 100}},
		}),
		req("shape", "SCHEMA", "PRE_RELEASE", &janusv1.SchemaCheck{
			SchemaId: "payment.v1", Fields: []*janusv1.FieldSpec{
				{Name: "amount_minor", Type: janusv1.FactType_FACT_TYPE_NUMBER},
			}}))

	d := decide(t, s, preRelease, nil)
	if d.Passed() {
		t.Fatal("a step declaring nothing was let through")
	}
	if d.Gate != janusv1.GateType_GATE_TYPE_SCHEMA {
		t.Fatalf("the refusal came from %s; the schema check should have reached it first", d.Gate)
	}
	if len(d.Decided) != 1 || d.Decided[0] != "shape" {
		t.Fatalf("decided %v, want the refusal to short-circuit after the schema check", d.Decided)
	}
}

// A phase with nothing due decides nothing, and says so, rather than recording
// a pass that looks like a gate approved something.
func TestAPhaseWithNothingDueDecidesNothing(t *testing.T) {
	s := stateWith(t, janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		req("approval", "POLICY", "PRE_RELEASE", &janusv1.PolicyCheck{Expr: "true"}))
	d := decide(t, s, preExecution, nil)
	if !d.Passed() {
		t.Fatalf("a phase with no requirements refused: %s", d.Reason)
	}
	if len(d.Decided) != 0 {
		t.Fatalf("decided %v, want nothing", d.Decided)
	}
	if !strings.Contains(d.Reason, "no gates are due") {
		t.Fatalf("the reason claims something was decided: %s", d.Reason)
	}
}

// The provenance record carries every check that ran, which is what an
// adverse-action explanation is generated from.
func TestTheDPRCarriesEveryCheckThatRan(t *testing.T) {
	s := stateWith(t, janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		req("shape", "SCHEMA", "PRE_RELEASE", &janusv1.SchemaCheck{
			SchemaId: "s", Fields: []*janusv1.FieldSpec{
				{Name: "amount_minor", Type: janusv1.FactType_FACT_TYPE_NUMBER},
			}}),
		req("limit", "RISK_LIMIT", "PRE_RELEASE", &janusv1.RiskLimitCheck{
			Thresholds: []*janusv1.RiskLimitCheck_Threshold{{Fact: "amount_minor", Max: 1000000}},
		}))

	d := decide(t, s, preRelease, map[string]saga.FactValue{"amount_minor": gate.Number(100)})
	dpr := d.DPR("dpr-1")
	if got := len(dpr.GetValidations()); got != 2 {
		t.Fatalf("the DPR holds %d validations, want one per check", got)
	}
	if len(dpr.GetGrounds()) != 2 {
		t.Fatalf("the DPR holds %d grounds, want one per check", len(dpr.GetGrounds()))
	}
	if dpr.GetIntentRef() != "in" {
		t.Fatalf("the DPR does not link to the intent: %q", dpr.GetIntentRef())
	}
	for _, v := range dpr.GetValidations() {
		if v.GetRequirementId() == "" {
			t.Fatal("a validation does not say which requirement it is")
		}
		if v.GetReason() == "" {
			t.Fatal("a validation records no reason, so the DPR explains nothing")
		}
	}

	// The composite verdict points at the DPR and accounts for both checks.
	verdict := d.GateVerdict("ev-9")
	if verdict.GetDprRef() != "ev-9" {
		t.Fatalf("the verdict does not cite its provenance record")
	}
	if len(verdict.GetDecided()) != 2 {
		t.Fatalf("the verdict accounts for %v, want both requirements", verdict.GetDecided())
	}
	if verdict.GetGate() != janusv1.GateType_GATE_TYPE_COMPOSITE {
		t.Fatalf("a unanimous pass is attributed to %s rather than to the composition",
			verdict.GetGate())
	}
}

// ---- admission ----------------------------------------------------------------

func planWith(steps ...*janusv1.PlannedStep) *janusv1.SagaBegin {
	return &janusv1.SagaBegin{
		SagaId: "sg", Mode: "supervised",
		Intent: &janusv1.Intent{IntentId: "in", MandateRef: "m-1"},
		Plan:   steps,
	}
}

func TestAdmissionRefusesAnIrreversibleStepNoRuleCovers(t *testing.T) {
	e := gate.NewEngine(mustPolicy(t, wiresPolicy))
	begin := planWith(&janusv1.PlannedStep{
		StepId: "send", Action: "email.send",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE,
	})
	err := e.Admit(begin)
	if err == nil {
		t.Fatal("an irreversible step with no rule behind it was admitted")
	}
	if !strings.Contains(err.Error(), "needs a gate standing in for the compensation") {
		t.Fatalf("the error does not explain the gap: %v", err)
	}
}

func TestAdmissionAllowsACompensableStepNoRuleCovers(t *testing.T) {
	e := gate.NewEngine(mustPolicy(t, wiresPolicy))
	begin := planWith(&janusv1.PlannedStep{
		StepId: "book", Action: "booking.create",
		EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
		CompensationAction: "booking.cancel",
	})
	if err := e.Admit(begin); err != nil {
		t.Fatalf("a step that declares how to undo itself needs no gate: %v", err)
	}
	if len(begin.GetGatePlan()) != 0 {
		t.Fatal("a step no rule matched was given requirements anyway")
	}
	if begin.GetGatePolicyVersion() == "" {
		t.Fatal("the saga records no policy version, so nothing pins what it was admitted under")
	}
}

func TestAdmissionRefusesACompensableStepWithNeitherUndoNorRule(t *testing.T) {
	e := gate.NewEngine(mustPolicy(t, wiresPolicy))
	begin := planWith(&janusv1.PlannedStep{
		StepId: "book", Action: "booking.create",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
	})
	if err := e.Admit(begin); err == nil {
		t.Fatal("a step with no compensation and no gate was admitted")
	}
}

// The gate plan a saga is admitted with is what it carries for the rest of its
// life, so it has to be the policy's answer rather than a summary of it.
func TestAdmissionRecordsTheResolvedRequirements(t *testing.T) {
	e := gate.NewEngine(mustPolicy(t, wiresPolicy))
	begin := planWith(&janusv1.PlannedStep{
		StepId: "wire", Action: "payments.wire",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
	})
	if err := e.Admit(begin); err != nil {
		t.Fatal(err)
	}
	if got := len(begin.GetGatePlan()); got != 1 {
		t.Fatalf("the gate plan covers %d steps, want 1", got)
	}
	sg := begin.GetGatePlan()[0]
	if sg.GetRuleId() != "wires" {
		t.Fatalf("the plan cites rule %q, want the one that matched", sg.GetRuleId())
	}
	if got := len(sg.GetRequire()); got != 3 {
		t.Fatalf("the plan carries %d requirements, want every one the rule lists", got)
	}
	if begin.GetGatePolicyVersion() != e.Version() {
		t.Fatal("the pinned version is not the engine's policy")
	}

	// And the saga it produces has to be admissible to the state machine too,
	// which enforces the same invariant from the other side.
	payload, err := proto.Marshal(begin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saga.Apply(saga.State{},
		saga.Event{Seq: 1, Kind: evidence.KindSagaBegin, Payload: payload}); err != nil {
		t.Fatalf("the engine admitted a plan the state machine refuses: %v", err)
	}
}

// A gate that only runs after an unrecallable effect has fired is not
// protection, and admission is where that has to be caught.
func TestAdmissionRefusesProtectionThatArrivesTooLate(t *testing.T) {
	e := gate.NewEngine(mustPolicy(t, `{
	  "id": "test.late",
	  "rules": [{
	    "id": "late",
	    "match": {"effect_classes": ["IRREVERSIBLE_IMMEDIATE"]},
	    "require": [{"id":"a","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"true"}}]
	  }]
	}`))
	begin := planWith(&janusv1.PlannedStep{
		StepId: "send", Action: "email.send",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE,
	})
	err := e.Admit(begin)
	if err == nil {
		t.Fatal("an immediate effect gated only after the fact was admitted")
	}
	if !strings.Contains(err.Error(), "already done") {
		t.Fatalf("the error does not explain the ordering problem: %v", err)
	}
}

// The mirror: a held effect whose gates all run before the step produces it.
func TestAdmissionRefusesAHeldEffectNothingJudges(t *testing.T) {
	e := gate.NewEngine(mustPolicy(t, `{
	  "id": "test.early",
	  "rules": [{
	    "id": "early",
	    "match": {"effect_classes": ["IRREVERSIBLE_GATED"]},
	    "require": [{"id":"a","gate":"POLICY","phase":"PRE_EXECUTION","policy":{"expr":"true"}}]
	  }]
	}`))
	begin := planWith(&janusv1.PlannedStep{
		StepId: "wire", Action: "payments.wire",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
	})
	if err := e.Admit(begin); err == nil {
		t.Fatal("an effect the outbox will hold was admitted with nothing to judge it")
	}
}

func TestExplainDescribesWhatAPlanOwes(t *testing.T) {
	e := gate.NewEngine(mustPolicy(t, wiresPolicy))
	out := e.Explain(planWith(&janusv1.PlannedStep{
		StepId: "wire", Action: "payments.wire",
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
	}))
	for _, want := range []string{"test.wires", "wire", "shape", "limit", "approval",
		"PRE_EXECUTION", "PRE_RELEASE", "payments need an approval"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the explanation does not mention %q:\n%s", want, out)
		}
	}
}
