package gate_test

import (
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/saga"
)

// modePolicy scopes a gate to supervised sagas, which is what makes the mode
// load-bearing and is the arrangement the vocabulary check exists to protect.
func modePolicy(t *testing.T) *gate.Policy {
	t.Helper()
	p := &gate.Policy{
		ID: "gate.mode.test",
		Rules: []gate.Rule{{
			ID: "supervised-effects-need-a-person",
			// COMPENSABLE, not IRREVERSIBLE_GATED, and the step below declares a
			// compensation. That combination is what makes this the real hole:
			// an irreversible step with no matching rule is refused anyway,
			// because `admissibleWithoutGates` insists that an effect which
			// cannot be taken back has a gate standing in for the compensation
			// it cannot have. A compensable step that declares its undo is
			// admissible with no gates at all — so when the mode-scoped rule
			// silently fails to match, the saga is admitted, ungated, and
			// nothing says anything.
			Match: gate.Match{
				EffectClasses: []string{"COMPENSABLE"},
				Modes:         []string{string(saga.ModeSupervised)},
			},
			Require: []gate.Requirement{{
				ID: "four-eyes", Gate: gate.GateHuman, Phase: gate.PhasePreRelease,
				Human: &gate.HumanSpec{Roles: []string{"credit-officer"}, Quorum: 1},
			}},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func modeBegin(mode string) *janusv1.SagaBegin {
	return &janusv1.SagaBegin{
		SagaId: "sg_mode",
		Mode:   mode,
		Intent: &janusv1.Intent{
			IntentId: "in_mode", Principal: "pr_bank",
			Originator: "human:desk@bank", MandateRef: "m", Scope: "s",
		},
		Plan: []*janusv1.PlannedStep{{
			StepId: "st_wire", Participant: "tool_payments", Action: "payments.wire",
			EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: "payments.refund",
		}},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
	}
}

// TestAMisspelledModeIsRefusedRatherThanUnscoped is the finding Phase 6e fixes,
// written as the thing that used to happen.
//
// The mode arrives from the caller and its only use was as a match key. A policy
// rule scoped to `modes: ["supervised"]` applied to a saga that said
// "supervised" and did not apply to one that said "supervized" — so a typo, or a
// caller who preferred fewer gates, removed the gate. The failure was silent and
// in the direction that removes protection.
func TestAMisspelledModeIsRefusedRatherThanUnscoped(t *testing.T) {
	e := gate.NewEngine(modePolicy(t))

	// The correct spelling: the rule applies and the step gets its gate.
	good := modeBegin(string(saga.ModeSupervised))
	if err := e.Admit(good); err != nil {
		t.Fatalf("a supervised saga was not admissible: %v", err)
	}
	if len(good.GetGatePlan()) != 1 {
		t.Fatalf("a supervised saga was admitted with %d gated steps, want 1 — the rest of "+
			"this test proves nothing if the rule does not apply", len(good.GetGatePlan()))
	}

	// One letter different. Before 6e this was admitted with no gates at all.
	bad := modeBegin("supervized")
	err := e.Admit(bad)
	if err == nil {
		t.Fatalf("a saga declaring mode %q was admitted with %d gated steps — one letter "+
			"removed the four-eyes gate and nothing objected", bad.GetMode(),
			len(bad.GetGatePlan()))
	}
	for _, want := range []string{"exploratory", "supervised", "crystallized"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, and the realistic way to reach it is a "+
				"typo: %v", want, err)
		}
	}
}

// TestAnEmptyModeStaysValid.
//
// Every saga in the fixture corpus was recorded without a mode, and defaulting
// the empty string to something would change which rules match for histories
// already written down. An unscoped saga asks for the rules that apply to
// everything, which is a coherent thing to ask for.
func TestAnEmptyModeStaysValid(t *testing.T) {
	e := gate.NewEngine(modePolicy(t))
	begin := modeBegin("")
	err := e.Admit(begin)
	if err == nil {
		// It is admissible only if the step is admissible without gates; what
		// matters here is that it was not refused *for its mode*.
		return
	}
	if strings.Contains(err.Error(), "not one of exploratory") {
		t.Fatalf("an unscoped saga was refused for its mode: %v", err)
	}
}

// TestCrystallizedIsRefusedUntilThereAreTemplates.
//
// Crystallized mode means "a validated template with the model confined
// to declared slots". There is no template registry, so admitting one would
// promise a confinement nothing implements — and a mode that reads as a
// restriction and imposes none is the failure this whole sub-phase is about.
func TestCrystallizedIsRefusedUntilThereAreTemplates(t *testing.T) {
	e := gate.NewEngine(modePolicy(t))
	err := e.Admit(modeBegin(string(saga.ModeCrystallized)))
	if err == nil {
		t.Fatal("a crystallized saga was admitted, but nothing in this build can confine one " +
			"to a template")
	}
	if !strings.Contains(err.Error(), "template") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}
