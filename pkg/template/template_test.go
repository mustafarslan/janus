package template_test

import (
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/template"
)

func plan(action string) []*janusv1.PlannedStep {
	return []*janusv1.PlannedStep{
		{
			StepId: "st_check", Participant: "tool_credit", Action: "credit.score",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
		},
		{
			StepId: "st_pay", Participant: "tool_payments", Action: action,
			EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: "payments.refund",
			DependsOn:          []string{"st_check"},
		},
	}
}

// run builds one committed saga with the given facts on st_pay.
func run(id string, facts map[string]saga.FactValue) template.Run {
	st := &saga.Step{ID: "st_pay", Facts: facts}
	return template.Run{
		State: saga.State{
			SagaID: id, Status: saga.StatusCommitted,
			Order: []string{"st_pay"}, Steps: map[string]*saga.Step{"st_pay": st},
			EvidenceRoot: []byte("root-" + id),
		},
		Begin: &janusv1.SagaBegin{SagaId: id, Mode: "supervised", Plan: plan("payments.wire")},
	}
}

func text(v string) saga.FactValue {
	return saga.FactValue{Type: janusv1.FactType_FACT_TYPE_TEXT, Text: v}
}

func number(v int64) saga.FactValue {
	return saga.FactValue{Type: janusv1.FactType_FACT_TYPE_NUMBER, Number: v}
}

func extract(t *testing.T, runs ...template.Run) *template.Template {
	t.Helper()
	tpl, err := template.Extract("tpl_loan", "1.0.0", "pr_bank", 2, runs, nil)
	if err != nil {
		t.Fatalf("extracting: %v", err)
	}
	return tpl
}

// TestATemplateIsTheShapeAndTheSlotsAreWhatVaried.
func TestATemplateIsTheShapeAndTheSlotsAreWhatVaried(t *testing.T) {
	tpl := extract(t,
		run("sg1", map[string]saga.FactValue{"amount": number(100), "currency": text("EUR")}),
		run("sg2", map[string]saga.FactValue{"amount": number(250), "currency": text("EUR")}),
		run("sg3", map[string]saga.FactValue{"amount": number(900), "currency": text("EUR")}),
	)

	if len(tpl.Steps) != 2 {
		t.Fatalf("the template has %d steps, want the 2 the plan declared", len(tpl.Steps))
	}
	if len(tpl.Slots) != 2 {
		t.Fatalf("the template declares %d slots, want 2: %+v", len(tpl.Slots), tpl.Slots)
	}

	byName := map[string]template.Slot{}
	for _, s := range tpl.Slots {
		byName[s.Name] = s
	}
	if got := byName["amount"]; got.Kind != "NUMBER" || len(got.Observed) != 3 {
		t.Errorf("the amount slot is %s with %d observed values, want NUMBER with 3: %+v",
			got.Kind, len(got.Observed), got)
	}
	// A slot with one observed value across every run is a constant somebody has
	// not noticed, and the template says so rather than hiding it.
	if got := byName["currency"]; len(got.Observed) != 1 {
		t.Errorf("the currency slot observed %d values; it never varied and the template "+
			"should record that: %+v", len(got.Observed), got)
	}

	// Provenance an auditor can check: roots, not just ids.
	if tpl.Provenance.Runs != 3 || len(tpl.Provenance.EvidenceRoots) != 3 {
		t.Errorf("provenance claims %d runs with %d roots", tpl.Provenance.Runs,
			len(tpl.Provenance.EvidenceRoots))
	}
	if tpl.Provenance.ExtractedFrom != "supervised" {
		t.Errorf("provenance says the runs were %q", tpl.Provenance.ExtractedFrom)
	}
}

// TestATemplateIsNotExtractedFromTooFewRuns is the "crystallising an accident"
// refusal made enforceable.
//
// A template extracted from two runs that happened to take the same branch would
// confine every later saga to that branch, and the confinement would read as a
// control while being a coincidence. No number makes that impossible; this is the
// number below which nobody can pretend otherwise.
func TestATemplateIsNotExtractedFromTooFewRuns(t *testing.T) {
	_, err := template.Extract("tpl_loan", "1.0.0", "pr_bank", 2, []template.Run{
		run("sg1", nil), run("sg2", nil),
	}, nil)
	if err == nil {
		t.Fatal("a template was extracted from two runs")
	}
	if !strings.Contains(err.Error(), "coincidence") {
		t.Errorf("the refusal does not say why the count matters: %v", err)
	}
}

// TestShapesAreNotMerged: a template covering "roughly these steps" would be a
// confinement with an argument about what roughly means, and the argument would
// happen after somebody had already run under it.
func TestShapesAreNotMerged(t *testing.T) {
	odd := run("sg3", nil)
	odd.Begin.Plan = plan("payments.wire.large")

	_, err := template.Extract("tpl_loan", "1.0.0", "pr_bank", 2, []template.Run{
		run("sg1", nil), run("sg2", nil), odd,
	}, nil)
	if err == nil {
		t.Fatal("two different shapes were merged into one template")
	}
	if !strings.Contains(err.Error(), "different shape") {
		t.Errorf("the refusal does not name the reason: %v", err)
	}
}

// TestOnlyCommittedRunsAreExtractedFrom: a shape taken from a run that failed is
// a shape nobody has evidence works.
func TestOnlyCommittedRunsAreExtractedFrom(t *testing.T) {
	bad := run("sg3", nil)
	bad.State.Status = saga.StatusCompensated

	_, err := template.Extract("tpl_loan", "1.0.0", "pr_bank", 2, []template.Run{
		run("sg1", nil), run("sg2", nil), bad,
	}, nil)
	if err == nil {
		t.Fatal("a template was extracted from a run that did not commit")
	}
}

// TestMatchRefusesEveryKindOfDeviation, and reports all of them at once —
// somebody handed a plan that does not match is going to fix it, and one
// difference at a time makes that a conversation.
func TestMatchRefusesEveryKindOfDeviation(t *testing.T) {
	tpl := extract(t, run("sg1", nil), run("sg2", nil), run("sg3", nil))

	if err := template.Match(tpl, plan("payments.wire")); err != nil {
		t.Fatalf("the plan the template was extracted from does not match it: %v", err)
	}

	for _, tc := range []struct {
		name string
		plan []*janusv1.PlannedStep
		want string
	}{
		{"a different action", plan("payments.wire.large"), "action"},
		{"an extra step", append(plan("payments.wire"), &janusv1.PlannedStep{
			StepId: "st_extra", Participant: "tool_payments", Action: "payments.notify",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
		}), "not in the template"},
		{"a missing step", plan("payments.wire")[:1], "not in the plan"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := template.Match(tpl, tc.plan)
			if err == nil {
				t.Fatal("the deviation was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name the deviation (%s): %v", tc.want, err)
			}
		})
	}

	// A different participant *and* a different action reports both.
	deviant := plan("payments.wire.large")
	deviant[1].Participant = "tool_other"
	err := template.Match(tpl, deviant)
	if err == nil {
		t.Fatal("two deviations were accepted")
	}
	if !strings.Contains(err.Error(), "action") || !strings.Contains(err.Error(), "participant") {
		t.Errorf("only one of two deviations was reported: %v", err)
	}
}

// TestConfinesFactsRefusesAnUndeclaredFact is the "confined to declared slots"
// half of crystallized mode.
func TestConfinesFactsRefusesAnUndeclaredFact(t *testing.T) {
	tpl := extract(t,
		run("sg1", map[string]saga.FactValue{"amount": number(1)}),
		run("sg2", map[string]saga.FactValue{"amount": number(2)}),
		run("sg3", map[string]saga.FactValue{"amount": number(3)}),
	)

	if err := template.ConfinesFacts(tpl, "st_pay", []string{"amount"}); err != nil {
		t.Fatalf("a declared slot was refused: %v", err)
	}
	err := template.ConfinesFacts(tpl, "st_pay", []string{"amount", "override"})
	if err == nil {
		t.Fatal("a fact the template declares no slot for was accepted; the free part is " +
			"not enumerated and the template confines nothing")
	}
	if !strings.Contains(err.Error(), "override") {
		t.Errorf("the refusal does not name the undeclared fact: %v", err)
	}
}
