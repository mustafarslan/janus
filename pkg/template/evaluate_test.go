package template_test

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/template"
)

// sourceRuns builds three committed runs and the template extracted from them,
// which is the state every test here starts from: a document whose claims are
// all true, so that each test can make exactly one of them false.
func sourceRuns(t *testing.T) (*template.Template, []template.Run) {
	t.Helper()
	runs := []template.Run{
		run("sg1", map[string]saga.FactValue{"amount": number(100), "currency": text("EUR")}),
		run("sg2", map[string]saga.FactValue{"amount": number(250), "currency": text("EUR")}),
		run("sg3", map[string]saga.FactValue{"amount": number(400), "currency": text("GBP")}),
	}
	tpl, err := template.Extract("tpl_loan", "1.0.0", "pr_bank", 2, runs, nil)
	if err != nil {
		t.Fatalf("extracting: %v", err)
	}
	return tpl, runs
}

func evaluate(t *testing.T, tpl *template.Template, runs []template.Run) *janusv1.EvaluationReport {
	t.Helper()
	rep, err := template.Evaluate(tpl, runs, nil)
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	return rep
}

func checkNamed(rep *janusv1.EvaluationReport, name string) *janusv1.EvaluationReport_Check {
	for _, c := range rep.GetChecks() {
		if c.GetName() == name {
			return c
		}
	}
	return nil
}

// A template straight out of extraction evaluates clean, and says which
// triggers that covers.
//
// The covered list is the product. It is what is required before a reshaped
// template can be activated, and before this evaluator the only way to produce
// it was to type the strings.
func TestAFreshlyExtractedTemplateEvaluatesCleanAndCoversItsTriggers(t *testing.T) {
	tpl, runs := sourceRuns(t)
	rep := evaluate(t, tpl, runs)

	if !rep.GetPassed() {
		t.Fatalf("a template evaluated against the runs it was extracted from did not "+
			"pass: %+v", rep.GetChecks())
	}
	if rep.GetHarnessVersion() != template.HarnessVersion {
		t.Fatalf("the report does not name the harness that produced it: %q",
			rep.GetHarnessVersion())
	}
	want := []string{"shape_change", "slot_change"}
	if got := rep.GetTriggersCovered(); !slices.Equal(got, want) {
		t.Fatalf("the report covers %v, want %v", got, want)
	}
	// The child check is skipped rather than passed when nothing is declared:
	// a report saying "checked" about something it did not check is worse than
	// no report.
	if c := checkNamed(rep, template.CheckChildren); c != nil {
		t.Fatalf("a template declaring no children reported a children check: %+v", c)
	}
}

// The evidence roots are checked against the log, which is the one claim a
// template makes that the log can settle.
//
// Item 55 said so itself and nothing did it: the roots were recorded at
// extraction and never read again, so a document could name three sagas, carry
// three roots that belong to nothing, and be activated on a report somebody
// typed.
func TestAProvenanceThatTheLogDoesNotBearOutFails(t *testing.T) {
	tpl, runs := sourceRuns(t)
	tpl.Provenance.EvidenceRoots[1] = hex.EncodeToString([]byte("not-the-root"))

	rep := evaluate(t, tpl, runs)
	if rep.GetPassed() {
		t.Fatal("a template naming an evidence root the log does not have evaluated clean")
	}
	c := checkNamed(rep, template.CheckProvenance)
	if c == nil || c.GetPassed() {
		t.Fatalf("the provenance check did not fail: %+v", c)
	}
	if !strings.Contains(c.GetDetail(), "sg2") {
		t.Fatalf("the failure does not name the run that disagrees: %s", c.GetDetail())
	}

	// And the run count is a claim too: a hand-written document asserting fewer
	// runs than a shape may be extracted from must not evaluate clean. The
	// three lists have to stay the same length, because `Validate` refuses a
	// document whose count disagrees with them before this harness sees it.
	tpl, runs = sourceRuns(t)
	tpl.Provenance.Runs = 2
	tpl.Provenance.SagaIDs = tpl.Provenance.SagaIDs[:2]
	tpl.Provenance.EvidenceRoots = tpl.Provenance.EvidenceRoots[:2]
	rep = evaluate(t, tpl, runs[:2])
	if rep.GetPassed() {
		t.Fatal("a template claiming two source runs evaluated clean; three is the fewest a " +
			"shape may be extracted from")
	}
	if c := checkNamed(rep, template.CheckProvenance); c == nil ||
		!strings.Contains(c.GetDetail(), "fewest") {
		t.Fatalf("the failure does not say why the count matters: %+v", c)
	}

	// The other two things provenance asserts about each run. `Extract` refuses
	// a mismatch on both, so only a hand-written document can carry one -- which
	// is exactly the document this harness exists to catch.
	tpl, runs = sourceRuns(t)
	runs[2].State.Status = saga.StatusCompensated
	if rep = evaluate(t, tpl, runs); rep.GetPassed() {
		t.Fatal("a template naming a run that compensated evaluated clean")
	}

	tpl, runs = sourceRuns(t)
	tpl.Provenance.ExtractedFrom = "exploratory"
	rep = evaluate(t, tpl, runs)
	if rep.GetPassed() {
		t.Fatal("a template claiming to come from exploratory runs, over supervised ones, " +
			"evaluated clean; which mode a shape came from is what a reader weighs it by")
	}
}

// A document edited after extraction no longer matches the runs it names, and
// the shape check is what catches it.
//
// This is the case the harness exists for. Extraction guarantees the shape
// describes its sources; nothing guaranteed the *registered* document was the
// one extraction produced.
func TestATemplateEditedAfterExtractionFailsItsShapeCheck(t *testing.T) {
	tpl, runs := sourceRuns(t)
	tpl.Steps[1].Participant = "tool_other"

	rep := evaluate(t, tpl, runs)
	if rep.GetPassed() {
		t.Fatal("a template whose step was repointed after extraction evaluated clean " +
			"against the runs it claims to describe")
	}
	if c := checkNamed(rep, template.CheckShape); c == nil || c.GetPassed() {
		t.Fatalf("the shape check did not fail: %+v", c)
	}
	// And it does not claim to have covered the trigger it just failed.
	if slices.Contains(rep.GetTriggersCovered(), "shape_change") {
		t.Fatalf("a report whose shape check failed claims to cover shape_change: %v",
			rep.GetTriggersCovered())
	}
}

// A slot removed by hand still matches the shape and stops covering the runs.
//
// The two checks are separate because the failures are: the template would
// refuse the very runs it claims to describe, while its DAG is untouched. If
// one check covered both, a slot edit would report as a shape failure and an
// operator would go looking at the wrong half of the document.
func TestASlotRemovedAfterExtractionFailsAndUncoversItsTrigger(t *testing.T) {
	tpl, runs := sourceRuns(t)
	tpl.Slots = slices.DeleteFunc(tpl.Slots, func(s template.Slot) bool {
		return s.Name == "currency"
	})

	rep := evaluate(t, tpl, runs)
	if rep.GetPassed() {
		t.Fatal("a template that dropped a slot its source runs carried evaluated clean")
	}
	if c := checkNamed(rep, template.CheckShape); c == nil || !c.GetPassed() {
		t.Fatalf("dropping a slot was reported as a shape failure: %+v", c)
	}
	if c := checkNamed(rep, template.CheckSlots); c == nil || c.GetPassed() {
		t.Fatalf("the slots check did not fail: %+v", c)
	}
	if got := rep.GetTriggersCovered(); !slices.Equal(got, []string{"shape_change"}) {
		t.Fatalf("the report covers %v; the shape still holds and the slots do not", got)
	}
}

// A verdict may only be reached against the runs the document cites.
//
// An error rather than a failed check, because the two say different things: a
// failed check says the template is wrong, and this says the *evaluation* is —
// there is nothing to reach a verdict about. Both directions, because offering
// a subset is as much a different question as offering extra.
func TestAVerdictIsOnlyReachedAgainstTheRunsTheDocumentCites(t *testing.T) {
	tpl, runs := sourceRuns(t)

	if _, err := template.Evaluate(tpl, runs[:2], nil); err == nil {
		t.Fatal("a template was evaluated without one of the runs it names")
	}

	extra := append(append([]template.Run(nil), runs...),
		run("sg4", map[string]saga.FactValue{"amount": number(1)}))
	_, err := template.Evaluate(tpl, extra, nil)
	if err == nil {
		t.Fatal("a template was evaluated against a run it does not name")
	}
	if !strings.Contains(err.Error(), "sg4") {
		t.Fatalf("the refusal does not name the uncited run: %v", err)
	}
}

// The declared child claim is re-checked, and a failure uncovers shape_change.
//
// The child reference is part of the shape (`steps.<id>.child_template` fires
// shape_change), so a report whose child check failed must not claim to have
// covered a shape change — the evidence it rests on is exactly what did not
// hold.
func TestADeclaredChildIsRecheckedAndItsFailureUncoversShapeChange(t *testing.T) {
	runs := []template.Run{
		spawning("sg1", childPlan()), spawning("sg2", childPlan()), spawning("sg3", childPlan()),
	}
	children := map[string]*template.Template{"st_pay": childTemplate()}
	tpl, err := template.Extract("tpl_loan", "1.0.0", "pr_bank", 2, runs, children)
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]*template.Template{"tpl_settle": childTemplate()}

	rep, err := template.Evaluate(tpl, runs, held)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.GetPassed() {
		t.Fatalf("a template with a checked child reference did not pass: %+v", rep.GetChecks())
	}
	if c := checkNamed(rep, template.CheckChildren); c == nil || !c.GetPassed() {
		t.Fatalf("the children check did not run: %+v", c)
	}

	// The child template now says something else. The parent is unchanged and
	// its claim about what it delegates to is no longer true.
	moved := childTemplate()
	moved.Steps[0].Action = "ledger.reverse"
	rep, err = template.Evaluate(tpl, runs, map[string]*template.Template{"tpl_settle": moved})
	if err != nil {
		t.Fatal(err)
	}
	if rep.GetPassed() {
		t.Fatal("a template whose declared child no longer has the shape its source runs " +
			"spawned evaluated clean")
	}
	if slices.Contains(rep.GetTriggersCovered(), "shape_change") {
		t.Fatalf("a report whose children check failed claims to cover shape_change: %v",
			rep.GetTriggersCovered())
	}
}
