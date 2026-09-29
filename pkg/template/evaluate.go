package template

import (
	"encoding/hex"
	"fmt"
	"sort"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Template conformance.
//
// # Why this is not the manifest harness
//
// `registry.Evaluate` runs a participant's declared actions against sandbox
// doubles, because a manifest's claims are about *behaviour*: this compensation
// restores, this limit refuses, two deliveries under one key land once. Nothing
// but execution can falsify that.
//
// A template claims nothing about behaviour. Its three claims are **shape**
// ("later sagas will look like this"), **slots** ("this is the whole of what
// varies") and **provenance** ("these runs are where it came from"), and every
// one of them is a statement about runs that are already in the log. So this
// harness re-reads them. It executes nothing, needs no sandbox, and its verdict
// is reproducible from the evidence by anyone holding the same log — which is a
// stronger property than the manifest side can offer, not a weaker one.
//
// It is tempting to call the honest harness
// a replay question belonging to the spot-replay daemon. Replay *re-executes*
// sagas, which tests whether participants still behave — the manifest's claim,
// already covered. Re-matching the recorded log is a different question and is
// the template's own.
//
// # What it cannot do
//
// It cannot say the shape is a good one. That a template describes the runs it
// was extracted from is exactly what extraction guaranteed; re-checking it
// catches a document edited afterwards and nothing else. **Whether those runs
// were representative is a judgement, and no harness produces it** — which is
// why `janus-registry template extract` prints and stops. A clean report here
// means "this document still says what the log says it said", not "this is a
// shape worth confining sagas to".

// HarnessVersion identifies the template conformance code that produced a
// verdict.
//
// Distinct from `registry.HarnessVersion`, and deliberately: a report is only as
// meaningful as the harness that reached it, and an audit reading a template's
// EVALUATED event has to be able to tell a run of this from a string somebody
// typed.
const HarnessVersion = "janus-template-conformance/1"

// Check names, as they appear in a report.
const (
	CheckProvenance = "provenance_matches_log"
	CheckShape      = "shape_matches_runs"
	CheckSlots      = "slots_cover_runs"
	CheckChildren   = "children_match_declared"
)

// Trigger names this harness can cover. They are `registry`'s constants, spelt
// here because `pkg/template` may not import `pkg/registry`.
const (
	triggerShapeChange = "shape_change"
	triggerSlotChange  = "slot_change"
)

// Evaluate checks a template against the runs it claims to come from.
//
// `runs` is the caller's log walk — the same one `Extract` takes, and the CLI
// fills both the same way. Every saga the template's provenance names must be
// offered, and nothing else: a report assembled from a *different* set of runs
// would be checking the document against evidence it does not cite.
//
// `childTemplates` is keyed by **template id** — the documents this template's
// steps name — where `Extract`'s `children` is keyed by **step id**. The two are
// the same Go type and mean different things, which is why they have different
// names: `Extract` is told which template each step should delegate to, and this
// is handed the documents to check that against.
//
// `TriggersCovered` is computed from what passed rather than set to a constant.
// A report that named `shape_change` while its shape check failed would be the
// exact thing this repository exists to prevent — a control that reads as
// working — and worse here than elsewhere, because that string is the only thing
// standing between a reshaped template and activation.
func Evaluate(t *Template, runs []Run,
	childTemplates map[string]*Template) (*janusv1.EvaluationReport, error) {

	if err := t.Validate(); err != nil {
		return nil, err
	}
	report := &janusv1.EvaluationReport{
		HarnessVersion: HarnessVersion,
		Sandbox:        "re-matched its source runs",
	}

	byID, err := runsByProvenance(t, runs)
	if err != nil {
		return nil, err
	}

	report.Checks = append(report.Checks, checkProvenance(t, byID))
	shape := checkShape(t, byID)
	slots := checkSlots(t, byID)
	report.Checks = append(report.Checks, shape, slots)
	kids := checkDeclaredChildren(t, byID, childTemplates)
	if kids != nil {
		report.Checks = append(report.Checks, kids)
	}

	report.Passed = true
	for _, c := range report.GetChecks() {
		if !c.GetSkipped() && !c.GetPassed() {
			report.Passed = false
		}
	}

	// A trigger is covered only by the checks that answer it. `shape_change`
	// asks whether the evidence still covers this DAG, so the child references
	// -- part of the shape -- have to hold too.
	if shape.GetPassed() && (kids == nil || kids.GetPassed()) {
		report.TriggersCovered = append(report.TriggersCovered, triggerShapeChange)
	}
	if slots.GetPassed() {
		report.TriggersCovered = append(report.TriggersCovered, triggerSlotChange)
	}
	sort.Strings(report.TriggersCovered)
	return report, nil
}

// runsByProvenance refuses a report assembled from the wrong runs.
//
// Not a check in the report but an error, because the two are different things:
// a failed check says the template is wrong, and this says the *evaluation* is —
// there is nothing to report a verdict about.
func runsByProvenance(t *Template, runs []Run) (map[string]Run, error) {
	offered := make(map[string]Run, len(runs))
	for _, r := range runs {
		offered[r.State.SagaID] = r
	}
	out := make(map[string]Run, len(t.Provenance.SagaIDs))
	for _, id := range t.Provenance.SagaIDs {
		r, ok := offered[id]
		if !ok {
			return nil, fmt.Errorf("%w: template %s@%s names saga %q in its provenance and it "+
				"was not offered; a verdict reached without it would be about evidence the "+
				"document does not cite", ErrInvalid, t.TemplateID, t.Version, id)
		}
		out[id] = r
	}
	for id := range offered {
		if _, cited := out[id]; !cited {
			return nil, fmt.Errorf("%w: saga %q was offered and template %s@%s does not name it; "+
				"a template is checked against the runs it claims, not against a set somebody "+
				"chose afterwards", ErrInvalid, id, t.TemplateID, t.Version)
		}
	}
	return out, nil
}

// checkProvenance is the one claim a template makes that the log can settle.
//
// Item 55 said so itself: "an auditor should read `Provenance.EvidenceRoots`
// against the log instead: that is the one claim a template makes which the log
// can check." Nothing did until this.
func checkProvenance(t *Template, byID map[string]Run) *janusv1.EvaluationReport_Check {
	p := t.Provenance
	fail := func(format string, args ...any) *janusv1.EvaluationReport_Check {
		return &janusv1.EvaluationReport_Check{
			Name: CheckProvenance, Action: t.TemplateID,
			Detail: fmt.Sprintf(format, args...),
		}
	}
	// The three lists agreeing in length is `Validate`'s rule, checked before
	// this runs and not repeated here — a second copy would drift from the
	// first, and the branch would be unreachable meanwhile.
	if p.Runs < MinimumRuns {
		return fail("the document claims %d run(s); %d is the fewest a shape may be extracted "+
			"from, and a template asserting fewer was not produced by extraction", p.Runs,
			MinimumRuns)
	}
	for i, id := range p.SagaIDs {
		r := byID[id]
		if got := hex.EncodeToString(r.State.EvidenceRoot); got != p.EvidenceRoots[i] {
			return fail("the document says saga %q committed at evidence root %s and the log "+
				"says %s; the roots are what make the provenance checkable rather than "+
				"believed", id, short(p.EvidenceRoots[i]), short(got))
		}
		// The other two things provenance asserts about each run, both of which
		// `Extract` refuses a mismatch on. A hand-written document can assert
		// either, and until they are read here a template could claim to come
		// from supervised runs that were exploratory, or name a saga that
		// compensated.
		if r.State.Status != saga.StatusCommitted {
			return fail("the document names saga %q as a source run and the log says it is "+
				"%s; a shape taken from a run that did not succeed is a shape nobody has "+
				"evidence works", id, r.State.Status)
		}
		if got := r.Begin.GetMode(); got != p.ExtractedFrom {
			return fail("the document says it was extracted from %q runs and saga %q ran in "+
				"mode %q; which mode a shape came from is what a reader weighs it by",
				p.ExtractedFrom, id, got)
		}
	}
	return &janusv1.EvaluationReport_Check{
		Name: CheckProvenance, Action: t.TemplateID, Passed: true,
		Detail: fmt.Sprintf("%d run(s) named, each committed at the evidence root the document "+
			"records", p.Runs),
	}
}

// checkShape re-matches the document against the plans it was extracted from.
//
// What this catches is a template edited after extraction — a step's participant
// changed, a dependency dropped — which is the one way a registered document can
// stop describing its own provenance. `Match` compares in both directions, so a
// step added to the document and a step removed from it both fail.
func checkShape(t *Template, byID map[string]Run) *janusv1.EvaluationReport_Check {
	for _, id := range t.Provenance.SagaIDs {
		if err := Match(t, byID[id].Begin.GetPlan()); err != nil {
			return &janusv1.EvaluationReport_Check{
				Name: CheckShape, Action: t.TemplateID,
				Detail: fmt.Sprintf("saga %q, which this document names as a source run, does "+
					"not have its shape: %v", id, err),
			}
		}
	}
	return &janusv1.EvaluationReport_Check{
		Name: CheckShape, Action: t.TemplateID, Passed: true,
		Detail: fmt.Sprintf("every one of the %d source run(s) matches the declared shape",
			t.Provenance.Runs),
	}
}

// checkSlots asks whether the enumerated free part still covers the runs.
//
// A slot removed from the document by hand is the case: the shape still matches,
// and a fact one of the source runs carried now has no slot — so the template
// would refuse the very runs it claims to describe. The whole claim of a
// template is that the free part is enumerated (`Slot`), and this is where that
// claim meets evidence.
func checkSlots(t *Template, byID map[string]Run) *janusv1.EvaluationReport_Check {
	for _, id := range t.Provenance.SagaIDs {
		st := byID[id].State
		for _, stepID := range st.Order {
			step := st.Steps[stepID]
			if step == nil || len(step.Facts) == 0 {
				continue
			}
			names := make([]string, 0, len(step.Facts))
			for name := range step.Facts {
				names = append(names, name)
			}
			sort.Strings(names)
			if err := ConfinesFacts(t, stepID, names); err != nil {
				return &janusv1.EvaluationReport_Check{
					Name: CheckSlots, Action: t.TemplateID,
					Detail: fmt.Sprintf("saga %q, a source run, carries facts this document "+
						"declares no slot for: %v", id, err),
				}
			}
		}
	}
	return &janusv1.EvaluationReport_Check{
		Name: CheckSlots, Action: t.TemplateID, Passed: true,
		Detail: fmt.Sprintf("%d slot(s) cover every fact the source runs declared", len(t.Slots)),
	}
}

// checkDeclaredChildren re-checks the declared-children claim against the same runs.
//
// Skipped, not passed, when the document declares no children: a report saying
// "checked" about something it did not check is worse than no report
// (`registry.Evaluate` makes the same distinction for an irreversible action).
// A skipped check does not fail the report, and `shape_change` is still covered
// -- there is no child claim to falsify.
func checkDeclaredChildren(t *Template, byID map[string]Run,
	childTemplates map[string]*Template) *janusv1.EvaluationReport_Check {

	declared := map[string]string{}
	for _, s := range t.Steps {
		if s.ChildTemplate != "" {
			declared[s.StepID] = s.ChildTemplate
		}
	}
	if len(declared) == 0 {
		return nil
	}
	for stepID, want := range declared {
		child, held := childTemplates[want]
		if !held {
			return &janusv1.EvaluationReport_Check{
				Name: CheckChildren, Action: t.TemplateID,
				Detail: fmt.Sprintf("step %q confines its children to template %q, which was "+
					"not offered, so the claim could not be checked against the runs", stepID,
					want),
			}
		}
		for _, id := range t.Provenance.SagaIDs {
			r := byID[id]
			begin, spawned := r.Children[stepID]
			if !spawned {
				return &janusv1.EvaluationReport_Check{
					Name: CheckChildren, Action: t.TemplateID,
					Detail: fmt.Sprintf("step %q confines its children to %q and source run %q "+
						"did not delegate at that step; the constraint rests on nothing",
						stepID, want, id),
				}
			}
			if err := Match(child, begin.GetPlan()); err != nil {
				return &janusv1.EvaluationReport_Check{
					Name: CheckChildren, Action: t.TemplateID,
					Detail: fmt.Sprintf("step %q confines its children to %q and the sub-saga "+
						"source run %q spawned does not have that shape: %v", stepID, want, id, err),
				}
			}
		}
	}
	return &janusv1.EvaluationReport_Check{
		Name: CheckChildren, Action: t.TemplateID, Passed: true,
		Detail: fmt.Sprintf("%d declared child template(s) match what every source run spawned",
			len(declared)),
	}
}

func short(root string) string {
	if len(root) <= 12 {
		return root
	}
	return root[:12] + "…"
}
