package template

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
)

// MinimumRuns is the fewest runs a template may be extracted from.
//
// It exists because of the failure this whole idea invites: **crystallising an
// accident**. A template extracted from two runs that happened to take the same
// branch would confine every later saga to that branch, and the confinement
// would read as a control while being a coincidence. There is no number that
// makes that impossible; three is the number below which nobody should be able
// to pretend otherwise, and the refusal names the count so a reader can argue
// with it.
const MinimumRuns = 3

// Run is one completed saga offered to the extractor.
type Run struct {
	// State is the saga's projection, replayed from the log.
	State saga.State
	// Begin is what its SAGA_BEGIN declared. The shape is taken from here rather
	// than from the projection, because the plan is what a later saga will be
	// compared against — a template extracted from what *happened* would confine
	// future sagas to the outcome of past ones, which is a different and much
	// stranger claim.
	Begin *janusv1.SagaBegin
	// Children are the SAGA_BEGINs of the sub-sagas this run's steps spawned,
	// keyed by the spawning step's id.
	//
	// The caller fills this because reading them is a log walk and `Extract` is
	// pure. `State.Steps[id].Child` says *that* a step delegated and to which
	// saga id; what that saga's plan was is on its own SAGA_BEGIN, which is a
	// second read the extractor cannot do for itself.
	Children map[string]*janusv1.SagaBegin
}

// Extract builds a template from runs that share one shape.
//
// Every run must be committed, and every run must have the same shape. Two
// shapes are not merged into one template with optional steps: a template
// covering "roughly these steps" would be a confinement with an argument about
// what roughly means, and the argument would happen after somebody had already
// run under it.
//
// # children, and why the operator has to name them
//
// `children` maps a **spawning step's id** to the template its sub-sagas must
// pin — note that `Evaluate`'s `childTemplates` is keyed by template id instead,
// because it is handed documents to check rather than told which step gets which.
// It is supplied rather than derived, and that is not a shortcut — it is forced
// by what a run contains. Templates are extracted from *supervised* runs, and a
// supervised run's children are supervised sagas, which pin no template. There
// is nothing in the evidence to read the answer out of.
//
// So the operator asserts it and this function **checks** the assertion, the way
// a change record is recomputed rather than believed: the named
// template must `Match` every one of those runs' child plans. An assertion
// nobody checks is the shape of every defect this repository keeps finding.
//
// The cost is an ordering: templates are registered leaves-first, and a parent
// cannot be extracted until its children's templates exist.
func Extract(id, version, principal string, risk uint32, runs []Run,
	children map[string]*Template) (*Template, error) {
	if len(runs) < MinimumRuns {
		return nil, fmt.Errorf("%w: %d run(s) is not enough to extract a shape from; a "+
			"template built from fewer than %d is a coincidence somebody would be confined "+
			"to", ErrInvalid, len(runs), MinimumRuns)
	}

	ordered := append([]Run(nil), runs...)
	sort.Slice(ordered, func(i, j int) bool {
		return ordered[i].State.SagaID < ordered[j].State.SagaID
	})

	steps := StepsOfPlan(ordered[0].Begin.GetPlan())
	want := Shape(steps)
	mode := ordered[0].Begin.GetMode()

	prov := Provenance{Runs: len(ordered), ExtractedFrom: mode}
	seenSaga := map[string]struct{}{}
	// factName -> stepID -> observed values, and the type each was seen as.
	observed := map[string]map[string]map[string]struct{}{}
	kinds := map[string]map[string]string{}

	for _, r := range ordered {
		id := r.State.SagaID
		if _, dup := seenSaga[id]; dup {
			return nil, fmt.Errorf("%w: saga %q was offered twice, which would make the run "+
				"count say more than the evidence does", ErrInvalid, id)
		}
		seenSaga[id] = struct{}{}

		if r.State.Status != saga.StatusCommitted {
			return nil, fmt.Errorf("%w: saga %q is %s; a template is extracted from runs that "+
				"succeeded, because a shape taken from a run that failed is a shape nobody "+
				"has evidence works", ErrInvalid, id, r.State.Status)
		}
		if got := Shape(StepsOfPlan(r.Begin.GetPlan())); got != want {
			return nil, fmt.Errorf("%w: saga %q has a different shape from %q, and shapes are "+
				"not merged — a template covering both would confine neither",
				ErrInvalid, id, ordered[0].State.SagaID)
		}
		if r.Begin.GetMode() != mode {
			return nil, fmt.Errorf("%w: saga %q ran in mode %q and %q ran in %q; a template "+
				"cannot say which mode it was extracted from if the runs disagree",
				ErrInvalid, id, r.Begin.GetMode(), ordered[0].State.SagaID, mode)
		}
		if len(r.State.EvidenceRoot) == 0 {
			return nil, fmt.Errorf("%w: saga %q committed without an evidence root, so its "+
				"place in this template's provenance could not be checked against the log",
				ErrInvalid, id)
		}
		if err := checkChildren(r, children); err != nil {
			return nil, err
		}

		prov.SagaIDs = append(prov.SagaIDs, id)
		prov.EvidenceRoots = append(prov.EvidenceRoots, hex.EncodeToString(r.State.EvidenceRoot))

		for _, stepID := range r.State.Order {
			st := r.State.Steps[stepID]
			if st == nil {
				continue
			}
			for name, v := range st.Facts {
				kind := factKind(v)
				if observed[name] == nil {
					observed[name] = map[string]map[string]struct{}{}
					kinds[name] = map[string]string{}
				}
				if prev, ok := kinds[name][stepID]; ok && prev != kind {
					return nil, fmt.Errorf("%w: fact %q on step %q is %s in one run and %s in "+
						"another; a slot whose type is not settled cannot be declared",
						ErrInvalid, name, stepID, prev, kind)
				}
				kinds[name][stepID] = kind
				if observed[name][stepID] == nil {
					observed[name][stepID] = map[string]struct{}{}
				}
				observed[name][stepID][factText(v)] = struct{}{}
			}
		}
	}

	withChildren := append([]Step(nil), steps...)
	for i := range withChildren {
		if child, ok := children[withChildren[i].StepID]; ok {
			withChildren[i].ChildTemplate = child.TemplateID
		}
	}
	t := &Template{
		Version: version, TemplateID: id, Principal: principal,
		Steps: withChildren, Risk: risk, Provenance: prov,
	}
	for name, byStep := range observed {
		for stepID, values := range byStep {
			vals := make([]string, 0, len(values))
			for v := range values {
				vals = append(vals, v)
			}
			sort.Strings(vals)
			t.Slots = append(t.Slots, Slot{
				Name: name, StepID: stepID, Kind: kinds[name][stepID], Observed: vals,
			})
		}
	}
	sort.Slice(t.Slots, func(i, j int) bool {
		if t.Slots[i].StepID != t.Slots[j].StepID {
			return t.Slots[i].StepID < t.Slots[j].StepID
		}
		return t.Slots[i].Name < t.Slots[j].Name
	})

	if err := t.Validate(); err != nil {
		return nil, err
	}
	return t, nil
}

func factKind(v saga.FactValue) string {
	switch v.Type {
	case janusv1.FactType_FACT_TYPE_NUMBER:
		return "NUMBER"
	case janusv1.FactType_FACT_TYPE_FLAG:
		return "FLAG"
	case janusv1.FactType_FACT_TYPE_TEXT:
		return "TEXT"
	default:
		return v.Type.String()
	}
}

func factText(v saga.FactValue) string {
	switch v.Type {
	case janusv1.FactType_FACT_TYPE_NUMBER:
		return strconv.FormatInt(v.Number, 10)
	case janusv1.FactType_FACT_TYPE_FLAG:
		return strconv.FormatBool(v.Flag)
	default:
		return v.Text
	}
}

// checkChildren holds one run's delegation against what the operator declared.
//
// Three refusals, and each one closes a way of ending up with a template that
// confines less than it appears to.
//
//   - A step that spawned in one run and not another. Which steps delegate is
//     part of the shape, and `Shape` cannot see it — spawns are declared on
//     STEP_PREPARE, not on the plan. Merging those runs would produce a template
//     whose child constraint applied to some sagas and not others, which is the
//     "roughly these steps" argument arriving by a different door.
//   - A step that spawned with no declared child template. The template would
//     then say nothing about the sub-saga, which would then run unconfined.
//   - A declared child template whose shape the run's actual child does not
//     match, or a declaration for a step that never spawned. Both are claims
//     about delegation that the evidence does not support, and a claim nobody
//     checks is what this function exists to prevent.
//
// Between them the second and third also settle which steps delegate across the
// cluster, from both sides — see the comment where the third one ends.
func checkChildren(r Run, children map[string]*Template) error {
	spawned := map[string]struct{}{}
	for _, stepID := range r.State.Order {
		st := r.State.Steps[stepID]
		if st == nil || st.Child == nil {
			continue
		}
		spawned[stepID] = struct{}{}

		declared, named := children[stepID]
		if !named {
			return fmt.Errorf("%w: in saga %q step %q delegates to sub-saga %q and no child "+
				"template was named for it; a template whose step spawns and does not say what "+
				"the child is confined to stops confining at that step",
				ErrInvalid, r.State.SagaID, stepID, st.Child.SagaID)
		}
		begin, ok := r.Children[stepID]
		if !ok || begin == nil {
			return fmt.Errorf("%w: step %q of saga %q delegates to sub-saga %q, whose "+
				"beginning was not offered, so the claim that it has the shape of %q could "+
				"not be checked against the log",
				ErrInvalid, stepID, r.State.SagaID, st.Child.SagaID, declared.TemplateID)
		}
		if err := Match(declared, begin.GetPlan()); err != nil {
			return fmt.Errorf("%w: step %q of saga %q was declared to delegate to template "+
				"%s, and the sub-saga it actually spawned does not have that shape: %w",
				ErrInvalid, stepID, r.State.SagaID, declared.TemplateID, err)
		}
	}

	for stepID := range children {
		if _, did := spawned[stepID]; !did {
			return fmt.Errorf("%w: a child template was named for step %q, which does not "+
				"delegate in saga %q; declaring a child nobody spawned puts a constraint in "+
				"the template that no run is evidence for",
				ErrInvalid, stepID, r.State.SagaID)
		}
	}

	// Cross-run agreement about *which* steps delegate falls out of the two
	// checks above and does not need a third.
	//
	// `Shape` cannot see delegation — spawns are on STEP_PREPARE, not on the
	// plan — so two runs with identical plans can branch differently, and that
	// still has to be refused. It is, from both sides: a step the first run
	// spawned and this one did not is caught when this run reaches "named for a
	// step that does not delegate", and one this run spawned and the first did
	// not is caught when the first run reaches "spawned and no child template
	// was named". Adding an explicit comparison would put a control here that
	// nothing can reach, which is the failure this repository keeps finding.
	return nil
}
