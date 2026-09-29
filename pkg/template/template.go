// Package template is crystallization: a saga shape extracted from runs
// that already happened, which later sagas can be confined to.
//
// # What a template is for
//
// Crystallized mode has one meaning — "a validated
// template, LLM confined to declared slots" — and the value is narrower than it
// sounds. A template does not make a saga safe. It makes a saga *shaped*: the
// steps, their order, their participants and their effect classes are fixed in
// advance, and the only thing a model gets to decide is what goes in the slots.
//
// That is worth having because it converts an open-ended question — what will
// this agent do — into a closed one — which of these declared values did it
// choose. The second question has an answer a person can check before the saga
// runs.
//
// # What it does not do
//
// **A template removes no gates.** Gate resolution is unchanged, and the mode is
// still only a match key in the policy. What confinement buys is that a policy
// author *may* write lighter rules for crystallized mode and be able to justify
// it, because the plan can no longer be anything. The mechanism never trades
// anything away by itself, and a deployment that writes no crystallized-specific
// rules gets exactly the gates it had.
package template

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"
	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// ErrInvalid means a template could not confine anything.
var ErrInvalid = errors.New("template: invalid")

// Template is a saga shape, versioned and pinnable.
type Template struct {
	// Version is what a saga pins, e.g. "1.0.0".
	Version string `json:"version" cbor:"1,keyasint"`
	// TemplateID names the shape, e.g. "tpl_loan_intake".
	TemplateID string `json:"template_id" cbor:"2,keyasint"`
	// Principal is the legal entity answerable for this template, and is what
	// the signature over it is checked against — the same rule a participant
	// manifest follows.
	Principal string `json:"principal" cbor:"3,keyasint"`
	// Steps are the fixed shape, in the order they were declared.
	Steps []Step `json:"steps" cbor:"4,keyasint"`
	// Slots are the facts a saga may vary. A fact a saga carries that is not
	// declared here is a deviation, because the whole claim of a template is
	// that the free part is enumerated.
	Slots []Slot `json:"slots,omitempty" cbor:"5,keyasint,omitempty"`
	// Risk is the tier this shape runs at, in the registry's vocabulary: 1 is
	// highest risk, 4 is lowest.
	Risk uint32 `json:"risk" cbor:"6,keyasint"`
	// Provenance is where the shape came from.
	Provenance Provenance `json:"provenance" cbor:"7,keyasint"`
}

// Step is one node of the fixed shape.
//
// It carries what admission compares and nothing else. The facts a step ran with
// are not here: those are what the slots describe, and a template that recorded
// the values it was extracted from would be a recording rather than a shape.
type Step struct {
	StepID             string `json:"step_id" cbor:"1,keyasint"`
	Participant        string `json:"participant" cbor:"2,keyasint"`
	Action             string `json:"action" cbor:"3,keyasint"`
	EffectClass        string `json:"effect_class" cbor:"4,keyasint"`
	CompensationAction string `json:"compensation_action,omitempty" cbor:"5,keyasint,omitempty"`
	// DependsOn is sorted, so two extractions of the same shape produce the same
	// document.
	DependsOn []string `json:"depends_on,omitempty" cbor:"6,keyasint,omitempty"`
	// ChildTemplate is the template a sub-saga spawned by this step must pin.
	//
	// It is what makes a crystallized *tree* confined rather than a confined
	// saga with unconfined delegates. A step that declares it refuses
	// a child pinning anything else; a step that does not declare it refuses a
	// child at all, because a template extracted from runs that never spawned
	// says nothing about what spawning would do.
	//
	// An id, not an id@version. Pinning the version here deadlocks against
	// supersession: the declared version is superseded the moment its successor is
	// activated, and a superseded template does not admit a saga -- so the child
	// pinning the declared version is refused as not ACTIVE and the child
	// pinning the active version is refused by this constraint. The version
	// question belongs to the child template's own lifecycle, which the
	// `shape_change` trigger is what guards.
	//
	// It is deliberately absent from `Shape`: `Shape` is computed from
	// `StepsOfPlan`, a plan carries no child reference, and clustering runs by a
	// field one side cannot produce would put every run in its own cluster.
	ChildTemplate string `json:"child_template,omitempty" cbor:"7,keyasint,omitempty"`
}

// Slot is one fact a saga may choose.
type Slot struct {
	// Name is the fact's key, as the step carries it.
	Name string `json:"name" cbor:"1,keyasint"`
	// StepID is the step the fact belongs to. A slot is scoped to its step: the
	// same key on two steps is two slots, because they are two decisions.
	StepID string `json:"step_id" cbor:"2,keyasint"`
	// Kind is the fact's type as the evidence records it — TEXT, NUMBER, FLAG. A slot whose observed values disagreed about type is a slot the
	// extraction refuses to declare.
	Kind string `json:"kind" cbor:"3,keyasint"`
	// Observed are the distinct values seen while extracting, sorted. They are
	// kept because they are the honest answer to "how much did this actually
	// vary" — a slot with one observed value across forty runs is a constant
	// somebody has not noticed, and a reader should be able to see that.
	//
	// They are *not* an allowed-value list. Confinement is to the slot, not to
	// its history; a template that refused a value merely because it had not
	// been seen would be a lookup table.
	Observed []string `json:"observed,omitempty" cbor:"4,keyasint,omitempty"`
}

// Provenance says which runs a template was extracted from.
//
// The evidence roots are the point. A list of saga ids is a claim; a list of
// evidence roots is something a reader can check against the log, and a template
// asserting a shape "seen in forty runs" is only worth anything if the forty
// runs can be found.
type Provenance struct {
	// Runs is how many sagas were clustered.
	Runs int `json:"runs" cbor:"1,keyasint"`
	// SagaIDs are those sagas, sorted.
	SagaIDs []string `json:"saga_ids" cbor:"2,keyasint"`
	// EvidenceRoots are their commit roots, in the same order, hex encoded.
	EvidenceRoots []string `json:"evidence_roots" cbor:"3,keyasint"`
	// ExtractedFrom names the mode those runs were in. A template is meant to be
	// extracted from *successful supervised runs*, so a template built from
	// anything else is recording where it came from rather than being refused —
	// a reader deciding whether to activate it should see that.
	ExtractedFrom string `json:"extracted_from" cbor:"4,keyasint"`
}

// Shape is the canonical string form of a template's step DAG.
//
// Two sagas belong in one cluster when their shapes are equal. It is exact
// rather than approximate: a template covering "roughly these steps" would be a
// confinement with an argument about what roughly means, and the argument would
// happen after somebody had already run under it.
func Shape(steps []Step) string {
	var b strings.Builder
	for _, s := range steps {
		deps := append([]string(nil), s.DependsOn...)
		sort.Strings(deps)
		fmt.Fprintf(&b, "%s|%s|%s|%s|%s\n",
			s.StepID, s.Participant, s.Action, s.EffectClass,
			strings.Join(deps, ","))
	}
	return b.String()
}

// StepsOfPlan reads the shape out of a recorded plan.
func StepsOfPlan(plan []*janusv1.PlannedStep) []Step {
	out := make([]Step, 0, len(plan))
	for _, p := range plan {
		deps := append([]string(nil), p.GetDependsOn()...)
		sort.Strings(deps)
		out = append(out, Step{
			StepID:             p.GetStepId(),
			Participant:        p.GetParticipant(),
			Action:             p.GetAction(),
			EffectClass:        p.GetEffectClass().String(),
			CompensationAction: p.GetCompensationAction(),
			DependsOn:          deps,
		})
	}
	return out
}

// Validate refuses a template that could not confine anything.
func (t *Template) Validate() error {
	switch {
	case t == nil:
		return fmt.Errorf("%w: the template is absent", ErrInvalid)
	case t.TemplateID == "":
		return fmt.Errorf("%w: a template needs an id, because a saga pins it by name", ErrInvalid)
	case t.Version == "":
		return fmt.Errorf("%w: template %q has no version, so a pin could not say which "+
			"shape it meant", ErrInvalid, t.TemplateID)
	case t.Principal == "":
		return fmt.Errorf("%w: template %q names no principal, so there is nobody the "+
			"signature over it could be checked against", ErrInvalid, t.TemplateID)
	case len(t.Steps) == 0:
		return fmt.Errorf("%w: template %q declares no steps, and a shape with no steps "+
			"confines nothing", ErrInvalid, t.TemplateID)
	case t.Risk == 0 || t.Risk > 4:
		return fmt.Errorf("%w: template %q declares risk tier %d; the registry's tiers are "+
			"1 (highest) to 4", ErrInvalid, t.TemplateID, t.Risk)
	}

	seen := map[string]struct{}{}
	for _, s := range t.Steps {
		if s.StepID == "" {
			return fmt.Errorf("%w: template %q has a step with no id", ErrInvalid, t.TemplateID)
		}
		if _, dup := seen[s.StepID]; dup {
			return fmt.Errorf("%w: template %q declares step %q twice, so a plan could "+
				"satisfy it two different ways", ErrInvalid, t.TemplateID, s.StepID)
		}
		seen[s.StepID] = struct{}{}
	}
	for _, s := range t.Steps {
		for _, d := range s.DependsOn {
			if _, ok := seen[d]; !ok {
				return fmt.Errorf("%w: template %q has step %q depending on %q, which the "+
					"template does not declare", ErrInvalid, t.TemplateID, s.StepID, d)
			}
		}
	}
	for _, sl := range t.Slots {
		if sl.Name == "" || sl.StepID == "" {
			return fmt.Errorf("%w: template %q has a slot with no name or no step",
				ErrInvalid, t.TemplateID)
		}
		if _, ok := seen[sl.StepID]; !ok {
			return fmt.Errorf("%w: template %q declares slot %q on step %q, which the "+
				"template does not declare", ErrInvalid, t.TemplateID, sl.Name, sl.StepID)
		}
	}
	if t.Provenance.Runs != len(t.Provenance.SagaIDs) ||
		len(t.Provenance.SagaIDs) != len(t.Provenance.EvidenceRoots) {
		return fmt.Errorf("%w: template %q claims %d runs but names %d sagas and %d roots; "+
			"provenance a reader cannot check against the log is a claim rather than evidence",
			ErrInvalid, t.TemplateID, t.Provenance.Runs,
			len(t.Provenance.SagaIDs), len(t.Provenance.EvidenceRoots))
	}
	return nil
}

// Encode returns the canonical CBOR of a template.
//
// Canonical because the content address is taken over these bytes and a
// signature covers them: two encodings of one document that hashed differently
// would make a pin ambiguous, which is the failure a content address exists to
// prevent.
func Encode(t *Template) ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	opts, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("template: encoder: %w", err)
	}
	out, err := opts.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("template: encode %s: %w", t.TemplateID, err)
	}
	return out, nil
}

// Decode reads a template from its canonical bytes, and validates it.
//
// Validated on the way in rather than trusted: these bytes came out of a log,
// and a template that cannot confine anything must not become the thing a saga
// is confined to.
func Decode(in []byte) (*Template, error) {
	var t Template
	if err := cbor.Unmarshal(in, &t); err != nil {
		return nil, fmt.Errorf("template: decode: %w", err)
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return &t, nil
}
