package gate

import (
	"slices"
	"strconv"
	"strings"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
)

// What a gate is allowed to know.
//
// The fact set is closed on purpose. A gate sees the values the step declared,
// plus a fixed set Janus derives from the saga's own record — what the step is,
// what class of effect it claims, who authorised the saga. It does not see the
// arguments in the content store, the model's reasoning, or anything it would
// have to fetch. Every value it decides on is in the evidence log, which is what
// makes the decision re-derivable years later by someone holding nothing but
// the log.
//
// The derived names live under reserved prefixes the step cannot write, so a
// step cannot claim to be a different step, or to belong to a mandate it does
// not. The saga state machine refuses a step that tries.

// Derived fact names. They are constants rather than string literals scattered
// through the code because a policy that misspells one gets an unknown-fact
// refusal, and a build that misspells one would get a silent behaviour change.
const (
	FactSagaID          = "saga.id"
	FactSagaMode        = "saga.mode"
	FactSagaGatedSteps  = "saga.gated_steps"
	FactSagaResources   = "saga.resources"
	FactStepID          = "step.id"
	FactStepParticipant = "step.participant"
	FactStepAction      = "step.action"
	FactStepEffectClass = "step.effect_class"
	FactStepAttempt     = "step.attempt"
	FactStepCompensable = "step.compensable"
	FactIntentID        = "intent.id"
	FactIntentPrincipal = "intent.principal"
	FactIntentOrigin    = "intent.originator"
	FactIntentMandate   = "intent.mandate_ref"
	FactIntentScope     = "intent.scope"
	// FactIntentConstraint is the prefix for the intent's constraint map, so a
	// policy can read a limit that travelled with the mandate rather than one
	// baked into the policy document.
	FactIntentConstraint = "intent.constraint."
)

// Environment builds the fact set a step's gates are evaluated against.
//
// declared is what the step itself put forward. At a pre-execution gate that is
// the proposal being judged, and the step has not recorded anything yet; at a
// release gate it is what the step recorded when it ran. Passing it in rather
// than reading it off the projection is what lets the same code judge a
// proposal and re-derive a decision from the log.
func Environment(s saga.State, st *saga.Step, declared map[string]saga.FactValue) Facts {
	f := make(Facts, len(declared)+16)
	for k, v := range declared {
		f[k] = Value{Type: v.Type, Text: v.Text, Num: v.Number, Flag: v.Flag}
	}

	f[FactSagaID] = TextValue(s.SagaID)
	f[FactSagaMode] = TextValue(s.Mode)
	f[FactSagaGatedSteps] = NumberValue(int64(countIrreversible(s)))
	f[FactSagaResources] = NumberValue(int64(len(saga.TouchedResources(s))))

	f[FactStepID] = TextValue(st.ID)
	f[FactStepParticipant] = TextValue(st.Participant)
	f[FactStepAction] = TextValue(st.Action)
	f[FactStepEffectClass] = TextValue(shortClass(st.EffectClass))
	// The attempt about to be made, not the one already made. A policy that
	// says "a third attempt needs a closer look" is asking about the attempt it
	// is being consulted for.
	f[FactStepAttempt] = NumberValue(int64(st.Attempt) + 1)
	f[FactStepCompensable] = FlagValue(st.Compensable())

	// Facts other steps published from what they found.
	//
	// Only from steps that have sealed. A finding from a step that might yet be
	// refused is a finding that can be withdrawn, and a gate resting on one
	// would be resting on a fact the saga may go on to disown — the same
	// reasoning that makes dependenciesSealed require SEALED rather than "the
	// result arrived".
	for _, id := range s.Order {
		other := s.Steps[id]
		if other.Status != saga.StepSealed && other.Status != saga.StepCommitted {
			continue
		}
		for k, v := range other.Published {
			f[saga.PublishedFactPrefix+id+"."+k] = Value{
				Type: v.Type, Text: v.Text, Num: v.Number, Flag: v.Flag,
			}
		}
	}

	f[FactIntentID] = TextValue(s.IntentID)
	f[FactIntentPrincipal] = TextValue(s.Intent.Principal)
	f[FactIntentOrigin] = TextValue(s.Intent.Originator)
	f[FactIntentMandate] = TextValue(s.Intent.MandateRef)
	f[FactIntentScope] = TextValue(s.Intent.Scope)
	for k, v := range s.Intent.Constraints {
		f[FactIntentConstraint+k] = TextValue(v)
	}
	return f
}

// countIrreversible counts steps whose effects cannot be taken back, which is
// the blast radius a risk limit is usually asked about.
func countIrreversible(s saga.State) int {
	n := 0
	for _, id := range s.Order {
		switch s.Steps[id].EffectClass {
		case janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
			janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE:
			n++
		}
	}
	return n
}

// FactsFromProto converts recorded facts into the declared form, for audit,
// which reads them back out of the log rather than off a live projection.
func FactsFromProto(in []*janusv1.Fact) map[string]saga.FactValue {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]saga.FactValue, len(in))
	for _, f := range in {
		switch v := f.GetValue().(type) {
		case *janusv1.Fact_Text:
			out[f.GetKey()] = saga.FactValue{Type: janusv1.FactType_FACT_TYPE_TEXT, Text: v.Text}
		case *janusv1.Fact_Number:
			out[f.GetKey()] = saga.FactValue{Type: janusv1.FactType_FACT_TYPE_NUMBER, Number: v.Number}
		case *janusv1.Fact_Flag:
			out[f.GetKey()] = saga.FactValue{Type: janusv1.FactType_FACT_TYPE_FLAG, Flag: v.Flag}
		}
	}
	return out
}

// Proto renders an environment for the wire, in sorted key order, so an
// answerer is shown the same closed set of facts an expression gate decides on
// — the step's own, the ones Janus derives, and what earlier steps published —
// and nothing a gate is not allowed to know.
func (f Facts) Proto() []*janusv1.Fact {
	values := make(map[string]saga.FactValue, len(f))
	for k, v := range f {
		values[k] = saga.FactValue{Type: v.Type, Text: v.Text, Number: v.Num, Flag: v.Flag}
	}
	return FactsToProto(values)
}

// FactsToProto renders declared facts for recording, in sorted key order so two
// coordinators holding the same facts write the same bytes.
func FactsToProto(in map[string]saga.FactValue) []*janusv1.Fact {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	out := make([]*janusv1.Fact, 0, len(keys))
	for _, k := range keys {
		v := in[k]
		f := &janusv1.Fact{Key: k}
		switch v.Type {
		case janusv1.FactType_FACT_TYPE_TEXT:
			f.Value = &janusv1.Fact_Text{Text: v.Text}
		case janusv1.FactType_FACT_TYPE_NUMBER:
			f.Value = &janusv1.Fact_Number{Number: v.Number}
		case janusv1.FactType_FACT_TYPE_FLAG:
			f.Value = &janusv1.Fact_Flag{Flag: v.Flag}
		}
		out = append(out, f)
	}
	return out
}

// Text builds a declared text fact, for callers assembling a step.
func Text(v string) saga.FactValue {
	return saga.FactValue{Type: janusv1.FactType_FACT_TYPE_TEXT, Text: v}
}

// Number builds a declared numeric fact. Money belongs here, in minor units.
func Number(v int64) saga.FactValue {
	return saga.FactValue{Type: janusv1.FactType_FACT_TYPE_NUMBER, Number: v}
}

// Flag builds a declared boolean fact.
func Flag(v bool) saga.FactValue {
	return saga.FactValue{Type: janusv1.FactType_FACT_TYPE_FLAG, Flag: v}
}

// describeFacts renders a fact set for an error message, sorted and with the
// derived names left out — an operator reading why a payment was refused wants
// the amount, not a restatement of the saga id they already have.
func describeFacts(f Facts) string {
	keys := make([]string, 0, len(f))
	for k := range f {
		if isDerived(k) {
			continue
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+f[k].String())
	}
	if len(parts) == 0 {
		return "no facts"
	}
	return strings.Join(parts, ", ")
}

func isDerived(key string) bool {
	for _, ns := range saga.ReservedFactNamespaces {
		if strings.HasPrefix(key, ns) {
			return true
		}
	}
	return false
}

// quantity renders a count with its noun, so messages read as sentences.
func quantity(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}
