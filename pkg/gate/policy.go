// Package gate decides whether an effect may proceed.
//
// The saga engine says what a step did; the outbox says when an effect may
// leave. This package is what stands between them and says whether it may leave
// at all. Phase 2 shipped the shape of that decision — a step reaches GATED and
// waits for a verdict — with a coordinator that supplied the verdict itself.
// This package supplies it from a policy instead, which is the difference
// between a control and a comment.
//
// Four things are load-bearing.
//
// # Gates are resolved once, at admission
//
// A saga's requirements are computed from the policy when it begins and written
// into its own SAGA_BEGIN, alongside the hash of the policy that produced them.
// A running saga is therefore governed by the rules that were in force when it
// started. Editing the policy governs the next saga; it cannot reach back and
// change what this one owed, and it cannot make an already-recorded decision
// look justified in hindsight.
//
// # Refusal is the default
//
// Every way a gate can fail to reach an answer is a refusal: an
// unknown fact, a type mismatch, a policy that covers no rule for the step, a
// requirement whose kind this build does not implement. The failure mode of a
// gate is to stop things. This costs availability and it is the trade the
// system exists to make — the alternative is a control whose failure mode is to
// let a payment through.
//
// # Decisions are re-derivable, not just recorded
//
// A verdict is recorded as an event, and everything the verdict rested on — the
// facts, the requirement list, the policy version — is recorded with it. That
// means the question "did the policy really say yes?" can be answered later by
// someone who does not trust the process that wrote the answer. Audit does
// exactly that. Recording a decision proves it was made; re-deriving it proves
// it was made correctly, and only the second one survives an adversary with
// commit access to the coordinator.
//
// # Phase is part of the requirement
//
// A gate that runs after the participant has acted can refuse to release an
// effect, which is everything for an effect the outbox is holding and nothing
// for one that has already fired. So each requirement declares when it is
// decided, and admission refuses a plan whose protection arrives too late.
package gate

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/fxamacker/cbor/v2"
	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/zeebo/blake3"
)

// Policy is a gate policy document.
//
// Rules are ordered and the first match wins, like a firewall ruleset. The
// alternative — union every matching rule — reads as more thorough and is
// harder to audit: "which clause refused this payment" stops having one answer,
// and a rule added at the top of the file changes the meaning of every rule
// below it in ways nobody can see by reading either. Composition is expressed
// by a rule requiring several gates, which is visible in one place.
type Policy struct {
	ID    string `json:"id"`
	Rules []Rule `json:"rules"`
}

// Rule binds a set of steps to the gates they must pass.
type Rule struct {
	ID      string        `json:"id"`
	Match   Match         `json:"match"`
	Require []Requirement `json:"require"`
}

// Match selects the steps a rule governs. An empty field matches anything; a
// non-empty one matches if any of its patterns matches. All non-empty fields
// must match, so conditions narrow rather than widen.
//
// Patterns are exact strings, or a prefix followed by "*". There is no regular
// expression syntax, because a policy that needs one has become a program.
type Match struct {
	// EffectClasses are short names: PURE, REVERSIBLE, COMPENSABLE,
	// IRREVERSIBLE_GATED, IRREVERSIBLE_IMMEDIATE.
	EffectClasses []string `json:"effect_classes,omitempty"`
	Participants  []string `json:"participants,omitempty"`
	Actions       []string `json:"actions,omitempty"`
	// Modes are saga execution modes: exploratory, supervised, crystallized.
	// A supervised saga can be made to carry gates an
	// exploratory one does not.
	Modes []string `json:"modes,omitempty"`
}

// Requirement is one checkpoint a matched step must pass.
type Requirement struct {
	ID    string `json:"id"`
	Gate  string `json:"gate"`
	Phase string `json:"phase"`

	// TimeoutSeconds is how long this gate may stay unanswered before the
	// system answers it FAIL on the deadline's behalf. Zero means no deadline: the gate waits forever, which is fail-closed
	// and is what every policy written before this field did.
	//
	// It is on the requirement rather than on HumanSpec because the expiry is
	// decided by the composition rather than by the human check — this slice
	// wires only HUMAN gates, and a validator that never answers is the same
	// operational hole reached by a policy edit rather than a schema change.
	TimeoutSeconds uint32 `json:"timeout_seconds,omitempty"`

	Schema    *SchemaSpec    `json:"schema,omitempty"`
	Policy    *PolicySpec    `json:"policy,omitempty"`
	RiskLimit *RiskLimitSpec `json:"risk_limit,omitempty"`
	Frontier  *FrontierSpec  `json:"frontier,omitempty"`
	Human     *HumanSpec     `json:"human,omitempty"`
	Validator *ValidatorSpec `json:"validator,omitempty"`
}

// HumanSpec requires a person to approve.
type HumanSpec struct {
	// Roles that entitle somebody to answer. Empty means any authenticated
	// human.
	Roles []string `json:"roles,omitempty"`
	// Quorum is how many distinct people must approve; zero means one.
	Quorum uint32 `json:"quorum,omitempty"`
	// SeparationOfDuty refuses an approval from the saga's initiating
	// principal — the four-eyes rule.
	SeparationOfDuty bool `json:"separation_of_duty,omitempty"`
	// RequireEstablishedIdentity checks the roles an OIDC provider *signed
	// for*, rather than the roles the answer claimed. Without it the gate reads
	// what the authenticating layer asserted, which is exactly as trustworthy
	// as that layer.
	//
	// Opt-in, and deliberately so: a control that has to be switched off to get
	// work done is a control that gets switched off. A deployment with no
	// identity verifier configured that turns this on gets a refusal rather
	// than a pass — a control that disables itself in the conditions it exists
	// for is not one.
	RequireEstablishedIdentity bool `json:"require_established_identity,omitempty"`
	// RequireStepUp additionally demands a WebAuthn assertion bound to *this*
	// approval — the saga, step, requirement and attempt — so that a stolen
	// session is not enough at the moment that matters. Implies
	// RequireEstablishedIdentity, since a step-up establishes presence and only
	// the token establishes who was present.
	RequireStepUp bool `json:"require_step_up,omitempty"`
}

// ValidatorSpec asks named independent participants whether the step is sound.
type ValidatorSpec struct {
	Validators []string `json:"validators"`
	Quorum     uint32   `json:"quorum,omitempty"`
	// EscalateOnDisagreement holds the step for a human when the validators do
	// not agree, rather than letting a majority carry it.
	EscalateOnDisagreement bool `json:"escalate_on_disagreement,omitempty"`
}

// SchemaSpec declares the facts a step must carry.
type SchemaSpec struct {
	SchemaID string      `json:"schema_id"`
	Fields   []FieldSpec `json:"fields"`
}

// FieldSpec is one declared fact.
type FieldSpec struct {
	Name string `json:"name"`
	// Type is text, number, or flag.
	Type     string `json:"type"`
	Optional bool   `json:"optional,omitempty"`
}

// PolicySpec is a boolean expression that must hold.
type PolicySpec struct {
	Expr string `json:"expr"`
	// Description is what the log says when this refuses.
	Description string `json:"description,omitempty"`
}

// RiskLimitSpec caps magnitude and blast radius.
type RiskLimitSpec struct {
	Thresholds []Threshold `json:"thresholds,omitempty"`
	// MaxGatedEffects caps irreversible steps per saga; zero means no cap.
	MaxGatedEffects uint32 `json:"max_gated_effects,omitempty"`
	// MaxResources caps distinct resources the saga may touch; zero means no cap.
	MaxResources uint32 `json:"max_resources,omitempty"`
}

// Threshold caps one numeric fact, inclusive.
type Threshold struct {
	Fact string `json:"fact"`
	Max  int64  `json:"max"`
}

// FrontierSpec makes a step wait for contending sagas to finish.
type FrontierSpec struct{}

// Gate type and phase names as they appear in a policy document.
const (
	GateSchema    = "SCHEMA"
	GatePolicy    = "POLICY"
	GateRiskLimit = "RISK_LIMIT"
	GateFrontier  = "FRONTIER"
	GateHuman     = "HUMAN"
	GateValidator = "VALIDATOR"

	PhasePreExecution = "PRE_EXECUTION"
	PhasePreRelease   = "PRE_RELEASE"
)

// ErrPolicy means the policy document is not usable.
//
// It is returned at load time rather than at gate time on purpose: a policy
// with a typo in an expression should fail when someone deploys it, not when a
// payment reaches the gate it guards.
var ErrPolicy = fmt.Errorf("gate: invalid policy")

// LoadPolicy parses and validates a policy document.
func LoadPolicy(raw []byte) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPolicy, err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadPolicyFile reads a policy from disk.
func LoadPolicyFile(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gate: read policy: %w", err)
	}
	p, err := LoadPolicy(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Validate checks the document is well formed and every expression compiles.
func (p *Policy) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("%w: policy has no id", ErrPolicy)
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("%w: policy %q has no rules, so it would refuse every effectful step",
			ErrPolicy, p.ID)
	}
	ruleIDs := map[string]bool{}
	for i := range p.Rules {
		r := &p.Rules[i]
		switch {
		case r.ID == "":
			return fmt.Errorf("%w: rule %d has no id, and a verdict has to be able to cite the "+
				"rule that produced it", ErrPolicy, i)
		case ruleIDs[r.ID]:
			return fmt.Errorf("%w: rule id %q appears twice", ErrPolicy, r.ID)
		}
		ruleIDs[r.ID] = true

		if err := r.Match.validate(); err != nil {
			return fmt.Errorf("%w: rule %q: %w", ErrPolicy, r.ID, err)
		}
		if len(r.Require) == 0 {
			// A rule that requires nothing is how an exemption gets written by
			// accident. Exempting a step is a decision worth stating out loud,
			// so it has to be a rule that requires a check which passes, not an
			// empty list that looks like an oversight either way.
			return fmt.Errorf("%w: rule %q requires no gates; to exempt a step, match it with a "+
				"rule whose requirement passes, so the exemption is visible", ErrPolicy, r.ID)
		}
		seen := map[string]bool{}
		for j := range r.Require {
			req := &r.Require[j]
			if req.ID == "" {
				return fmt.Errorf("%w: rule %q requirement %d has no id", ErrPolicy, r.ID, j)
			}
			if seen[req.ID] {
				return fmt.Errorf("%w: rule %q has two requirements called %q", ErrPolicy, r.ID, req.ID)
			}
			seen[req.ID] = true
			if err := req.validate(); err != nil {
				return fmt.Errorf("%w: rule %q requirement %q: %w", ErrPolicy, r.ID, req.ID, err)
			}
		}
	}
	return nil
}

func (m Match) validate() error {
	for _, c := range m.EffectClasses {
		if _, err := effectClassFor(c); err != nil {
			return err
		}
	}
	return nil
}

func (r *Requirement) validate() error {
	switch r.Phase {
	case PhasePreExecution, PhasePreRelease:
	case "":
		return fmt.Errorf("declares no phase; say %s or %s, because when a gate is decided is "+
			"the difference between preventing an effect and regretting it",
			PhasePreExecution, PhasePreRelease)
	default:
		return fmt.Errorf("has unknown phase %q", r.Phase)
	}

	set := 0
	for _, present := range []bool{
		r.Schema != nil, r.Policy != nil, r.RiskLimit != nil, r.Frontier != nil,
		r.Human != nil, r.Validator != nil,
	} {
		if present {
			set++
		}
	}
	if set != 1 {
		return fmt.Errorf("declares %d checks; a requirement is exactly one check", set)
	}

	switch r.Gate {
	case GateSchema:
		if r.Schema == nil {
			return fmt.Errorf("is a %s gate but carries a different check", r.Gate)
		}
		return r.Schema.validate()
	case GatePolicy:
		if r.Policy == nil {
			return fmt.Errorf("is a %s gate but carries a different check", r.Gate)
		}
		return r.Policy.validate()
	case GateRiskLimit:
		if r.RiskLimit == nil {
			return fmt.Errorf("is a %s gate but carries a different check", r.Gate)
		}
		return r.RiskLimit.validate()
	case GateFrontier:
		if r.Frontier == nil {
			return fmt.Errorf("is a %s gate but carries a different check", r.Gate)
		}
		if r.Phase != PhasePreRelease {
			// A frontier check asks which resources the step touched, and
			// nothing has touched anything before the step runs.
			return fmt.Errorf("is a %s gate in phase %s, but a step has touched no resources "+
				"before it runs; frontier checks are %s", r.Gate, r.Phase, PhasePreRelease)
		}
		return nil
	case GateHuman:
		if r.Human == nil {
			return fmt.Errorf("is a %s gate but carries a different check", r.Gate)
		}
		return r.Human.validate()
	case GateValidator:
		if r.Validator == nil {
			return fmt.Errorf("is a %s gate but carries a different check", r.Gate)
		}
		return r.Validator.validate()
	case "":
		return fmt.Errorf("declares no gate type")
	default:
		return fmt.Errorf("has unknown gate type %q", r.Gate)
	}
}

func (s *HumanSpec) validate() error {
	if s.Quorum > 1 && len(s.Roles) == 0 {
		// A quorum counts distinct people, and without a role there is nothing
		// distinguishing the second approver from the first except their name.
		// That is probably what the author wanted, but a quorum with no
		// entitlement behind it is worth saying out loud rather than assuming.
		return fmt.Errorf("asks for %d approvals but names no roles, so anybody authenticated "+
			"counts towards the quorum; say roles, or set quorum to 1", s.Quorum)
	}
	seen := map[string]bool{}
	for _, role := range s.Roles {
		if role == "" {
			return fmt.Errorf("names an empty role")
		}
		if seen[role] {
			return fmt.Errorf("names role %q twice", role)
		}
		seen[role] = true
	}
	return nil
}

func (s *ValidatorSpec) validate() error {
	if len(s.Validators) == 0 {
		// Independence is the point. A validator gate that accepted an opinion
		// from anybody would be satisfied by the participant being validated.
		return fmt.Errorf("names no validators, so any participant could render the opinion — " +
			"including the one being validated")
	}
	seen := map[string]bool{}
	for _, v := range s.Validators {
		if v == "" {
			return fmt.Errorf("names an empty validator")
		}
		if seen[v] {
			return fmt.Errorf("names validator %q twice, which would let one opinion count as two", v)
		}
		seen[v] = true
	}
	if int(s.Quorum) > len(s.Validators) {
		return fmt.Errorf("asks for %d agreeing opinions from %d validators, which can never be "+
			"reached", s.Quorum, len(s.Validators))
	}
	return nil
}

func (s *SchemaSpec) validate() error {
	if len(s.Fields) == 0 {
		return fmt.Errorf("declares no fields")
	}
	seen := map[string]bool{}
	for _, f := range s.Fields {
		if f.Name == "" {
			return fmt.Errorf("has a field with no name")
		}
		if seen[f.Name] {
			return fmt.Errorf("declares field %q twice", f.Name)
		}
		seen[f.Name] = true
		if _, err := factTypeFor(f.Type); err != nil {
			return fmt.Errorf("field %q: %w", f.Name, err)
		}
	}
	return nil
}

func (s *PolicySpec) validate() error {
	if s.Expr == "" {
		return fmt.Errorf("has an empty expression")
	}
	if _, err := Compile(s.Expr); err != nil {
		return err
	}
	return nil
}

func (s *RiskLimitSpec) validate() error {
	if len(s.Thresholds) == 0 && s.MaxGatedEffects == 0 && s.MaxResources == 0 {
		return fmt.Errorf("caps nothing")
	}
	for _, t := range s.Thresholds {
		if t.Fact == "" {
			return fmt.Errorf("has a threshold with no fact name")
		}
	}
	return nil
}

// ---- content addressing --------------------------------------------------------

// policyDomain separates a policy digest from every other hash Janus computes,
// so a digest produced in one role can never be substituted into another.
const policyDomain = "JANUS/gatepolicy/1\x00"

var canonicalEnc cbor.EncMode

func init() {
	var err error
	// RFC 8949 §4.2.1 core deterministic encoding: sorted keys, shortest-form
	// integers, no indefinite-length items. Two processes that hold the same
	// policy must compute the same version or the pinning is decorative.
	if canonicalEnc, err = cbor.CoreDetEncOptions().EncMode(); err != nil {
		panic(fmt.Sprintf("gate: build canonical CBOR encoder: %v", err))
	}
}

// Version is the content address of the policy: "blake3:" followed by the hex
// digest of its canonical encoding.
//
// It hashes the parsed policy rather than the file bytes, so reindenting the
// document does not invent a new policy, and a policy reconstructed from a log
// hashes to the value the log recorded. What it does mean is that the version
// identifies the rules, not the comments around them — which is the right
// trade, because the rules are what decided.
func (p *Policy) Version() string {
	enc, err := canonicalEnc.Marshal(p.canonical())
	if err != nil {
		// Unreachable: canonical() is built from strings, integers, and slices
		// of them. If it ever happens, refusing to name a version is safer than
		// naming one nothing can reproduce.
		panic(fmt.Sprintf("gate: encode policy %q: %v", p.ID, err))
	}
	h := blake3.New()
	_, _ = h.Write([]byte(policyDomain))
	_, _ = h.Write(enc)
	return "blake3:" + hex.EncodeToString(h.Sum(nil))
}

// canonical renders the policy as ordered primitives, so the digest depends on
// the rules and not on Go struct layout, JSON key order, or field additions
// that leave the meaning untouched.
func (p *Policy) canonical() []any {
	rules := make([]any, 0, len(p.Rules))
	for _, r := range p.Rules {
		reqs := make([]any, 0, len(r.Require))
		for _, q := range r.Require {
			reqs = append(reqs, q.canonical())
		}
		rules = append(rules, []any{
			r.ID,
			[]any{r.Match.EffectClasses, r.Match.Participants, r.Match.Actions, r.Match.Modes},
			reqs,
		})
	}
	return []any{"janus.gate.policy/1", p.ID, rules}
}

func (r Requirement) canonical() []any {
	out := []any{r.ID, r.Gate, r.Phase}
	switch {
	case r.Schema != nil:
		fields := make([]any, 0, len(r.Schema.Fields))
		for _, f := range r.Schema.Fields {
			fields = append(fields, []any{f.Name, f.Type, f.Optional})
		}
		out = append(out, []any{"schema", r.Schema.SchemaID, fields})
	case r.Policy != nil:
		out = append(out, []any{"policy", r.Policy.Expr, r.Policy.Description})
	case r.RiskLimit != nil:
		ths := make([]any, 0, len(r.RiskLimit.Thresholds))
		for _, t := range r.RiskLimit.Thresholds {
			ths = append(ths, []any{t.Fact, t.Max})
		}
		out = append(out, []any{"risk_limit", ths,
			int64(r.RiskLimit.MaxGatedEffects), int64(r.RiskLimit.MaxResources)})
	case r.Frontier != nil:
		out = append(out, []any{"frontier"})
	case r.Human != nil:
		out = append(out, []any{"human", r.Human.Roles,
			int64(r.Human.Quorum), r.Human.SeparationOfDuty})
	case r.Validator != nil:
		out = append(out, []any{"validator", r.Validator.Validators,
			int64(r.Validator.Quorum), r.Validator.EscalateOnDisagreement})
	}
	return out
}

// ---- resolution ----------------------------------------------------------------

// Subject is what a rule matches on: everything about a step that is known
// before it runs.
type Subject struct {
	StepID      string
	Participant string
	Action      string
	EffectClass janusv1.EffectClass
	Mode        string
}

// Resolve returns the first rule governing a step, or nil if none matches.
func (p *Policy) Resolve(s Subject) *Rule {
	for i := range p.Rules {
		if p.Rules[i].Match.matches(s) {
			return &p.Rules[i]
		}
	}
	return nil
}

func (m Match) matches(s Subject) bool {
	return matchAny(m.EffectClasses, shortClass(s.EffectClass)) &&
		matchAny(m.Participants, s.Participant) &&
		matchAny(m.Actions, s.Action) &&
		matchAny(m.Modes, s.Mode)
}

// matchAny reports whether any pattern matches. No patterns means no condition,
// which matches everything.
func matchAny(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pat := range patterns {
		if pat == "*" {
			return true
		}
		if prefix, ok := strings.CutSuffix(pat, "*"); ok {
			if strings.HasPrefix(value, prefix) {
				return true
			}
			continue
		}
		if pat == value {
			return true
		}
	}
	return false
}

// Requirements renders a rule's requirements as the wire form recorded in a
// saga's gate plan.
func (r *Rule) Requirements() []*janusv1.GateRequirement {
	out := make([]*janusv1.GateRequirement, 0, len(r.Require))
	for _, q := range r.Require {
		out = append(out, q.proto())
	}
	return out
}

func (r Requirement) proto() *janusv1.GateRequirement {
	out := &janusv1.GateRequirement{
		Id: r.ID, Gate: gateTypeFor(r.Gate), Phase: phaseFor(r.Phase),
		TimeoutSeconds: r.TimeoutSeconds,
	}
	switch {
	case r.Schema != nil:
		fields := make([]*janusv1.FieldSpec, 0, len(r.Schema.Fields))
		for _, f := range r.Schema.Fields {
			t, _ := factTypeFor(f.Type)
			fields = append(fields, &janusv1.FieldSpec{Name: f.Name, Type: t, Optional: f.Optional})
		}
		out.Check = &janusv1.GateRequirement_Schema{
			Schema: &janusv1.SchemaCheck{SchemaId: r.Schema.SchemaID, Fields: fields},
		}
	case r.Policy != nil:
		out.Check = &janusv1.GateRequirement_Policy{
			Policy: &janusv1.PolicyCheck{Expr: r.Policy.Expr, Description: r.Policy.Description},
		}
	case r.RiskLimit != nil:
		ths := make([]*janusv1.RiskLimitCheck_Threshold, 0, len(r.RiskLimit.Thresholds))
		for _, t := range r.RiskLimit.Thresholds {
			ths = append(ths, &janusv1.RiskLimitCheck_Threshold{Fact: t.Fact, Max: t.Max})
		}
		out.Check = &janusv1.GateRequirement_RiskLimit{
			RiskLimit: &janusv1.RiskLimitCheck{
				Thresholds:      ths,
				MaxGatedEffects: r.RiskLimit.MaxGatedEffects,
				MaxResources:    r.RiskLimit.MaxResources,
			},
		}
	case r.Frontier != nil:
		out.Check = &janusv1.GateRequirement_Frontier{Frontier: &janusv1.FrontierCheck{}}
	case r.Human != nil:
		out.Check = &janusv1.GateRequirement_Human{
			Human: &janusv1.HumanCheck{
				Roles:                      slices.Clone(r.Human.Roles),
				Quorum:                     r.Human.Quorum,
				SeparationOfDuty:           r.Human.SeparationOfDuty,
				RequireEstablishedIdentity: r.Human.RequireEstablishedIdentity,
				RequireStepUp:              r.Human.RequireStepUp,
			},
		}
	case r.Validator != nil:
		out.Check = &janusv1.GateRequirement_Validator{
			Validator: &janusv1.ValidatorCheck{
				Validators:             slices.Clone(r.Validator.Validators),
				Quorum:                 r.Validator.Quorum,
				EscalateOnDisagreement: r.Validator.EscalateOnDisagreement,
			},
		}
	}
	return out
}

// ---- enum names ----------------------------------------------------------------

func shortClass(c janusv1.EffectClass) string {
	return strings.TrimPrefix(c.String(), "EFFECT_CLASS_")
}

func effectClassFor(name string) (janusv1.EffectClass, error) {
	v, ok := janusv1.EffectClass_value["EFFECT_CLASS_"+name]
	if !ok || v == 0 {
		return 0, fmt.Errorf("unknown effect class %q", name)
	}
	return janusv1.EffectClass(v), nil
}

func factTypeFor(name string) (janusv1.FactType, error) {
	v, ok := janusv1.FactType_value["FACT_TYPE_"+strings.ToUpper(name)]
	if !ok || v == 0 {
		return 0, fmt.Errorf("unknown type %q; the types are text, number, and flag", name)
	}
	return janusv1.FactType(v), nil
}

func gateTypeFor(name string) janusv1.GateType {
	return janusv1.GateType(janusv1.GateType_value["GATE_TYPE_"+name])
}

func phaseFor(name string) janusv1.GatePhase {
	return janusv1.GatePhase(janusv1.GatePhase_value["GATE_PHASE_"+name])
}
