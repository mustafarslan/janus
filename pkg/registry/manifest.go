// Package registry holds the participant manifests every saga is judged
// against.
//
// A manifest is a participant's declaration: who it is, what it can do, what
// each action does to the world, and how each action can be taken back. A saga
// pins the exact version of the manifest that governed each of its steps, so
// "what was this agent allowed to do when the payment went out" is a question
// about recorded history rather than about current configuration.
//
// Four things are load-bearing.
//
// # A version is a promise, not a label
//
// A saga pins `payments-agent@3.2.1`. If that string can be made to mean
// different bytes tomorrow, the pin records nothing. So a manifest has both a
// declared version and a content address, every registry event carries both,
// and registering one version twice with different content is refused at the
// registry and reported as a finding by audit. Version pinning that nobody
// enforces is the most convincing kind of nothing.
//
// # Registration is not paperwork
//
// A participant claiming REVERSIBLE is claiming a perfect undo exists. The
// registry makes it demonstrate one against sandbox doubles before the claim
// can be activated (conformance.go). The effect classes drive gating —
// whether an effect is held until commit, whether a human has to approve it —
// so an unchecked claim is a way to route around the gates by declaration.
//
// # The declaration outranks the plan
//
// A step says it is about to perform `payments.wire` as COMPENSABLE; the
// manifest says `payments.wire` is IRREVERSIBLE_GATED. Admission refuses the
// saga rather than believing the step. This is what stands between an injected
// instruction and an ungated wire: relabelling the action is the cheapest
// attack on a system that gates by effect class, and it costs nothing to a
// planner that is writing its own plan.
//
// # The registry is a projection of the log
//
// Every mutation is an event in the evidence log, and the registry's state is
// folded from those events. Nothing here is the system of record;
// the log is. That is what lets an auditor holding a bundle re-derive which
// manifest was in force at a given sequence, without the registry service and
// without trusting it.
package registry

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

// Manifest is a participant's signed capability declaration.
//
// The document is JSON on disk and canonical CBOR when hashed or signed. It is
// hashed in its parsed form, so reindenting the file does not invent a new
// manifest and a manifest reconstructed from the log hashes to the value the
// log recorded.
type Manifest struct {
	// Version is what a saga pins, e.g. "3.2.1". It is the participant's own
	// name for this declaration; ContentAddress is what makes the name mean
	// exactly one thing.
	Version      string       `json:"version" cbor:"1,keyasint"`
	Identity     Identity     `json:"identity" cbor:"2,keyasint"`
	Runtime      Runtime      `json:"runtime" cbor:"3,keyasint"`
	Actions      []Action     `json:"actions" cbor:"4,keyasint"`
	Risk         Risk         `json:"risk" cbor:"5,keyasint"`
	Jurisdiction Jurisdiction `json:"jurisdiction" cbor:"6,keyasint"`
}

// Identity is who the participant is and who is answerable for it.
type Identity struct {
	ParticipantID string `json:"participant_id" cbor:"1,keyasint"`
	// Kind is AGENT, TOOL, SYSTEM, HUMAN or VALIDATOR.
	Kind string `json:"kind" cbor:"2,keyasint"`
	// Principal is the legal entity the participant acts for. Every gate that
	// enforces separation of duty compares against this.
	Principal string `json:"principal" cbor:"3,keyasint"`
	// PublicKeys are the keys the participant signs its own messages with.
	//
	// They do not establish the manifest's own signature: a document cannot
	// authenticate itself by naming the key that signed it. Trust in the
	// manifest comes from a store held by the registry operator (signature.go).
	PublicKeys []string `json:"public_keys,omitempty" cbor:"4,keyasint,omitempty"`
}

// Runtime pins what the participant actually is at this version — the model,
// the prompt, the policy bundle, the framework.
//
// This is the field set a change to which is the whole reason change events exist: a
// new model version or a new prompt is a different participant wearing the same
// name, and a bank's model inventory is exactly this table.
type Runtime struct {
	ModelID             string `json:"model_id,omitempty" cbor:"1,keyasint,omitempty"`
	ServingFingerprint  string `json:"model_serving_fingerprint,omitempty" cbor:"2,keyasint,omitempty"`
	PromptBundleHash    string `json:"prompt_bundle_hash,omitempty" cbor:"3,keyasint,omitempty"`
	PolicyBundleVersion string `json:"policy_bundle_version,omitempty" cbor:"4,keyasint,omitempty"`
	Framework           string `json:"framework,omitempty" cbor:"5,keyasint,omitempty"`
	SBOMRef             string `json:"sbom_ref,omitempty" cbor:"6,keyasint,omitempty"`
}

// Action is one thing the participant can be asked to do.
type Action struct {
	Name string `json:"name" cbor:"1,keyasint"`
	// EffectClass is PURE, REVERSIBLE, COMPENSABLE, IRREVERSIBLE_GATED or
	// IRREVERSIBLE_IMMEDIATE. It decides how Janus treats the action,
	// which is why the conformance harness checks it rather than believing it.
	EffectClass string `json:"effect_class" cbor:"2,keyasint"`
	// Compensation is how the action is taken back. Required for REVERSIBLE and
	// COMPENSABLE; refused for the irreversible classes, where declaring one
	// would mean the classification is wrong.
	Compensation *Compensation `json:"compensation,omitempty" cbor:"3,keyasint,omitempty"`
	// Idempotency is how a repeated delivery of this action is recognised as
	// the same one. Required for every effectful action: the outbox delivers
	// at least once, so an action with no recipe is an action that will
	// eventually happen twice.
	Idempotency *Idempotency `json:"idempotency,omitempty" cbor:"4,keyasint,omitempty"`
	// Limits cap the action's magnitude and rate. The policy engine enforces
	// them at the gate; the conformance harness checks the participant refuses
	// what it says it refuses.
	Limits *Limits `json:"limits,omitempty" cbor:"5,keyasint,omitempty"`
	// PreauthorizedMandate is the standing authority an IRREVERSIBLE_IMMEDIATE
	// action acts under, and is required for that class alone. An effect
	// that is in the world the moment the participant returns cannot be
	// authorised afterwards, so the authority has to exist beforehand and be
	// nameable.
	PreauthorizedMandate string `json:"preauthorized_mandate,omitempty" cbor:"6,keyasint,omitempty"`
}

// Compensation names the inverse action and is honest about what it leaves
// behind.
type Compensation struct {
	// Action is the name of the compensating action, which must itself be an
	// action of this manifest — an undo the participant cannot perform is not
	// an undo.
	Action string `json:"action" cbor:"1,keyasint"`
	// ParamMap maps the compensating action's arguments to the original's.
	ParamMap map[string]string `json:"param_map,omitempty" cbor:"2,keyasint,omitempty"`
	// MaxDelaySeconds is how long after the original the compensation still
	// works. A refund window closes; a booking becomes non-cancellable.
	MaxDelaySeconds int64 `json:"max_delay_seconds,omitempty" cbor:"3,keyasint,omitempty"`
	// ResidualEffects is what survives the undo — the statement line that
	// remains after a refund, the email the recipient already read. Required
	// for COMPENSABLE, because "semantic undo" means exactly that something
	// remains, and a compensation plan that does not say what is the reason
	// compensation gets mistaken for reversal.
	ResidualEffects string `json:"residual_effects,omitempty" cbor:"4,keyasint,omitempty"`
}

// Idempotency is the recipe for the key that makes a repeated delivery
// recognisable.
type Idempotency struct {
	// KeyRecipe names the argument fields the key is derived from, e.g.
	// "account,amount,intent_id". It is a list of field names rather than an
	// expression: a recipe nobody can read is a recipe nobody checks.
	KeyRecipe string `json:"key_recipe" cbor:"1,keyasint"`
	// WindowSeconds is how long the receiver remembers a key. Zero means the
	// participant makes no claim, which the harness records as untested rather
	// than as satisfied.
	WindowSeconds int64 `json:"window_seconds,omitempty" cbor:"2,keyasint,omitempty"`
}

// Limits are the bounds the participant claims to enforce on itself.
type Limits struct {
	// MaxAmount caps the action's principal numeric argument, named by
	// AmountField.
	MaxAmount int64 `json:"max_amount,omitempty" cbor:"1,keyasint,omitempty"`
	// AmountField is which argument MaxAmount caps.
	AmountField string `json:"amount_field,omitempty" cbor:"2,keyasint,omitempty"`
	Currency    string `json:"currency,omitempty" cbor:"3,keyasint,omitempty"`
	// RatePerHour caps invocations per hour; zero means unlimited.
	RatePerHour uint32 `json:"rate_per_hour,omitempty" cbor:"4,keyasint,omitempty"`
}

// Risk is the participant's tier and what would make its evaluation stale
// (SS1/23 model risk).
type Risk struct {
	// Tier is 1 (highest risk) to 4. It drives how much evidence a deployment
	// demands before activation and how often it revalidates.
	Tier uint32 `json:"tier" cbor:"1,keyasint"`

	// RevalidateAfterDays is how long this participant's evaluation stays good
	// for, if the vendor wants to say something stricter than the deployment's
	// own schedule.
	//
	// It is optional and it can only *tighten*. The cadence's home is the
	// deployment, keyed by risk tier, because a quarterly review is
	// something a regulator asks of an institution rather than of a piece of
	// software — and because a bank re-tiers a model without the vendor
	// reissuing a manifest. What a manifest can do is know something the tier
	// does not: a model that drifts in weeks should not sit on a yearly
	// schedule because its tier says it may.
	//
	// Nothing validates this against the deployment at registration, on
	// purpose. The shorter of the two is taken when the schedule is computed,
	// so re-tiering corrects itself and no manifest has to be reissued.
	RevalidateAfterDays uint32 `json:"revalidate_after_days,omitempty" cbor:"4,keyasint,omitempty"`
	// ValidationEvidence are bundle refs for the evidence that cleared this
	// version outside the sandbox — a model validation report, a backtest.
	ValidationEvidence []string `json:"validation_evidence,omitempty" cbor:"2,keyasint,omitempty"`
	// RevalidationTriggers are the changes that invalidate this version's
	// evaluation. A version whose successor fires one of these cannot inherit
	// its evidence (change.go).
	RevalidationTriggers []string `json:"revalidation_triggers,omitempty" cbor:"3,keyasint,omitempty"`
}

// Jurisdiction is where the participant may run and where its data may rest.
type Jurisdiction struct {
	DeployableIn  []string `json:"deployable_in,omitempty" cbor:"1,keyasint,omitempty"`
	DataResidency string   `json:"data_residency,omitempty" cbor:"2,keyasint,omitempty"`
	// Filings are references to registrations a jurisdiction requires before
	// the participant may act there (CAC algorithm filing).
	Filings []string `json:"filings,omitempty" cbor:"3,keyasint,omitempty"`
}

// Revalidation trigger names. A trigger outside this set is refused at load
// time: a typo in a trigger name produces a trigger that silently never fires,
// which is worse than no trigger at all because it reads as coverage.
const (
	TriggerModelChange  = "model_change"
	TriggerPromptChange = "prompt_change"
	TriggerPolicyChange = "policy_change"
	TriggerActionChange = "action_change"
	TriggerLimitChange  = "limit_change"
	// TriggerPeriodic fires on a calendar rather than on a change, so nothing
	// in a diff can match it. It is accepted here so a manifest can declare the
	// quarterly review SS1/23 expects; acting on it needs a scheduler Janus
	// does not have yet.
	TriggerPeriodic = "periodic"
)

// Revalidation trigger names for a template, which is the other document this
// registry holds.
//
// They are deliberately *not* in `knownTriggers()`. That list is what
// `Manifest.Validate` accepts, and a participant manifest declaring
// "shape_change" would be declaring coverage of something a participant does
// not have -- the same silent non-firing trigger the comment above warns about,
// arrived at from the other direction. A template does not declare its triggers
// at all, so there is no list to validate these against; they exist as
// constants because an evaluation that clears one has to name it, and a name
// that only ever appears as a string literal is a typo waiting to read as
// coverage.
const (
	// TriggerShapeChange fires when the step DAG differs: a step added, removed,
	// or pointed at a different participant, action, effect class, compensation
	// or dependency. It is the template's analogue of TriggerActionChange.
	TriggerShapeChange = "shape_change"
	// TriggerSlotChange fires when the *set* of things a saga may choose
	// changes -- a slot added, removed, or retyped. It does not fire when a
	// slot's observed values grow: those are a record of what extraction saw,
	// not a permission list, so a longer one confines exactly what the shorter
	// one did.
	TriggerSlotChange = "slot_change"
)

func knownTriggers() []string {
	return []string{
		TriggerModelChange, TriggerPromptChange, TriggerPolicyChange,
		TriggerActionChange, TriggerLimitChange, TriggerPeriodic,
	}
}

// ErrManifest means the manifest document is not usable.
//
// Like a gate policy, it is returned at load time rather than at use time: a
// manifest that contradicts itself should fail when somebody registers it, not
// when a saga pins it at three in the morning.
var ErrManifest = fmt.Errorf("registry: invalid manifest")

// LoadManifest parses and validates a manifest document.
func LoadManifest(raw []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrManifest, err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// LoadManifestFile reads a manifest from disk.
func LoadManifestFile(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: read manifest: %w", err)
	}
	m, err := LoadManifest(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// Validate checks the document is well formed and does not contradict itself.
func (m *Manifest) Validate() error {
	if m.Version == "" {
		return fmt.Errorf("%w: manifest declares no version, so no saga could pin it", ErrManifest)
	}
	if err := m.Identity.validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrManifest, err)
	}
	if len(m.Actions) == 0 {
		return fmt.Errorf("%w: participant %q declares no actions, so registering it says nothing "+
			"about what it may do", ErrManifest, m.Identity.ParticipantID)
	}

	byName := make(map[string]*Action, len(m.Actions))
	for i := range m.Actions {
		a := &m.Actions[i]
		if a.Name == "" {
			return fmt.Errorf("%w: action %d has no name", ErrManifest, i)
		}
		if _, dup := byName[a.Name]; dup {
			return fmt.Errorf("%w: action %q is declared twice, and the two declarations could "+
				"disagree about what it does", ErrManifest, a.Name)
		}
		byName[a.Name] = a
	}
	for i := range m.Actions {
		if err := m.Actions[i].validate(byName); err != nil {
			return fmt.Errorf("%w: action %q %w", ErrManifest, m.Actions[i].Name, err)
		}
	}

	if m.Risk.Tier < 1 || m.Risk.Tier > 4 {
		return fmt.Errorf("%w: risk tier is %d; tiers run 1 (highest risk) to 4, and an "+
			"unclassified participant cannot be placed in a model inventory",
			ErrManifest, m.Risk.Tier)
	}
	seen := map[string]bool{}
	// A period with no `periodic` trigger schedules nothing, and does it
	// silently — a vendor writes `revalidate_after_days: 30`, believes it has
	// asked for monthly review, and has asked for nothing. That is the exact
	// failure this project exists to prevent, so it is refused rather than
	// documented.
	if m.Risk.RevalidateAfterDays > 0 &&
		!slices.Contains(m.Risk.RevalidationTriggers, TriggerPeriodic) {
		return fmt.Errorf("%w: revalidate_after_days is %d but %q is not among the "+
			"revalidation triggers, so nothing would ever schedule one; add the trigger "+
			"or drop the period", ErrManifest, m.Risk.RevalidateAfterDays, TriggerPeriodic)
	}
	for _, t := range m.Risk.RevalidationTriggers {
		if !slices.Contains(knownTriggers(), t) {
			return fmt.Errorf("%w: unknown revalidation trigger %q; a trigger nothing can match "+
				"never fires, which reads as coverage and is not (known: %s)",
				ErrManifest, t, strings.Join(knownTriggers(), ", "))
		}
		if seen[t] {
			return fmt.Errorf("%w: revalidation trigger %q is declared twice", ErrManifest, t)
		}
		seen[t] = true
	}
	return nil
}

func (id Identity) validate() error {
	switch {
	case id.ParticipantID == "":
		return fmt.Errorf("manifest names no participant id")
	case id.Principal == "":
		return fmt.Errorf("participant %q names no principal; separation of duty and every "+
			"jurisdictional question resolve to the legal entity behind a participant",
			id.ParticipantID)
	}
	if _, err := participantKindFor(id.Kind); err != nil {
		return fmt.Errorf("participant %q: %w", id.ParticipantID, err)
	}
	return nil
}

func (a *Action) validate(byName map[string]*Action) error {
	class, err := EffectClassFor(a.EffectClass)
	if err != nil {
		return err
	}

	switch class {
	case janusv1.EffectClass_EFFECT_CLASS_PURE:
		if a.Compensation != nil {
			return fmt.Errorf("is PURE but declares a compensation; either it changes something " +
				"outside Janus, in which case it is not PURE, or there is nothing to undo")
		}
		if a.Idempotency != nil {
			return fmt.Errorf("is PURE but declares an idempotency recipe; nothing is delivered, " +
				"so nothing can be delivered twice")
		}
	case janusv1.EffectClass_EFFECT_CLASS_REVERSIBLE,
		janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE:
		if a.Compensation == nil {
			return fmt.Errorf("is %s and declares no compensation; the class is a claim that an "+
				"undo exists, and an undo nobody names cannot be planned, tested or run",
				a.EffectClass)
		}
		if err := a.Compensation.validate(class, byName); err != nil {
			return err
		}
		if a.Idempotency == nil {
			return fmt.Errorf("is %s and declares no idempotency recipe; delivery is at-least-once, "+
				"so an action with no key is one that eventually happens twice", a.EffectClass)
		}
	default:
		if a.Compensation != nil {
			return fmt.Errorf("is %s and declares a compensation; an effect that can be taken "+
				"back is not irreversible, and the classification decides whether Janus holds "+
				"it before it happens", a.EffectClass)
		}
		if a.Idempotency == nil {
			return fmt.Errorf("is %s and declares no idempotency recipe; this is the class where "+
				"a duplicate delivery cannot be undone", a.EffectClass)
		}
	}

	if class == janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE && a.PreauthorizedMandate == "" {
		return fmt.Errorf("is IRREVERSIBLE_IMMEDIATE and names no pre-authorized mandate; that " +
			"effect is in the world as soon as the participant returns, so the authority for it " +
			"has to exist before the step runs rather than be granted at a gate afterwards")
	}
	if class != janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE && a.PreauthorizedMandate != "" {
		return fmt.Errorf("names a pre-authorized mandate but is %s; a standing authority to act "+
			"without a gate belongs only to the class that cannot be gated", a.EffectClass)
	}

	if a.Idempotency != nil {
		if err := a.Idempotency.validate(); err != nil {
			return err
		}
	}
	if a.Limits != nil {
		if err := a.Limits.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Compensation) validate(class janusv1.EffectClass, byName map[string]*Action) error {
	if c.Action == "" {
		return fmt.Errorf("declares a compensation with no action")
	}
	inverse, ok := byName[c.Action]
	if !ok {
		return fmt.Errorf("compensates with %q, which this manifest does not declare; a "+
			"participant cannot be planned to run an undo it has not said it can perform",
			c.Action)
	}
	inverseClass, err := EffectClassFor(inverse.EffectClass)
	if err != nil {
		return err
	}
	switch inverseClass {
	case janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE:
		// Unwinding happens when something has already gone wrong, and a
		// compensation that itself needs a gate can be refused at exactly the
		// moment the saga has no other way out of QUARANTINE.
		return fmt.Errorf("compensates with %q, which is %s; an undo that cannot itself be "+
			"taken back leaves a failed saga with a choice between two irreversible outcomes",
			c.Action, inverse.EffectClass)
	}
	if class == janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE && c.ResidualEffects == "" {
		return fmt.Errorf("is COMPENSABLE but says nothing about residual effects; the class " +
			"means the undo is semantic rather than perfect, and what survives it is the part " +
			"a customer notices")
	}
	if class == janusv1.EffectClass_EFFECT_CLASS_REVERSIBLE && c.ResidualEffects != "" {
		return fmt.Errorf("is REVERSIBLE but names residual effects (%q); an undo that leaves "+
			"something behind is COMPENSABLE, and the difference decides whether Janus may run "+
			"the action optimistically", c.ResidualEffects)
	}
	return nil
}

func (i *Idempotency) validate() error {
	if strings.TrimSpace(i.KeyRecipe) == "" {
		return fmt.Errorf("declares an idempotency recipe with no fields")
	}
	for _, f := range strings.Split(i.KeyRecipe, ",") {
		if strings.TrimSpace(f) == "" {
			return fmt.Errorf("idempotency recipe %q has an empty field", i.KeyRecipe)
		}
	}
	if i.WindowSeconds < 0 {
		return fmt.Errorf("idempotency window is negative")
	}
	return nil
}

func (l *Limits) validate() error {
	if l.MaxAmount < 0 {
		return fmt.Errorf("declares a negative maximum amount")
	}
	if l.MaxAmount > 0 && l.AmountField == "" {
		return fmt.Errorf("caps an amount at %d but does not say which argument that is, so "+
			"nothing could enforce or test it", l.MaxAmount)
	}
	if l.MaxAmount == 0 && l.AmountField != "" {
		return fmt.Errorf("names amount field %q with no cap on it", l.AmountField)
	}
	if l.MaxAmount == 0 && l.RatePerHour == 0 {
		return fmt.Errorf("declares limits that cap nothing")
	}
	return nil
}

// Action returns the named action, or nil.
func (m *Manifest) Action(name string) *Action {
	for i := range m.Actions {
		if m.Actions[i].Name == name {
			return &m.Actions[i]
		}
	}
	return nil
}

// EffectClassOf reports the class the manifest declares for an action.
func (m *Manifest) EffectClassOf(action string) (janusv1.EffectClass, bool) {
	a := m.Action(action)
	if a == nil {
		return janusv1.EffectClass_EFFECT_CLASS_UNSPECIFIED, false
	}
	class, err := EffectClassFor(a.EffectClass)
	if err != nil {
		return janusv1.EffectClass_EFFECT_CLASS_UNSPECIFIED, false
	}
	return class, true
}

// EffectClassFor maps a short class name to the enum.
func EffectClassFor(name string) (janusv1.EffectClass, error) {
	v, ok := janusv1.EffectClass_value["EFFECT_CLASS_"+strings.ToUpper(name)]
	if !ok || v == 0 {
		return janusv1.EffectClass_EFFECT_CLASS_UNSPECIFIED,
			fmt.Errorf("has unknown effect class %q", name)
	}
	return janusv1.EffectClass(v), nil
}

// ShortClass renders an effect class the way a manifest writes it.
func ShortClass(c janusv1.EffectClass) string {
	return strings.TrimPrefix(c.String(), "EFFECT_CLASS_")
}

func participantKindFor(name string) (janusv1.ParticipantKind, error) {
	v, ok := janusv1.ParticipantKind_value["PARTICIPANT_KIND_"+strings.ToUpper(name)]
	if !ok || v == 0 {
		return janusv1.ParticipantKind_PARTICIPANT_KIND_UNSPECIFIED,
			fmt.Errorf("has unknown participant kind %q", name)
	}
	return janusv1.ParticipantKind(v), nil
}

// ---- content addressing --------------------------------------------------------

// manifestDomain separates a manifest digest from every other hash Janus
// computes, so a digest produced in one role can never be substituted into
// another.
const manifestDomain = "JANUS/manifest/1\x00"

var canonicalEnc cbor.EncMode

func init() {
	var err error
	// RFC 8949 §4.2.1 core deterministic encoding: sorted keys, shortest-form
	// integers, no indefinite-length items. Two processes holding the same
	// manifest must compute the same content address, or a pin means one thing
	// to the registry and another to the auditor checking it.
	if canonicalEnc, err = cbor.CoreDetEncOptions().EncMode(); err != nil {
		panic(fmt.Sprintf("registry: build canonical CBOR encoder: %v", err))
	}
}

// Canonical returns the bytes a manifest is hashed and signed over.
//
// These are the bytes the log stores. Recording a re-serialisation instead
// would mean the recorded signature covered something the log does not hold.
func (m *Manifest) Canonical() ([]byte, error) {
	blob, err := canonicalEnc.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("registry: encode manifest canonically: %w", err)
	}
	return blob, nil
}

// DecodeManifest parses canonical bytes back into a manifest and validates it.
//
// Validation on the way in matters as much as on the way out: these bytes come
// from a log, and a log an adversary has written to could carry a manifest that
// contradicts itself.
func DecodeManifest(canonical []byte) (*Manifest, error) {
	var m Manifest
	if err := cbor.Unmarshal(canonical, &m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrManifest, err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// ContentAddress is "blake3:" followed by the hex digest of the manifest's
// canonical encoding.
//
// It identifies the declaration rather than the file, so two people who format
// the same manifest differently register the same thing, and a version that has
// been edited is a different content address under the same name — which is the
// contradiction the registry refuses.
func (m *Manifest) ContentAddress() string {
	blob, err := m.Canonical()
	if err != nil {
		// Canonical encoding of a validated manifest cannot fail; a hash that
		// silently became a constant would make every pin agree with every
		// other, so this refuses to return one.
		panic(fmt.Sprintf("registry: content address of an unencodable manifest: %v", err))
	}
	return ContentAddressOf(blob)
}

// ContentAddressOf computes the content address of canonical manifest bytes.
func ContentAddressOf(canonical []byte) string {
	h := blake3.New()
	_, _ = h.WriteString(manifestDomain)
	_, _ = h.Write(canonical)
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return "blake3:" + hex.EncodeToString(sum[:])
}

// shortAddress abbreviates a content address for human-facing output.
func shortAddress(addr string) string {
	const keep = 12
	if i := strings.IndexByte(addr, ':'); i >= 0 && len(addr) > i+1+keep {
		return addr[:i+1+keep] + "…"
	}
	return addr
}
