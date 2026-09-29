package gate_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/gate"
)

// mustPolicy parses a policy the test expects to be valid.
func mustPolicy(t *testing.T, raw string) *gate.Policy {
	t.Helper()
	p, err := gate.LoadPolicy([]byte(raw))
	if err != nil {
		t.Fatalf("policy should be valid: %v", err)
	}
	return p
}

const wiresPolicy = `{
  "id": "test.wires",
  "rules": [
    {
      "id": "wires",
      "match": {"effect_classes": ["IRREVERSIBLE_GATED"]},
      "require": [
        {"id": "shape", "gate": "SCHEMA", "phase": "PRE_EXECUTION",
         "schema": {"schema_id": "payment.v1", "fields": [
            {"name": "amount_minor", "type": "number"},
            {"name": "currency", "type": "text"}]}},
        {"id": "limit", "gate": "RISK_LIMIT", "phase": "PRE_EXECUTION",
         "risk_limit": {"thresholds": [{"fact": "amount_minor", "max": 1000000}]}},
        {"id": "approval", "gate": "POLICY", "phase": "PRE_RELEASE",
         "policy": {"expr": "approved == true", "description": "payments need an approval"}}
      ]
    }
  ]
}`

// A policy is validated when it is loaded, not when a payment reaches the gate
// it guards. Every one of these would otherwise become a refusal at three in
// the morning attributed to the payment rather than to the file.
func TestPoliciesAreRejectedAtLoadTime(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		hint string
	}{
		{"no id", `{"rules":[]}`, "no id"},
		{"no rules", `{"id":"p","rules":[]}`, "no rules"},
		{"unknown field", `{"id":"p","ruls":[]}`, "unknown field"},
		{"rule with no id", `{"id":"p","rules":[{"require":[]}]}`, "no id"},
		{"duplicate rule id", `{"id":"p","rules":[
			{"id":"a","require":[{"id":"x","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"true"}}]},
			{"id":"a","require":[{"id":"y","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"true"}}]}]}`,
			"appears twice"},
		{"rule that requires nothing", `{"id":"p","rules":[{"id":"a","require":[]}]}`,
			"to exempt a step"},
		{"duplicate requirement id", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"true"}},
			{"id":"x","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"true"}}]}]}`,
			"two requirements called"},
		{"requirement with no phase", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"POLICY","policy":{"expr":"true"}}]}]}`, "declares no phase"},
		{"unknown phase", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"POLICY","phase":"LATER","policy":{"expr":"true"}}]}]}`, "unknown phase"},
		{"unknown gate type", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"VIBES","phase":"PRE_RELEASE","policy":{"expr":"true"}}]}]}`,
			"unknown gate type"},
		{"validator gate naming no validators", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"VALIDATOR","phase":"PRE_RELEASE","validator":{"validators":[]}}]}]}`,
			"including the one being validated"},
		{"validator gate naming one twice", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"VALIDATOR","phase":"PRE_RELEASE",
			 "validator":{"validators":["v1","v1"]}}]}]}`, "one opinion count as two"},
		{"validator quorum that can never be reached", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"VALIDATOR","phase":"PRE_RELEASE",
			 "validator":{"validators":["v1","v2"],"quorum":3}}]}]}`, "can never be reached"},
		{"human quorum with no roles behind it", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"HUMAN","phase":"PRE_RELEASE","human":{"quorum":2}}]}]}`,
			"anybody authenticated counts towards the quorum"},
		{"human gate naming a role twice", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"HUMAN","phase":"PRE_RELEASE",
			 "human":{"roles":["approver","approver"],"quorum":2}}]}]}`, "twice"},
		{"two checks in one requirement", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"true"},"frontier":{}}]}]}`,
			"exactly one check"},
		{"gate type disagrees with the check", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"SCHEMA","phase":"PRE_RELEASE","policy":{"expr":"true"}}]}]}`,
			"carries a different check"},
		{"expression that does not compile", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"amount = 3"}}]}]}`,
			"expression syntax"},
		{"empty expression", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":""}}]}]}`,
			"empty expression"},
		{"schema with no fields", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"SCHEMA","phase":"PRE_EXECUTION","schema":{"schema_id":"s"}}]}]}`,
			"no fields"},
		{"schema field with an unknown type", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"SCHEMA","phase":"PRE_EXECUTION","schema":{"schema_id":"s",
			 "fields":[{"name":"a","type":"decimal"}]}}]}]}`, "unknown type"},
		{"risk limit that caps nothing", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"RISK_LIMIT","phase":"PRE_EXECUTION","risk_limit":{}}]}]}`,
			"caps nothing"},
		{"unknown effect class in a matcher", `{"id":"p","rules":[{"id":"a",
			"match":{"effect_classes":["MOSTLY_HARMLESS"]},"require":[
			{"id":"x","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"true"}}]}]}`,
			"unknown effect class"},

		// A frontier check asks which resources a step touched, and a step that
		// has not run has touched none. Allowing it would produce a gate that
		// always passed while looking like it was doing something.
		{"frontier check before the step runs", `{"id":"p","rules":[{"id":"a","require":[
			{"id":"x","gate":"FRONTIER","phase":"PRE_EXECUTION","frontier":{}}]}]}`,
			"has touched no resources"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := gate.LoadPolicy([]byte(c.raw))
			if err == nil {
				t.Fatal("the policy was accepted")
			}
			if !strings.Contains(err.Error(), c.hint) {
				t.Fatalf("message does not mention %q: %v", c.hint, err)
			}
		})
	}
}

// The version is a content address of the rules, so reformatting the file does
// not invent a new policy and a saga admitted this morning still hashes to what
// its log recorded.
func TestVersionTracksMeaningRatherThanFormatting(t *testing.T) {
	original := mustPolicy(t, wiresPolicy)

	reformatted := mustPolicy(t, strings.ReplaceAll(
		strings.ReplaceAll(wiresPolicy, "\n", " "), "  ", " "))
	if original.Version() != reformatted.Version() {
		t.Fatal("reindenting the file changed the policy version")
	}

	// A changed threshold is a changed policy, and must say so.
	changed := mustPolicy(t, strings.Replace(wiresPolicy, "1000000", "9000000", 1))
	if original.Version() == changed.Version() {
		t.Fatal("raising a limit did not change the policy version")
	}

	// So is a changed expression, even one that looks equivalent.
	rewritten := mustPolicy(t, strings.Replace(wiresPolicy, "approved == true", "approved", 1))
	if original.Version() == rewritten.Version() {
		t.Fatal("rewriting an expression did not change the policy version")
	}

	if !strings.HasPrefix(original.Version(), "blake3:") {
		t.Fatalf("version %q does not name its hash function", original.Version())
	}
}

func TestVersionIsStableAcrossCalls(t *testing.T) {
	p := mustPolicy(t, wiresPolicy)
	first := p.Version()
	for range 20 {
		if got := p.Version(); got != first {
			t.Fatalf("version is not stable: %q then %q", first, got)
		}
	}
}

// Rules are ordered and the first match wins, so "which clause refused this"
// has exactly one answer.
func TestResolveTakesTheFirstMatchingRule(t *testing.T) {
	p := mustPolicy(t, `{
	  "id": "test.order",
	  "rules": [
	    {"id":"specific","match":{"actions":["payments.wire"]},
	     "require":[{"id":"a","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"true"}}]},
	    {"id":"prefix","match":{"actions":["payments.*"]},
	     "require":[{"id":"b","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"true"}}]},
	    {"id":"catchall","match":{},
	     "require":[{"id":"c","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"true"}}]}
	  ]
	}`)

	cases := []struct{ action, want string }{
		{"payments.wire", "specific"},
		{"payments.ach", "prefix"},
		{"docs.read", "catchall"},
	}
	for _, c := range cases {
		got := p.Resolve(gate.Subject{Action: c.action, Mode: "supervised"})
		if got == nil {
			t.Fatalf("%s: no rule matched, though a catch-all exists", c.action)
		}
		if got.ID != c.want {
			t.Fatalf("%s: matched %q, want %q", c.action, got.ID, c.want)
		}
	}
}

// An empty condition matches everything; a non-empty one narrows. Getting this
// backwards would turn a rule meant for wires into a rule for everything.
func TestMatchConditionsNarrowRatherThanWiden(t *testing.T) {
	p := mustPolicy(t, `{
	  "id": "test.match",
	  "rules": [{
	    "id":"eu-wires",
	    "match":{"effect_classes":["IRREVERSIBLE_GATED"],"modes":["supervised"]},
	    "require":[{"id":"a","gate":"POLICY","phase":"PRE_RELEASE","policy":{"expr":"true"}}]
	  }]
	}`)

	gated := janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED
	compensable := janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE

	if p.Resolve(gate.Subject{EffectClass: gated, Mode: "supervised"}) == nil {
		t.Fatal("a subject satisfying every condition did not match")
	}
	if p.Resolve(gate.Subject{EffectClass: gated, Mode: "exploratory"}) != nil {
		t.Fatal("a subject failing the mode condition matched anyway")
	}
	if p.Resolve(gate.Subject{EffectClass: compensable, Mode: "supervised"}) != nil {
		t.Fatal("a subject failing the effect-class condition matched anyway")
	}
}

func TestTheReferencePolicyIsValid(t *testing.T) {
	p, err := gate.LoadPolicyFile("../../docs/policy/reference.json")
	if err != nil {
		t.Fatalf("the policy shipped with the repository does not load: %v", err)
	}
	if p.Version() == "" {
		t.Fatal("no version")
	}
	// It has to cover the class the Phase 3 exit gate is about, or the chaos
	// suite would be exercising rules that stop nothing.
	if r := p.Resolve(gate.Subject{
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		Mode:        "supervised",
	}); r == nil {
		t.Fatal("the reference policy has no rule for IRREVERSIBLE_GATED steps")
	}
}

func TestLoadPolicyFileReportsAMissingFile(t *testing.T) {
	_, err := gate.LoadPolicyFile("testdata/nope.json")
	if err == nil {
		t.Fatal("a missing policy file was accepted")
	}
	if errors.Is(err, gate.ErrPolicy) {
		t.Fatalf("a missing file should not read as an invalid policy: %v", err)
	}
}

// TestAPolicyDocumentCanRequireAStepUp closes a gap that made two controls
// unreachable.
//
// 5b added require_established_identity and require_step_up to HumanCheck and
// taught the gate to enforce them, and both were tested — by constructing a
// HumanCheck in Go. The policy language, which is what a deployment actually
// writes, had no field for either. So the controls existed, worked, and could
// not be switched on by anybody: a step-up nobody can require is the same shape
// of problem as a step-up that establishes nothing.
func TestAPolicyDocumentCanRequireAStepUp(t *testing.T) {
	doc := []byte(`{
	  "id": "stepup.test",
	  "rules": [{
	    "id": "wires",
	    "match": {"effect_classes": ["IRREVERSIBLE_GATED"]},
	    "require": [{
	      "id": "four-eyes", "gate": "HUMAN", "phase": "PRE_RELEASE",
	      "human": {
	        "roles": ["credit-officer"], "quorum": 2,
	        "separation_of_duty": true,
	        "require_established_identity": true,
	        "require_step_up": true
	      }
	    }]
	  }]
	}`)
	var p gate.Policy
	if err := json.Unmarshal(doc, &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	reqs := p.Rules[0].Requirements()
	if len(reqs) != 1 {
		t.Fatalf("%d requirement(s)", len(reqs))
	}
	human := reqs[0].GetHuman()
	if !human.GetRequireStepUp() {
		t.Fatal("a policy document asking for a step-up produced a requirement that does not")
	}
	if !human.GetRequireEstablishedIdentity() {
		t.Fatal("require_established_identity did not survive the document")
	}
	// The rest of the spec still arrives, so this is an addition rather than a
	// rewrite of how a human requirement is read.
	if !human.GetSeparationOfDuty() || human.GetQuorum() != 2 {
		t.Fatalf("the rest of the human spec was lost: %+v", human)
	}
}
