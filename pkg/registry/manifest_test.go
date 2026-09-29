package registry_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/registry"
)

// wire is an honest manifest: a payment that can be refunded, a refund that
// takes it back, and a notification nobody can unsend. Every test that needs a
// valid manifest starts from this and breaks one thing.
func wireManifest() *registry.Manifest {
	return &registry.Manifest{
		Version: "1.0.0",
		Identity: registry.Identity{
			ParticipantID: "tool_payments",
			Kind:          "TOOL",
			Principal:     "pr_bank",
		},
		Runtime: registry.Runtime{
			ModelID:          "none",
			PromptBundleHash: "blake3:prompt-v1",
		},
		Actions: []registry.Action{
			{
				Name:        "payments.wire",
				EffectClass: "COMPENSABLE",
				Compensation: &registry.Compensation{
					Action:          "payments.refund",
					MaxDelaySeconds: 72 * 3600,
					ResidualEffects: "the statement line remains",
				},
				Idempotency: &registry.Idempotency{KeyRecipe: "account,amount,intent_id"},
				Limits:      &registry.Limits{MaxAmount: 10000, AmountField: "amount", Currency: "EUR"},
			},
			{
				Name:        "payments.refund",
				EffectClass: "REVERSIBLE",
				Compensation: &registry.Compensation{
					Action: "payments.wire",
				},
				Idempotency: &registry.Idempotency{KeyRecipe: "account,amount,intent_id"},
			},
			{
				Name:        "notify.email",
				EffectClass: "IRREVERSIBLE_GATED",
				Idempotency: &registry.Idempotency{KeyRecipe: "recipient,subject,intent_id"},
			},
			{
				Name:        "payments.quote",
				EffectClass: "PURE",
			},
		},
		Risk: registry.Risk{
			Tier:                 2,
			RevalidationTriggers: []string{registry.TriggerModelChange, registry.TriggerActionChange},
		},
		Jurisdiction: registry.Jurisdiction{DeployableIn: []string{"EU"}, DataResidency: "EU"},
	}
}

func TestTheReferenceManifestIsValid(t *testing.T) {
	if err := wireManifest().Validate(); err != nil {
		t.Fatalf("the manifest every other test breaks is itself invalid: %v", err)
	}
}

// TestAManifestThatContradictsItselfIsRefusedAtLoadTime is the point of
// validation: every one of these documents would otherwise be registered, then
// pinned by a saga, and only argue with itself at a gate.
func TestAManifestThatContradictsItselfIsRefusedAtLoadTime(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(*registry.Manifest)
		want   string
	}{
		{
			name:   "reversible with no compensation",
			break_: func(m *registry.Manifest) { m.Actions[1].Compensation = nil },
			want:   "undo nobody names",
		},
		{
			name:   "compensable that does not say what survives the undo",
			break_: func(m *registry.Manifest) { m.Actions[0].Compensation.ResidualEffects = "" },
			want:   "residual effects",
		},
		{
			name:   "reversible that leaves something behind",
			break_: func(m *registry.Manifest) { m.Actions[1].Compensation.ResidualEffects = "a log line" },
			want:   "is COMPENSABLE",
		},
		{
			name: "irreversible with a compensation",
			break_: func(m *registry.Manifest) {
				m.Actions[2].Compensation = &registry.Compensation{Action: "payments.refund"}
			},
			want: "not irreversible",
		},
		{
			name: "compensation the participant cannot perform",
			break_: func(m *registry.Manifest) {
				m.Actions[0].Compensation.Action = "payments.unsend"
			},
			want: "does not declare",
		},
		{
			name: "compensation that is itself irreversible",
			break_: func(m *registry.Manifest) {
				m.Actions[0].Compensation.Action = "notify.email"
			},
			want: "two irreversible outcomes",
		},
		{
			name:   "effectful action with no idempotency recipe",
			break_: func(m *registry.Manifest) { m.Actions[2].Idempotency = nil },
			want:   "duplicate delivery cannot be undone",
		},
		{
			name: "pure action that claims to be delivered",
			break_: func(m *registry.Manifest) {
				m.Actions[3].Idempotency = &registry.Idempotency{KeyRecipe: "x"}
			},
			want: "nothing is delivered",
		},
		{
			name: "immediate irreversible with no standing mandate",
			break_: func(m *registry.Manifest) {
				m.Actions[2].EffectClass = "IRREVERSIBLE_IMMEDIATE"
			},
			want: "pre-authorized mandate",
		},
		{
			name: "a mandate on a class that can be gated",
			break_: func(m *registry.Manifest) {
				m.Actions[2].PreauthorizedMandate = "mandate:standing"
			},
			want: "belongs only to the class that cannot be gated",
		},
		{
			name: "a revalidation trigger nothing can match",
			break_: func(m *registry.Manifest) {
				m.Risk.RevalidationTriggers = []string{"model_chagne"}
			},
			want: "never fires",
		},
		{
			name:   "no risk tier",
			break_: func(m *registry.Manifest) { m.Risk.Tier = 0 },
			want:   "model inventory",
		},
		{
			name:   "no principal",
			break_: func(m *registry.Manifest) { m.Identity.Principal = "" },
			want:   "names no principal",
		},
		{
			name: "two declarations of one action",
			break_: func(m *registry.Manifest) {
				m.Actions = append(m.Actions, m.Actions[0])
			},
			want: "declared twice",
		},
		{
			name: "a limit that caps something with no name",
			break_: func(m *registry.Manifest) {
				m.Actions[0].Limits.AmountField = ""
			},
			want: "which argument",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := wireManifest()
			tc.break_(m)
			err := m.Validate()
			if err == nil {
				t.Fatalf("the manifest was accepted; %s should be refused at load time", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused for the wrong reason:\n  got:  %v\n  want it to mention: %q",
					err, tc.want)
			}
		})
	}
}

// TestTheContentAddressIdentifiesTheDeclarationNotTheFile is what makes a pin
// mean one thing. Reformatting must not invent a new manifest; changing a claim
// must.
func TestTheContentAddressIdentifiesTheDeclarationNotTheFile(t *testing.T) {
	m := wireManifest()
	compact, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(m, "", "      ")
	if err != nil {
		t.Fatal(err)
	}

	a, err := registry.LoadManifest(compact)
	if err != nil {
		t.Fatal(err)
	}
	b, err := registry.LoadManifest(indented)
	if err != nil {
		t.Fatal(err)
	}
	if a.ContentAddress() != b.ContentAddress() {
		t.Fatalf("reindenting the file changed the content address:\n  %s\n  %s",
			a.ContentAddress(), b.ContentAddress())
	}

	changed := wireManifest()
	changed.Actions[0].Limits.MaxAmount = 10001
	if changed.ContentAddress() == a.ContentAddress() {
		t.Fatal("raising a limit by one euro left the content address unchanged, so a pin " +
			"would not notice the change")
	}
}

func TestCanonicalBytesRoundTrip(t *testing.T) {
	m := wireManifest()
	canonical, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	back, err := registry.DecodeManifest(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if back.ContentAddress() != m.ContentAddress() {
		t.Fatalf("a manifest decoded from the log hashes differently:\n  %s\n  %s",
			back.ContentAddress(), m.ContentAddress())
	}
	if got, want := back.Actions[0].Compensation.Action, "payments.refund"; got != want {
		t.Fatalf("compensation survived the round trip as %q, want %q", got, want)
	}
}

func TestUnknownFieldsAreRefused(t *testing.T) {
	raw := []byte(`{"version":"1.0.0","identity":{"participant_id":"x","kind":"TOOL",
		"principal":"p"},"actions":[],"risk":{"tier":2},"jurisdiction":{},"scope":"everything"}`)
	if _, err := registry.LoadManifest(raw); err == nil {
		t.Fatal("a manifest with an unrecognised field was accepted; a claim Janus does not " +
			"understand must not read as one it agreed to")
	}
}

// TestTheReferenceManifestShippedWithTheRepositoryIsUsable. It is the manifest
// the round-trip script registers and the one a reader copies, so it has to
// load, hash, and survive its own conformance harness against the sandbox that
// ships beside it.
func TestTheReferenceManifestShippedWithTheRepositoryIsUsable(t *testing.T) {
	m, err := registry.LoadManifestFile("../../docs/registry/reference.json")
	if err != nil {
		t.Fatalf("the manifest shipped with the repository does not load: %v", err)
	}
	if m.ContentAddress() == "" {
		t.Fatal("no content address")
	}

	// It has to declare the action the reference gate policy stops, or the two
	// documents describe different systems.
	if class, ok := m.EffectClassOf("payments.wire.large"); !ok ||
		registry.ShortClass(class) != "IRREVERSIBLE_GATED" {
		t.Fatal("the reference manifest does not register payments.wire.large as " +
			"IRREVERSIBLE_GATED, which is the action the reference gate policy exists to hold")
	}

	doubles, err := registry.LoadDoubles("../../docs/registry/reference-sandbox.json")
	if err != nil {
		t.Fatalf("the sandbox shipped with the repository does not load: %v", err)
	}
	report, err := registry.Evaluate(t.Context(), m, doubles)
	if err != nil {
		t.Fatal(err)
	}
	if !report.GetPassed() {
		t.Fatalf("the reference manifest fails its own conformance harness:\n%s",
			registry.ReportText(report))
	}
}
