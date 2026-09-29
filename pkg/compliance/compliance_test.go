package compliance_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/compliance"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// TestAPackNamingACheckThisBuildDoesNotKnowIsRefused.
//
// A pack is data and legal review updates it, which is the design — and it is
// exactly why a typo has to be refused loudly. An article mapped to a check
// that does not exist would evaluate to nothing and report as satisfied, which
// is the most expensive kind of green: a compliance report that claims a
// control nobody implemented.
func TestAPackNamingACheckThisBuildDoesNotKnowIsRefused(t *testing.T) {
	path := writePack(t, `{
      "id": "typo", "version": "0.1.0",
      "articles": [{"id": "Art.1", "title": "t", "requires": ["every_action_is_lovely"]}]
    }`)
	_, err := compliance.LoadPack(path)
	if err == nil {
		t.Fatal("a pack requiring a check that does not exist was accepted")
	}
	if !strings.Contains(err.Error(), "not a check this build knows") {
		t.Fatalf("the refusal does not say the check is unknown: %v", err)
	}
	if !strings.Contains(err.Error(), "Known checks:") {
		t.Fatalf("the refusal does not say what is available, so whoever wrote the pack "+
			"cannot fix it: %v", err)
	}
}

// TestAnArticleThatChecksNothingIsRefused. An article nothing evaluates reports
// as satisfied, which is worse than an article nobody mapped.
func TestAnArticleThatChecksNothingIsRefused(t *testing.T) {
	path := writePack(t, `{
      "id": "empty", "version": "0.1.0",
      "articles": [{"id": "Art.1", "title": "t", "requires": []}]
    }`)
	if _, err := compliance.LoadPack(path); err == nil {
		t.Fatal("an article requiring nothing was accepted")
	}
}

// TestAPackWithoutAVersionIsRefused. A report has to say which mapping it was
// run against, and "the current one" is not an answer six months later.
func TestAPackWithoutAVersionIsRefused(t *testing.T) {
	path := writePack(t, `{
      "id": "unversioned",
      "articles": [{"id": "Art.1", "title": "t", "requires": ["every_participant_declares_a_risk_tier"]}]
    }`)
	if _, err := compliance.LoadPack(path); err == nil {
		t.Fatal("a pack with no version was accepted")
	}
}

// TestAPolicyThatGatesAnIrreversibleEffectWithoutAPersonIsExposed is the
// finding the linter exists to produce.
func TestAPolicyThatGatesAnIrreversibleEffectWithoutAPersonIsExposed(t *testing.T) {
	subject := compliance.Subject{
		Registry: registryWith(t, "IRREVERSIBLE_GATED"),
		Policy: policyWith(t, gate.Requirement{
			ID: "just-a-flag", Gate: gate.GatePolicy, Phase: gate.PhasePreRelease,
			Policy: &gate.PolicySpec{Expr: `approved == true`, Description: "a flag"},
		}),
	}
	report := compliance.Lint(subject, packs(t))
	if report.Clean() {
		t.Fatal("a policy whose only control over an irreversible effect is a flag the " +
			"agent sets was reported as clean")
	}
	if !mentions(report, "without requiring a person") {
		t.Fatalf("the finding does not say what is missing:\n%s", report)
	}
}

// TestAPolicyWithAHumanGateSatisfiesIt, so the check above is not simply always
// failing.
func TestAPolicyWithAHumanGateSatisfiesIt(t *testing.T) {
	subject := compliance.Subject{
		Registry: registryWith(t, "IRREVERSIBLE_GATED"),
		Policy: policyWith(t, gate.Requirement{
			ID: "four-eyes", Gate: gate.GateHuman, Phase: gate.PhasePreRelease,
			Human: &gate.HumanSpec{
				Roles: []string{"credit-officer"}, Quorum: 2, SeparationOfDuty: true,
			},
		}),
	}
	report := compliance.Lint(subject, packs(t))
	if !report.Clean() {
		t.Fatalf("a policy requiring two people, neither the initiator, was reported "+
			"exposed:\n%s", report)
	}
}

// TestAnUnrunnableCheckIsUnknownRatherThanSatisfied.
//
// Reporting a check that could not run as a pass is how a compliance report
// comes to claim more than anybody established.
func TestAnUnrunnableCheckIsUnknownRatherThanSatisfied(t *testing.T) {
	subject := compliance.Subject{Registry: registryWith(t, "PURE")} // no policy
	report := compliance.Lint(subject, packs(t))
	if report.Unknown == 0 {
		t.Fatalf("with no policy supplied, nothing was reported unknown:\n%s", report)
	}
	for _, f := range report.Findings {
		if f.Status == compliance.StatusUnknown {
			for _, detail := range f.Detail {
				if strings.Contains(detail, "no policy was supplied") {
					return
				}
			}
		}
	}
	t.Fatalf("no unknown finding says why it could not run:\n%s", report)
}

// TestABrokenReversibilityClaimIsExposed. An action that says it can be taken
// back and names nothing to take it back with is a broken declaration, not an
// oversight measure.
func TestABrokenReversibilityClaimIsExposed(t *testing.T) {
	// COMPENSABLE with no compensation cannot be registered — the manifest
	// validator refuses it, which is the check working one layer down. So the
	// exposure this article is about is reached the way it would be in life:
	// an action that is honest about being irreversible, with a policy that
	// puts nothing in front of it.
	subject := compliance.Subject{
		Registry: registryWith(t, "IRREVERSIBLE_GATED"),
		Policy: policyWith(t, gate.Requirement{
			ID: "schema-only", Gate: gate.GateSchema, Phase: gate.PhasePreRelease,
			Schema: &gate.SchemaSpec{
				SchemaID: "x.v1",
				Fields:   []gate.FieldSpec{{Name: "amount_minor", Type: "number"}},
			},
		}),
	}
	report := compliance.Lint(subject, packs(t))
	if report.Clean() {
		t.Fatalf("an irreversible action behind a schema check and nothing else was "+
			"reported clean:\n%s", report)
	}
}

// ---- fixtures --------------------------------------------------------------

func packs(t *testing.T) []*compliance.Pack {
	t.Helper()
	loaded, err := compliance.LoadPacks("../../docs/compliance/packs")
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func writePack(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pack.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// registryWith registers one participant with one action of the given class,
// through the recorder and into a log, and folds the registry back out of it.
//
// Built rather than hand-assembled: a Registry is a projection of the log,
// and a test that constructed one directly would be checking the
// linter against a shape the system cannot actually produce.
func registryWith(t *testing.T, class string) *registry.Registry {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_registry", Principal: "pr_bank", Kind: "SYSTEM",
	}, registry.New(), trust)

	action := registry.Action{Name: "act", EffectClass: class}
	doubles := registry.NewDoubles("s")
	switch class {
	case "PURE":
		doubles = doubles.With("act", registry.Double{})
	case "COMPENSABLE", "REVERSIBLE":
		action.Compensation = &registry.Compensation{
			Action: "undo", MaxDelaySeconds: 60, ResidualEffects: "none",
		}
		action.Idempotency = &registry.Idempotency{KeyRecipe: "saga_id"}
		doubles = doubles.With("act", registry.Double{Deltas: map[string]int64{"x": -1}}).
			With("undo", registry.Double{Deltas: map[string]int64{"x": 1}})
	default:
		action.Idempotency = &registry.Idempotency{KeyRecipe: "saga_id"}
		// An irreversible action carries a ceiling. Without one the fixture
		// itself trips irreversible_actions_declare_limits, which is the check
		// working — but it would make every test using this registry assert
		// about limits when it means to assert about something else.
		action.Limits = &registry.Limits{
			MaxAmount: 100_000, AmountField: "amount", Currency: "EUR", RatePerHour: 10,
		}
		doubles = doubles.With("act", registry.Double{Deltas: map[string]int64{"x": -1}})
	}
	actions := []registry.Action{action}
	if action.Compensation != nil {
		actions = append(actions, registry.Action{
			Name: "undo", EffectClass: "REVERSIBLE",
			Compensation: &registry.Compensation{Action: "act"},
			Idempotency:  &registry.Idempotency{KeyRecipe: "saga_id"},
		})
	}

	m := &registry.Manifest{
		Version:  "1.0.0",
		Identity: registry.Identity{ParticipantID: "tool_x", Kind: "TOOL", Principal: "pr_bank"},
		Runtime:  registry.Runtime{ModelID: "none", PromptBundleHash: "blake3:t"},
		Actions:  actions,
		Risk: registry.Risk{
			Tier:                 2,
			RevalidationTriggers: []string{registry.TriggerModelChange, registry.TriggerActionChange},
		},
		Jurisdiction: registry.Jurisdiction{DeployableIn: []string{"EU"}, DataResidency: "EU"},
	}
	sig, err := registry.Sign(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := rec.Register(ctx, m, sig); err != nil {
		t.Fatal(err)
	}
	report, err := registry.Evaluate(ctx, m, doubles)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Evaluate(ctx, "tool_x", "1.0.0", report); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, "tool_x", "1.0.0"); err != nil {
		t.Fatal(err)
	}

	events, err := registry.LoadEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	folded, err := registry.Fold(events)
	if err != nil {
		t.Fatal(err)
	}
	return folded
}

func policyWith(t *testing.T, requirement gate.Requirement) *gate.Policy {
	t.Helper()
	p := &gate.Policy{
		ID: "test",
		Rules: []gate.Rule{{
			ID:      "irreversible",
			Match:   gate.Match{EffectClasses: []string{"IRREVERSIBLE_GATED"}},
			Require: []gate.Requirement{requirement},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

func mentions(r *compliance.Report, text string) bool {
	return strings.Contains(r.String(), text)
}

// TestAnUnpinnedDeploymentIsUnknownNotExposed.
//
// A deployment that has not declared a jurisdiction has not failed to enforce a
// pin; it has not made the declaration. Reporting that as a violation would
// push deployments into declaring a jurisdiction in order to clear a report,
// which is how a control comes to exist because a report asked for it rather
// than because anybody decided it.
func TestAnUnpinnedDeploymentIsUnknownNotExposed(t *testing.T) {
	subject := compliance.Subject{Registry: registryWith(t, "PURE")}
	res := compliance.Run("jurisdiction_is_pinned_and_enforced", subject)
	if !res.Unknown {
		t.Fatalf("an unpinned deployment was not reported unknown: %+v", res)
	}
	if !strings.Contains(res.Detail, "declares no jurisdiction to pin") {
		t.Fatalf("the detail does not say why it could not run: %q", res.Detail)
	}
}

// TestAPinNoParticipantCanSatisfyIsExposed. The registry here declares EU, and
// a deployment pinned to DE is not covered by it — Janus does not decide that a
// member state is inside a supranational declaration, because which body's
// rules that holds under is not something a string comparison can know.
func TestAPinNoParticipantCanSatisfyIsExposed(t *testing.T) {
	subject := compliance.Subject{
		Registry: registryWith(t, "PURE"),
		Tenant:   tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"},
	}
	res := compliance.Run("jurisdiction_is_pinned_and_enforced", subject)
	if res.Satisfied || res.Unknown {
		t.Fatalf("a pin no participant satisfies was not reported as exposed: %+v", res)
	}
	if !strings.Contains(res.Detail, "may not be used there") {
		t.Fatalf("the detail does not name the problem: %q", res.Detail)
	}
}

func TestAPinEveryParticipantSatisfiesIsSatisfied(t *testing.T) {
	subject := compliance.Subject{
		Registry: registryWith(t, "PURE"),
		Tenant:   tenancy.Tenant{ID: "bank_a", Jurisdiction: "EU"},
	}
	res := compliance.Run("jurisdiction_is_pinned_and_enforced", subject)
	if !res.Satisfied {
		t.Fatalf("a pin every participant satisfies was not satisfied: %+v", res)
	}
}

// TestTheWeakerJurisdictionCheckIsUnchanged. The two checks answer different
// questions and a pack mapped to the weaker one should keep getting the weaker
// answer: this registry declares a jurisdiction, so "every participant declares
// one" is satisfied even where the pin above is not.
func TestTheWeakerJurisdictionCheckIsUnchanged(t *testing.T) {
	subject := compliance.Subject{
		Registry: registryWith(t, "PURE"),
		Tenant:   tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"},
	}
	res := compliance.Run("every_participant_declares_jurisdiction", subject)
	if !res.Satisfied {
		t.Fatalf("the declaration check changed meaning: %+v", res)
	}
}

// registryOf builds a registry from one caller-shaped manifest, so a test can
// state exactly the property it is about.
//
// registryWith above is keyed by effect class and always produces a TOOL naming
// a model; the two newest checks are about a manifest's *optional*
// fields, so they need a fixture that can leave one out.
func registryOf(t *testing.T, mutate func(*registry.Manifest)) *registry.Registry {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_registry", Principal: "pr_bank", Kind: "SYSTEM",
	}, registry.New(), trust)

	m := &registry.Manifest{
		Version: "1.0.0",
		Identity: registry.Identity{
			ParticipantID: "ag_underwriter", Kind: "AGENT", Principal: "pr_bank",
		},
		Runtime: registry.Runtime{ModelID: "glm-5.3", PromptBundleHash: "blake3:t"},
		Actions: []registry.Action{{
			Name: "act", EffectClass: "IRREVERSIBLE_GATED",
			Idempotency: &registry.Idempotency{KeyRecipe: "saga_id"},
			Limits:      &registry.Limits{MaxAmount: 1000, AmountField: "amount", Currency: "EUR"},
		}},
		Risk: registry.Risk{
			Tier:                 2,
			RevalidationTriggers: []string{registry.TriggerModelChange, registry.TriggerActionChange},
		},
		Jurisdiction: registry.Jurisdiction{DeployableIn: []string{"EU"}, DataResidency: "EU"},
	}
	mutate(m)

	sig, err := registry.Sign(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := rec.Register(ctx, m, sig); err != nil {
		t.Fatalf("registering: %v", err)
	}
	doubles := registry.NewDoubles("s")
	for _, a := range m.Actions {
		switch {
		case a.EffectClass == "PURE":
			doubles = doubles.With(a.Name, registry.Double{})
		case a.Name == "undo":
			doubles = doubles.With(a.Name, registry.Double{Deltas: map[string]int64{"x": 1}})
		default:
			doubles = doubles.With(a.Name, registry.Double{Deltas: map[string]int64{"x": -1}})
		}
	}
	report, err := registry.Evaluate(ctx, m, doubles)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Evaluate(ctx, m.Identity.ParticipantID, "1.0.0", report); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, m.Identity.ParticipantID, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	events, err := registry.LoadEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	folded, err := registry.Fold(events)
	if err != nil {
		t.Fatal(err)
	}
	return folded
}

// TestAnUnboundedIrreversibleActionIsFound is the check finding something, which
// is the half a satisfied fixture cannot demonstrate.
//
// It also proves the check is not a restatement of what admission already
// refuses: the manifest below registers and activates cleanly with no Limits at
// all, so `Manifest.validate` accepts it. A check that could only ever pass —
// because every manifest reaching it was already required to satisfy the
// property — would be a check that cannot fail.
func TestAnUnboundedIrreversibleActionIsFound(t *testing.T) {
	reg := registryOf(t, func(m *registry.Manifest) { m.Actions[0].Limits = nil })
	res := compliance.Run("irreversible_actions_declare_limits",
		compliance.Subject{Registry: reg})
	if res.Unknown {
		t.Fatalf("the check could not run: %s", res.Detail)
	}
	if res.Satisfied {
		t.Fatal("an IRREVERSIBLE_GATED action with no limits was reported as satisfying " +
			"a requirement for limits")
	}
	if !strings.Contains(res.Detail, "ag_underwriter/act") {
		t.Errorf("the finding does not name the action: %s", res.Detail)
	}
}

// TestABoundedIrreversibleActionSatisfies keeps the check from reporting
// everything, which would make it noise rather than a finding.
func TestABoundedIrreversibleActionSatisfies(t *testing.T) {
	reg := registryOf(t, func(*registry.Manifest) {})
	res := compliance.Run("irreversible_actions_declare_limits",
		compliance.Subject{Registry: reg})
	if !res.Satisfied {
		t.Fatalf("an action declaring limits was reported as exposed: %s", res.Detail)
	}
}

// TestAReversibleActionWithNoLimitsIsNotReported: the line is drawn where the
// undo stops existing. A linter that flagged recoverable actions would report
// what does not matter, and a reader who learns to skip findings skips the ones
// that do.
func TestAReversibleActionWithNoLimitsIsNotReported(t *testing.T) {
	reg := registryOf(t, func(m *registry.Manifest) {
		m.Actions[0] = registry.Action{
			Name: "act", EffectClass: "COMPENSABLE",
			Compensation: &registry.Compensation{
				Action: "undo", MaxDelaySeconds: 60, ResidualEffects: "none",
			},
			Idempotency: &registry.Idempotency{KeyRecipe: "saga_id"},
		}
		m.Actions = append(m.Actions, registry.Action{
			Name: "undo", EffectClass: "REVERSIBLE",
			Compensation: &registry.Compensation{Action: "act"},
			Idempotency:  &registry.Idempotency{KeyRecipe: "saga_id"},
		})
	})
	res := compliance.Run("irreversible_actions_declare_limits",
		compliance.Subject{Registry: reg})
	if !res.Satisfied {
		t.Fatalf("a compensable action with no limits was reported: %s", res.Detail)
	}
}

// TestAnAgentThatNamesNoModelIsFound.
func TestAnAgentThatNamesNoModelIsFound(t *testing.T) {
	reg := registryOf(t, func(m *registry.Manifest) { m.Runtime.ModelID = "" })
	res := compliance.Run("every_agent_identifies_its_model",
		compliance.Subject{Registry: reg})
	if res.Unknown {
		t.Fatalf("the check could not run: %s", res.Detail)
	}
	if res.Satisfied {
		t.Fatal("an AGENT naming no model satisfied a model-inventory requirement")
	}
	if !strings.Contains(res.Detail, "ag_underwriter") {
		t.Errorf("the finding does not name the agent: %s", res.Detail)
	}
}

// TestAToolIsNotAskedForAModel. Only an agent runs one, and a finding nobody can
// act on is how a report stops being read.
func TestAToolIsNotAskedForAModel(t *testing.T) {
	reg := registryOf(t, func(m *registry.Manifest) {
		m.Identity.ParticipantID = "tool_ledger"
		m.Identity.Kind = "TOOL"
		m.Runtime.ModelID = ""
	})
	res := compliance.Run("every_agent_identifies_its_model",
		compliance.Subject{Registry: reg})
	if !res.Unknown {
		t.Fatalf("with no agents registered the answer should be unknown, got %+v", res)
	}
	if !strings.Contains(res.Detail, "cannot tell those apart") {
		t.Errorf("the unknown does not give both readings, so a reader cannot tell "+
			"'no models' from 'models nobody registered': %s", res.Detail)
	}
}

// TestRemovingACheckFromAPackChangesTheReport is the standard every check
// is held to: each has a test that fails when the check is removed.
//
// A check that no pack references is unreachable — the pack is its only
// consumer — so a new check and its mapping have to arrive together, and this is
// what proves the mapping is live rather than decorative.
func TestRemovingACheckFromAPackChangesTheReport(t *testing.T) {
	reg := registryOf(t, func(m *registry.Manifest) { m.Actions[0].Limits = nil })
	subject := compliance.Subject{Registry: reg}

	withCheck := writePack(t, `{
      "id": "p", "version": "0.1.0",
      "articles": [{"id": "A.1", "title": "limits on output",
                    "requires": ["irreversible_actions_declare_limits"]}]
    }`)
	// Mapped to a *different* check the same subject satisfies, rather than to
	// nothing: the loader refuses an article with an empty `requires`, on the
	// grounds that an article nothing evaluates reports as satisfied. So the
	// comparison holds the pack's shape constant and varies only which check it
	// names.
	without := writePack(t, `{
      "id": "p", "version": "0.1.0",
      "articles": [{"id": "A.1", "title": "limits on output",
                    "requires": ["every_participant_declares_a_risk_tier"]}]
    }`)

	exposed := reportOf(t, withCheck, subject)
	if !strings.Contains(exposed, "EXPOSED") {
		t.Fatalf("the mapped pack did not report the unbounded action:\n%s", exposed)
	}
	silent := reportOf(t, without, subject)
	if strings.Contains(silent, "EXPOSED") {
		t.Fatalf("dropping the check from the pack still reported an exposure, so the "+
			"mapping is not what produced it:\n%s", silent)
	}
}

// reportOf lints a subject against one pack file.
func reportOf(t *testing.T, path string, subject compliance.Subject) string {
	t.Helper()
	pack, err := compliance.LoadPack(path)
	if err != nil {
		t.Fatal(err)
	}
	return compliance.Lint(subject, []*compliance.Pack{pack}).String()
}
