package projection_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/projection"
	"github.com/mustafarslan/janus/pkg/registry"
)

// actions builds a manifest's action list for an effect class.
//
// Two shapes rather than one parameterised shape, because the manifest validator
// enforces rules that make them genuinely different documents: an
// IRREVERSIBLE_GATED action may not declare a compensation (an effect that can
// be taken back is not irreversible), and nothing may compensate *with* an
// irreversible action (an undo that cannot itself be undone leaves a failed saga
// choosing between two irreversible outcomes). Those are real rules and the test
// fixtures respect them rather than route around them.
func actions(effect string) []registry.Action {
	if effect == "IRREVERSIBLE_GATED" {
		return []registry.Action{{
			Name:        "notify.email",
			EffectClass: "IRREVERSIBLE_GATED",
			Idempotency: &registry.Idempotency{KeyRecipe: "recipient,intent_id"},
		}}
	}
	return []registry.Action{{
		Name:        "payments.wire",
		EffectClass: effect,
		Compensation: &registry.Compensation{
			Action: "payments.refund", MaxDelaySeconds: 3600,
			ResidualEffects: "the statement line remains",
		},
		Idempotency: &registry.Idempotency{KeyRecipe: "account,amount,intent_id"},
		Limits:      &registry.Limits{MaxAmount: 10000, AmountField: "amount", Currency: "EUR"},
	}, {
		Name:         "payments.refund",
		EffectClass:  "REVERSIBLE",
		Compensation: &registry.Compensation{Action: "payments.wire"},
		Idempotency:  &registry.Idempotency{KeyRecipe: "account,amount,intent_id"},
	}}
}

func testManifest(participant, version string, effect string) *registry.Manifest {
	return &registry.Manifest{
		Version:  version,
		Identity: registry.Identity{ParticipantID: participant, Kind: "TOOL", Principal: "pr_bank"},
		Runtime:  registry.Runtime{ModelID: "none", PromptBundleHash: "blake3:prompt-v1"},
		Actions:  actions(effect),
		Risk: registry.Risk{
			Tier:                 2,
			RevalidationTriggers: []string{registry.TriggerModelChange, registry.TriggerActionChange},
		},
		Jurisdiction: registry.Jurisdiction{
			DeployableIn: []string{"EU", "DE"}, DataResidency: "EU",
		},
	}
}

// registryLog writes a registry history with every transition the state machine
// has: register, evaluate, activate, a second version, a revalidation trigger,
// and a suspension. It returns the directory and the sequences at which the
// interesting things happened.
//
// The history matters more than its length. A projection that agreed with the
// log about a registry where nothing had ever been suspended would be agreeing
// about the easy half.
func registryLog(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	operator := evidence.ParticipantRef{
		ID: "ag_operator", Principal: "pr_bank", Kind: "AGENT", ManifestVersion: "1.0.0",
	}
	rec := registry.NewRecorder(app, operator, registry.New(), trust)

	register := func(participant, version, effect string) *registry.Manifest {
		m := testManifest(participant, version, effect)
		sig, err := registry.Sign(m, signer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rec.Register(ctx, m, sig); err != nil {
			t.Fatalf("register %s@%s: %v", participant, version, err)
		}
		return m
	}
	pass := func(m *registry.Manifest) {
		report := &janusv1.EvaluationReport{
			Passed: true, HarnessVersion: "test", Sandbox: "double",
			// The triggers the manifest declares have to be covered, or the
			// version owes one and cannot be activated -- which is the rule this
			// history is here to exercise later, deliberately, on 2.0.0.
			TriggersCovered: m.Risk.RevalidationTriggers,
		}
		if err := rec.Evaluate(ctx, m.Identity.ParticipantID, m.Version, report); err != nil {
			t.Fatalf("evaluate %s@%s: %v", m.Identity.ParticipantID, m.Version, err)
		}
	}

	a := register("tool_payments", "1.0.0", "COMPENSABLE")
	pass(a)
	if err := rec.Activate(ctx, "tool_payments", "1.0.0"); err != nil {
		t.Fatal(err)
	}

	b := register("tool_notify", "1.0.0", "IRREVERSIBLE_GATED")
	pass(b)
	if err := rec.Activate(ctx, "tool_notify", "1.0.0"); err != nil {
		t.Fatal(err)
	}

	// A second version of the first participant, registered but never activated,
	// so "the active version" and "the latest version" are different answers.
	c := register("tool_payments", "2.0.0", "COMPENSABLE")
	pass(c)

	// A revalidation trigger, which is the state an inventory report is really
	// asking about: a version owing one cannot be activated.
	if err := rec.RequireRevalidation(ctx, "tool_payments", "2.0.0",
		[]string{"model-change"}, "the model behind it moved"); err != nil {
		t.Fatal(err)
	}

	// And a suspension, so the history contains a version that was in good
	// standing and is not any more.
	if err := rec.Suspend(ctx, "tool_notify", "1.0.0", "an incident"); err != nil {
		t.Fatal(err)
	}
	return dir
}

// describeRegistry renders a registry so two of them can be compared as text.
func describeRegistry(t *testing.T, reg *registry.Registry) string {
	t.Helper()
	out := ""
	for _, pid := range reg.Participants() {
		active := "(none)"
		if e, ok := reg.Active(pid); ok {
			active = e.Version
		}
		out += fmt.Sprintf("%s active=%s\n", pid, active)
		for _, e := range reg.Versions(pid) {
			out += fmt.Sprintf("  %s state=%s addr=%s reg=%d act=%d last=%d triggers=%v\n",
				e.Version, e.State, e.ContentAddress,
				e.RegisteredSeq, e.ActivatedSeq, e.LastSeq, e.PendingTriggers)
			for _, act := range e.Manifest.Actions {
				out += fmt.Sprintf("    action %s %s\n", act.Name, act.EffectClass)
			}
		}
	}
	return out
}

// TestTheProjectedRegistryFoldsAsTheLogDoes.
//
// `pkg/registry`'s own doc comment argues against putting the registry in a
// table, and it names what a table would lose: resolution as of a sequence, an
// auditor rebuilding from a bundle, and tamper detection from the chain. This
// checks the first of those has not been lost and that the everyday answer is
// unchanged — the projection stores the *events* and folds them with the same
// `registry.Fold`, so the only thing that differs is where the bytes were read
// from.
func TestTheProjectedRegistryFoldsAsTheLogDoes(t *testing.T) {
	store, ctx := newStore(t)
	dir := registryLog(t)

	proj := projection.NewProjector(store, dir)
	head, err := proj.CatchUp(ctx)
	if err != nil {
		t.Fatalf("catch up: %v", err)
	}

	fromLog, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	fromProjection, err := proj.Registry(ctx, head)
	if err != nil {
		t.Fatal(err)
	}

	if len(fromLog.Participants()) == 0 {
		t.Fatal("the registry history is empty, so this comparison is vacuous")
	}
	if want, got := describeRegistry(t, fromLog), describeRegistry(t, fromProjection); want != got {
		t.Errorf("the projected registry differs from the log's.\n--- log ---\n%s\n--- projection ---\n%s",
			want, got)
	}

	// As of a sequence, at every sequence the log has. This is the property the
	// registry's doc comment says a table would cost, so it is checked
	// exhaustively rather than at a sample point.
	logEvents, err := registry.LoadEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(logEvents) < 5 {
		t.Fatalf("only %d registry events; not enough history to be worth walking", len(logEvents))
	}
	changes := 0
	var previous string
	for _, ev := range logEvents {
		wantReg, err := registry.FoldUntil(logEvents, ev.Seq)
		if err != nil {
			t.Fatal(err)
		}
		gotReg, err := store.RegistryAsOf(ctx, ev.Seq, head)
		if err != nil {
			t.Fatalf("as of %d: %v", ev.Seq, err)
		}
		want, got := describeRegistry(t, wantReg), describeRegistry(t, gotReg)
		if want != got {
			t.Errorf("as of sequence %d the two disagree.\n--- log ---\n%s\n--- projection ---\n%s",
				ev.Seq, want, got)
		}
		if want != previous {
			changes++
			previous = want
		}
	}
	if changes < 3 {
		t.Errorf("the registry only looked different at %d points across %d events, so "+
			"walking every sequence tested almost nothing", changes, len(logEvents))
	}
	t.Logf("agreed at all %d registry sequences, through %d distinct states",
		len(logEvents), changes)
}

// TestTheInventoryRowsSayWhatTheRegistrySays checks the tables that exist
// for querying rather than folding.
func TestTheInventoryRowsSayWhatTheRegistrySays(t *testing.T) {
	store, ctx, dsn := newStoreDSN(t)
	dir := registryLog(t)

	if _, err := projection.NewProjector(store, dir).CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}

	conn := connect(t, ctx, dsn)
	for _, pid := range reg.Participants() {
		var active string
		if err := conn.QueryRow(ctx,
			`SELECT active_version FROM participants WHERE participant_id = $1`, pid).
			Scan(&active); err != nil {
			t.Fatalf("participant %s is missing from the inventory: %v", pid, err)
		}
		want := ""
		if e, ok := reg.Active(pid); ok {
			want = e.Version
		}
		if active != want {
			t.Errorf("%s: inventory says active=%q, the registry says %q", pid, active, want)
		}
		for _, e := range reg.Versions(pid) {
			var state string
			var triggers []string
			if err := conn.QueryRow(ctx,
				`SELECT state, pending_triggers FROM manifest_versions
				 WHERE participant_id = $1 AND version = $2`, pid, e.Version).
				Scan(&state, &triggers); err != nil {
				t.Fatalf("%s@%s is missing from the inventory: %v", pid, e.Version, err)
			}
			if state != string(e.State) {
				t.Errorf("%s@%s: inventory says %s, the registry says %s",
					pid, e.Version, state, e.State)
			}
			if len(triggers) != len(e.PendingTriggers) {
				t.Errorf("%s@%s: inventory holds %d pending triggers, the registry has %d",
					pid, e.Version, len(triggers), len(e.PendingTriggers))
			}
		}
	}

	// A suspended version must read as suspended. The inventory exists so an
	// operator can ask "what is not in good standing", and that answer being
	// right is the only reason to have the table.
	var suspended int
	if err := conn.QueryRow(ctx,
		`SELECT count(*) FROM manifest_versions WHERE state = 'SUSPENDED'`).Scan(&suspended); err != nil {
		t.Fatal(err)
	}
	if suspended != 1 {
		t.Errorf("the inventory holds %d suspended versions, the history suspended 1", suspended)
	}
}
