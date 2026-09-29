package outbox_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// The last place a jurisdiction pin has to hold.
//
// A saga can be pinned to DE, admitted against a DE participant, and write its
// payloads to a DE bucket — and then hand the payment instruction to an
// endpoint in Ohio, because until this the outbox delivered to a target whose
// location nothing recorded. Every earlier check protected the preparation; the
// gap was at the moment the data left.

// pinnedLog opens an appender bound to a tenant.
func pinnedLog(t *testing.T, tenant tenancy.Tenant) (*evidence.Appender, string) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Tenant: tenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	return app, dir
}

// placed is a Residency that says whatever the test tells it to, so the outbox
// can be lied to about where a target is — the same reason CommitAuthority is
// an interface.
type placed struct {
	place outbox.Placement
	known bool
	err   error
}

func (p placed) Placement(context.Context, string) (outbox.Placement, bool, error) {
	return p.place, p.known, p.err
}

func inDE() placed {
	return placed{place: outbox.Placement{DeployableIn: []string{"DE"}}, known: true}
}

// TestAPinnedLogWillNotHoldAnEffectForAForeignTarget refuses at the earliest
// point it can.
//
// At hold rather than only at release, so the saga fails while it can still be
// compensated. An effect held for a target it may never reach would commit and
// then sit undeliverable forever — fail-closed, and stuck in the one state that
// needs a person.
func TestAPinnedLogWillNotHoldAnEffectForAForeignTarget(t *testing.T) {
	app, _ := pinnedLog(t, tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"})
	r := releaser(t, app, fixedAuthority{root: []byte("root"), committed: true}, newTarget(),
		func(o *outbox.Options) {
			o.Residency = placed{
				place: outbox.Placement{DeployableIn: []string{"US"}}, known: true,
			}
		})

	_, err := r.Hold(context.Background(), heldEffect("ef_1", "sg_1", "st_1"))
	if !errors.Is(err, outbox.ErrResidency) {
		t.Fatalf("a DE-pinned log held an effect for a US target: %v", err)
	}
	if !strings.Contains(err.Error(), "may be used in US") {
		t.Fatalf("the refusal does not name where the target is: %v", err)
	}
}

// TestATargetNothingPlacesIsRefused is the case admission cannot reach.
//
// A target is a string chosen by whoever composed the effect and resolved to a
// transport by whoever runs the daemon. Nothing requires it to name a
// registered participant, and an endpoint nobody registered is not thereby
// local.
func TestATargetNothingPlacesIsRefused(t *testing.T) {
	app, _ := pinnedLog(t, tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"})
	r := releaser(t, app, fixedAuthority{root: []byte("root"), committed: true}, newTarget(),
		func(o *outbox.Options) { o.Residency = placed{known: false} })

	_, err := r.Hold(context.Background(), heldEffect("ef_1", "sg_1", "st_1"))
	if !errors.Is(err, outbox.ErrResidency) {
		t.Fatalf("an unplaced target was accepted: %v", err)
	}
	if !strings.Contains(err.Error(), "not thereby local") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// TestAPinnedLogWithNoWayToResolveATargetRefuses. A deployment that believes it
// is pinned and is not is worse than one that knows it is not: the belief is
// what a compliance report would be written from.
func TestAPinnedLogWithNoWayToResolveATargetRefuses(t *testing.T) {
	app, _ := pinnedLog(t, tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"})
	r := releaser(t, app, fixedAuthority{root: []byte("root"), committed: true}, newTarget(), nil)

	if _, err := r.Hold(context.Background(), heldEffect("ef_1", "sg_1", "st_1")); !errors.Is(
		err, outbox.ErrResidency) {
		t.Fatalf("a pinned releaser with no residency source held the effect anyway: %v", err)
	}
}

// TestDataResidencyIsCheckedAtTheTargetToo. Where a target runs and where it
// keeps what it receives are different questions, and a target in Frankfurt
// that stores in Ohio has answered one of them.
func TestDataResidencyIsCheckedAtTheTargetToo(t *testing.T) {
	app, _ := pinnedLog(t, tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"})
	r := releaser(t, app, fixedAuthority{root: []byte("root"), committed: true}, newTarget(),
		func(o *outbox.Options) {
			o.Residency = placed{known: true, place: outbox.Placement{
				DeployableIn: []string{"DE"}, DataResidency: "US",
			}}
		})

	_, err := r.Hold(context.Background(), heldEffect("ef_1", "sg_1", "st_1"))
	if !errors.Is(err, outbox.ErrResidency) {
		t.Fatalf("a target storing in US was accepted by a DE pin: %v", err)
	}
	if !strings.Contains(err.Error(), "keeps what it receives in US") {
		t.Fatalf("the refusal does not name the residency: %v", err)
	}
}

// TestReleaseChecksAgainEvenWhenTheHoldPassed covers an effect held before a
// deployment declared its jurisdiction, or before the target's manifest was
// suspended. This is the check that runs immediately before the bytes leave.
func TestReleaseChecksAgainEvenWhenTheHoldPassed(t *testing.T) {
	app, dir := pinnedLog(t, tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"})
	tg := newTarget()
	auth := fixedAuthority{root: []byte("root"), committed: true}

	// Held while the target was placed in DE.
	held := releaser(t, app, auth, tg, func(o *outbox.Options) { o.Residency = inDE() })
	if _, err := held.Hold(context.Background(), heldEffect("ef_1", "sg_1", "st_1")); err != nil {
		t.Fatal(err)
	}

	// Released after it moved.
	moved := releaser(t, app, auth, tg, func(o *outbox.Options) {
		o.Residency = placed{known: true, place: outbox.Placement{DeployableIn: []string{"US"}}}
	})
	state := loadState(t, dir)
	effects := outbox.EffectsFor(state, "sg_1")
	if len(effects) != 1 {
		t.Fatalf("%d effect(s) held", len(effects))
	}
	if err := moved.Release(context.Background(), *effects[0]); !errors.Is(err, outbox.ErrResidency) {
		t.Fatalf("the effect was delivered to a target that had moved: %v", err)
	}
	if tg.appliedCount() != 0 {
		t.Fatal("the target received the effect")
	}
}

// TestAnUnpinnedLogDeliversAnywhere. Every deployment before Phase 5c is this
// one, and it must not need a Residency at all — a check that made existing
// deployments supply new configuration to keep working is a check that gets
// switched off.
func TestAnUnpinnedLogDeliversAnywhere(t *testing.T) {
	app, dir := newLog(t)
	tg := newTarget()
	r := releaser(t, app, fixedAuthority{root: []byte("root"), committed: true}, tg, nil)

	if _, err := r.Hold(context.Background(), heldEffect("ef_1", "sg_1", "st_1")); err != nil {
		t.Fatalf("an unpinned log was refused: %v", err)
	}
	effects := outbox.EffectsFor(loadState(t, dir), "sg_1")
	if err := r.Release(context.Background(), *effects[0]); err != nil {
		t.Fatalf("an unpinned log could not release: %v", err)
	}
	if tg.appliedCount() != 1 {
		t.Fatalf("the target applied %d effect(s)", tg.appliedCount())
	}
}

// TestAMatchingTargetIsDelivered is the positive control: the check refuses the
// wrong thing rather than everything.
func TestAMatchingTargetIsDelivered(t *testing.T) {
	app, dir := pinnedLog(t, tenancy.Tenant{ID: "bank_a", Jurisdiction: "DE"})
	tg := newTarget()
	r := releaser(t, app, fixedAuthority{root: []byte("root"), committed: true}, tg,
		func(o *outbox.Options) {
			o.Residency = placed{known: true, place: outbox.Placement{
				DeployableIn: []string{"EU", "DE"}, DataResidency: "DE",
			}}
		})

	if _, err := r.Hold(context.Background(), heldEffect("ef_1", "sg_1", "st_1")); err != nil {
		t.Fatal(err)
	}
	effects := outbox.EffectsFor(loadState(t, dir), "sg_1")
	if err := r.Release(context.Background(), *effects[0]); err != nil {
		t.Fatalf("a target in the tenant's own jurisdiction was refused: %v", err)
	}
	if tg.appliedCount() != 1 {
		t.Fatalf("the target applied %d effect(s)", tg.appliedCount())
	}
}

// TestLogResidencyReadsTheRegistry checks the implementation a daemon actually
// runs with, rather than only the interface the tests lie through.
func TestLogResidencyReadsTheRegistry(t *testing.T) {
	dir := registryLog(t, "tool_payments", []string{"DE"}, "DE")
	res := outbox.NewLogResidency(dir)

	place, ok, err := res.Placement(context.Background(), "tool_payments")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("a registered participant is not placed")
	}
	if len(place.DeployableIn) != 1 || place.DeployableIn[0] != "DE" ||
		place.DataResidency != "DE" {
		t.Fatalf("read placement %+v", place)
	}

	// A target nothing registered is unplaced rather than an error: "nobody
	// declared this" is an answer, and the refusal it produces says so.
	if _, ok, err := res.Placement(context.Background(), "some_endpoint"); err != nil || ok {
		t.Fatalf("an unregistered target was placed (ok=%v, err=%v)", ok, err)
	}
}

// registryLog writes a log with one active participant declaring a
// jurisdiction, which is what LogResidency resolves a target against.
func registryLog(t *testing.T, participant string, deployableIn []string,
	dataResidency string) string {

	t.Helper()
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
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "sys_registry", Principal: "pr_bank", Kind: "SYSTEM",
	}, registry.New(), trust)

	m := &registry.Manifest{
		Version:  "1.0.0",
		Identity: registry.Identity{ParticipantID: participant, Kind: "TOOL", Principal: "pr_bank"},
		Runtime:  registry.Runtime{ModelID: "none", PromptBundleHash: "blake3:t"},
		Actions: []registry.Action{{
			Name: "transfer", EffectClass: "IRREVERSIBLE_GATED",
			Idempotency: &registry.Idempotency{KeyRecipe: "saga_id"},
		}},
		Risk: registry.Risk{
			Tier:                 2,
			RevalidationTriggers: []string{registry.TriggerModelChange},
		},
		Jurisdiction: registry.Jurisdiction{
			DeployableIn: deployableIn, DataResidency: dataResidency,
		},
	}
	sig, err := registry.Sign(m, signer)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := rec.Register(ctx, m, sig); err != nil {
		t.Fatal(err)
	}
	doubles := registry.NewDoubles("s").
		With("transfer", registry.Double{Deltas: map[string]int64{"x": -1}})
	rep, err := registry.Evaluate(ctx, m, doubles)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Evaluate(ctx, participant, m.Version, rep); err != nil {
		t.Fatal(err)
	}
	if err := rec.Activate(ctx, participant, m.Version); err != nil {
		t.Fatal(err)
	}
	return dir
}
