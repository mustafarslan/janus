package outbox_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/saga"
)

// fixedModes lets a test lie to the outbox about what mode a saga is in.
//
// The point of the interface is that the outbox must not take a caller's word
// for the answer, so a test has to be able to give it a wrong one.
type fixedModes struct {
	mode string
	ok   bool
	err  error
}

func (m fixedModes) ModeOf(context.Context, string) (string, bool, error) {
	return m.mode, m.ok, m.err
}

// TestAnExploratoryEffectDoesNotReachTheWorld is exploratory mode's
// "sandbox effects only", stated as the thing it has to mean.
//
// Until Phase 6e it meant nothing: a saga could declare exploratory mode, be
// admitted, and have the outbox deliver a payment, because the outbox had never
// heard of modes.
func TestAnExploratoryEffectDoesNotReachTheWorld(t *testing.T) {
	app, _ := newLog(t)
	tg := newTarget()
	r := releaser(t, app, fixedAuthority{root: []byte("root"), committed: true}, tg,
		func(o *outbox.Options) {
			o.Modes = fixedModes{mode: string(saga.ModeExploratory), ok: true}
		})

	ctx := context.Background()
	if _, err := r.Hold(ctx, heldEffect("ef1", "sg1", "st1")); !errors.Is(err, outbox.ErrExploratory) {
		t.Fatalf("holding an exploratory saga's effect for a real target: %v", err)
	}
	if tg.appliedCount() != 0 {
		t.Fatalf("an exploratory saga's effect reached the target %d times", tg.appliedCount())
	}
}

// TestAnExploratoryEffectReachesADeclaredSandbox: the mode is a restriction, not
// a prohibition. A deployment that has said which targets are sandboxes gets to
// use them.
func TestAnExploratoryEffectReachesADeclaredSandbox(t *testing.T) {
	app, dir := newLog(t)
	tg := newTarget()
	r := releaser(t, app, fixedAuthority{root: []byte("root"), committed: true}, tg,
		func(o *outbox.Options) {
			o.Modes = fixedModes{mode: string(saga.ModeExploratory), ok: true}
			o.SandboxTargets = []string{"payments"}
		})

	ctx := context.Background()
	if _, err := r.Hold(ctx, heldEffect("ef1", "sg1", "st1")); err != nil {
		t.Fatalf("holding an exploratory saga's effect for a declared sandbox: %v", err)
	}
	if err := r.Release(ctx, *loadState(t, dir).Effects["ef1"]); err != nil {
		t.Fatalf("releasing into a declared sandbox: %v", err)
	}
	if tg.appliedCount() != 1 {
		t.Errorf("the sandbox received the effect %d times, want 1", tg.appliedCount())
	}
}

// TestAnUnknownModeIsRefusedAtRelease is the fail-closed direction.
//
// A resolver that errors, or that has never heard of the saga, must refuse. The
// alternative is that a lookup failure delivers a payment — which is the same
// trade every other check in this package makes and is worth making explicit,
// because "we could not tell" reads as harmless and is not.
func TestAnUnknownModeIsRefusedAtRelease(t *testing.T) {
	for _, tc := range []struct {
		name  string
		modes outbox.SagaModes
	}{
		{"the resolver failed", fixedModes{err: errors.New("database is down")}},
		{"the log has no such saga", fixedModes{ok: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, _ := newLog(t)
			tg := newTarget()
			r := releaser(t, app, fixedAuthority{root: []byte("root"), committed: true}, tg,
				func(o *outbox.Options) { o.Modes = tc.modes })

			_, err := r.Hold(context.Background(), heldEffect("ef1", "sg1", "st1"))
			if !errors.Is(err, outbox.ErrExploratory) {
				t.Fatalf("an effect whose mode could not be determined was not refused: %v", err)
			}
			if tg.appliedCount() != 0 {
				t.Errorf("it reached the target %d times anyway", tg.appliedCount())
			}
		})
	}
}

// TestASupervisedEffectIsUnaffected: the check is scoped to exploratory sagas,
// and every deployment that does not use the mode must behave exactly as before.
func TestASupervisedEffectIsUnaffected(t *testing.T) {
	app, dir := newLog(t)
	tg := newTarget()
	r := releaser(t, app, fixedAuthority{root: []byte("root"), committed: true}, tg,
		func(o *outbox.Options) {
			o.Modes = fixedModes{mode: string(saga.ModeSupervised), ok: true}
		})

	ctx := context.Background()
	if _, err := r.Hold(ctx, heldEffect("ef1", "sg1", "st1")); err != nil {
		t.Fatal(err)
	}
	if err := r.Release(ctx, *loadState(t, dir).Effects["ef1"]); err != nil {
		t.Fatal(err)
	}
	if tg.appliedCount() != 1 {
		t.Errorf("a supervised saga's effect was applied %d times, want 1", tg.appliedCount())
	}
}

// TestAnAlreadyHeldExploratoryEffectIsStillRefused.
//
// The check at Hold is a courtesy: it stops an exploratory effect being captured
// in the first place, and a deployment that upgraded to this build would have
// effects already in its log that never passed it. The check at Release is the
// one that counts, and this proves it stands on its own — the effect is written
// into the log directly, the way an older build would have left it, and then
// released.
//
// Removing the Hold check leaves this passing. Removing the Release check makes
// it fail, which is the right way round: the outbox is the last thing between a
// decision and the world.
func TestAnAlreadyHeldExploratoryEffectIsStillRefused(t *testing.T) {
	app, dir := newLog(t)
	tg := newTarget()

	// Held with modes not configured, which is exactly what an older build did.
	prior := releaser(t, app, fixedAuthority{root: []byte("root"), committed: true}, tg, nil)
	ctx := context.Background()
	if _, err := prior.Hold(ctx, heldEffect("ef1", "sg1", "st1")); err != nil {
		t.Fatal(err)
	}

	// Now a build that knows about modes picks up the same log.
	aware := releaser(t, app, fixedAuthority{root: []byte("root"), committed: true}, tg,
		func(o *outbox.Options) {
			o.Modes = fixedModes{mode: string(saga.ModeExploratory), ok: true}
		})
	err := aware.Release(ctx, *loadState(t, dir).Effects["ef1"])
	if !errors.Is(err, outbox.ErrExploratory) {
		t.Fatalf("an effect held before modes were enforced was released anyway: %v", err)
	}
	if tg.appliedCount() != 0 {
		t.Errorf("it reached the target %d times", tg.appliedCount())
	}
}
