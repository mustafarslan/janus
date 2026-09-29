package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/saga"
)

// The Phase 3 exit gate, as a crash test.
//
// The plan asks for a demonstration that an IRREVERSIBLE_GATED effect cannot
// fire before commit under fault injection. "Demonstrably" is the operative
// word: the release path checks its authority, and the unit tests establish
// that it refuses when the answer is no, but neither shows what happens when the
// process dies in the middle of the sequence — which is the only situation
// where the ordering could be got wrong without anybody noticing.
//
// So the effect here is delivered to a file that survives the SIGKILL, standing
// in for a receiving system with its own durable store. The parent can then ask
// the two questions that matter, at every crash point:
//
//	1. If the ledger contains anything at all, does the saga's log contain a
//	   COMMIT? An entry without one means money moved before it was authorised.
//	2. Once everything has finished, is the effect in the ledger exactly once?
//
// The first is invariant I4 stated for every instant rather than for the end.
// The second is what exactly-once means in practice: Janus retries under a
// stable idempotency key, the receiver recognises it, and the effect happens
// once however many times it was attempted.

// ledger is a receiving system that records applied effects on disk.
//
// It reads the file before writing, which is how a real receiver honouring an
// idempotency key behaves, and it is what makes a retried delivery absorbable
// rather than duplicated.
type ledger struct{ path string }

func (l ledger) Deliver(_ context.Context, e outbox.Effect) (outbox.Receipt, error) {
	applied, err := l.keys()
	if err != nil {
		return outbox.Receipt{Retryable: true}, err
	}
	if applied[e.IdemKey] {
		return outbox.Receipt{Ref: "ledger/" + e.IdemKey, Duplicate: true}, nil
	}

	// Fault injection inside the release sequence.
	//
	// The parent's crash points fall between recorded transitions, so they
	// cannot reliably land in the middle of a delivery — and the middle of a
	// delivery is the one place where the ordering could be wrong without
	// anything noticing. These two points bracket the actual side effect:
	//
	//	before-apply  the attempt was announced and nothing happened. Recovery
	//	              must retry, and the effect must still end up applied once.
	//	after-apply   the effect happened and its receipt was never written.
	//	              Recovery cannot know whether it landed, so it retries; the
	//	              receiver must absorb the repeat under the same key.
	//
	// The second is the case that would produce a duplicate payment if the
	// idempotency key were not stable across attempts, which is why the key is
	// fixed when the effect is held rather than generated per attempt.
	dieAt := os.Getenv("JANUS_CHAOS_DIE_AT")
	if dieAt == "before-apply" {
		die()
	}

	// The side effect. A kill immediately before this leaves the announcement
	// in the log with nothing applied; a kill immediately after leaves it
	// applied with no receipt. Both are states recovery has to handle, and both
	// are reachable here.
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return outbox.Receipt{Retryable: true}, err
	}
	defer func() { _ = f.Close() }()
	if _, err := fmt.Fprintf(f, "%s\n", e.IdemKey); err != nil {
		return outbox.Receipt{Retryable: true}, err
	}
	if err := f.Sync(); err != nil {
		return outbox.Receipt{Retryable: true}, err
	}

	// The effect has now happened in the receiving system and Janus has not yet
	// recorded that it did.
	if dieAt == "after-apply" {
		_ = f.Close()
		die()
	}
	return outbox.Receipt{Ref: "ledger/" + e.IdemKey}, nil
}

// die terminates the process as abruptly as the operating system allows, so no
// deferred close, flush, or seal runs. A process that tidies up on the way out
// is testing its shutdown path rather than a crash.
func die() {
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	// Unreachable in practice; present so the function cannot fall through to
	// the caller and silently continue if the signal is ever blocked.
	os.Exit(137)
}

func (l ledger) keys() (map[string]bool, error) {
	out := map[string]bool{}
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out[line] = true
		}
	}
	return out, sc.Err()
}

// entries returns every line, so duplicates are visible rather than collapsed.
func (l ledger) entries() ([]string, error) {
	var out []string
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

// ledgerPath puts the receiving system's store beside the evidence directory it
// belongs to, and nowhere else.
//
// It has to be per-run. A ledger shared between the uninterrupted run and the
// crash runs would let one run's applied effect look, to another run's
// invariant check, like an effect that fired with no authority behind it — which
// is exactly what the check reported the first time this was wired up wrongly.
func ledgerPath(dir string) string { return filepath.Clean(dir) + ".ledger" }

// gatedEffectScenario runs a saga whose one effectful step is IRREVERSIBLE_GATED,
// holds the effect, commits, and then releases it.
func gatedEffectScenario() scenario {
	const sagaID, stepID, effectID = "sg_gated", "wire", "ef_wire"

	plan := admitted(&janusv1.SagaBegin{
		SagaId: sagaID,
		Intent: &janusv1.Intent{
			IntentId:   "in_gated",
			Principal:  "pr_chaos",
			MandateRef: "mandate:sg_gated",
			Scope:      "payments",
		},
		Mode: "supervised",
		Plan: []*janusv1.PlannedStep{{
			StepId: stepID, Participant: "ag_chaos", Action: "wire_transfer",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	})

	held := func(string) *janusv1.EffectHeld {
		return &janusv1.EffectHeld{
			EffectId: effectID, SagaId: sagaID, StepId: stepID,
			Target: "payments", Action: "wire_transfer",
			IdemKey:     "idem-" + effectID,
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}
	}

	return scenario{
		name:  "outbox-gated-effect",
		sagas: []string{sagaID},
		// Hosted, the ledger connects to the daemon as a deliverer instead of
		// being handed to a Releaser this process built. Everything else is the
		// same run: the effect is held before the step reports, it goes nowhere
		// until the saga commits, and the daemon releases it then.
		hosted: &hostedPlan{
			prog:         script{begin: plan, touches: map[string]string{stepID: "acct:wire"}},
			target:       "payments",
			newDeliverer: func(dir string) outbox.Deliverer { return ledger{path: ledgerPath(dir)} },
			holdFor:      held,
		},
		run: func(ctx context.Context, app *evidence.Appender, dir string, report func(saga.State)) error {
			lg := ledger{path: ledgerPath(dir)}
			releaser, err := outbox.NewReleaser(outbox.Options{
				Appender:    app,
				Participant: participant,
				Authority:   outbox.NewLiveLogAuthority(dir, liveRead(app)),
				Deliverers:  map[string]outbox.Deliverer{"payments": lg},
				MaxAttempts: 8,
			})
			if err != nil {
				return err
			}

			// The effect is captured before the step reports its result, so the
			// log holds the effect before the step can claim success.
			ob, err := outbox.Load(dir)
			if err != nil {
				return err
			}
			if _, held := ob.Effect(effectID); !held {
				if _, err := releaser.Hold(ctx, &janusv1.EffectHeld{
					EffectId: effectID, SagaId: sagaID, StepId: stepID,
					Target: "payments", Action: "wire_transfer",
					IdemKey:     "idem-" + effectID,
					EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
				}); err != nil {
					return err
				}
				report(mustSagaState(dir, sagaID))
			}

			// Drive the saga to commit. Nothing has left the building yet.
			prog := script{begin: plan, touches: map[string]string{stepID: "acct:wire"}}
			committed, err := drive(ctx, app, dir, sagaID, prog, report)
			if err != nil {
				return err
			}
			if committed.Status != saga.StatusCommitted {
				return fmt.Errorf("saga finished as %s rather than committing", committed.Status)
			}

			// Only now may the effect go. Retried until it lands or is frozen,
			// because a crash mid-attempt leaves an effect that must be
			// re-attempted under the same key.
			for range 8 {
				ob, err := outbox.Load(dir)
				if err != nil {
					return err
				}
				e, ok := ob.Effect(effectID)
				if !ok {
					return fmt.Errorf("effect %s vanished from the outbox", effectID)
				}
				if !e.Pending() {
					break
				}
				if err := releaser.Release(ctx, *e); err != nil {
					return fmt.Errorf("release: %w", err)
				}
				report(mustSagaState(dir, sagaID))
			}
			return nil
		},

		// At every crash point: nothing may be in the ledger unless the log
		// contains a commit that authorised it.
		invariant: func(states map[string]saga.State) error {
			return nil // replaced below by outboxInvariant, which needs the dir
		},

		check: func(states map[string]saga.State) error {
			st, ok := states[sagaID]
			if !ok {
				return fmt.Errorf("saga %s is missing", sagaID)
			}
			if st.Status != saga.StatusCommitted {
				return fmt.Errorf("saga is %s, want COMMITTED", st.Status)
			}
			return nil
		},
	}
}

// mustSagaState replays a saga for reporting purposes.
func mustSagaState(dir, sagaID string) saga.State {
	s, err := saga.ReplaySaga(dir, sagaID)
	if err != nil {
		return saga.State{SagaID: sagaID}
	}
	return s
}

// outboxInvariant is the Phase 3 exit gate check, evaluated against a directory
// after a kill.
//
// It is a directory check rather than a projection check because the ledger —
// the thing that stands for the outside world — is not in the projection. That
// is the point: the question is whether the world changed before the log said
// it could, and only one of those two lives inside Janus.
func outboxInvariant(dir string, sagaIDs []string) error {
	lg := ledger{path: ledgerPath(dir)}
	entries, err := lg.entries()
	if err != nil {
		return fmt.Errorf("read the ledger: %w", err)
	}
	if len(entries) == 0 {
		return nil
	}

	// Something is in the world. There had better be a commit behind it.
	states := map[string]saga.State{}
	for _, id := range sagaIDs {
		events, err := saga.LoadEvents(dir, id)
		if err != nil {
			return fmt.Errorf("load saga %s: %w", id, err)
		}
		if len(events) == 0 {
			continue
		}
		st, err := saga.Replay(events)
		if err != nil {
			return fmt.Errorf("replay saga %s: %w", id, err)
		}
		states[id] = st
	}

	ob, err := outbox.Load(dir)
	if err != nil {
		return fmt.Errorf("load the outbox: %w", err)
	}
	if findings := outbox.Unauthorised(outbox.Audit(ob, states)); len(findings) > 0 {
		var b strings.Builder
		for _, f := range findings {
			b.WriteString("\n        " + f.String())
		}
		return fmt.Errorf("an effect is in the world without authority:%s", b.String())
	}

	// The ledger holds real applied effects, so every one of them must
	// correspond to an effect the outbox released under a commit.
	for _, key := range entries {
		matched := false
		for _, id := range ob.Order {
			e := ob.Effects[id]
			if e.IdemKey == key && e.Attempts > 0 {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("the ledger contains %q but no announced release in the log "+
				"accounts for it, so an effect reached the world with no evidence in front "+
				"of it", key)
		}
	}
	return nil
}

// outboxFinalCheck asserts exactly-once after everything has settled.
func outboxFinalCheck(dir string) error {
	lg := ledger{path: ledgerPath(dir)}
	entries, err := lg.entries()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("the effect never reached the ledger, so a committed saga failed to " +
			"release what it promised")
	}
	// The receiver absorbs repeats, so the ledger holds one line per effect
	// however many times it was attempted. More than one means a duplicate
	// payment, which is the failure this whole subsystem exists to prevent.
	seen := map[string]int{}
	for _, k := range entries {
		seen[k]++
	}
	for k, n := range seen {
		if n != 1 {
			return fmt.Errorf("effect %q was applied %d times; exactly-once means once", k, n)
		}
	}

	ob, err := outbox.Load(dir)
	if err != nil {
		return err
	}
	for _, id := range ob.Order {
		if e := ob.Effects[id]; e.State != outbox.StateDelivered {
			return fmt.Errorf("effect %s finished as %s rather than DELIVERED", e.ID, e.State)
		}
	}
	return nil
}
