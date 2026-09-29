package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

// Crashes during concurrent sagas contending for one resource.
//
// Every other scenario drives its sagas in isolation, so the suite proved
// nothing about a crash while two sagas are competing — which is precisely where
// the frontier index and the commit-safety check (invariant I6) do their work,
// and was the part of Phase 2 with the least crash coverage.
//
// # What this asserts, and why it is not "only one may commit"
//
// I6 is an ordering property, not an exclusion: *no commit while a conflicting
// earlier-sequenced touch on any claimed resource is unsealed*. Two sagas
// writing one account may both commit — one after the other. What must never
// happen is the later one committing while the earlier is still in flight,
// because that is a saga resting on a fact that can still be withdrawn.
//
// So the invariant checked after every kill is: **a committed saga has no
// blockers**. That is I6 stated directly against the recovered log, and it is
// stable under recovery — sequence numbers are monotonic, so a touch that was
// later cannot become earlier.
//
// # The interleaving is seeded, and the seed is printed
//
// Exhaustive enumeration across two sagas is not affordable: the crash points
// multiply. The order the two are driven in comes from a seeded generator, the
// seed is printed at the start of the run, and every child process gets the same
// one — a resumed coordinator that re-derived a different interleaving would be
// running a different scenario from the one being compared against.

func contendingWriters() scenario {
	const aID, bID = "sg_race_a", "sg_race_b"
	const resource = "acct:contended"

	// IRREVERSIBLE_GATED, because that is what the reference policy attaches its
	// frontier requirement to — and the frontier gate is the only thing that
	// enforces I6. A compensable step contending for the same account would be
	// a scenario about nothing.
	wire := func(sagaID string) *janusv1.SagaBegin {
		return admitted(&janusv1.SagaBegin{
			SagaId: sagaID,
			Intent: &janusv1.Intent{
				IntentId:   "in_" + sagaID,
				Principal:  "pr_chaos",
				MandateRef: "mandate:" + sagaID,
				Scope:      "payments",
			},
			Mode: "supervised",
			Plan: []*janusv1.PlannedStep{{
				StepId: "wire", Participant: "ag_chaos", Action: "wire_transfer",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
			}},
		})
	}

	progFor := func(sagaID string) script {
		return script{
			begin:   wire(sagaID),
			touches: map[string]string{"wire": resource},
		}
	}

	return scenario{
		name:  "contending-writers",
		sagas: []string{aID, bID},
		run: func(ctx context.Context, app *evidence.Appender, dir string,
			report func(saga.State)) error {

			// The order the two sagas reach the resource in is what the seed
			// chooses, and it is the only thing that varies. Every child gets
			// the same seed: a resumed coordinator that re-derived a different
			// order would be running a different scenario from the one it is
			// being compared against.
			rng := rand.New(rand.NewSource(int64(interleaveSeed)))
			first, second := aID, bID
			if rng.Intn(2) == 1 {
				first, second = bID, aID
			}

			// The first saga runs until it has sealed: its step has touched the
			// account and it has not committed, so the resource is held by
			// something still in flight. Driving it to completion instead --
			// which the first version of this scenario did -- means the second
			// saga arrives after the first has settled and the two never
			// contend at all. The dirCheck below is what caught that.
			if err := driveUntilSealed(ctx, app, dir, first, progFor(first), report); err != nil {
				return err
			}

			// Now the second one arrives at a resource the first is holding. Its
			// frontier gate escalates and it waits: not an error, and the point
			// of the scenario.
			if err := driveTolerantly(ctx, app, dir, second, progFor(second), report); err != nil {
				return err
			}

			// The first commits, which settles the resource...
			if err := driveTolerantly(ctx, app, dir, first, progFor(first), report); err != nil {
				return err
			}
			// ...and only then can the second.
			return driveTolerantly(ctx, app, dir, second, progFor(second), report)
		},
		check: func(states map[string]saga.State) error {
			for _, id := range []string{aID, bID} {
				if got := states[id].Status; got != saga.StatusCommitted {
					return fmt.Errorf("%s is %s, want COMMITTED — both sagas should get "+
						"through, one after the other", id, got)
				}
			}
			return contendingInvariant(states)
		},
		invariant: contendingInvariant,
		// The scenario is worthless if the two sagas never actually collided,
		// and "both committed" is exactly what a run with no contention looks
		// like. So the log is asked whether a frontier gate ever escalated: if
		// it did not, the sagas ran past each other and this scenario proved
		// nothing.
		dirCheck: func(dir string) error {
			escalated, err := frontierEscalated(dir, []string{aID, bID})
			if err != nil {
				return err
			}
			if !escalated {
				return fmt.Errorf("neither saga was ever held at the frontier gate, so they " +
					"never contended and this scenario asserted nothing; check that both " +
					"still touch the same resource and that the policy still puts a frontier " +
					"requirement on their effect class")
			}
			return nil
		},
	}
}

// frontierEscalated reports whether any of these sagas was held at a frontier
// gate at some point in the log.
//
// Read from the recorded verdicts rather than from the final projection,
// because by the time both sagas have committed their gates all read PASS —
// the contention is in the history, not in the outcome.
func frontierEscalated(dir string, ids []string) (bool, error) {
	for _, id := range ids {
		events, err := saga.LoadEvents(dir, id)
		if err != nil {
			return false, err
		}
		for _, ev := range events {
			if ev.Kind != evidence.KindGateVerdict {
				continue
			}
			var msg janusv1.GateVerdict
			if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
				return false, fmt.Errorf("decoding a verdict of %s: %w", id, err)
			}
			if msg.GetGate() == janusv1.GateType_GATE_TYPE_FRONTIER &&
				msg.GetVerdict() == janusv1.Verdict_VERDICT_ESCALATE {
				return true, nil
			}
		}
	}
	return false, nil
}

// contendingInvariant is I6 against whatever the log currently says.
//
// A committed saga must have no blockers: nothing earlier than it, on a resource
// it touched, still in flight. It is evaluated after every kill, so a saga that
// has not started yet is simply absent and contributes nothing.
//
// It is deliberately expressed with the same `saga.Index` the coordinator's
// frontier gate uses rather than with a hand-rolled comparison. A harness that
// computed commit safety its own way would be checking its own opinion, and the
// interesting failure is the one where the index itself is wrong.
func contendingInvariant(states map[string]saga.State) error {
	ix := saga.NewIndex()
	for _, s := range states {
		ix.Add(s)
	}
	for id, s := range states {
		if s.Status != saga.StatusCommitted {
			continue
		}
		if ok, blockers := ix.MayCommit(id); !ok {
			return fmt.Errorf("%s is COMMITTED while %d conflicting earlier touch(es) are "+
				"still unsettled, which is invariant I6: %s", id, len(blockers), blockers[0])
		}
	}
	return nil
}

// driveUntilSealed advances a saga to the point where its step has touched its
// resource and it has not committed, and does nothing if it is already past
// that.
//
// Tolerant of being past it because the harness re-enters run() after every
// kill: a saga that committed before the crash must not be driven backwards or
// treated as an error.
func driveUntilSealed(ctx context.Context, app *evidence.Appender, dir, sagaID string,
	prog saga.Program, report func(saga.State)) error {

	if s, err := saga.ReplaySaga(dir, sagaID); err == nil &&
		(s.Terminal() || s.Status == saga.StatusSealing) {
		return nil
	}
	c, err := resume(app, dir, sagaID, prog)
	if err != nil {
		return err
	}
	c.OnTransition(report)
	if err := c.DriveUntilSealed(ctx); err != nil && !errors.Is(err, saga.ErrWaiting) {
		return fmt.Errorf("driving %s to sealing: %w", sagaID, err)
	}
	return nil
}

// driveTolerantly advances a saga and treats "held at a gate" as a normal
// outcome rather than a failure.
//
// A frontier gate that escalates is this scenario working: the saga is waiting
// for the other one to settle, and the pass that settles it is what frees this.
func driveTolerantly(ctx context.Context, app *evidence.Appender, dir, sagaID string,
	prog saga.Program, report func(saga.State)) error {

	if s, err := saga.ReplaySaga(dir, sagaID); err == nil && s.Terminal() {
		return nil
	}
	if _, err := drive(ctx, app, dir, sagaID, prog, report); err != nil &&
		!errors.Is(err, saga.ErrWaiting) {
		return fmt.Errorf("driving %s: %w", sagaID, err)
	}
	return nil
}
