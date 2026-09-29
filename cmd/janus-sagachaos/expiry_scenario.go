package main

import (
	"context"
	"fmt"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Crashes around a gate deadline nobody answers.
//
// Item 12 closed with the expiry built and this recorded as what was left. The
// entry named both obstacles and both are real:
//
//   - **The suite had one policy and it declares no deadlines.** The reference
//     policy now carries a rule for `payments.wire.unanswered` with a one-second
//     human gate. It sits ahead of the general `wires` rule and matches on the
//     action, so it reaches this scenario and nothing else — first match wins
//     (`gate.Policy.Resolve`).
//
//   - **A killed run takes longer than an uninterrupted one.** A deadline that
//     expired in one and not the other would fail the suite's determinism
//     comparison for a reason that is not a bug. This scenario is one nobody
//     ever answers, so the only way it can end is by expiring: both runs always
//     reach the same outcome, and the extra time a kill costs changes when that
//     happens rather than whether it does.
//
// # Why this one runs the ticker when nothing else does
//
// Every other scenario runs the daemon with its ticker off, because background
// work would make what a kill interrupted depend on a timer rather than on the
// transition under test. Here the ticker is the thing being killed: an expiry
// is recorded by the daemon and by nothing else, so a run with the
// ticker off would be waiting for a deadline that never arrives.
//
// It is safe here for a specific reason rather than a general one. The deadline
// is anchored at a *recorded* time — `saga.GateOpenedAt`, the step's result —
// so it falls at the same place in the saga's history however long the run
// takes, and the expiry is exactly one extra transition in every run.
//
// # Why it is hosted-only
//
// A library-embedded coordinator has no ticker, so in-process its gate waits
// forever. That is correct behaviour, because gate expiry is a daemon
// capability; running this
// scenario there would produce a saga that never finishes rather than a test.

func gateDeadlineExpires() scenario {
	const sagaID = "sg_deadline"

	begin := admitted(&janusv1.SagaBegin{
		SagaId: sagaID,
		Intent: &janusv1.Intent{
			IntentId:   "in_" + sagaID,
			Principal:  "pr_chaos",
			MandateRef: "mandate:" + sagaID,
			Scope:      "payments",
		},
		Mode: "supervised",
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Participant: "ag_chaos", Action: "payments.wire.unanswered",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	})
	prog := script{begin: begin}

	return scenario{
		name:       "gate-deadline-expires",
		sagas:      []string{sagaID},
		hostedOnly: true,
		run: func(ctx context.Context, app *evidence.Appender, dir string,
			report func(saga.State)) error {

			// Nothing answers. The saga can only leave the gate by the daemon
			// recording the deadline on the deadline's behalf.
			_, err := driveTolerating(ctx, app, dir, sagaID, prog, report)
			return err
		},
		check: func(states map[string]saga.State) error {
			s := states[sagaID]
			// Refused, not committed: the payment must not have gone out
			// because nobody got round to approving it.
			if s.Status == saga.StatusCommitted {
				return fmt.Errorf("%s committed, so an unanswered four-eyes gate let a "+
					"payment through on the strength of nobody objecting", sagaID)
			}
			expiry, err := recordedExpiry(s)
			if err != nil {
				return err
			}
			if expiry == nil {
				return fmt.Errorf("%s is %s and no expiry was recorded, so whatever stopped "+
					"it was not the deadline", sagaID, s.Status)
			}
			return nil
		},
		invariant: func(states map[string]saga.State) error {
			s, ok := states[sagaID]
			if !ok {
				return nil
			}
			// At most one expiry, however many times a killed daemon restarted
			// and looked at the same overdue gate. A second would be a duplicate
			// refusal in the record of a decision that was made once.
			n := 0
			for _, st := range s.Steps {
				for _, a := range st.Answers {
					if a.Reason == saga.ExpiryReason {
						n++
					}
				}
			}
			if n > 1 {
				return fmt.Errorf("%s carries %d expiries for one deadline; a restarted "+
					"daemon recorded the same refusal again", sagaID, n)
			}
			return nil
		},
		hosted: &hostedPlan{
			prog: prog,
			// Fast enough that a crash point is not dominated by waiting, slow
			// enough that the ticker is not the only thing running.
			tick: 50 * time.Millisecond,
		},
	}
}

// recordedExpiry finds the answer the daemon wrote on the deadline's behalf.
//
// It asks the same predicate the enforcer and the auditor use rather than
// matching on the reason string, so a scenario that passed while the three
// disagreed about what an expiry is would not be possible.
func recordedExpiry(s saga.State) (*saga.GateAnswerRecord, error) {
	for _, st := range s.Steps {
		for i := range st.Answers {
			a := st.Answers[i]
			if a.Reason == saga.ExpiryReason {
				return &a, nil
			}
		}
	}
	return nil, nil
}
