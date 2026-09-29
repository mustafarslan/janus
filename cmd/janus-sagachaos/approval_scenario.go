package main

import (
	"context"
	"fmt"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/saga"
)

// A payment that needs two people and two machines to agree, killed at every
// point along the way.
//
// This is the scenario the other ones cannot reach. Every gate exercised
// elsewhere decides on the spot: a schema check, a limit, an expression over
// facts the step declared. A four-eyes payment does not. It sits there — for a
// moment here, for hours in a bank — while approvals arrive one at a time from
// different people, and the saga's obligation lives entirely in a log that
// several processes have now died holding.
//
// The crash points that matter are the ones between an approval and the
// decision that reads it. A coordinator that folded the approval into its own
// memory and then died would lose it, and the successor would ask a credit
// officer to approve a payment they had already approved — or, worse, count the
// second approval as a second person. Answers are recorded as their own events
// precisely so that neither happens, and this is what checks it.
//
// The composition also has to hold under the kills: two validators must both
// agree, two *distinct* humans must approve, and neither may be the principal
// the saga was raised for. None of those is a property of a single event.

// answerSet plays one party: one validator agent and one person.
//
// One Program can only ever supply one answer per gate — it is a pure function
// of (step, attempt, requirement), so it has no way to say something different
// the second time. That is a fair model of reality rather than an awkwardness
// to work around: a quorum is satisfied by different parties, not by one party
// asked twice, and the state machine refuses the latter outright. So a scenario
// needing two approvals drives the saga twice, once as each side.
type answerSet struct {
	script
	// validator is the participant this side answers as, or empty for a side
	// that renders no opinion.
	validator string
	// human is the person this side approves as, with the roles the
	// authenticating layer asserted for them. Empty means this side approves
	// nothing.
	human string
	roles []string
}

func (a answerSet) Answer(stepID string, attempt uint32, requirementID string) *janusv1.GateAnswer {
	switch requirementID {
	case "large-wire-second-opinion":
		if a.validator == "" {
			return nil
		}
		return &janusv1.GateAnswer{
			Actor:   &janusv1.Actor{Participant: &janusv1.ParticipantRef{Id: a.validator}},
			Verdict: janusv1.Verdict_VERDICT_PASS,
			Reason:  "within the mandate",
		}
	case "large-wire-four-eyes":
		if a.human == "" {
			return nil
		}
		return &janusv1.GateAnswer{
			Actor:   &janusv1.Actor{HumanSubject: a.human},
			Verdict: janusv1.Verdict_VERDICT_PASS,
			Roles:   a.roles,
			AuthRef: "auth:" + a.human,
		}
	}
	return nil
}

// chaosPrincipal is who every scenario's saga is raised for, so separation of
// duty has a concrete thing to be about.
const chaosPrincipal = "pr_chaos"

// fourEyesScenario runs a large payment through a validator quorum and a
// two-person approval, and releases it only after both.
func fourEyesScenario() scenario {
	const sagaID, stepID, effectID = "sg_fourEyes", "wire", "ef_four_eyes"

	plan := admitted(&janusv1.SagaBegin{
		SagaId: sagaID,
		Intent: &janusv1.Intent{
			IntentId:   "in_four_eyes",
			Principal:  chaosPrincipal,
			MandateRef: "mandate:" + sagaID,
			Scope:      "payments",
		},
		Mode: "supervised",
		Plan: []*janusv1.PlannedStep{
			// The balance is read by a step of its own, so the payment is
			// judged against a number it never gets to state.
			{StepId: "balance", Participant: "ag_chaos", Action: "balance.read",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
			{StepId: stepID, Participant: "ag_chaos", Action: "payments.wire.large",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
				DependsOn:   []string{"balance"}},
		},
	})

	// Hoisted out of run so the hosted plan can play the same two parties. They
	// have to be the same two: a quorum satisfied by different people in the
	// hosted run than in the in-process one would be a different scenario
	// wearing the same name.
	hostedBase := script{
		begin: plan,
		published: map[string]map[string]saga.FactValue{
			"balance": {"available_minor": gate.Number(10_000_000)},
		},
		touches: map[string]string{stepID: "acct:wire"},
	}
	hostedHeld := func(string) *janusv1.EffectHeld {
		return &janusv1.EffectHeld{
			EffectId: effectID, SagaId: sagaID, StepId: stepID,
			Target: "payments", Action: "wire_transfer",
			IdemKey:     "idem-" + effectID,
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}
	}

	return scenario{
		name:  "four-eyes-approval",
		sagas: []string{sagaID},
		hosted: &hostedPlan{
			prog:         hostedBase,
			target:       "payments",
			newDeliverer: func(dir string) outbox.Deliverer { return ledger{path: ledgerPath(dir)} },
			holdFor:      hostedHeld,
			answerers: []answerSet{
				{script: hostedBase, validator: "ag_credit_policy",
					human: "alice", roles: []string{"credit-officer"}},
				{script: hostedBase, validator: "ag_sanctions",
					human: "carol", roles: []string{"treasury-approver"}},
			},
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

			base := script{
				begin: plan,
				published: map[string]map[string]saga.FactValue{
					// A quarter of this is 2,500,000; the payment is well under.
					"balance": {"available_minor": gate.Number(10_000_000)},
				},
				touches: map[string]string{stepID: "acct:wire"},
			}

			// Two passes as two different parties. A quorum is not satisfied
			// by one party answering twice — the state machine refuses that —
			// so the harness has to be honest about it too.
			credit := answerSet{script: base,
				validator: "ag_credit_policy", human: "alice", roles: []string{"credit-officer"}}
			treasury := answerSet{script: base,
				validator: "ag_sanctions", human: "carol", roles: []string{"treasury-approver"}}

			if _, err := driveTolerating(ctx, app, dir, sagaID, credit, report); err != nil {
				return err
			}
			final, err := drive(ctx, app, dir, sagaID, treasury, report)
			if err != nil {
				return err
			}
			if final.Status != saga.StatusCommitted {
				return fmt.Errorf("saga finished as %s rather than committing", final.Status)
			}

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

		check: func(states map[string]saga.State) error {
			st, ok := states[sagaID]
			if !ok {
				return fmt.Errorf("saga %s is missing", sagaID)
			}
			if st.Status != saga.StatusCommitted {
				return fmt.Errorf("saga is %s, want COMMITTED", st.Status)
			}
			step, _ := st.Step(stepID)

			// Every approval that was given is on the record, once each. A
			// coordinator that lost one across a crash and re-asked would show
			// up here as a duplicate; one that double-counted would show up as
			// the wrong number of distinct answerers.
			people := map[string]bool{}
			validatorsSeen := map[string]bool{}
			for _, a := range step.Answers {
				if a.Human {
					if people[a.ActorID] {
						return fmt.Errorf("%q approved twice", a.ActorID)
					}
					people[a.ActorID] = true
					if a.ActorID == chaosPrincipal {
						return fmt.Errorf("the payment was approved by the principal it was raised for")
					}
					continue
				}
				validatorsSeen[a.ActorID] = true
			}
			if len(people) != 2 {
				return fmt.Errorf("%d distinct people approved, want 2", len(people))
			}
			if len(validatorsSeen) != 2 {
				return fmt.Errorf("%d distinct validators answered, want 2", len(validatorsSeen))
			}
			return nil
		},
	}
}

// selfApprovalScenario is the same payment approved by the person who raised
// it. Four eyes means the gate refuses rather than waiting for somebody else.
func selfApprovalScenario() scenario {
	const sagaID, stepID = "sg_selfApproval", "wire"

	plan := admitted(&janusv1.SagaBegin{
		SagaId: sagaID,
		Intent: &janusv1.Intent{
			IntentId:   "in_self_approval",
			Principal:  chaosPrincipal,
			MandateRef: "mandate:" + sagaID,
			Scope:      "payments",
		},
		Mode: "supervised",
		Plan: []*janusv1.PlannedStep{
			{StepId: "balance", Participant: "ag_chaos", Action: "balance.read",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
			{StepId: stepID, Participant: "ag_chaos", Action: "payments.wire.large",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
				DependsOn:   []string{"balance"}},
		},
	})

	selfBase := script{
		begin: plan,
		published: map[string]map[string]saga.FactValue{
			"balance": {"available_minor": gate.Number(10_000_000)},
		},
		touches: map[string]string{stepID: "acct:wire"},
	}

	return scenario{
		name:  "self-approval-refused",
		sagas: []string{sagaID},
		// The second party answers as a validator and as nobody at all: the
		// point of the scenario is that the only person who approved is the one
		// the saga was raised for, so there is no second human to be found. The
		// gate has to refuse rather than wait, and hosted it has to refuse for
		// the same reason.
		hosted: &hostedPlan{
			prog: selfBase,
			answerers: []answerSet{
				{script: selfBase, validator: "ag_credit_policy",
					human: chaosPrincipal, roles: []string{"credit-officer"}},
				{script: selfBase, validator: "ag_sanctions"},
			},
		},
		run: func(ctx context.Context, app *evidence.Appender, dir string, report func(saga.State)) error {
			base := script{
				begin: plan,
				published: map[string]map[string]saga.FactValue{
					"balance": {"available_minor": gate.Number(10_000_000)},
				},
				touches: map[string]string{stepID: "acct:wire"},
			}
			// The principal the saga was raised for approves it themselves,
			// holding a role that would otherwise entitle them to. The
			// validators are satisfied, so nothing else is standing in the way
			// and the four-eyes rule is the only thing left to refuse it.
			self := answerSet{script: base,
				validator: "ag_credit_policy", human: chaosPrincipal,
				roles: []string{"credit-officer"}}
			if _, err := driveTolerating(ctx, app, dir, sagaID, self, report); err != nil {
				return err
			}
			final, err := drive(ctx, app, dir, sagaID,
				answerSet{script: base, validator: "ag_sanctions"}, report)
			if err != nil {
				return err
			}
			if final.Status == saga.StatusCommitted {
				return fmt.Errorf("a payment approved only by the principal who raised it committed")
			}
			return nil
		},

		check: func(states map[string]saga.State) error {
			st, ok := states[sagaID]
			if !ok {
				return fmt.Errorf("saga %s is missing", sagaID)
			}
			if st.Status != saga.StatusCompensated {
				return fmt.Errorf("saga is %s, want COMPENSATED", st.Status)
			}
			step, _ := st.Step(stepID)
			if step.Status != saga.StepRefused {
				return fmt.Errorf("step %s is %s, want REFUSED", stepID, step.Status)
			}
			// Refused rather than still waiting. The distinction is the point:
			// an attempted control violation must not look like nobody having
			// got round to approving yet.
			if step.Gate.Verdict != janusv1.Verdict_VERDICT_FAIL {
				return fmt.Errorf("the gate recorded %s; a self-approval must be refused, not "+
					"waited past", step.Gate.Verdict)
			}
			return nil
		},
	}
}
