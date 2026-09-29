package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/saga"
)

// A scenario is a saga shape worth being killed in the middle of.
//
// The set is chosen by where the state machine has to make an irreversible
// decision, because those are the moments where a crash can produce a state
// nobody designed: the instant a gate refuses, the instant a retry budget runs
// out, the instant a compensation fails, and — the one with real money behind
// it — the instant between a parent committing and its sub-saga following.
type scenario struct {
	name string
	// sagas lists every saga id the scenario produces, so recovery can be
	// checked against all of them and not just the one that is easy to reach.
	sagas []string
	// run drives the scenario, resuming from whatever the log already holds.
	run func(ctx context.Context, app *evidence.Appender, dir string, report func(saga.State)) error
	// check asserts the outcome is the one the scenario is about, so that a
	// bug which makes every saga quarantine cannot pass by being consistent.
	check func(states map[string]saga.State) error
	// invariant asserts what must hold at *every* moment, not just at the end.
	//
	// The distinction matters most for sub-sagas. A family that is consistent
	// once both sagas have finished says nothing about the window between a
	// parent's commit and its child's, and that window is exactly where a
	// crash can release effects on an authority that never existed. This is
	// evaluated against the state recovered from the log after each kill, so
	// a saga that has not started yet is simply absent.
	invariant func(states map[string]saga.State) error
	// dirInvariant is the same idea for a property that is not visible in a
	// projection — notably whether the outside world has changed. The outbox
	// scenario needs it: the ledger standing in for a receiving system lives on
	// disk, not in the log, and the whole question is whether it changed before
	// the log authorised it.
	dirInvariant func(dir string) error
	// dirCheck is the settled-state counterpart to dirInvariant.
	dirCheck func(dir string) error
	// hostedOnly marks a scenario that only means anything against the daemon.
	//
	// There is exactly one, and the reason is that a gate expiry is a
	// daemon capability. A library-embedded coordinator has no ticker, so its
	// gates wait forever — which is correct behaviour and makes the in-process
	// version of this scenario a saga that never finishes rather than a test.
	// Skipping it there is the honest statement of that asymmetry.
	hostedOnly bool
	// hosted is how the scenario is played against janus-orchd in -hosted mode,
	// or nil for one that cannot be driven over the wire yet.
	//
	// A scenario is hostable when everything outside the coordinator can reach
	// it over the service: participants (always), and since 4b a deliverer for
	// the target its effects go to. The ones that still need a validator's
	// answer, or that spawn a sub-saga, are not; hosting them is not built.
	hosted *hostedPlan
}

// tickFor is the daemon's ticker interval for one scenario: off unless it
// asked, which all but one do not.
func tickFor(plan hostedPlan) time.Duration {
	if plan.tick > 0 {
		return plan.tick
	}
	return -1
}

// hostedPlan is a scenario's script plus whatever else has to be connected to
// the daemon for it to run.
type hostedPlan struct {
	prog script
	// target is the outbox target this scenario delivers to, and newDeliverer
	// builds the thing that can reach it. Both empty when the scenario holds no
	// effects.
	//
	// The deliverer connects rather than being compiled into the daemon,
	// because that is the arrangement a deployment has and therefore the one
	// worth killing: a chaos run where the daemon could reach the ledger by
	// calling a function in its own address space would not be exercising the
	// stream at all.
	target       string
	newDeliverer func(dir string) outbox.Deliverer
	// holdFor is the effect to capture, and it is captured before the saga is
	// driven at all — which is the pessimistic order and the right one. A proxy
	// records the invocation it intercepted before anything judges it, because
	// an effect Janus knows about can be refused and an effect it does not know
	// about cannot.
	holdFor func(dir string) *janusv1.EffectHeld
	// tick is the daemon's ticker interval for this scenario. Zero leaves it
	// off, which is what every scenario but one wants: background work would
	// make what a kill interrupted depend on a timer rather than on the
	// transition under test.
	//
	// The exception is the gate-deadline scenario, where the ticker *is* the
	// thing being killed. It is safe there for a specific reason rather than a
	// general one: the deadline is anchored at a recorded time, so it falls at
	// the same point in the saga's history however long the run takes, and the
	// expiry is exactly one extra transition in every run.
	tick time.Duration
	// answerers are the parties this scenario can answer a gate as, in order.
	//
	// A quorum is satisfied by distinct parties — the state machine refuses the
	// same one asked twice — so the nth outstanding answer is asked of the nth
	// answerer. Which n that is comes from the projection's answers_recorded
	// rather than from anything this driver remembers, so a kill in the middle
	// of a quorum resumes without re-approving as somebody whose approval is
	// already on the record.
	answerers []answerSet
	// spawns are the sub-sagas the primary saga's steps delegate to, keyed by
	// step id, and also lists the other sagas in the family so they are driven
	// alongside it.
	//
	// A family is driven round-robin rather than in a fixed order, which is the
	// honest shape: a cascade child seals and waits for an authority that only
	// its parent's commit creates, and nothing in a deployment sequences those
	// two for you.
	spawns map[string]*janusv1.ChildSaga
	also   []hostedMember
}

// hostedMember is one more saga in a family, with its own script.
type hostedMember struct {
	prog   script
	spawns map[string]*janusv1.ChildSaga
}

var participant = evidence.ParticipantRef{
	ID: "ag_chaos", ManifestVersion: "1.0.0", Principal: "pr_chaos",
}

// ---- the scripted participant ------------------------------------------------

// script is a Program whose answers are a pure function of (step, attempt), so
// a coordinator that resumes mid-saga produces the same history as the one it
// replaced.
type script struct {
	begin *janusv1.SagaBegin
	// failUntil makes a step return a retryable error until the given attempt.
	failUntil map[string]uint32
	// fatal makes a step fail unretryably.
	fatal map[string]bool
	// refuse makes the step propose facts the reference policy will not accept,
	// so a refusal in these scenarios comes from the policy rather than from a
	// harness that decided the answer in advance.
	refuse map[string]bool
	// overLimit makes a step propose an amount above the policy's threshold.
	overLimit map[string]bool
	// undoFails makes a compensation fail, which is what sends a saga to
	// QUARANTINE rather than to COMPENSATED.
	undoFails map[string]bool
	// touches records a resource touch per step, so frontier claims are
	// exercised rather than always empty.
	touches map[string]string
	// published are facts a step puts on the record from what it found, keyed
	// by step, for a later step's gate to be judged against.
	published map[string]map[string]saga.FactValue
	// authority is the parent saga whose commit authorises this one.
	authority string
}

func (s script) Begin() *janusv1.SagaBegin { return s.begin }

func (s script) Run(stepID string, attempt uint32) saga.StepOutcome {
	out := saga.StepOutcome{Status: janusv1.Outcome_STATUS_OK}
	switch {
	case s.fatal[stepID]:
		out.Status = janusv1.Outcome_STATUS_TERMINAL_ERROR
	case attempt <= s.failUntil[stepID]:
		out.Status = janusv1.Outcome_STATUS_RETRYABLE_ERROR
	}
	if res, ok := s.touches[stepID]; ok && out.Status == janusv1.Outcome_STATUS_OK {
		out.Touches = []*janusv1.ResourceTouch{
			{ResourceId: res, Mode: janusv1.ResourceTouch_MODE_WRITE},
		}
	}
	if facts, ok := s.published[stepID]; ok && out.Status == janusv1.Outcome_STATUS_OK {
		out.Published = facts
	}
	return out
}

// Facts is what the step puts before its gates.
//
// It is a pure function of (step, attempt) for the same reason Run is: a
// resumed coordinator re-proposes what its predecessor proposed, and the state
// machine insists the step that runs is the step that was judged. A harness
// that varied its facts between attempts would trip that check on an honest
// retry and look like a bug in the machine rather than in the harness.
func (s script) Facts(stepID string, _ uint32) map[string]saga.FactValue {
	amount := int64(250000)
	if s.overLimit[stepID] {
		amount = 5000000
	}
	return map[string]saga.FactValue{
		"amount_minor": gate.Number(amount),
		"currency":     gate.Text("EUR"),
		"counterparty": gate.Text("cp_" + stepID),
		"recipient":    gate.Text("ops@example.com"),
		"approved":     gate.Flag(!s.refuse[stepID]),
	}
}

func (s script) Undo(stepID string) janusv1.Outcome_Status {
	if s.undoFails[stepID] {
		return janusv1.Outcome_STATUS_TERMINAL_ERROR
	}
	return janusv1.Outcome_STATUS_OK
}

// ---- plan helpers -------------------------------------------------------------

func compensable(id string, deps ...string) *janusv1.PlannedStep {
	return &janusv1.PlannedStep{
		StepId: id, Participant: "ag_chaos", Action: id,
		EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
		CompensationAction: id + ".undo", DependsOn: deps,
	}
}

func pure(id string, deps ...string) *janusv1.PlannedStep {
	return &janusv1.PlannedStep{
		StepId: id, Participant: "ag_chaos", Action: id,
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE, DependsOn: deps,
	}
}

// engine is the gate engine every scenario is admitted under. It is a package
// variable rather than a parameter because admission happens while the scenario
// list is being built, before any test has a context to thread one through.
var engine *gate.Engine

// loadPolicy reads the reference policy and builds the engine.
func loadPolicy(path string) error {
	p, err := gate.LoadPolicyFile(path)
	if err != nil {
		return err
	}
	engine = gate.NewEngine(p)
	return nil
}

func plan(sagaID string, steps ...*janusv1.PlannedStep) *janusv1.SagaBegin {
	return admitted(&janusv1.SagaBegin{
		SagaId: sagaID,
		Intent: &janusv1.Intent{
			IntentId: "in_" + sagaID,
			// A mandate reference, because the reference policy refuses an
			// irreversible payment that has no authority behind it.
			MandateRef: "mandate:" + sagaID,
			Principal:  "pr_chaos",
		},
		Mode: "supervised", Plan: steps,
	})
}

// admitted resolves the saga's gate plan from the policy, refusing to build a
// scenario whose plan the policy would not admit.
//
// Panicking is right here: an inadmissible plan in the chaos suite is a bug in
// the suite, discovered before any saga runs, and a scenario that silently ran
// ungated would make the whole exercise prove nothing.
func admitted(begin *janusv1.SagaBegin) *janusv1.SagaBegin {
	if err := engine.Admit(begin); err != nil {
		panic(fmt.Sprintf("scenario %q is not admissible: %v", begin.GetSagaId(), err))
	}
	return begin
}

// drive resumes one saga and runs it to a terminal state.
func drive(ctx context.Context, app *evidence.Appender, dir, sagaID string,
	prog saga.Program, report func(saga.State)) (saga.State, error) {
	c, err := resume(app, dir, sagaID, prog)
	if err != nil {
		return saga.State{}, err
	}
	c.OnTransition(report)
	return c.Drive(ctx)
}

// resume builds a coordinator with a gatekeeper attached.
//
// The gatekeeper reads the log for its cross-saga view rather than being handed
// one, which is what makes a resumed coordinator see the same conflicts its
// predecessor saw: there is nothing in memory for it to have lost.
func resume(app *evidence.Appender, dir, sagaID string, prog saga.Program) (*saga.Coordinator, error) {
	c, err := saga.ResumeSaga(app, dir, sagaID, participant, prog)
	if err != nil {
		return nil, err
	}
	// Live: the scenario's appender is open on this directory while the
	// gatekeeper replays it. The suite has hit the resulting torn tail before
	// (an earlier fix closed it once, by another route).
	c = c.WithGatekeeper(gate.NewKeeper(gate.IndexFromLiveLog(dir,
		func() uint64 { return app.Stats().LastSeq })))
	if sc, ok := prog.(script); ok && sc.authority != "" {
		c = c.WithAuthority(sc.authority)
	}
	return c, nil
}

// driveTolerating runs a saga as far as it will go and accepts it stopping at a
// gate that is waiting for somebody.
//
// A saga held by a human is not a failure, and the whole reason a four-eyes
// payment takes two passes is that the first answerer cannot also be the
// second. Treating the wait as an error would make the scenario impossible to
// write honestly.
func driveTolerating(ctx context.Context, app *evidence.Appender, dir, sagaID string,
	prog saga.Program, report func(saga.State)) (saga.State, error) {
	s, err := drive(ctx, app, dir, sagaID, prog, report)
	if errors.Is(err, saga.ErrWaiting) {
		return s, nil
	}
	return s, err
}

// single builds a scenario driving one saga.
func single(name string, prog script, want saga.Status) scenario {
	id := prog.begin.GetSagaId()
	return scenario{
		name:   name,
		hosted: &hostedPlan{prog: prog},
		sagas:  []string{id},
		run: func(ctx context.Context, app *evidence.Appender, dir string, report func(saga.State)) error {
			_, err := drive(ctx, app, dir, id, prog, report)
			return err
		},
		check: func(states map[string]saga.State) error {
			if got := states[id].Status; got != want {
				return fmt.Errorf("saga %s is %s, want %s", id, got, want)
			}
			return nil
		},
	}
}

// ---- the scenarios ------------------------------------------------------------

// scenarios is built after the policy loads, because every plan in it is
// admitted against that policy while it is being built. A package-level literal
// would run before main could read the file.
var scenarios []scenario

func buildScenarios() []scenario {
	return []scenario{
		contendingWriters(),
		gateDeadlineExpires(),

		single("happy-path",
			script{
				begin:   plan("sg_happy", pure("read"), compensable("pay", "read")),
				touches: map[string]string{"pay": "acct:1"},
			},
			saga.StatusCommitted),

		single("parallel-branches",
			script{
				begin: plan("sg_parallel",
					pure("root"),
					compensable("left", "root"),
					compensable("right", "root"),
					compensable("join", "left", "right")),
				touches: map[string]string{"left": "acct:1", "right": "acct:2", "join": "ledger"},
			},
			saga.StatusCommitted),

		// A retry budget spent across a crash must not reset. If recovery
		// recounted attempts from zero, a step would get unlimited retries and the
		// saga would hold its resources forever.
		single("retry-then-succeed",
			script{
				begin: plan("sg_retry", func() *janusv1.PlannedStep {
					st := compensable("flaky")
					st.MaxRetries = 2
					return st
				}()),
				failUntil: map[string]uint32{"flaky": 2},
				touches:   map[string]string{"flaky": "acct:1"},
			},
			saga.StatusCommitted),

		// A poisoned step unwinds the saga. The crash-sensitive part is that the
		// steps which already succeeded must still be undone.
		single("poison-step-unwinds",
			script{
				begin:   plan("sg_poison", compensable("charge"), compensable("ship", "charge")),
				fatal:   map[string]bool{"ship": true},
				touches: map[string]string{"charge": "acct:1"},
			},
			saga.StatusCompensated),

		// A gate refusing an effect is not the same as a step failing, and the
		// distinction has to survive a crash in the middle of acting on it.
		single("gate-refusal-unwinds",
			script{
				begin:   plan("sg_gate", compensable("charge"), compensable("notify", "charge")),
				refuse:  map[string]bool{"notify": true},
				touches: map[string]string{"charge": "acct:1"},
			},
			saga.StatusCompensated),

		// A compensation that fails must freeze the saga with its outstanding
		// effects listed, and must still do so if the coordinator dies while
		// deciding that.
		single("failed-compensation-quarantines",
			script{
				begin:     plan("sg_quarantine", compensable("charge"), compensable("ship", "charge")),
				fatal:     map[string]bool{"ship": true},
				undoFails: map[string]bool{"charge": true},
				touches:   map[string]string{"charge": "acct:1"},
			},
			saga.StatusQuarantine),

		cascadeFamily(),
		autonomousFamily(),
		withOutboxChecks(gatedEffectScenario()),
		withRogueChecks(rogueStepScenario()),
		withOutboxChecks(fourEyesScenario()),
		selfApprovalScenario(),
	}
}

// withOutboxChecks attaches the directory-level checks that the Phase 3 exit
// gate turns on.
func withOutboxChecks(sc scenario) scenario {
	ids := sc.sagas
	sc.invariant = nil
	sc.dirInvariant = func(dir string) error { return outboxInvariant(dir, ids) }
	sc.dirCheck = outboxFinalCheck
	return sc
}

// cascadeFamily is the scenario with the most at stake.
//
// A cascade sub-saga's effects are released only when its parent commits, so
// there is a window between the parent's commit and the child's in which the
// coordinator holds an obligation that exists nowhere but in its own memory —
// unless the log carries it. This kills the coordinator inside that window
// repeatedly and checks the obligation is honoured by whoever picks it up.
func cascadeFamily() scenario {
	const parentID, childID = "sg_family", "sg_family_child"

	parentPlan := plan(parentID, compensable("delegate"))
	childPlan := &janusv1.SagaBegin{
		SagaId: childID, Intent: &janusv1.Intent{IntentId: "in_child"}, Mode: "supervised",
		Plan: []*janusv1.PlannedStep{compensable("charge")},
		Parent: &janusv1.ParentSaga{
			SagaId: parentID, StepId: "delegate",
			CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE,
		},
	}

	return scenario{
		name:  "subsaga-cascade",
		sagas: []string{parentID, childID},
		// Hosted, nothing sequences the two sagas: the driver acts on whichever
		// has something to do. The child seals and waits, the parent commits,
		// and the daemon resolves the child's authority from the parent's log
		// rather than from anything a client asserted — which is the only way
		// it can be resolved safely, since a client that could assert an
		// authority could release a child's effects on one that never existed.
		hosted: &hostedPlan{
			prog: script{begin: parentPlan},
			spawns: map[string]*janusv1.ChildSaga{"delegate": {
				SagaId:     childID,
				CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE,
			}},
			also: []hostedMember{{
				prog: script{begin: childPlan, touches: map[string]string{"charge": "acct:1"}},
			}},
		},
		run: func(ctx context.Context, app *evidence.Appender, dir string, report func(saga.State)) error {
			// The child runs to SEALING first: its effects are held, waiting
			// for an authority that does not exist yet.
			childProg := script{begin: childPlan, touches: map[string]string{"charge": "acct:1"}}
			cc, err := resume(app, dir, childID, childProg)
			if err != nil {
				return err
			}
			cc.OnTransition(report)
			if err := cc.DriveUntilSealed(ctx); err != nil {
				return err
			}

			// The parent's step delegates to that child and then commits.
			parentProg := spawningScript{
				script: script{begin: parentPlan},
				spawns: map[string]*janusv1.ChildSaga{"delegate": {
					SagaId:     childID,
					CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE,
				}},
			}
			parent, err := drive(ctx, app, dir, parentID, parentProg, report)
			if err != nil {
				return err
			}

			// Only now may the child commit, and only on the authority the
			// parent's commit created. A coordinator that has just started
			// reaches this same point by reading the log.
			authority, err := saga.AuthorizeCommit(parent, childID)
			if err != nil {
				return fmt.Errorf("the parent committed but would not authorise its child: %w", err)
			}
			cc2, err := resume(app, dir, childID, childProg)
			if err != nil {
				return err
			}
			cc2.OnTransition(report)
			_, err = cc2.WithAuthority(authority).Drive(ctx)
			return err
		},
		check: func(states map[string]saga.State) error {
			parent, child := states[parentID], states[childID]
			if parent.Status != saga.StatusCommitted {
				return fmt.Errorf("parent is %s, want COMMITTED", parent.Status)
			}
			if child.Status != saga.StatusCommitted {
				return fmt.Errorf("child is %s, want COMMITTED", child.Status)
			}
			if child.AuthorizedBy != parentID {
				return fmt.Errorf("child committed on authority %q, want %q", child.AuthorizedBy, parentID)
			}
			fam := saga.Family{Parent: parent, Children: map[string]saga.State{childID: child}}
			if problems := fam.Check(); len(problems) > 0 {
				return fmt.Errorf("the family is inconsistent after recovery: %v", problems)
			}
			return nil
		},
		// The safety property, stated for every instant rather than for the
		// end: a cascade child's effects are released only on its parent's
		// authority, so at no point may the child be committed while the
		// parent is not.
		invariant: func(states map[string]saga.State) error {
			child, ok := states[childID]
			if !ok || child.Status != saga.StatusCommitted {
				return nil
			}
			parent, ok := states[parentID]
			if !ok {
				return fmt.Errorf("the cascade child has committed but its parent has no log at all")
			}
			if parent.Status != saga.StatusCommitted {
				return fmt.Errorf("the cascade child has committed while its parent is %s",
					parent.Status)
			}
			if child.AuthorizedBy != parentID {
				return fmt.Errorf("the cascade child committed on authority %q, not its parent",
					child.AuthorizedBy)
			}
			return nil
		},
	}
}

// autonomousFamily checks the other half of the contract: a child that commits
// on its own authority keeps what it did, and a parent that unwinds afterwards
// compensates with its own declared action rather than reaching into the
// child's transaction.
func autonomousFamily() scenario {
	const parentID, childID = "sg_auto", "sg_auto_child"

	childPlan := &janusv1.SagaBegin{
		SagaId: childID, Intent: &janusv1.Intent{IntentId: "in_child"}, Mode: "supervised",
		Plan: []*janusv1.PlannedStep{compensable("charge")},
		Parent: &janusv1.ParentSaga{
			SagaId: parentID, StepId: "delegate",
			CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_AUTONOMOUS,
		},
	}

	return scenario{
		name:  "subsaga-autonomous-parent-fails",
		sagas: []string{parentID, childID},
		// An autonomous child commits on its own authority, so hosted there is
		// nothing for the daemon to resolve — which is the point of the
		// scenario, and worth having under kills over the wire too: the parent
		// unwinds and the child, already committed, stays committed.
		hosted: &hostedPlan{
			prog: script{
				begin: plan(parentID, compensable("delegate"), compensable("settle", "delegate")),
				fatal: map[string]bool{"settle": true},
			},
			spawns: map[string]*janusv1.ChildSaga{"delegate": {
				SagaId:     childID,
				CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_AUTONOMOUS,
			}},
			also: []hostedMember{{
				prog: script{begin: childPlan, touches: map[string]string{"charge": "acct:9"}},
			}},
		},
		run: func(ctx context.Context, app *evidence.Appender, dir string, report func(saga.State)) error {
			childProg := script{begin: childPlan, touches: map[string]string{"charge": "acct:9"}}
			if _, err := drive(ctx, app, dir, childID, childProg, report); err != nil {
				return err
			}

			// The parent delegates, then a later step fails fatally. The child
			// has already committed and stays committed.
			parentProg := spawningScript{
				script: script{
					begin: plan(parentID, compensable("delegate"), compensable("settle", "delegate")),
					fatal: map[string]bool{"settle": true},
				},
				spawns: map[string]*janusv1.ChildSaga{"delegate": {
					SagaId:     childID,
					CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_AUTONOMOUS,
				}},
			}
			_, err := drive(ctx, app, dir, parentID, parentProg, report)
			return err
		},
		check: func(states map[string]saga.State) error {
			parent, child := states[parentID], states[childID]
			if parent.Status != saga.StatusCompensated {
				return fmt.Errorf("parent is %s, want COMPENSATED", parent.Status)
			}
			// The point of the scenario: the parent unwound and the child did
			// not follow it.
			if child.Status != saga.StatusCommitted {
				return fmt.Errorf("an autonomous child is %s after its parent unwound, want COMMITTED",
					child.Status)
			}
			if got := saga.CascadeUnwind(parent); len(got) != 0 {
				return fmt.Errorf("an autonomous child was listed for cascade unwind: %+v", got)
			}
			return nil
		},
	}
}

// spawningScript is a Program whose steps delegate to sub-sagas.
type spawningScript struct {
	script
	spawns map[string]*janusv1.ChildSaga
}

func (s spawningScript) Spawns(stepID string) *janusv1.ChildSaga { return s.spawns[stepID] }

func scenarioByName(name string) (scenario, bool) {
	for _, sc := range scenarios {
		if sc.name == name {
			return sc, true
		}
	}
	return scenario{}, false
}

// liveRead is how a scenario reads the directory its own appender is writing:
// the acknowledged head, so a half-written record is not mistaken for damage,
// and the appender as the locator, so finding one saga's events does
// not mean reading everybody's.
func liveRead(app *evidence.Appender) func() []evidence.ReadOption {
	return func() []evidence.ReadOption {
		return []evidence.ReadOption{
			evidence.AsOf(app.Stats().LastSeq),
			evidence.WithLocator(app),
		}
	}
}
