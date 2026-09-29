package saga_test

import (
	"errors"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

const (
	cascade    = janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE
	autonomous = janusv1.ChildCommitMode_CHILD_COMMIT_MODE_AUTONOMOUS
)

// delegating returns a step that hands its work to a sub-saga.
func delegating(id string, class janusv1.EffectClass) *janusv1.PlannedStep {
	p := &janusv1.PlannedStep{StepId: id, EffectClass: class}
	if class == janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE ||
		class == janusv1.EffectClass_EFFECT_CLASS_REVERSIBLE {
		p.CompensationAction = "undo_" + id
	}
	return p
}

// childBegin builds a sub-saga's SagaBegin, declaring its parentage.
func childBegin(sagaID, parentSaga, parentStep string, mode janusv1.ChildCommitMode,
	steps ...*janusv1.PlannedStep) *janusv1.SagaBegin {
	return &janusv1.SagaBegin{
		SagaId: sagaID,
		Intent: &janusv1.Intent{IntentId: "in_child"},
		Plan:   steps,
		Parent: &janusv1.ParentSaga{SagaId: parentSaga, StepId: parentStep, CommitMode: mode},
	}
}

func compensableStep(id string) *janusv1.PlannedStep {
	return &janusv1.PlannedStep{
		StepId: id, EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
		CompensationAction: "undo_" + id,
	}
}

func immediateStep(id string) *janusv1.PlannedStep {
	return &janusv1.PlannedStep{
		StepId: id, EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_IMMEDIATE,
	}
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

// A cascade child promises its parent can still withdraw it. An effect that
// fires the moment it runs makes that promise impossible to keep, so the
// contradiction has to be caught before anything happens rather than when the
// parent tries to withdraw and finds it cannot.
func TestCascadeChildMayNotContainAnImmediateIrreversibleEffect(t *testing.T) {
	_, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin,
		childBegin("sg_child", "sg_parent", "s1", cascade, immediateStep("c1"))))
	if !errors.Is(err, saga.ErrNotAdmitted) {
		t.Fatalf("a cascade child with an immediate irreversible step was admitted: %v", err)
	}
	if !strings.Contains(err.Error(), "withdraw") {
		t.Errorf("the error does not explain why cascade is the problem: %v", err)
	}
}

// The same plan is admissible in the two places where nobody is being promised
// a withdrawal that cannot happen. Without these, the rule above could be
// satisfied by simply banning the effect class everywhere, which would be a
// different and much blunter design.
func TestImmediateIrreversibleEffectsAreAdmissibleWhereNothingPromisesWithdrawal(t *testing.T) {
	// The step still needs a gate decided before it runs — being admissible
	// here is about who is promised a withdrawal, not about being ungoverned.
	t.Run("root saga", func(t *testing.T) {
		if _, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, &janusv1.SagaBegin{
			SagaId: "sg_root", Intent: &janusv1.Intent{IntentId: "in"},
			GatePolicyVersion: testPolicy,
			Plan:              []*janusv1.PlannedStep{immediateStep("s1")},
			GatePlan:          []*janusv1.StepGates{plannedGates("s1", "PRE_EXECUTION")},
		})); err != nil {
			t.Fatalf("a root saga may contain an immediate irreversible step: %v", err)
		}
	})

	t.Run("autonomous child", func(t *testing.T) {
		begin := childBegin("sg_child", "sg_parent", "s1", autonomous, immediateStep("c1"))
		begin.GatePolicyVersion = testPolicy
		begin.GatePlan = []*janusv1.StepGates{plannedGates("c1", "PRE_EXECUTION")}
		if _, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, begin)); err != nil {
			t.Fatalf("an autonomous child may contain an immediate irreversible step: %v", err)
		}
	})
}

func TestChildMustDeclareItsCommitMode(t *testing.T) {
	_, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin, &janusv1.SagaBegin{
		SagaId: "sg_child", Intent: &janusv1.Intent{IntentId: "in"},
		Plan:   []*janusv1.PlannedStep{compensableStep("c1")},
		Parent: &janusv1.ParentSaga{SagaId: "sg_parent", StepId: "s1"},
	}))
	if !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("a sub-saga with no declared commit mode was accepted: %v", err)
	}
}

func TestSagaMayNotBeItsOwnParent(t *testing.T) {
	_, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin,
		childBegin("sg_1", "sg_1", "s1", cascade, compensableStep("c1"))))
	if !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("a saga was allowed to parent itself: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Spawning
// ---------------------------------------------------------------------------

func spawnedParent(t *testing.T, class janusv1.EffectClass, mode janusv1.ChildCommitMode) saga.State {
	t.Helper()
	s := begun(t, planWith(delegating("s1", class)))
	return mustApply(t, s, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "s1",
		Spawns: &janusv1.ChildSaga{SagaId: "sg_child", CommitMode: mode},
	})
}

// A step's effect class is the promise it was admitted on. PURE says it touches
// nothing, and delegating to a saga that may touch anything makes that promise
// unverifiable rather than merely optimistic.
func TestPureStepMayNotSpawnASubSaga(t *testing.T) {
	s := begun(t, planWith(pureStep("s1")))
	_, err := saga.Apply(s, ev(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "s1",
		Spawns: &janusv1.ChildSaga{SagaId: "sg_child", CommitMode: cascade},
	}))
	if !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("a PURE step was allowed to spawn a sub-saga: %v", err)
	}
}

func TestSpawnRecordsTheLink(t *testing.T) {
	s := spawnedParent(t, janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE, cascade)
	link, ok := saga.ChildOf(s, "s1")
	if !ok {
		t.Fatal("the spawning step records no child")
	}
	if link.SagaID != "sg_child" || !link.Cascades() {
		t.Fatalf("recorded child is %+v, want cascade sg_child", link)
	}
	if id, ok := saga.StepForChild(s, "sg_child"); !ok || id != "s1" {
		t.Fatalf("StepForChild returned (%q, %v), want (s1, true)", id, ok)
	}
}

func TestStepMayNotSpawnItsOwnSaga(t *testing.T) {
	s := begun(t, planWith(compensableStep("s1")))
	_, err := saga.Apply(s, ev(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "s1",
		Spawns: &janusv1.ChildSaga{SagaId: "sg", CommitMode: cascade},
	}))
	if !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("a step spawned the saga it belongs to: %v", err)
	}
}

func TestTwoStepsMayNotSpawnTheSameSubSaga(t *testing.T) {
	s := begun(t, planWith(compensableStep("s1"), compensableStep("s2")))
	s = mustApply(t, s, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "s1",
		Spawns: &janusv1.ChildSaga{SagaId: "sg_child", CommitMode: cascade},
	})
	_, err := saga.Apply(s, ev(t, 3, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "s2",
		Spawns: &janusv1.ChildSaga{SagaId: "sg_child", CommitMode: cascade},
	}))
	if !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("two steps spawned the same sub-saga id: %v", err)
	}
}

// A retry is a new attempt, and the sub-saga it delegates to is a saga in its
// own right that has already reached a conclusion. Reusing the id would make
// the log unable to say which attempt an event belongs to.
func TestRetryingASpawnMustDelegateToANewSubSaga(t *testing.T) {
	plan := delegating("s1", janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE)
	plan.MaxRetries = 1
	s := begun(t, planWith(plan))
	s = mustApply(t, s, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "s1",
		Spawns: &janusv1.ChildSaga{SagaId: "sg_child_1", CommitMode: cascade},
	})
	s = mustApply(t, s, 3, evidence.KindStepResult, &janusv1.StepResult{
		SagaId: "sg", StepId: "s1",
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_RETRYABLE_ERROR},
	})

	t.Run("same id refused", func(t *testing.T) {
		_, err := saga.Apply(s, ev(t, 4, evidence.KindStepPrepare, &janusv1.StepPrepare{
			SagaId: "sg", StepId: "s1",
			Spawns: &janusv1.ChildSaga{SagaId: "sg_child_1", CommitMode: cascade},
		}))
		if !errors.Is(err, saga.ErrTransition) {
			t.Fatalf("a retry reused the previous sub-saga id: %v", err)
		}
	})

	// Changing the mode on retry would let a coordinator escape the cascade
	// obligation it accepted when the step was first admitted.
	t.Run("changed mode refused", func(t *testing.T) {
		_, err := saga.Apply(s, ev(t, 4, evidence.KindStepPrepare, &janusv1.StepPrepare{
			SagaId: "sg", StepId: "s1",
			Spawns: &janusv1.ChildSaga{SagaId: "sg_child_2", CommitMode: autonomous},
		}))
		if !errors.Is(err, saga.ErrTransition) {
			t.Fatalf("a retry changed the commit mode from cascade to autonomous: %v", err)
		}
	})

	t.Run("new id accepted", func(t *testing.T) {
		next := mustApply(t, s, 4, evidence.KindStepPrepare, &janusv1.StepPrepare{
			SagaId: "sg", StepId: "s1",
			Spawns: &janusv1.ChildSaga{SagaId: "sg_child_2", CommitMode: cascade},
		})
		if link, _ := saga.ChildOf(next, "s1"); link.SagaID != "sg_child_2" {
			t.Fatalf("after a retry the recorded child is %q, want sg_child_2", link.SagaID)
		}
	})
}

// ---------------------------------------------------------------------------
// Commit authority
// ---------------------------------------------------------------------------

// sealedChild drives a sub-saga to the point where only the commit is left.
func sealedChild(t *testing.T, mode janusv1.ChildCommitMode) saga.State {
	t.Helper()
	s, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin,
		childBegin("sg_child", "sg_parent", "s1", mode, pureStep("c1"))))
	if err != nil {
		t.Fatal(err)
	}
	s = mustApply(t, s, 2, evidence.KindStepPrepare,
		&janusv1.StepPrepare{SagaId: "sg_child", StepId: "c1"})
	s = mustApply(t, s, 3, evidence.KindStepResult, &janusv1.StepResult{
		SagaId: "sg_child", StepId: "c1",
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	})
	return mustApply(t, s, 4, evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg_child"})
}

// This is the check that makes cascade mean something. Without it a coordinator
// with a bug could release a child's effects while the parent was still
// deciding, and the log would show an ordinary commit.
func TestCascadeChildCannotCommitOnItsOwnAuthority(t *testing.T) {
	s := sealedChild(t, cascade)
	_, err := saga.Apply(s, ev(t, 5, evidence.KindCommit, &janusv1.Commit{SagaId: "sg_child"}))
	if !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("a cascade sub-saga committed unauthorised: %v", err)
	}
}

func TestCascadeChildCannotCommitOnSomeoneElsesAuthority(t *testing.T) {
	s := sealedChild(t, cascade)
	_, err := saga.Apply(s, ev(t, 5, evidence.KindCommit, &janusv1.Commit{
		SagaId: "sg_child", AuthorizedBy: "sg_someone_else",
	}))
	if !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("a cascade sub-saga committed on an unrelated saga's authority: %v", err)
	}
}

func TestCascadeChildCommitsWithItsParentsAuthority(t *testing.T) {
	s := sealedChild(t, cascade)
	s = mustApply(t, s, 5, evidence.KindCommit, &janusv1.Commit{
		SagaId: "sg_child", AuthorizedBy: "sg_parent",
	})
	if s.Status != saga.StatusCommitted {
		t.Fatalf("status is %s, want COMMITTED", s.Status)
	}
	if s.AuthorizedBy != "sg_parent" {
		t.Fatalf("the commit authority was not recorded: %q", s.AuthorizedBy)
	}
}

// The check is symmetric on purpose. A coordinator that hands an authorisation
// to a saga that needs none has confused two transactions, and the safe failure
// is a refused commit rather than a released effect.
func TestSagasThatNeedNoAuthorityMayNotCarryOne(t *testing.T) {
	t.Run("autonomous child", func(t *testing.T) {
		s := sealedChild(t, autonomous)
		_, err := saga.Apply(s, ev(t, 5, evidence.KindCommit, &janusv1.Commit{
			SagaId: "sg_child", AuthorizedBy: "sg_parent",
		}))
		if !errors.Is(err, saga.ErrTransition) {
			t.Fatalf("an autonomous sub-saga accepted a parent authorisation: %v", err)
		}
	})

	t.Run("root saga", func(t *testing.T) {
		s := begun(t, planWith(pureStep("s1")))
		s = step(t, s, "s1", 2)
		s = mustApply(t, s, 4, evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"})
		_, err := saga.Apply(s, ev(t, 5, evidence.KindCommit, &janusv1.Commit{
			SagaId: "sg", AuthorizedBy: "sg_parent",
		}))
		if !errors.Is(err, saga.ErrTransition) {
			t.Fatalf("a root saga accepted an authorisation from a parent it does not have: %v", err)
		}
	})
}

func TestAutonomousChildCommitsAlone(t *testing.T) {
	s := sealedChild(t, autonomous)
	s = mustApply(t, s, 5, evidence.KindCommit, &janusv1.Commit{SagaId: "sg_child"})
	if s.Status != saga.StatusCommitted {
		t.Fatalf("an autonomous sub-saga could not commit alone: %s", s.Status)
	}
}

// ---------------------------------------------------------------------------
// Cross-saga ordering
// ---------------------------------------------------------------------------

// committedParent drives a parent through spawning a child and committing.
func committedParent(t *testing.T, mode janusv1.ChildCommitMode) saga.State {
	t.Helper()
	s := spawnedParent(t, janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE, mode)
	s = mustApply(t, s, 3, evidence.KindStepResult, &janusv1.StepResult{
		SagaId: "sg", StepId: "s1", Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	})
	s = mustApply(t, s, 4, evidence.KindGateVerdict, &janusv1.GateVerdict{
		SagaId: "sg", StepId: "s1", Verdict: janusv1.Verdict_VERDICT_PASS,
	})
	s = mustApply(t, s, 5, evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg"})
	return mustApply(t, s, 6, evidence.KindCommit, &janusv1.Commit{SagaId: "sg"})
}

func TestAuthorizeCommitRequiresTheParentToHaveCommittedFirst(t *testing.T) {
	running := spawnedParent(t, janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE, cascade)
	if _, err := saga.AuthorizeCommit(running, "sg_child"); !errors.Is(err, saga.ErrNotAuthorized) {
		t.Fatalf("a child was authorised while its parent was still running: %v", err)
	}

	committed := committedParent(t, cascade)
	who, err := saga.AuthorizeCommit(committed, "sg_child")
	if err != nil {
		t.Fatalf("a committed parent refused to authorise its child: %v", err)
	}
	if who != "sg" {
		t.Fatalf("authority is %q, want the parent saga id", who)
	}
}

func TestAuthorizeCommitRefusesStrangersAndAutonomousChildren(t *testing.T) {
	committed := committedParent(t, cascade)
	if _, err := saga.AuthorizeCommit(committed, "sg_not_mine"); !errors.Is(err, saga.ErrNotAuthorized) {
		t.Fatalf("a parent authorised a saga it never spawned: %v", err)
	}

	auto := committedParent(t, autonomous)
	if _, err := saga.AuthorizeCommit(auto, "sg_child"); !errors.Is(err, saga.ErrNotAuthorized) {
		t.Fatalf("a parent authorised an autonomous child that needs no authority: %v", err)
	}
}

// The gap between a parent committing and its children following is the one
// place a crash is safe, and recovery has to be able to see what is still owed.
func TestPendingAuthorizationIsTheRecoveryWorkList(t *testing.T) {
	parent := committedParent(t, cascade)
	child := sealedChildOf(t, parent, cascade)

	fam := saga.Family{Parent: parent, Children: map[string]saga.State{"sg_child": child}}
	if got := fam.PendingAuthorization(); len(got) != 1 || got[0] != "sg_child" {
		t.Fatalf("pending authorisation is %v, want [sg_child]", got)
	}

	committed := mustApply(t, child, 9, evidence.KindCommit, &janusv1.Commit{
		SagaId: "sg_child", AuthorizedBy: "sg",
	})
	fam.Children["sg_child"] = committed
	if got := fam.PendingAuthorization(); len(got) != 0 {
		t.Fatalf("a committed child is still listed as pending: %v", got)
	}
}

// sealedChildOf builds a sub-saga that agrees with what its parent recorded.
func sealedChildOf(t *testing.T, parent saga.State, mode janusv1.ChildCommitMode) saga.State {
	t.Helper()
	stepID, ok := saga.StepForChild(parent, "sg_child")
	if !ok {
		t.Fatal("the parent did not spawn sg_child")
	}
	s, err := saga.Apply(saga.State{}, ev(t, 1, evidence.KindSagaBegin,
		childBegin("sg_child", parent.SagaID, stepID, mode, pureStep("c1"))))
	if err != nil {
		t.Fatal(err)
	}
	s = mustApply(t, s, 2, evidence.KindStepPrepare,
		&janusv1.StepPrepare{SagaId: "sg_child", StepId: "c1"})
	s = mustApply(t, s, 3, evidence.KindStepResult, &janusv1.StepResult{
		SagaId: "sg_child", StepId: "c1",
		Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	})
	return mustApply(t, s, 4, evidence.KindSealRequest, &janusv1.SealRequest{SagaId: "sg_child"})
}

// ---------------------------------------------------------------------------
// Family consistency
// ---------------------------------------------------------------------------

func TestAWellFormedFamilyHasNothingToReport(t *testing.T) {
	parent := committedParent(t, cascade)
	child := mustApply(t, sealedChildOf(t, parent, cascade), 9, evidence.KindCommit,
		&janusv1.Commit{SagaId: "sg_child", AuthorizedBy: "sg"})

	fam := saga.Family{Parent: parent, Children: map[string]saga.State{"sg_child": child}}
	if problems := fam.Check(); len(problems) > 0 {
		t.Fatalf("a well-formed family reported problems:\n  %s", strings.Join(problems, "\n  "))
	}
}

// The worst disagreement is about the mode itself: each side then believes the
// other is responsible for withdrawing the effects, so nobody is.
func TestFamilyCheckCatchesADisagreementAboutTheMode(t *testing.T) {
	parent := committedParent(t, cascade)
	child := sealedChildOf(t, parent, autonomous)

	fam := saga.Family{Parent: parent, Children: map[string]saga.State{"sg_child": child}}
	problems := fam.Check()
	if len(problems) == 0 {
		t.Fatal("a family where parent and child disagree about the commit mode was reported clean")
	}
	if !strings.Contains(strings.Join(problems, " "), "believes it is") {
		t.Errorf("the disagreement is not explained: %v", problems)
	}
}

func TestFamilyCheckCatchesAChildThatCommittedWithoutItsParent(t *testing.T) {
	parent := spawnedParent(t, janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE, cascade)
	child := sealedChildOf(t, parent, cascade)
	// Forge the commit the state machine would have refused, to prove the
	// cross-saga check does not depend on the per-saga one having run.
	child.Status = saga.StatusCommitted
	child.AuthorizedBy = "sg"

	fam := saga.Family{Parent: parent, Children: map[string]saga.State{"sg_child": child}}
	problems := fam.Check()
	if len(problems) == 0 {
		t.Fatal("a cascade child that committed before its parent was reported clean")
	}
	if !strings.Contains(strings.Join(problems, " "), "has committed while its parent") {
		t.Errorf("the ordering violation is not named: %v", problems)
	}
}

func TestFamilyCheckCatchesAnAbandonedCascadeChild(t *testing.T) {
	parent := spawnedParent(t, janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE, cascade)
	parent = mustApply(t, parent, 3, evidence.KindAbort, &janusv1.Abort{
		SagaId: "sg", ReasonRef: "operator changed their mind",
	})
	child := sealedChildOf(t, parent, cascade)

	fam := saga.Family{Parent: parent, Children: map[string]saga.State{"sg_child": child}}
	problems := fam.Check()
	if len(problems) == 0 {
		t.Fatalf("a cascade child left running under a %s parent was reported clean", parent.Status)
	}
	if !strings.Contains(strings.Join(problems, " "), "still") {
		t.Errorf("the abandoned child is not named: %v", problems)
	}
}

func TestFamilyCheckCatchesMissingAndUnclaimedChildren(t *testing.T) {
	parent := committedParent(t, cascade)

	t.Run("missing", func(t *testing.T) {
		fam := saga.Family{Parent: parent, Children: map[string]saga.State{}}
		if problems := fam.Check(); len(problems) != 1 ||
			!strings.Contains(problems[0], "missing from the family") {
			t.Fatalf("a spawned but absent child was not reported: %v", problems)
		}
	})

	t.Run("unclaimed", func(t *testing.T) {
		child := mustApply(t, sealedChildOf(t, parent, cascade), 9, evidence.KindCommit,
			&janusv1.Commit{SagaId: "sg_child", AuthorizedBy: "sg"})
		stranger := sealedChild(t, autonomous)
		fam := saga.Family{Parent: parent, Children: map[string]saga.State{
			"sg_child": child, "sg_stranger": stranger,
		}}
		problems := fam.Check()
		if len(problems) != 1 || !strings.Contains(problems[0], "no step of") {
			t.Fatalf("an unclaimed sub-saga was not reported: %v", problems)
		}
	})
}

// ---------------------------------------------------------------------------
// Unwinding
// ---------------------------------------------------------------------------

// A parent that unwinds takes its cascade children with it and leaves its
// autonomous ones alone. That difference is the whole of what the two modes buy
// and the only thing a coordinator has to act on.
func TestParentUnwindCascadesToCascadeChildrenOnly(t *testing.T) {
	s := begun(t, planWith(
		delegating("s1", janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE),
		delegating("s2", janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE),
	))
	s = mustApply(t, s, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "s1",
		Spawns: &janusv1.ChildSaga{SagaId: "sg_cascade", CommitMode: cascade},
	})
	s = mustApply(t, s, 3, evidence.KindStepResult, &janusv1.StepResult{
		SagaId: "sg", StepId: "s1", Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	})
	s = mustApply(t, s, 4, evidence.KindGateVerdict, &janusv1.GateVerdict{
		SagaId: "sg", StepId: "s1", Verdict: janusv1.Verdict_VERDICT_PASS,
	})
	s = mustApply(t, s, 5, evidence.KindStepPrepare, &janusv1.StepPrepare{
		SagaId: "sg", StepId: "s2",
		Spawns: &janusv1.ChildSaga{SagaId: "sg_auto", CommitMode: autonomous},
	})
	s = mustApply(t, s, 6, evidence.KindStepResult, &janusv1.StepResult{
		SagaId: "sg", StepId: "s2", Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
	})
	s = mustApply(t, s, 7, evidence.KindGateVerdict, &janusv1.GateVerdict{
		SagaId: "sg", StepId: "s2", Verdict: janusv1.Verdict_VERDICT_PASS,
	})

	s = mustApply(t, s, 8, evidence.KindAbort, &janusv1.Abort{SagaId: "sg", ReasonRef: "stop"})

	unwind := saga.CascadeUnwind(s)
	if len(unwind) != 1 || unwind[0].SagaID != "sg_cascade" {
		t.Fatalf("cascade unwind is %+v, want only sg_cascade", unwind)
	}

	// The autonomous child is not abandoned — the parent still has to undo it
	// with its own declared compensation, which is what it was admitted on.
	if st, _ := s.Step("s2"); st.Compensation != saga.CompRequired {
		t.Fatalf("the step that spawned the autonomous child is %q, want REQUIRED", st.Compensation)
	}
}

// A sub-saga that is still running when its parent unwinds is not the ordinary
// "did the call happen?" ambiguity: the child's own log says exactly what it
// did, so it must be unwound rather than deferred.
func TestAnInFlightSubSagaIsUnwoundRatherThanAssumedHarmless(t *testing.T) {
	s := spawnedParent(t, janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE, cascade)
	if st, _ := s.Step("s1"); st.Status != saga.StepPrepared {
		t.Fatalf("expected the spawning step to be PREPARED, got %s", st.Status)
	}

	s = mustApply(t, s, 3, evidence.KindAbort, &janusv1.Abort{SagaId: "sg", ReasonRef: "stop"})

	if got := saga.CascadeUnwind(s); len(got) != 1 || got[0].SagaID != "sg_child" {
		t.Fatalf("an in-flight cascade sub-saga was left out of the unwind: %+v", got)
	}
}

// An ordinary PREPARED step must keep its existing behaviour: the ambiguity is
// real there and is resolved by idempotency keys in Phase 3, not by guessing.
func TestAnInFlightOrdinaryStepIsStillDeferred(t *testing.T) {
	s := begun(t, planWith(compensableStep("s1")))
	s = mustApply(t, s, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "s1"})
	s = mustApply(t, s, 3, evidence.KindAbort, &janusv1.Abort{SagaId: "sg", ReasonRef: "stop"})

	if st, _ := s.Step("s1"); st.Compensation != saga.CompNotNeeded {
		t.Fatalf("a PREPARED step with no sub-saga is %q, want no compensation", st.Compensation)
	}
}

// A family split across two rule sets: a parent admitted before an upgrade and
// a child admitted after it. Every other check in Family.Check assumes the two
// agree about what a history means, so this one has to come first to be read.
func TestFamilyCheckCatchesAFamilyOnTwoRuleSets(t *testing.T) {
	parent := committedParent(t, cascade)
	child := mustApply(t, sealedChildOf(t, parent, cascade), 9, evidence.KindCommit,
		&janusv1.Commit{SagaId: "sg_child", AuthorizedBy: "sg"})
	child.Semantics = 2 // the parent's history carries no pin, so it folds as 1

	fam := saga.Family{Parent: parent, Children: map[string]saga.State{"sg_child": child}}
	problems := strings.Join(fam.Check(), " ")
	if !strings.Contains(problems, "folds under semantics 2 while its parent sg folds under 1") {
		t.Fatalf("a child on version 2 under a version-1 parent was not named: %q", problems)
	}
}
