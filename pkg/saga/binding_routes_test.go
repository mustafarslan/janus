package saga_test

import (
	"errors"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
	"google.golang.org/protobuf/proto"
)

// The routes around the semantics-2 proposal pin, found by reading the
// code, that semantics 3 closes. Each is a history of
// individually well-formed events; each folds under version 2, which is why it
// is a version and not a fix, and each is refused under version 3.

type rec struct {
	kind evidence.Kind
	msg  proto.Message
}

func events(t *testing.T, recs []rec) []saga.Event {
	t.Helper()
	out := make([]saga.Event, 0, len(recs))
	for i, r := range recs {
		p, err := proto.Marshal(r.msg)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, saga.Event{Seq: uint64(i + 1), Kind: r.kind, Payload: p})
	}
	return out
}

func million() []*janusv1.Fact {
	return []*janusv1.Fact{{Key: "amount_minor", Value: &janusv1.Fact_Number{Number: 1_000_000}}}
}

// approvedNothingThenAMillion: a step escalates having proposed nothing, a
// person approves it, the gate passes on nothing, and the step prepares on
// 1,000,000. With `spawns` set, the prepare also delegates to a sub-saga the
// person was never asked about.
func approvedNothingThenAMillion(t *testing.T, version uint32, prepFacts []*janusv1.Fact,
	spawns *janusv1.ChildSaga) []saga.Event {
	t.Helper()
	h := approvalHistory(t, version, nil)
	pass, err := proto.Marshal(&janusv1.GateVerdict{
		SagaId: "sg", StepId: "wire", Gate: janusv1.GateType_GATE_TYPE_COMPOSITE,
		Verdict: janusv1.Verdict_VERDICT_PASS, Decided: []string{"pre-approval"},
	})
	if err != nil {
		t.Fatal(err)
	}
	h[3] = saga.Event{Seq: 4, Kind: evidence.KindGateVerdict, Payload: pass}
	prep, err := proto.Marshal(&janusv1.StepPrepare{
		SagaId: "sg", StepId: "wire", Facts: prepFacts, Spawns: spawns,
		EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
	})
	if err != nil {
		t.Fatal(err)
	}
	return append(h, saga.Event{Seq: 5, Kind: evidence.KindStepPrepare, Payload: prep})
}

// TestAnApprovalOfNothingDoesNotLetAMillionRun is route (b). Semantics 2 pinned the
// escalation's facts and compared the verdict with them, but the prepare that
// followed was compared only if the pass had left a fact map behind -- and a
// pass on nothing leaves none.
func TestAnApprovalOfNothingDoesNotLetAMillionRun(t *testing.T) {
	_, err := saga.Replay(approvedNothingThenAMillion(t, 3, million(), nil))
	if err == nil {
		t.Fatal("under semantics 3 a step whose gate passed a proposal of nothing ran on " +
			"1,000,000; the approval was about a step that stated no amount")
	}
	if !errors.Is(err, saga.ErrTransition) ||
		!strings.Contains(err.Error(), "differ from the ones its gates were shown") {
		t.Fatalf("refused, but not because the step ran on something it was not judged on: %v", err)
	}
	if _, err := saga.Replay(approvedNothingThenAMillion(t, 3, nil, nil)); err != nil {
		t.Fatalf("the step ran on exactly what was approved -- nothing -- and was refused: %v", err)
	}
}

// TestADelegationIsPartOfTheProposal is route (c). The escalation recorded no
// sub-saga; the step then prepares delegating to one that commits on its own.
func TestADelegationIsPartOfTheProposal(t *testing.T) {
	rogue := &janusv1.ChildSaga{
		SagaId: "sg_rogue", CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_AUTONOMOUS,
	}
	_, err := saga.Replay(approvedNothingThenAMillion(t, 3, nil, rogue))
	if err == nil {
		t.Fatal("under semantics 3 an approval of a step that delegated nothing let it run " +
			"delegating to an autonomous sub-saga")
	}
	if !strings.Contains(err.Error(), `delegates nothing and is running as one that delegates `+
		`to autonomous sub-saga "sg_rogue"`) {
		t.Fatalf("refused, but the operator is not told the delegation changed: %v", err)
	}
}

// TestTheEscalationPinsItsDelegation: what the escalation recorded is on the
// projection, which is what lets a daemon refuse a changed spawn after a
// restart, and the coordinator prepare what was asked about.
func TestTheEscalationPinsItsDelegation(t *testing.T) {
	h := approvalHistory(t, 3, nil)
	var esc janusv1.GateVerdict
	if err := proto.Unmarshal(h[1].Payload, &esc); err != nil {
		t.Fatal(err)
	}
	esc.Spawns = &janusv1.ChildSaga{
		SagaId: "sg_kid", CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE,
	}
	p, err := proto.Marshal(&esc)
	if err != nil {
		t.Fatal(err)
	}
	h[1].Payload = p
	s, err := saga.Replay(h[:2])
	if err != nil {
		t.Fatal(err)
	}
	got, ok := saga.SpawnUnderDecision(s, s.Steps["wire"])
	if !ok || got.GetSagaId() != "sg_kid" ||
		got.GetCommitMode() != janusv1.ChildCommitMode_CHILD_COMMIT_MODE_CASCADE {
		t.Fatalf("the escalation delegated to cascade sub-saga sg_kid and the pin says %v (%v)", got, ok)
	}
	b := s.Clone()
	b.Steps["wire"].ProposalSpawn = nil
	if d := saga.Diff(s, b); len(d) == 0 {
		t.Fatal("two projections pinned to different delegations compared equal")
	}
}

// releaseAnsweredEarly: a release requirement is answered while the step is
// still PLANNED -- before it has run, let alone produced anything.
func releaseAnsweredEarly(t *testing.T, version uint32) []saga.Event {
	t.Helper()
	return events(t, []rec{
		{evidence.KindSagaBegin, &janusv1.SagaBegin{
			SagaId: "sg", SemanticsVersion: version,
			Intent: &janusv1.Intent{IntentId: "in", Principal: "bob"},
			Plan: []*janusv1.PlannedStep{{
				StepId: "wire", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
			}},
			GatePlan: []*janusv1.StepGates{{StepId: "wire", RuleId: "r", Require: []*janusv1.GateRequirement{{
				Id: "release-approval", Gate: janusv1.GateType_GATE_TYPE_HUMAN,
				Phase: janusv1.GatePhase_GATE_PHASE_PRE_RELEASE,
				Check: &janusv1.GateRequirement_Human{Human: &janusv1.HumanCheck{
					Roles: []string{"officer"}, Quorum: 1,
				}},
			}}}},
		}},
		{evidence.KindGateAnswer, &janusv1.GateAnswer{
			SagaId: "sg", StepId: "wire", RequirementId: "release-approval", Attempt: 1,
			Actor:   &janusv1.Actor{HumanSubject: "alice"},
			Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"officer"}, AuthRef: "auth:alice",
		}},
	})
}

// TestAReleaseApprovalIsNotTakenBeforeTheStepRuns is route (d).
func TestAReleaseApprovalIsNotTakenBeforeTheStepRuns(t *testing.T) {
	_, err := saga.Replay(releaseAnsweredEarly(t, 3))
	if err == nil {
		t.Fatal("under semantics 3 an approval of what a step produced was recorded before the " +
			"step had run; it would be counted when the release gate decided the same attempt")
	}
	if !strings.Contains(err.Error(), "for a pre_release requirement and the step is at pre_execution") {
		t.Fatalf("refused, but not because the answer came before its question: %v", err)
	}
}

// TestTheRoutesStillFoldUnderVersionTwo: the reason these are a semantics
// version. A version-2 log may hold any of them, legally, and must go on
// meaning what it meant; naming them is the audit's job.
func TestTheRoutesStillFoldUnderVersionTwo(t *testing.T) {
	rogue := &janusv1.ChildSaga{
		SagaId: "sg_rogue", CommitMode: janusv1.ChildCommitMode_CHILD_COMMIT_MODE_AUTONOMOUS,
	}
	for name, h := range map[string][]saga.Event{
		"approval of nothing, run on a million": approvedNothingThenAMillion(t, 2, million(), nil),
		"delegation added after the approval":   approvedNothingThenAMillion(t, 2, nil, rogue),
		"release answered before the step ran":  releaseAnsweredEarly(t, 2),
	} {
		s, err := saga.Replay(h)
		if err != nil {
			t.Errorf("%s: legal under semantics 2 and no longer folds: %v", name, err)
			continue
		}
		if st := s.Steps["wire"]; st.ProposalSpawn != nil {
			t.Errorf("%s: semantics 2 folded a pinned delegation %v it never recorded", name, st.ProposalSpawn)
		}
	}
}

// approvedBeforeAsked: a person's answer to a pre-execution requirement is
// recorded before the gate has escalated anything -- before there is a
// question -- and the pass that follows is on 1,000,000.
func approvedBeforeAsked(t *testing.T, version uint32) []saga.Event {
	t.Helper()
	h := approvalHistory(t, version, nil)
	// Drop the escalation: the answer (h[2]) now precedes any question.
	h = append([]saga.Event{h[0]}, h[2:]...)
	for i := range h {
		h[i].Seq = uint64(i + 1)
	}
	return h
}

// TestAnApprovalIsNotTakenBeforeTheQuestionIsAsked: found in review of
// semantics 3. An answer is bound to the proposal it was asked about, and before
// the escalation there is no proposal -- so an answer given then is about
// nothing, and would be counted for whatever the gate later passed.
func TestAnApprovalIsNotTakenBeforeTheQuestionIsAsked(t *testing.T) {
	_, err := saga.Replay(approvedBeforeAsked(t, 3))
	if err == nil {
		t.Fatal("under semantics 3 an approval recorded before any question was asked was " +
			"counted for a pass on 1,000,000")
	}
	if !strings.Contains(err.Error(), "before any proposal was put to it") {
		t.Fatalf("refused, but not because nothing had been asked: %v", err)
	}
	if _, err := saga.Replay(approvedBeforeAsked(t, 2)); err != nil {
		t.Fatalf("legal under semantics 2 and no longer folds: %v", err)
	}
}
