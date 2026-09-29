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

// swappedApproval is the history semantics 2 is about. A person is asked to approve
// a wire of 100 before it runs, approves it, and the pass that follows is on
// 1,000,000 — which a daemon produced from nothing more than the participant
// declaring again while the question was open, or restarting before the answer
// arrived. Every event in it is individually well formed.
func swappedApproval(t *testing.T, version uint32) []saga.Event {
	t.Helper()
	return approvalHistory(t, version, []*janusv1.Fact{
		{Key: "amount_minor", Value: &janusv1.Fact_Number{Number: 100}},
	})
}

// approvalHistory escalates on `asked` and passes on 1,000,000.
func approvalHistory(t *testing.T, version uint32, asked []*janusv1.Fact) []saga.Event {
	t.Helper()
	amount := func(n int64) []*janusv1.Fact {
		return []*janusv1.Fact{{Key: "amount_minor", Value: &janusv1.Fact_Number{Number: n}}}
	}
	msgs := []struct {
		kind evidence.Kind
		msg  proto.Message
	}{
		{evidence.KindSagaBegin, &janusv1.SagaBegin{
			SagaId: "sg", SemanticsVersion: version,
			Intent: &janusv1.Intent{IntentId: "in", Principal: "bob"},
			Plan: []*janusv1.PlannedStep{{
				StepId: "wire", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
			}},
			GatePlan: []*janusv1.StepGates{{StepId: "wire", RuleId: "wires", Require: []*janusv1.GateRequirement{{
				Id: "pre-approval", Gate: janusv1.GateType_GATE_TYPE_HUMAN,
				Phase: janusv1.GatePhase_GATE_PHASE_PRE_EXECUTION,
				Check: &janusv1.GateRequirement_Human{Human: &janusv1.HumanCheck{
					Roles: []string{"credit-officer"}, Quorum: 1, SeparationOfDuty: true,
				}},
			}, limitGate("wire-limit", "amount_minor", 10_000_000)}}},
		}},
		{evidence.KindGateVerdict, &janusv1.GateVerdict{
			SagaId: "sg", StepId: "wire", Gate: janusv1.GateType_GATE_TYPE_HUMAN,
			Verdict: janusv1.Verdict_VERDICT_ESCALATE, Facts: asked,
		}},
		{evidence.KindGateAnswer, &janusv1.GateAnswer{
			SagaId: "sg", StepId: "wire", RequirementId: "pre-approval", Attempt: 1,
			Actor:   &janusv1.Actor{HumanSubject: "alice"},
			Verdict: janusv1.Verdict_VERDICT_PASS, Roles: []string{"credit-officer"},
			AuthRef: "auth:alice", Reason: "ok for 100",
		}},
		{evidence.KindGateVerdict, &janusv1.GateVerdict{
			SagaId: "sg", StepId: "wire", Gate: janusv1.GateType_GATE_TYPE_COMPOSITE,
			Verdict: janusv1.Verdict_VERDICT_PASS, Decided: []string{"pre-approval"},
			Facts: amount(1_000_000),
		}},
	}
	out := make([]saga.Event, 0, len(msgs))
	for i, m := range msgs {
		payload, err := proto.Marshal(m.msg)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, saga.Event{Seq: uint64(i + 1), Kind: m.kind, Payload: payload})
	}
	return out
}

// TestAnApprovalIsNotCountedForAProposalItWasNotGivenFor is semantics 2's rule,
// in the only place it is enforced: the fold. The coordinator no longer writes
// this history, so without this test the check would be one nothing reaches.
func TestAnApprovalIsNotCountedForAProposalItWasNotGivenFor(t *testing.T) {
	_, err := saga.Replay(swappedApproval(t, 2))
	if err == nil {
		t.Fatal("under semantics 2 an approval given while the proposal was 100 was counted " +
			"for a pass on 1,000,000, and the saga folded as though nothing happened")
	}
	if !errors.Is(err, saga.ErrTransition) {
		t.Fatalf("refused, but not as an illegal transition: %v", err)
	}
	if !strings.Contains(err.Error(), "the answers recorded for it were given about the first") {
		t.Fatalf("refused for some other reason than the swap: %v", err)
	}
}

// TestASwapRecordedUnderVersionOneStillFolds is the other direction, and the
// reason this is a semantics version rather than a fix: a log written before
// semantics 2 holds exactly this, legally, and it must go on meaning what it
// meant. Naming it is the audit's job (FindingProposalChanged), not the fold's.
func TestASwapRecordedUnderVersionOneStillFolds(t *testing.T) {
	s, err := saga.Replay(swappedApproval(t, 1))
	if err != nil {
		t.Fatalf("a history that was legal under semantics 1 no longer folds: %v", err)
	}
	if st := s.Steps["wire"]; st.Proposal != nil {
		t.Errorf("semantics 1 folded a pinned proposal %v; version 1 never recorded one, and "+
			"a version-1 saga's projection must not change under a version-2 build", st.Proposal)
	}
}

// TestTheEscalationPinsWhatWasAsked: the proposal is on the projection from the
// moment the question is asked, which is what lets the coordinator decide on it
// after a restart and a daemon refuse a participant that tries to change it.
func TestTheEscalationPinsWhatWasAsked(t *testing.T) {
	events := swappedApproval(t, 2)
	s, err := saga.Replay(events[:2])
	if err != nil {
		t.Fatal(err)
	}
	pinned, ok := saga.ProposalUnderDecision(s.Steps["wire"])
	if !ok {
		t.Fatal("an escalation on 100 left no proposal under decision")
	}
	if got := saga.DescribeFacts(pinned); len(got) != 1 || got[0] != "amount_minor=100" {
		t.Fatalf("pinned %v, want [amount_minor=100]", got)
	}
}

// TestAnApprovalOfNothingIsNotAnApprovalOfAMillion: a step can escalate having
// proposed no facts at all, and "asked about nothing" has to pin as firmly as
// "asked about 100". A marker that read "is there a proposal map?" would see
// none here and let the pass on 1,000,000 through.
func TestAnApprovalOfNothingIsNotAnApprovalOfAMillion(t *testing.T) {
	_, err := saga.Replay(approvalHistory(t, 2, nil))
	if err == nil {
		t.Fatal("an approval given for a step that proposed nothing was counted for a pass " +
			"on 1,000,000")
	}
	if !strings.Contains(err.Error(), "the answers recorded for it were given about the first") {
		t.Fatalf("refused for some other reason than the swap: %v", err)
	}
}

// TestADivergentProposalIsADivergence: spot-replay and the determinism checks
// compare projections with saga.Diff, and a pinned proposal is an input to the
// next decision, so two folds that disagree about it are not the same fold.
func TestADivergentProposalIsADivergence(t *testing.T) {
	events := swappedApproval(t, 2)
	a, err := saga.Replay(events[:2])
	if err != nil {
		t.Fatal(err)
	}
	b := a.Clone()
	b.Steps["wire"].Proposal = map[string]saga.FactValue{
		"amount_minor": {Type: janusv1.FactType_FACT_TYPE_NUMBER, Number: 1_000_000},
	}
	if d := saga.Diff(a, b); len(d) == 0 {
		t.Fatal("two projections pinned to different proposals compared equal")
	}
}
