package outbox_test

import (
	"context"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/saga"
)

// TestAnAdoptedCommitAuthorisesARelease is an observation rather than a
// requirement, and it is written down because the behaviour it records was
// nobody's decision.
//
// After a failover, a promoted replica adopts records the previous writer never
// acknowledged: recovery keeps every complete record, so a COMMIT can be in the
// log without any client ever having been told the saga committed (and
// the tenure records the boundary precisely so the span is visible).
//
// The release authority replays the saga and asks one question — is it COMMITTED
// — and a COMMIT that was written is a COMMIT. So a promoted daemon will release
// an irreversible effect on the strength of a commit nobody was told about.
//
// **This is not obviously wrong.** The log is the authority; that is the whole
// design, and the alternative — an effect that the log says was authorised and
// the outbox refuses to release — is its own kind of incoherence. What it is not
// is a decision somebody took. This test makes the behaviour visible so that the
// next person to think about it is arguing with a fact rather than discovering
// one.
func TestAnAdoptedCommitAuthorisesARelease(t *testing.T) {
	app, dir := newLog(t)
	ctx := context.Background()
	r := saga.NewRunner(app, participant)

	begin := &janusv1.SagaBegin{
		SagaId: "sg_adopted", Intent: &janusv1.Intent{IntentId: "in_adopted"},
		Plan: []*janusv1.PlannedStep{{
			StepId: "s1", EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		GatePolicyVersion: "blake3:test",
		GatePlan: []*janusv1.StepGates{{
			StepId: "s1", RuleId: "wires",
			Require: []*janusv1.GateRequirement{{
				Id: "approval", Gate: janusv1.GateType_GATE_TYPE_POLICY,
				Phase: janusv1.GatePhase_GATE_PHASE_PRE_RELEASE,
				Check: &janusv1.GateRequirement_Policy{Policy: &janusv1.PolicyCheck{Expr: "true"}},
			}},
		}},
	}
	for _, step := range []func() error{
		func() error { _, err := r.Begin(ctx, begin); return err },
		func() error {
			_, err := r.PrepareStep(ctx, &janusv1.StepPrepare{SagaId: "sg_adopted", StepId: "s1"})
			return err
		},
		func() error {
			_, err := r.StepResult(ctx, &janusv1.StepResult{
				SagaId: "sg_adopted", StepId: "s1",
				Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			})
			return err
		},
		func() error {
			_, err := r.Gate(ctx, &janusv1.GateVerdict{
				SagaId: "sg_adopted", StepId: "s1", Verdict: janusv1.Verdict_VERDICT_PASS,
				Gate: janusv1.GateType_GATE_TYPE_COMPOSITE, Decided: []string{"approval"},
			})
			return err
		},
		func() error { _, err := r.Seal(ctx, &janusv1.SealRequest{SagaId: "sg_adopted"}); return err },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}

	// The commit lands. In the failover this models, the primary died before the
	// follower acknowledged this far — so these bytes reached the replica's disk
	// and no client was ever told the saga committed.
	commitRef, err := r.Commit(ctx, &janusv1.Commit{
		SagaId: "sg_adopted", EvidenceRoot: []byte("root-adopted"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// The promotion: a tenure whose acknowledged head sits *below* the commit,
	// which is exactly what `janus-replicad promote -acknowledged` records when
	// the follower was behind.
	st := app.Stats()
	chain := st.LastChain
	tenure := evidence.Tenure{
		InheritedSeq: st.LastSeq, InheritedChain: "blake3:" + hexOf(chain[:]),
		AcknowledgedSeq: commitRef.Seq - 1,
		KeyID:           "ed25519-standby", Operator: "op_drill", Node: "region-b",
	}
	if _, err := app.RecordTenure(ctx, tenure, participant); err != nil {
		t.Fatal(err)
	}
	if tenure.Adopted() == 0 {
		t.Fatal("the fixture adopted nothing, so it does not model the case")
	}

	// The observation. The authority reads the log and finds a commit.
	root, ok, err := outbox.NewLogAuthority(dir).Committed(ctx, "sg_adopted")
	if err != nil {
		t.Fatalf("the authority errored on a promoted log: %v", err)
	}
	if !ok {
		t.Fatal("OBSERVATION CHANGED: the authority refused a commit that the log " +
			"contains. Something now distinguishes an adopted commit from an " +
			"acknowledged one — which may be an improvement, and is a change to " +
			"behaviour this test exists to keep visible. Update the documentation " +
			"to say which it is.")
	}
	if string(root) != "root-adopted" {
		t.Fatalf("authority returned root %q", root)
	}

	// And nothing in the outbox's world can tell the difference: the tenure that
	// records the boundary is in the log, and the authority does not read it.
	// That is the finding, stated as an assertion so it cannot rot quietly.
	if tenure.AcknowledgedSeq >= commitRef.Seq {
		t.Fatal("the fixture's tenure acknowledges the commit, so this proves nothing")
	}
}

// hexOf renders a chain hash the way a tenure records it.
func hexOf(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0x0f])
	}
	return string(out)
}
