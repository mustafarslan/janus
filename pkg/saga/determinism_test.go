package saga_test

import (
	"context"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

// A running coordinator and a reader replaying the log must hold the same
// projection, down to the fields nobody looks at until much later.
//
// The interesting ones are a step's recorded touches and the time its attempt
// started. Neither changes how the saga looks now; both decide what happens
// next — which saga is judged to have reached a resource first (I6), and
// whether an attempt is judged to have timed out. A divergence in them is
// invisible in a status display and decisive in a commit-safety check, which
// is exactly the kind of drift invariant I5 exists to forbid.
func TestLiveProjectionMatchesReplay(t *testing.T) {
	app, dir, _ := newLog(t)
	defer app.Close()
	ctx := context.Background()
	r := saga.NewRunner(app, evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1", Principal: "pr_1"})

	if _, err := r.Begin(ctx, &janusv1.SagaBegin{
		SagaId: "sg_probe",
		Plan: []*janusv1.PlannedStep{
			{
				StepId: "s1", Participant: "ag_1", Action: "read",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE,
			},
			{
				StepId: "s2", Participant: "ag_1", Action: "write", DependsOn: []string{"s1"},
				EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
				CompensationAction: "unwrite",
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	// A PURE step reporting a read, then a compensable step reporting a write:
	// two touches recorded at different sequences, so an off-by-one in either
	// direction shows up.
	for _, step := range []struct {
		id   string
		res  string
		mode janusv1.ResourceTouch_Mode
	}{
		{"s1", "acct:1", janusv1.ResourceTouch_MODE_READ},
		{"s2", "acct:1", janusv1.ResourceTouch_MODE_WRITE},
	} {
		if _, err := r.PrepareStep(ctx, &janusv1.StepPrepare{SagaId: "sg_probe", StepId: step.id}); err != nil {
			t.Fatalf("prepare %s: %v", step.id, err)
		}
		if _, err := r.StepResult(ctx, &janusv1.StepResult{
			SagaId: "sg_probe", StepId: step.id,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			Touches: []*janusv1.ResourceTouch{{ResourceId: step.res, Mode: step.mode}},
		}); err != nil {
			t.Fatalf("result %s: %v", step.id, err)
		}
		if step.id == "s2" {
			if _, err := r.Gate(ctx, &janusv1.GateVerdict{
				SagaId: "sg_probe", StepId: step.id, Verdict: janusv1.Verdict_VERDICT_PASS,
			}); err != nil {
				t.Fatalf("gate %s: %v", step.id, err)
			}
		}
	}

	live := r.State()
	replayed, err := saga.ReplaySaga(dir, "sg_probe")
	if err != nil {
		t.Fatal(err)
	}
	if d := saga.Diff(live, replayed); len(d) > 0 {
		t.Fatalf("the running projection and a replay of the log disagree:\n  %v", d)
	}

	// Diff is only as good as what it compares, so assert the two fields that
	// motivated this test directly rather than trusting it to cover them.
	for _, id := range []string{"s1", "s2"} {
		l, rp := live.Steps[id], replayed.Steps[id]
		if len(l.Touches) != 1 || len(rp.Touches) != 1 {
			t.Fatalf("step %s: expected one touch each, got %d live and %d replayed",
				id, len(l.Touches), len(rp.Touches))
		}
		if l.Touches[0].Seq != rp.Touches[0].Seq {
			t.Errorf("step %s touch sequence: live %d, replay %d",
				id, l.Touches[0].Seq, rp.Touches[0].Seq)
		}
		if !l.PreparedAt.Equal(rp.PreparedAt) {
			t.Errorf("step %s prepared at: live %s, replay %s", id, l.PreparedAt, rp.PreparedAt)
		}
		if l.PreparedAt.IsZero() {
			t.Errorf("step %s has no prepared time, so a timeout could never be judged", id)
		}
	}
}
