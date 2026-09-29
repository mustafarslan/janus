package saga_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/saga"
)

// remoteProgram stands in for participants in another process: it answers only
// for the steps whose results have arrived.
type remoteProgram struct {
	begin    *janusv1.SagaBegin
	reported map[string]bool
}

func (p remoteProgram) Begin() *janusv1.SagaBegin { return p.begin }

func (p remoteProgram) Run(stepID string, _ uint32) saga.StepOutcome {
	if !p.reported[stepID] {
		// The coordinator must never get here for an unreported step. Reaching
		// it means Reported was not consulted, and the log is about to record
		// an outcome the participant never gave.
		panic("Run called for step " + stepID + ", whose participant has not reported")
	}
	return saga.StepOutcome{Status: janusv1.Outcome_STATUS_OK}
}

func (p remoteProgram) Undo(string) janusv1.Outcome_Status {
	return janusv1.Outcome_STATUS_OK
}

func (p remoteProgram) Reported(stepID string, _ uint32) bool { return p.reported[stepID] }

// TestASagaWaitingOnAParticipantSaysSoRatherThanStalling is the distinction the
// hosted coordinator turns on.
//
// A stall is a bug: the saga has work it cannot do and somebody has to look at
// the code. Waiting for a participant that has not answered yet is the ordinary
// life of a service, and reporting it as a stall would bury a real defect under
// a stream of sagas that are simply in flight. The error has to name which of
// the two it is, and which step.
func TestASagaWaitingOnAParticipantSaysSoRatherThanStalling(t *testing.T) {
	app, dir, _ := newRemoteLog(t)
	defer func() { _ = app.Close() }()

	prog := remoteProgram{begin: twoBranchPlan(), reported: map[string]bool{}}
	coord := saga.NewCoordinator(runnerFor(app), prog).WithEvidenceDir(dir)

	_, err := coord.Drive(context.Background())
	if !errors.Is(err, saga.ErrAwaitingParticipant) {
		t.Fatalf("a saga whose participant has not answered is waiting, not stalled; "+
			"got %v", err)
	}
	if !contains(err.Error(), "st_left") {
		t.Fatalf("the error must name the step being waited on, or an operator cannot "+
			"tell which participant is silent; got %q", err)
	}
}

// TestAParallelBranchRunsWhileAnotherWaitsOnItsParticipant is why the wait skips
// the step rather than stopping the saga.
//
// The two branches of this plan depend on nothing, so a coordinator that
// stopped at the first unanswered participant would run them one at a time —
// turning every parallel plan into a serial one the moment it was hosted, with
// nothing in the log to say why it got slower.
func TestAParallelBranchRunsWhileAnotherWaitsOnItsParticipant(t *testing.T) {
	app, dir, _ := newRemoteLog(t)
	defer func() { _ = app.Close() }()

	// The right-hand participant has answered; the left-hand one has not.
	prog := remoteProgram{begin: twoBranchPlan(), reported: map[string]bool{"st_right": true}}
	coord := saga.NewCoordinator(runnerFor(app), prog).WithEvidenceDir(dir)

	state, err := coord.Drive(context.Background())
	if !errors.Is(err, saga.ErrAwaitingParticipant) {
		t.Fatalf("the left branch is still waiting, so the saga is not finished; got %v", err)
	}
	if got := state.Steps["st_right"].Status; got != saga.StepSealed {
		t.Fatalf("the answered branch must make progress while the other waits: "+
			"st_right is %s, want %s — a hosted coordinator that serialises "+
			"independent branches is a regression nothing else would catch",
			got, saga.StepSealed)
	}
	if got := state.Steps["st_left"].Status; got != saga.StepPrepared {
		t.Fatalf("st_left is %s, want %s: the step whose participant is silent should be "+
			"prepared and waiting, not skipped or failed", got, saga.StepPrepared)
	}
}

// TestAnInProcessProgramIsUnaffectedByTheWait guards the compatibility claim.
// Every Program written before Reporter existed must behave exactly as it did.
func TestAnInProcessProgramIsUnaffectedByTheWait(t *testing.T) {
	app, dir, _ := newRemoteLog(t)
	defer func() { _ = app.Close() }()

	coord := saga.NewCoordinator(runnerFor(app), localProgram{begin: twoBranchPlan()}).
		WithEvidenceDir(dir)

	state, err := coord.Drive(context.Background())
	if err != nil {
		t.Fatalf("a program that answers immediately should still run to commit: %v", err)
	}
	if state.Status != saga.StatusCommitted {
		t.Fatalf("saga is %s, want %s", state.Status, saga.StatusCommitted)
	}
}

// localProgram is the pre-Reporter shape: it always has its answer.
type localProgram struct{ begin *janusv1.SagaBegin }

func (p localProgram) Begin() *janusv1.SagaBegin { return p.begin }
func (p localProgram) Run(string, uint32) saga.StepOutcome {
	return saga.StepOutcome{Status: janusv1.Outcome_STATUS_OK}
}
func (p localProgram) Undo(string) janusv1.Outcome_Status { return janusv1.Outcome_STATUS_OK }

func twoBranchPlan() *janusv1.SagaBegin {
	return &janusv1.SagaBegin{
		SagaId: "sg_remote",
		Mode:   "supervised",
		Intent: &janusv1.Intent{
			IntentId:   "in_remote",
			Principal:  "acct_1",
			Originator: "human:desk@bank",
			MandateRef: "mandate:ops",
			Scope:      "two independent reads",
		},
		Plan: []*janusv1.PlannedStep{
			{StepId: "st_left", Participant: "tool_a", Action: "a.read",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
			{StepId: "st_right", Participant: "tool_b", Action: "b.read",
				EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
		},
	}
}

func runnerFor(app *evidence.Appender) *saga.Runner {
	return saga.NewRunner(app, evidence.ParticipantRef{
		ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: "acct_1", Kind: "AGENT",
	})
}

func newRemoteLog(t *testing.T) (*evidence.Appender, string, *keys.Signer) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	return app, dir, signer
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
