package console_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/console"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/saga"
)

// ---------------------------------------------------------------------------
// a log with a payment stuck at a four-eyes gate
// ---------------------------------------------------------------------------

const (
	testSaga      = "sg_console_0001"
	testStep      = "st_wire"
	testPrincipal = "pr_treasury"
	fourEyesReq   = "wire-four-eyes"
	secondOpinion = "wire-second-opinion"
)

// policy gates a large wire on two named validators and two people who are not
// the initiator — the shape the reference policy uses, small enough to read.
func policy(t *testing.T) *gate.Policy {
	t.Helper()
	p := &gate.Policy{
		ID: "console.test",
		Rules: []gate.Rule{{
			ID:    "large-wires",
			Match: gate.Match{EffectClasses: []string{"IRREVERSIBLE_GATED"}},
			Require: []gate.Requirement{
				{
					ID: secondOpinion, Gate: gate.GateValidator, Phase: gate.PhasePreRelease,
					Validator: &gate.ValidatorSpec{
						Validators: []string{"ag_credit_policy"}, Quorum: 1,
					},
				},
				{
					ID: fourEyesReq, Gate: gate.GateHuman, Phase: gate.PhasePreRelease,
					Human: &gate.HumanSpec{
						Roles:            []string{"credit-officer", "treasury-approver"},
						Quorum:           2,
						SeparationOfDuty: true,
					},
				},
			},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	return p
}

// program runs one irreversible step and answers nothing, so the saga reaches
// its gates and stops there — which is the state a console exists to show.
type program struct {
	begin  *janusv1.SagaBegin
	answer func(stepID string, attempt uint32, requirementID string) *janusv1.GateAnswer
}

func (p program) Begin() *janusv1.SagaBegin { return p.begin }

func (p program) Run(string, uint32) saga.StepOutcome {
	return saga.StepOutcome{Status: janusv1.Outcome_STATUS_OK}
}

func (p program) Undo(string) janusv1.Outcome_Status { return janusv1.Outcome_STATUS_OK }

func (p program) Facts(string, uint32) map[string]saga.FactValue {
	return map[string]saga.FactValue{
		"amount_minor": gate.Number(2_500_000),
		"currency":     gate.Text("EUR"),
		"counterparty": gate.Text("DE89370400440532013000"),
	}
}

func (p program) Answer(stepID string, attempt uint32, requirementID string) *janusv1.GateAnswer {
	if p.answer == nil {
		return nil
	}
	return p.answer(stepID, attempt, requirementID)
}

// validatorAgrees is the opinion the independent validator gives, so that the
// human gate becomes the thing the saga is waiting on. Without it the
// composition stops at the validator and never reaches the people.
func validatorAgrees(_ string, _ uint32, requirementID string) *janusv1.GateAnswer {
	if requirementID != secondOpinion {
		return nil
	}
	return &janusv1.GateAnswer{
		Actor:   &janusv1.Actor{Participant: &janusv1.ParticipantRef{Id: "ag_credit_policy"}},
		Verdict: janusv1.Verdict_VERDICT_PASS,
		Reason:  "within the mandate",
	}
}

// waitingLog builds an evidence directory holding one saga stopped at its
// gates, and returns the directory and the writer key set.
func waitingLog(t *testing.T, answer func(string, uint32, string) *janusv1.GateAnswer) (string, keys.PublicKeySet) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}

	begin := &janusv1.SagaBegin{
		SagaId: testSaga,
		Mode:   "supervised",
		Intent: &janusv1.Intent{
			IntentId:   "in_console",
			Principal:  testPrincipal,
			Originator: "human:desk@bank",
			MandateRef: "mandate:payments",
			Scope:      "settle one invoice",
		},
		Plan: []*janusv1.PlannedStep{{
			StepId:      testStep,
			Participant: "tool_payments",
			Action:      "payments.wire.large",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
		ManifestPins: map[string]string{"tool_payments": "1.0.0"},
	}
	engine := gate.NewEngine(policy(t))
	if err := engine.Admit(begin); err != nil {
		t.Fatalf("the test plan is not admissible: %v", err)
	}

	runner := saga.NewRunner(app, evidence.ParticipantRef{
		ID: "ag_coordinator", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
	})
	coord := saga.NewCoordinator(runner, program{begin: begin, answer: answer}).
		WithGatekeeper(gate.NewKeeper(gate.IndexFromLog(dir)))

	_, err = coord.Drive(context.Background())
	if !errors.Is(err, saga.ErrWaiting) {
		t.Fatalf("the saga did not stop at its gates: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, keys.PublicKeySet{signer.KeyID(): signer.Public()}
}

// ---------------------------------------------------------------------------
// topology
// ---------------------------------------------------------------------------

func TestTheOverviewCountsWhatNeedsAttention(t *testing.T) {
	dir, _ := waitingLog(t, nil)

	o, err := console.Open(dir).Overview()
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Sagas) != 1 {
		t.Fatalf("the overview shows %d sagas", len(o.Sagas))
	}
	if o.Waiting != 1 {
		t.Fatalf("the overview reports %d waiting steps, want 1; a console whose front page "+
			"does not surface a stuck payment is a list", o.Waiting)
	}
	row := o.Sagas[0]
	if row.SagaID != testSaga || row.Principal != testPrincipal {
		t.Fatalf("row: %+v", row)
	}
}

func TestASagaShowsWhatItIsWaitingForAndWhy(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)

	d, err := console.Open(dir).Saga(testSaga)
	if err != nil {
		t.Fatal(err)
	}
	if d.MandateRef != "mandate:payments" || d.Scope != "settle one invoice" {
		t.Fatalf("the page does not carry the authority the saga acts under: %+v", d)
	}
	if d.PolicyVersion == "" {
		t.Fatal("the page does not pin the gate policy the saga was admitted under")
	}
	if len(d.Steps) != 1 {
		t.Fatalf("%d steps", len(d.Steps))
	}
	step := d.Steps[0]
	if step.EffectClass != "IRREVERSIBLE_GATED" {
		t.Fatalf("effect class shown as %q", step.EffectClass)
	}
	if len(step.Gates) != 2 {
		t.Fatalf("%d gates shown, want the two the saga was admitted under", len(step.Gates))
	}

	var human *console.GateView
	for i := range step.Gates {
		if step.Gates[i].RequirementID == fourEyesReq {
			human = &step.Gates[i]
		}
	}
	if human == nil {
		t.Fatal("the four-eyes gate is not shown")
	}
	if human.Verdict != "ESCALATE" {
		t.Fatalf("the four-eyes gate reads %q, want ESCALATE", human.Verdict)
	}
	if !strings.Contains(human.Reason, "approval") {
		t.Fatalf("the gate does not say what it is waiting for: %q", human.Reason)
	}
	if human.Detail == "" || human.Reason == "" {
		t.Fatalf("the gate says neither what it asks for nor why it is waiting: %+v", human)
	}
	if !human.Human || !human.External {
		t.Fatalf("the four-eyes gate is not marked answerable by a person: %+v", human)
	}

	// The pin is resolved against a registry that has never heard of this
	// participant, and the page has to say so rather than leaving it blank.
	if len(d.Pins) != 1 || !d.Pins[0].Unresolved {
		t.Fatalf("pins: %+v — an unresolvable pin must be visible, not silent", d.Pins)
	}
}

// ---------------------------------------------------------------------------
// the queue
// ---------------------------------------------------------------------------

func TestTheQueueShowsWhatAPersonMustDecide(t *testing.T) {
	dir, _ := waitingLog(t, validatorAgrees)

	q, err := console.Open(dir).Queue()
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Items) != 1 {
		t.Fatalf("%d items in the queue, want 1", len(q.Items))
	}
	item := q.Items[0]
	if item.SagaID != testSaga || item.StepID != testStep {
		t.Fatalf("item: %+v", item)
	}
	if item.Initiator != testPrincipal {
		t.Fatalf("the queue does not name who the saga was raised for, so nobody can see "+
			"whether approving it would be a self-approval: %+v", item)
	}
	if item.Facts["amount_minor"] != "2500000" {
		t.Fatalf("the queue does not show what is being approved: %+v", item.Facts)
	}
	if !item.Answerable {
		t.Fatal("the item is not marked answerable, though a human gate is outstanding")
	}

	// The validator has agreed, so the only thing outstanding is the people.
	if len(item.Outstanding) != 1 || !item.Outstanding[0].Human {
		t.Fatalf("outstanding: %+v", item.Outstanding)
	}
}

// TestAValidatorGateIsShownButNotOfferedToAPerson. It is why nothing is moving,
// so an operator has to see it; it is answered by the participants it names
// under their own identities, so nobody may sign it off from a screen.
func TestAValidatorGateIsShownButNotOfferedToAPerson(t *testing.T) {
	dir, _ := waitingLog(t, nil)

	q, err := console.Open(dir).Queue()
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Items) != 1 {
		t.Fatalf("%d items in the queue", len(q.Items))
	}
	var humans, validators int
	for _, g := range q.Items[0].Outstanding {
		if g.Human {
			humans++
		} else {
			validators++
		}
	}
	if humans != 1 || validators != 1 {
		t.Fatalf("outstanding: %d human, %d validator — both belong on the screen", humans, validators)
	}
}

// TestTheQueueDoesNotInventWaiting. A queue that listed steps no coordinator
// had reached would invite people to approve things that are not being asked.
func TestTheQueueDoesNotInventWaiting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A saga that begins carrying a human gate, and nothing else. No
	// coordinator has evaluated anything.
	begin := &janusv1.SagaBegin{
		SagaId: "sg_unstarted",
		Mode:   "supervised",
		Intent: &janusv1.Intent{IntentId: "in_x", Principal: testPrincipal},
		Plan: []*janusv1.PlannedStep{{
			StepId: "st_x", Participant: "tool_payments", Action: "payments.wire.large",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	}
	if err := gate.NewEngine(policy(t)).Admit(begin); err != nil {
		t.Fatal(err)
	}
	runner := saga.NewRunner(app, evidence.ParticipantRef{ID: "ag_x", Kind: "AGENT"})
	if _, err := runner.Begin(context.Background(), begin); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	q, err := console.Open(dir).Queue()
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Items) != 0 {
		t.Fatalf("the queue offers %d step(s) for approval that no coordinator has gated", len(q.Items))
	}
}

// finish resumes the saga and drives it to a terminal state, the way the
// coordinator that owns it would after an answer arrives.
//
// It is a separate process from the console in a real deployment, which is why
// the console had to close the log before this can open it: one writer per
// evidence directory (evidence.ErrLocked).
func finish(t *testing.T, dir string) saga.State {
	t.Helper()
	app, err := evidence.Open(evidence.Options{Dir: dir, SyncMode: segment.SyncModeNone})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	state, err := saga.ReplaySaga(dir, testSaga)
	if err != nil {
		t.Fatal(err)
	}
	runner := saga.NewRunner(app, evidence.ParticipantRef{
		ID: "ag_coordinator", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
	})
	// The program's Begin is only consulted when the log is empty, which it is
	// not; a resumed coordinator takes the saga from the record.
	coord := saga.NewCoordinator(runner, program{answer: validatorAgrees}).
		WithGatekeeper(gate.NewKeeper(gate.IndexFromLog(dir)))
	coord.Resume(state)

	final, err := coord.Drive(context.Background())
	if err != nil {
		t.Fatalf("driving the saga after the approvals failed: %v", err)
	}
	return final
}
