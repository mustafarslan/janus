package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/saga"
)

// participant is who this benchmark writes as. The measurements are about the
// decision path, not about identity, but every event carries one and an empty
// ref would be refused.
var participant = evidence.ParticipantRef{
	ID: "ag_latency", ManifestVersion: "1.0.0", Principal: "pr_latency",
}

// wire is a one-step saga whose step is IRREVERSIBLE_GATED, which is what the
// reference policy attaches its whole gate stack to: SCHEMA, two POLICY gates
// and RISK_LIMIT at PRE_EXECUTION, then POLICY and FRONTIER at PRE_RELEASE.
//
// One step rather than several because the unit S4 budgets is one gated side
// effect. A longer plan would measure the same decision several times and
// report the sum as if it were the per-effect cost.
type wire struct {
	sagaID   string
	resource string
}

// engine is the gate engine every saga here is admitted under. It is a package
// variable for the same reason it is one in janus-sagachaos: admission has to
// happen inside Begin, which has no error return and nothing to thread through.
var engine *gate.Engine

// Begin returns the saga to start, with its gate plan already resolved.
//
// `Admit` is what attaches the policy's requirements to the planned step, and
// without it the step reaches the coordinator with no gates on it at all — a
// benchmark of an ungated effect, reported as if it were the gated one. It is
// called here rather than once at start-up because it mutates the message, and
// Begin must hand out a fresh one each time.
//
// Panicking on refusal is right: `run` admits the same plan before any timing
// starts, so a refusal at this point is a bug in the benchmark and not a
// property of the deployment.
func (w wire) Begin() *janusv1.SagaBegin {
	b := &janusv1.SagaBegin{
		SagaId: w.sagaID,
		Intent: &janusv1.Intent{
			IntentId: "in_" + w.sagaID,
			// The reference policy refuses an irreversible payment with no
			// mandate behind it, so this is load-bearing rather than filler.
			MandateRef: "mandate:" + w.sagaID,
			Principal:  participant.Principal,
			Scope:      "payments",
		},
		Mode: "supervised",
		Plan: []*janusv1.PlannedStep{{
			StepId: "wire", Participant: participant.ID, Action: "wire_transfer",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		}},
	}
	if err := engine.Admit(b); err != nil {
		panic(fmt.Sprintf("the benchmark's saga is not admissible: %v", err))
	}
	return b
}

// Run returns instantly and always succeeds.
//
// That is the point: with a participant that costs nothing, the time a step
// takes *is* the latency Janus added, which is what the budget
// is for.
// A participant that did real work would fold its own latency into the number
// and make the result unattributable.
func (w wire) Run(string, uint32) saga.StepOutcome {
	return saga.StepOutcome{
		Status: janusv1.Outcome_STATUS_OK,
		Touches: []*janusv1.ResourceTouch{
			{ResourceId: w.resource, Mode: janusv1.ResourceTouch_MODE_WRITE},
		},
	}
}

func (w wire) Facts(string, uint32) map[string]saga.FactValue {
	return map[string]saga.FactValue{
		"amount_minor": gate.Number(250000),
		"currency":     gate.Text("EUR"),
		"counterparty": gate.Text("cp_" + w.sagaID),
		"approved":     gate.Flag(true),
	}
}

func (w wire) Undo(string) janusv1.Outcome_Status { return janusv1.Outcome_STATUS_OK }

// timedKeeper wraps a gatekeeper and records how long each decision took,
// bucketed by phase.
//
// It wraps rather than reimplements because a benchmark that measured its own
// copy of the decision path would report a number about the copy. Every gate
// this times is the gate a deployment runs, reached through the same interface
// the coordinator calls.
type timedKeeper struct {
	inner saga.Gatekeeper

	mu  sync.Mutex
	obs map[janusv1.GatePhase][]time.Duration
	// fewest is the smallest number of requirements any single decision at
	// this phase actually judged.
	//
	// It is here because the most likely way this benchmark lies is by being
	// fast for the wrong reason. A plan that reached the coordinator with its
	// gate requirements missing — an `Admit` that silently did nothing, a
	// policy edited so its rule no longer matches — decides nothing, returns
	// almost instantly, and passes both budgets comfortably. Reporting the
	// count alongside the timing makes that visible instead of flattering:
	// a zero here means the number next to it is meaningless.
	fewest map[janusv1.GatePhase]int
}

func newTimedKeeper(inner saga.Gatekeeper) *timedKeeper {
	return &timedKeeper{
		inner:  inner,
		obs:    map[janusv1.GatePhase][]time.Duration{},
		fewest: map[janusv1.GatePhase]int{},
	}
}

func (k *timedKeeper) Decide(phase janusv1.GatePhase, s saga.State, st *saga.Step,
	declared map[string]saga.FactValue) (*janusv1.GateVerdict, *janusv1.DecisionProvenanceRecord, error) {

	t0 := time.Now()
	v, d, err := k.inner.Decide(phase, s, st, declared)
	took := time.Since(t0)

	k.mu.Lock()
	k.obs[phase] = append(k.obs[phase], took)
	if n := len(v.GetDecided()); err == nil {
		if cur, seen := k.fewest[phase]; !seen || n < cur {
			k.fewest[phase] = n
		}
	}
	k.mu.Unlock()
	return v, d, err
}

// take returns the observations for one phase and forgets them, so a caller
// measuring several configurations against one keeper does not carry the
// previous configuration's samples into the next one's percentiles.
func (k *timedKeeper) take(phase janusv1.GatePhase) ([]time.Duration, int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	out, fewest := k.obs[phase], k.fewest[phase]
	k.obs[phase] = nil
	delete(k.fewest, phase)
	return out, fewest
}

// seed fills the log with committed sagas so that the index a frontier gate
// builds has something to read.
//
// They are committed rather than left in flight because a settled touch is what
// a realistic background looks like: a log accumulates finished work, and an
// unsettled one would block every subject saga at the frontier gate and measure
// a stall instead of a decision.
//
// Resources are drawn from a pool the subjects also draw from, so the projection
// index — which reads only the sagas touching the subject's own resources —
// does real work rather than matching nothing. The pool size is the knob: a
// large pool makes the two index implementations diverge fastest, a small one
// makes them converge.
func seed(ctx context.Context, app *evidence.Appender, dir string, n, pool int,
	keeper saga.Gatekeeper) error {

	for i := range n {
		w := wire{
			sagaID:   fmt.Sprintf("sg_bg_%06d", i),
			resource: fmt.Sprintf("acct:%04d", i%pool),
		}
		c, err := saga.ResumeSaga(app, dir, w.sagaID, participant, w)
		if err != nil {
			return err
		}
		s, err := c.WithGatekeeper(keeper).Drive(ctx)
		if err != nil {
			return fmt.Errorf("seed saga %s: %w", w.sagaID, err)
		}
		if s.Status != saga.StatusCommitted {
			return fmt.Errorf("seed saga %s is %s, want COMMITTED — the background "+
				"has to be settled or every subject stalls at the frontier gate",
				w.sagaID, s.Status)
		}
	}
	return nil
}
