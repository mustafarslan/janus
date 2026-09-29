package saga_test

import (
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

// Compensation ordering is the kind of thing that looks right in review and
// fails under a shape nobody pictured — a diamond, a step that never ran, a
// branch that failed halfway. So the invariants are checked against generated
// plans rather than the handful of shapes I happened to think of.
//
// Every run prints its seed and JANUS_SEED pins it, so a failure found here is
// reproduced by copying one number.

func propSeed(t *testing.T) uint64 {
	t.Helper()
	if s := os.Getenv("JANUS_SEED"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatalf("JANUS_SEED=%q is not a number: %v", s, err)
		}
		return v
	}
	return uint64(time.Now().UnixNano())
}

// generatedPlan is a random but valid saga plan.
type generatedPlan struct {
	Seed  uint64
	Begin *janusv1.SagaBegin
	// Ran lists the steps that actually executed, in a legal order.
	Ran []string
	// Effectful says which steps left something behind.
	Effectful map[string]bool
}

func (g generatedPlan) String() string {
	return fmt.Sprintf("seed=%d steps=%d ran=%v", g.Seed, len(g.Begin.Plan), g.Ran)
}

// generatePlan builds a random acyclic plan and decides how far it got.
func generatePlan(rng *rand.Rand, seed uint64) generatedPlan {
	n := 2 + rng.IntN(7)
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("s%d", i)
	}

	begin := &janusv1.SagaBegin{SagaId: "sg_prop", Intent: &janusv1.Intent{IntentId: "in"}}
	effectful := map[string]bool{}

	for i, id := range ids {
		// Dependencies only point backwards, which keeps the plan acyclic by
		// construction while still producing chains, diamonds, and forests.
		var deps []string
		for j := range i {
			if rng.IntN(3) == 0 {
				deps = append(deps, ids[j])
			}
		}

		step := &janusv1.PlannedStep{StepId: id, DependsOn: deps}
		switch rng.IntN(4) {
		case 0:
			step.EffectClass = janusv1.EffectClass_EFFECT_CLASS_PURE
		case 1:
			step.EffectClass = janusv1.EffectClass_EFFECT_CLASS_REVERSIBLE
			step.CompensationAction = id + ".undo"
			effectful[id] = true
		default:
			step.EffectClass = janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE
			step.CompensationAction = id + ".undo"
			effectful[id] = true
		}
		begin.Plan = append(begin.Plan, step)
	}

	// Run a prefix of a legal execution order: some sagas fail early, some run
	// to completion before something else goes wrong.
	var ran []string
	done := map[string]bool{}
	budget := 1 + rng.IntN(n)
	for range n {
		if len(ran) >= budget {
			break
		}
		var ready []string
		for _, id := range ids {
			if done[id] {
				continue
			}
			ok := true
			for _, dep := range depsOf(begin, id) {
				if !done[dep] {
					ok = false
					break
				}
			}
			if ok {
				ready = append(ready, id)
			}
		}
		if len(ready) == 0 {
			break
		}
		pick := ready[rng.IntN(len(ready))]
		done[pick] = true
		ran = append(ran, pick)
	}

	return generatedPlan{Seed: seed, Begin: begin, Ran: ran, Effectful: effectful}
}

func depsOf(begin *janusv1.SagaBegin, id string) []string {
	for _, p := range begin.Plan {
		if p.GetStepId() == id {
			return p.GetDependsOn()
		}
	}
	return nil
}

// driveForward replays the plan up to the point it stopped.
func driveForward(t *testing.T, g generatedPlan) (saga.State, uint64) {
	t.Helper()
	gated := map[string]bool{}
	for _, p := range g.Begin.Plan {
		gated[p.GetStepId()] = p.GetEffectClass() != janusv1.EffectClass_EFFECT_CLASS_PURE
	}

	events := []saga.Event{ev(t, 1, evidence.KindSagaBegin, g.Begin)}
	seq := uint64(2)
	for _, id := range g.Ran {
		events = append(events,
			ev(t, seq, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg_prop", StepId: id}),
			ev(t, seq+1, evidence.KindStepResult, &janusv1.StepResult{
				SagaId: "sg_prop", StepId: id,
				Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			}),
		)
		seq += 2
		if gated[id] {
			events = append(events, ev(t, seq, evidence.KindGateVerdict, &janusv1.GateVerdict{
				SagaId: "sg_prop", StepId: id, Verdict: janusv1.Verdict_VERDICT_PASS,
			}))
			seq++
		}
	}
	s, err := saga.Replay(events)
	if err != nil {
		t.Fatalf("%s: driving forward: %v", g, err)
	}
	return s, seq
}

// TestPropertyCompensationUndoesEverythingInOrder is the core property loop.
func TestPropertyCompensationUndoesEverythingInOrder(t *testing.T) {
	base := propSeed(t)
	t.Logf("compensation property base seed %d (rerun with JANUS_SEED=%d)", base, base)

	rounds := 300
	if testing.Short() {
		rounds = 40
	}

	for i := range rounds {
		seed := base + uint64(i)
		rng := rand.New(rand.NewPCG(seed, 0x9E3779B97F4A7C15))
		g := generatePlan(rng, seed)

		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			s, seq := driveForward(t, g)

			s, err := saga.Apply(s, ev(t, seq, evidence.KindCompensate, &janusv1.Compensate{
				SagaId: "sg_prop", ReasonRef: "property test",
			}))
			if err != nil {
				t.Fatalf("%s: opening compensation: %v", g, err)
			}
			seq++

			// A saga with nothing live is finished immediately.
			if s.Status == saga.StatusCompensated {
				assertNothingOutstanding(t, g, s)
				return
			}
			if s.Status != saga.StatusCompensating {
				t.Fatalf("%s: saga is %s after COMPENSATE", g, s.Status)
			}

			undone := runCompensations(t, g, &s, &seq)

			// Closure: every effectful step that ran has been undone.
			for _, id := range g.Ran {
				if !g.Effectful[id] {
					continue
				}
				if !slices.Contains(undone, id) {
					t.Fatalf("%s: step %s left an effect that was never undone (order %v)", g, id, undone)
				}
			}
			// And nothing that did not run was undone.
			for _, id := range undone {
				if !slices.Contains(g.Ran, id) {
					t.Fatalf("%s: step %s was undone but never ran", g, id)
				}
			}

			assertReverseTopological(t, g, undone)
			assertNothingOutstanding(t, g, s)
			if !saga.Compensated(s) {
				t.Fatalf("%s: saga is %s, want fully compensated", g, s.Status)
			}
		})
	}
}

// runCompensations undoes everything the plan says to and returns the order it
// happened in.
//
// It follows plan.Order strictly — first entry, every time — rather than asking
// Next() for whatever is ready. That distinction matters: an earlier version of
// this test used Next(), which skips blocked steps and therefore silently
// corrected a wrong plan. It passed against a planner deliberately broken to
// emit forward order, because the state machine's own enforcement was doing the
// work. Driving strictly by Order is how a caller uses the planner, so it is
// what the test has to exercise; a wrong order now gets refused and the test
// fails.
func runCompensations(t *testing.T, g generatedPlan, s *saga.State, seq *uint64) []string {
	t.Helper()
	var undone []string

	for range len(g.Begin.Plan) + 1 {
		plan, err := saga.PlanCompensation(*s)
		if err != nil {
			t.Fatalf("%s: planning: %v", g, err)
		}
		if len(plan.Order) == 0 {
			break
		}
		assertPlanIsReverseTopological(t, g, plan)
		id := plan.Order[0]
		if blockers := plan.Blocked[id]; len(blockers) > 0 {
			t.Fatalf("%s: the planner put %s first but says it is blocked by %v; "+
				"a caller following the plan in order would stall", g, id, blockers)
		}

		next, err := saga.Apply(*s, ev(t, *seq, evidence.KindStepPrepare, &janusv1.StepPrepare{
			SagaId: "sg_prop", StepId: id + "~undo", Compensates: id,
		}))
		if err != nil {
			t.Fatalf("%s: preparing compensation of %s: %v", g, id, err)
		}
		*seq++
		next, err = saga.Apply(next, ev(t, *seq, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg_prop", StepId: id + "~undo",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}))
		if err != nil {
			t.Fatalf("%s: completing compensation of %s: %v", g, id, err)
		}
		*seq++
		*s = next
		undone = append(undone, id)
	}
	return undone
}

// assertPlanIsReverseTopological checks the planner's output directly, rather
// than only the order things ended up happening in.
func assertPlanIsReverseTopological(t *testing.T, g generatedPlan, plan saga.CompensationPlan) {
	t.Helper()
	pos := map[string]int{}
	for i, id := range plan.Order {
		pos[id] = i
	}
	for _, id := range plan.Order {
		for _, dep := range depsOf(g.Begin, id) {
			depPos, ok := pos[dep]
			if !ok {
				continue
			}
			if depPos < pos[id] {
				t.Fatalf("%s: plan undoes %s before %s, which depends on it: %v",
					g, dep, id, plan.Order)
			}
		}
	}
}

// assertReverseTopological is invariant I7: a step is never undone before
// something that depended on it.
func assertReverseTopological(t *testing.T, g generatedPlan, undone []string) {
	t.Helper()
	pos := map[string]int{}
	for i, id := range undone {
		pos[id] = i
	}
	for _, id := range undone {
		for _, dep := range depsOf(g.Begin, id) {
			depPos, ok := pos[dep]
			if !ok {
				continue // the dependency left nothing to undo
			}
			if depPos < pos[id] {
				t.Fatalf("%s: %s was undone before %s, which depended on it (order %v)",
					g, dep, id, undone)
			}
		}
	}
}

func assertNothingOutstanding(t *testing.T, g generatedPlan, s saga.State) {
	t.Helper()
	if left := saga.Outstanding(s); len(left) > 0 {
		t.Fatalf("%s: saga reports %v still outstanding after compensating", g, left)
	}
}

// TestPropertyFailedCompensationAlwaysQuarantines: whatever the shape and
// whichever compensation fails, the saga must freeze rather than carry on and
// leave a hole in the undo sequence.
func TestPropertyFailedCompensationAlwaysQuarantines(t *testing.T) {
	base := propSeed(t)
	t.Logf("quarantine property base seed %d (rerun with JANUS_SEED=%d)", base, base)

	rounds := 200
	if testing.Short() {
		rounds = 30
	}

	for i := range rounds {
		seed := base + uint64(i)
		rng := rand.New(rand.NewPCG(seed, 0x2545F4914F6CDD1D))
		g := generatePlan(rng, seed)

		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			s, seq := driveForward(t, g)
			s, err := saga.Apply(s, ev(t, seq, evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg_prop"}))
			if err != nil {
				t.Fatalf("%s: %v", g, err)
			}
			seq++
			if s.Status != saga.StatusCompensating {
				return // nothing to undo in this shape
			}

			plan, err := saga.PlanCompensation(s)
			if err != nil {
				t.Fatalf("%s: %v", g, err)
			}
			// Fail a randomly chosen one of the ready compensations.
			id, ok := plan.Next()
			if !ok {
				t.Fatalf("%s: nothing ready to compensate", g)
			}

			s, err = saga.Apply(s, ev(t, seq, evidence.KindStepPrepare, &janusv1.StepPrepare{
				SagaId: "sg_prop", StepId: id + "~undo", Compensates: id,
			}))
			if err != nil {
				t.Fatalf("%s: %v", g, err)
			}
			seq++
			s, err = saga.Apply(s, ev(t, seq, evidence.KindStepResult, &janusv1.StepResult{
				SagaId: "sg_prop", StepId: id + "~undo",
				Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_TERMINAL_ERROR},
			}))
			if err != nil {
				t.Fatalf("%s: %v", g, err)
			}
			seq++

			if s.Status != saga.StatusQuarantine {
				t.Fatalf("%s: saga is %s after a failed compensation of %s, want QUARANTINE", g, s.Status, id)
			}
			if s.QuarantineReason == "" {
				t.Fatalf("%s: quarantine gives no reason", g)
			}
			// The handover note must name the failed step and everything still
			// live, or whoever picks it up cannot tell what is left.
			if !slices.Contains(s.Outstanding, id) {
				t.Fatalf("%s: outstanding %v does not name the failed step %s", g, s.Outstanding, id)
			}
			for _, other := range g.Ran {
				if g.Effectful[other] && other != id && !slices.Contains(s.Outstanding, other) {
					if s.Steps[other].Compensation == saga.CompDone {
						continue
					}
					t.Fatalf("%s: %s still has an effect but is not in outstanding %v", g, other, s.Outstanding)
				}
			}
			// And nothing may proceed afterwards.
			if _, err := saga.Apply(s, ev(t, seq, evidence.KindStepPrepare, &janusv1.StepPrepare{
				SagaId: "sg_prop", StepId: "anything~undo", Compensates: id,
			})); err == nil {
				t.Fatalf("%s: compensation continued after quarantine", g)
			}
		})
	}
}

// TestPropertyCompensationReplaysIdentically: the undo phase is evidence, and
// replaying it must land in the same place (invariant I5).
func TestPropertyCompensationReplaysIdentically(t *testing.T) {
	base := propSeed(t)
	t.Logf("replay property base seed %d (rerun with JANUS_SEED=%d)", base, base)

	rounds := 150
	if testing.Short() {
		rounds = 25
	}

	for i := range rounds {
		seed := base + uint64(i)
		rng := rand.New(rand.NewPCG(seed, 0x94D049BB133111EB))
		g := generatePlan(rng, seed)

		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			// Build the whole history, forward and undo, as an event list.
			gated := map[string]bool{}
			for _, p := range g.Begin.Plan {
				gated[p.GetStepId()] = p.GetEffectClass() != janusv1.EffectClass_EFFECT_CLASS_PURE
			}
			events := []saga.Event{ev(t, 1, evidence.KindSagaBegin, g.Begin)}
			seq := uint64(2)
			for _, id := range g.Ran {
				events = append(events,
					ev(t, seq, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg_prop", StepId: id}),
					ev(t, seq+1, evidence.KindStepResult, &janusv1.StepResult{
						SagaId: "sg_prop", StepId: id,
						Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
					}))
				seq += 2
				if gated[id] {
					events = append(events, ev(t, seq, evidence.KindGateVerdict, &janusv1.GateVerdict{
						SagaId: "sg_prop", StepId: id, Verdict: janusv1.Verdict_VERDICT_PASS,
					}))
					seq++
				}
			}
			events = append(events, ev(t, seq, evidence.KindCompensate, &janusv1.Compensate{SagaId: "sg_prop"}))
			seq++

			s, err := saga.Replay(events)
			if err != nil {
				t.Fatalf("%s: %v", g, err)
			}
			for s.Status == saga.StatusCompensating {
				plan, err := saga.PlanCompensation(s)
				if err != nil || len(plan.Order) == 0 {
					break
				}
				id, ok := plan.Next()
				if !ok {
					break
				}
				events = append(events,
					ev(t, seq, evidence.KindStepPrepare, &janusv1.StepPrepare{
						SagaId: "sg_prop", StepId: id + "~undo", Compensates: id,
					}),
					ev(t, seq+1, evidence.KindStepResult, &janusv1.StepResult{
						SagaId: "sg_prop", StepId: id + "~undo",
						Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
					}))
				seq += 2
				if s, err = saga.Replay(events); err != nil {
					t.Fatalf("%s: %v", g, err)
				}
			}

			first, err := saga.Replay(events)
			if err != nil {
				t.Fatalf("%s: %v", g, err)
			}
			for round := range 5 {
				again, err := saga.Replay(events)
				if err != nil {
					t.Fatalf("%s: replay %d: %v", g, round, err)
				}
				if diff := saga.Diff(first, again); len(diff) > 0 {
					t.Fatalf("%s: replay %d diverged: %v", g, round, diff)
				}
			}
		})
	}
}
