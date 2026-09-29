package saga_test

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/saga"
)

// touchingSaga builds a one-step saga that touches a resource, driven to SEALED.
// startSeq controls where its touch lands in the global order, which is what
// decides who was first.
func touchingSaga(t *testing.T, sagaID, resource string, mode janusv1.ResourceTouch_Mode, startSeq uint64) saga.State {
	t.Helper()
	begin := &janusv1.SagaBegin{
		SagaId: sagaID,
		Plan: []*janusv1.PlannedStep{{
			StepId:             "st",
			EffectClass:        janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: "undo",
		}},
	}
	events := []saga.Event{
		ev(t, startSeq, evidence.KindSagaBegin, begin),
		ev(t, startSeq+1, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: sagaID, StepId: "st"}),
		ev(t, startSeq+2, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: sagaID, StepId: "st",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			Touches: []*janusv1.ResourceTouch{{ResourceId: resource, Mode: mode}},
		}),
		ev(t, startSeq+3, evidence.KindGateVerdict, &janusv1.GateVerdict{
			SagaId: sagaID, StepId: "st", Verdict: janusv1.Verdict_VERDICT_PASS,
		}),
	}
	s, err := saga.Replay(events)
	if err != nil {
		t.Fatalf("building %s: %v", sagaID, err)
	}
	return s
}

// finish drives a sealed saga to a terminal state.
func finish(t *testing.T, s saga.State, seq uint64, commit bool) saga.State {
	t.Helper()
	var err error
	if commit {
		s, err = saga.Apply(s, ev(t, seq, evidence.KindSealRequest, &janusv1.SealRequest{
			SagaId: s.SagaID, Frontiers: claimsFor(s),
		}))
		if err != nil {
			t.Fatal(err)
		}
		s, err = saga.Apply(s, ev(t, seq+1, evidence.KindCommit, &janusv1.Commit{SagaId: s.SagaID}))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s, err = saga.Apply(s, ev(t, seq, evidence.KindCompensate, &janusv1.Compensate{SagaId: s.SagaID}))
	if err != nil {
		t.Fatal(err)
	}
	for s.Status == saga.StatusCompensating {
		plan, perr := saga.PlanCompensation(s)
		if perr != nil || len(plan.Order) == 0 {
			break
		}
		id := plan.Order[0]
		seq++
		s, err = saga.Apply(s, ev(t, seq, evidence.KindStepPrepare, &janusv1.StepPrepare{
			SagaId: s.SagaID, StepId: id + "~undo", Compensates: id,
		}))
		if err != nil {
			t.Fatal(err)
		}
		seq++
		s, err = saga.Apply(s, ev(t, seq, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: s.SagaID, StepId: id + "~undo",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		}))
		if err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func claimsFor(s saga.State) []*janusv1.FrontierClaim {
	var out []*janusv1.FrontierClaim
	for _, r := range saga.TouchedResources(s) {
		out = append(out, &janusv1.FrontierClaim{ResourceId: r})
	}
	return out
}

// TestLaterSagaWaitsForAnUnfinishedEarlierOne is invariant I6. Committing over
// work that may still be reversed would rest the later saga on a fact that can
// be withdrawn — and nothing in its own evidence would show anything wrong.
func TestLaterSagaWaitsForAnUnfinishedEarlierOne(t *testing.T) {
	first := touchingSaga(t, "sg_first", "acct:1", janusv1.ResourceTouch_MODE_WRITE, 10)
	second := touchingSaga(t, "sg_second", "acct:1", janusv1.ResourceTouch_MODE_READ, 100)

	ix := saga.NewIndex(first, second)

	ok, blockers := ix.MayCommit("sg_second")
	if ok {
		t.Fatal("the later saga was cleared to commit while the earlier one is still running")
	}
	if len(blockers) != 1 {
		t.Fatalf("got %d blockers, want 1: %v", len(blockers), blockers)
	}
	if blockers[0].BlockingSaga != "sg_first" || blockers[0].Resource != "acct:1" {
		t.Fatalf("blocker names the wrong thing: %+v", blockers[0])
	}
	if blockers[0].Reason == "" {
		t.Fatal("blocker gives no reason an operator could act on")
	}

	// The earlier saga is not blocked by the later one.
	if ok, b := ix.MayCommit("sg_first"); !ok {
		t.Fatalf("the earlier saga was blocked by later work: %v", b)
	}

	// Once the first finishes, the second is clear.
	ix.Add(finish(t, first, 20, true))
	if ok, b := ix.MayCommit("sg_second"); !ok {
		t.Fatalf("the later saga is still blocked after the earlier one committed: %v", b)
	}
}

// TestCompensatedEarlierSagaAlsoClears: finishing by undoing is still finishing.
func TestCompensatedEarlierSagaAlsoClears(t *testing.T) {
	first := touchingSaga(t, "sg_first", "acct:1", janusv1.ResourceTouch_MODE_WRITE, 10)
	second := touchingSaga(t, "sg_second", "acct:1", janusv1.ResourceTouch_MODE_WRITE, 100)

	ix := saga.NewIndex(finish(t, first, 20, false), second)
	if ok, b := ix.MayCommit("sg_second"); !ok {
		t.Fatalf("a compensated predecessor still blocks: %v", b)
	}
}

// TestQuarantineBlocksIndefinitely: a frozen saga is not finished. Its effects
// are still in the world and nobody has decided what to do about them, so
// letting later work commit over them would build on a state a human has
// explicitly not signed off.
func TestQuarantineBlocksIndefinitely(t *testing.T) {
	first := touchingSaga(t, "sg_first", "acct:1", janusv1.ResourceTouch_MODE_WRITE, 10)
	stuck, err := saga.Apply(first, ev(t, 20, evidence.KindQuarantine, &janusv1.Quarantine{
		SagaId: "sg_first", Reason: "compensation failed",
	}))
	if err != nil {
		t.Fatal(err)
	}
	second := touchingSaga(t, "sg_second", "acct:1", janusv1.ResourceTouch_MODE_WRITE, 100)

	ix := saga.NewIndex(stuck, second)
	ok, blockers := ix.MayCommit("sg_second")
	if ok {
		t.Fatal("a quarantined saga did not hold the frontier")
	}
	if blockers[0].BlockingStatus != saga.StatusQuarantine {
		t.Fatalf("blocker status is %s, want QUARANTINE", blockers[0].BlockingStatus)
	}
	// The reason must tell an operator this will not clear on its own.
	if !strings.Contains(blockers[0].Reason, "human") {
		t.Fatalf("the reason does not say a human is needed: %s", blockers[0].Reason)
	}
}

// TestTwoReadsDoNotConflict: neither changes anything, so their order is
// immaterial and making them wait would be pure contention for no safety.
func TestTwoReadsDoNotConflict(t *testing.T) {
	first := touchingSaga(t, "sg_first", "acct:1", janusv1.ResourceTouch_MODE_READ, 10)
	second := touchingSaga(t, "sg_second", "acct:1", janusv1.ResourceTouch_MODE_READ, 100)

	ix := saga.NewIndex(first, second)
	if ok, b := ix.MayCommit("sg_second"); !ok {
		t.Fatalf("two readers blocked each other: %v", b)
	}
}

func TestDifferentResourcesDoNotConflict(t *testing.T) {
	first := touchingSaga(t, "sg_first", "acct:1", janusv1.ResourceTouch_MODE_WRITE, 10)
	second := touchingSaga(t, "sg_second", "acct:2", janusv1.ResourceTouch_MODE_WRITE, 100)

	ix := saga.NewIndex(first, second)
	if ok, b := ix.MayCommit("sg_second"); !ok {
		t.Fatalf("sagas on unrelated resources blocked each other: %v", b)
	}
}

// TestUnknownSagaIsNotAssumedFinished: treating an absent saga as settled would
// make a safety property depend on how complete the index happens to be.
func TestUnknownSagaIsNotAssumedFinished(t *testing.T) {
	second := touchingSaga(t, "sg_second", "acct:1", janusv1.ResourceTouch_MODE_WRITE, 100)
	// The index knows about the later saga but not the earlier one, whose touch
	// is nonetheless visible through its own record.
	first := touchingSaga(t, "sg_first", "acct:1", janusv1.ResourceTouch_MODE_WRITE, 10)

	full := saga.NewIndex(first, second)
	if ok, _ := full.MayCommit("sg_second"); ok {
		t.Fatal("an unfinished predecessor did not block")
	}
}

// TestFrontierStopsAtTheFirstUnfinishedTouch: a watermark that jumped over a
// saga still in flight would claim the resource is clear up to a point a later
// reversal could invalidate.
func TestFrontierStopsAtTheFirstUnfinishedTouch(t *testing.T) {
	done := finish(t, touchingSaga(t, "sg_a", "acct:1", janusv1.ResourceTouch_MODE_WRITE, 10), 20, true)
	running := touchingSaga(t, "sg_b", "acct:1", janusv1.ResourceTouch_MODE_WRITE, 100)
	later := finish(t, touchingSaga(t, "sg_c", "acct:1", janusv1.ResourceTouch_MODE_WRITE, 200), 210, true)

	ix := saga.NewIndex(done, running, later)

	// sg_a's touch is at 12 (begin+prepare+result). The frontier must stop
	// there and not advance past the running saga to sg_c's touch.
	got := ix.Frontier("acct:1")
	if got != 12 {
		t.Fatalf("frontier is %d, want it to stop at the last settled touch before the running saga", got)
	}

	// Once the running saga finishes, the watermark moves past both.
	ix.Add(finish(t, running, 150, true))
	if got := ix.Frontier("acct:1"); got != 202 {
		t.Fatalf("frontier is %d after the blocker finished, want it to advance to the last touch", got)
	}
}

// TestSealMustClaimEveryResourceTouched: a claim set that misses a resource
// would seal a footprint smaller than the saga actually has, and the safety
// check downstream would then be asking about the wrong set.
func TestSealMustClaimEveryResourceTouched(t *testing.T) {
	begin := &janusv1.SagaBegin{
		SagaId: "sg",
		Plan: []*janusv1.PlannedStep{{
			StepId: "st", EffectClass: janusv1.EffectClass_EFFECT_CLASS_COMPENSABLE,
			CompensationAction: "undo",
		}},
	}
	s, err := saga.Replay([]saga.Event{
		ev(t, 1, evidence.KindSagaBegin, begin),
		ev(t, 2, evidence.KindStepPrepare, &janusv1.StepPrepare{SagaId: "sg", StepId: "st"}),
		ev(t, 3, evidence.KindStepResult, &janusv1.StepResult{
			SagaId: "sg", StepId: "st",
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
			Touches: []*janusv1.ResourceTouch{
				{ResourceId: "acct:1", Mode: janusv1.ResourceTouch_MODE_WRITE},
				{ResourceId: "acct:2", Mode: janusv1.ResourceTouch_MODE_READ},
			},
		}),
		ev(t, 4, evidence.KindGateVerdict, &janusv1.GateVerdict{
			SagaId: "sg", StepId: "st", Verdict: janusv1.Verdict_VERDICT_PASS,
		}),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Claiming only one of the two resources is refused.
	_, err = saga.Apply(s, ev(t, 5, evidence.KindSealRequest, &janusv1.SealRequest{
		SagaId: "sg", Frontiers: []*janusv1.FrontierClaim{{ResourceId: "acct:1"}},
	}))
	if err == nil {
		t.Fatal("a seal claiming only some of the touched resources was accepted")
	}

	// Claiming both succeeds and the claims are recorded.
	sealed, err := saga.Apply(s, ev(t, 5, evidence.KindSealRequest, &janusv1.SealRequest{
		SagaId: "sg",
		Frontiers: []*janusv1.FrontierClaim{
			{ResourceId: "acct:1", LastSealedSeq: 7},
			{ResourceId: "acct:2", LastSealedSeq: 9},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Frontiers["acct:1"] != 7 || sealed.Frontiers["acct:2"] != 9 {
		t.Fatalf("claims were not recorded: %v", sealed.Frontiers)
	}
}

// TestClaimsCoverEverythingTouched: the helper that builds claims must not miss
// a resource, or a caller using it would produce exactly the seal the check
// above rejects.
func TestClaimsCoverEverythingTouched(t *testing.T) {
	s := touchingSaga(t, "sg", "acct:1", janusv1.ResourceTouch_MODE_WRITE, 10)
	ix := saga.NewIndex(s)

	claims := ix.Claims("sg")
	if len(claims) != 1 || claims[0].GetResourceId() != "acct:1" {
		t.Fatalf("claims are %v, want one for acct:1", claims)
	}
	if _, err := saga.Apply(s, ev(t, 20, evidence.KindSealRequest, &janusv1.SealRequest{
		SagaId: "sg", Frontiers: claims,
	})); err != nil {
		t.Fatalf("claims produced by the index were rejected by the seal check: %v", err)
	}
}

// TestPropertyFrontierSafety generates interleaved sagas and checks the
// invariant that matters: nothing is ever cleared to commit while a conflicting
// earlier touch belongs to a saga that has not finished.
func TestPropertyFrontierSafety(t *testing.T) {
	base := propSeed(t)
	t.Logf("frontier property base seed %d (rerun with JANUS_SEED=%d)", base, base)

	rounds := 200
	if testing.Short() {
		rounds = 30
	}

	for i := range rounds {
		seed := base + uint64(i)
		rng := rand.New(rand.NewPCG(seed, 0xA24BAED4963EE407))

		t.Run(fmt.Sprintf("seed_%d", seed), func(t *testing.T) {
			resources := []string{"acct:1", "acct:2", "acct:3"}
			nSagas := 2 + rng.IntN(5)

			var states []saga.State
			seq := uint64(10)
			for n := range nSagas {
				id := fmt.Sprintf("sg_%02d", n)
				res := resources[rng.IntN(len(resources))]
				mode := janusv1.ResourceTouch_MODE_READ
				if rng.IntN(2) == 0 {
					mode = janusv1.ResourceTouch_MODE_WRITE
				}
				s := touchingSaga(t, id, res, mode, seq)
				seq += 100

				// Some sagas finish, some are left in flight, some quarantine.
				switch rng.IntN(4) {
				case 0:
					s = finish(t, s, seq-50, true)
				case 1:
					s = finish(t, s, seq-50, false)
				case 2:
					var err error
					s, err = saga.Apply(s, ev(t, seq-50, evidence.KindQuarantine,
						&janusv1.Quarantine{SagaId: id, Reason: "stuck"}))
					if err != nil {
						t.Fatal(err)
					}
				}
				states = append(states, s)
			}

			ix := saga.NewIndex(states...)

			for _, s := range states {
				ok, blockers := ix.MayCommit(s.SagaID)

				// Recompute the answer independently from the raw touches.
				wantBlocked := independentlyBlocked(ix, states, s)
				if ok == wantBlocked {
					t.Fatalf("seed %d: MayCommit(%s)=%v but an independent check says blocked=%v (blockers %v)",
						seed, s.SagaID, ok, wantBlocked, blockers)
				}
				// Every reported blocker must be real.
				for _, b := range blockers {
					if b.BlockingSaga == s.SagaID {
						t.Fatalf("seed %d: %s reported as blocking itself", seed, s.SagaID)
					}
					if b.BlockingStatus == saga.StatusCommitted || b.BlockingStatus == saga.StatusCompensated {
						t.Fatalf("seed %d: a finished saga (%s) was reported as a blocker", seed, b.BlockingSaga)
					}
				}
			}

			// The frontier never exceeds the sequence of the first unsettled
			// touch on that resource.
			for _, r := range ix.Resources() {
				f := ix.Frontier(r)
				for _, s := range states {
					settled := s.Status == saga.StatusCommitted || s.Status == saga.StatusCompensated
					if settled {
						continue
					}
					for _, stepID := range s.Order {
						for _, tch := range s.Steps[stepID].Touches {
							if tch.Resource == r && f >= tch.Seq {
								t.Fatalf("seed %d: frontier on %s is %d, past an unsettled touch at %d by %s",
									seed, r, f, tch.Seq, s.SagaID)
							}
						}
					}
				}
			}
		})
	}
}

// independentlyBlocked recomputes the answer from the touches directly, so the
// property test is not just re-running the implementation it is checking.
func independentlyBlocked(ix *saga.Index, states []saga.State, s saga.State) bool {
	settled := map[string]bool{}
	for _, other := range states {
		settled[other.SagaID] = other.Status == saga.StatusCommitted ||
			other.Status == saga.StatusCompensated
	}

	for _, stepID := range s.Order {
		for _, mine := range s.Steps[stepID].Touches {
			for _, other := range states {
				if other.SagaID == s.SagaID || settled[other.SagaID] {
					continue
				}
				for _, otherStep := range other.Order {
					for _, theirs := range other.Steps[otherStep].Touches {
						if theirs.Resource != mine.Resource || theirs.Seq >= mine.Seq {
							continue
						}
						isWrite := mine.Mode == janusv1.ResourceTouch_MODE_WRITE ||
							theirs.Mode == janusv1.ResourceTouch_MODE_WRITE
						if isWrite {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
