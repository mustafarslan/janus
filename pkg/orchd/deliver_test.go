package orchd_test

import (
	"context"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/console"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/outbox"
)

// TestAnEffectGoesOutThroughAConnectedDeliverer is the whole point of the
// stream: the thing that can reach the target is in another process, and the
// outbox still decides when it may be reached.
//
// The order asserted here is invariant I1's. The effect is held before its step
// reports, it stays held while a human is asked, and it is handed to the
// deliverer only after the saga commits — with EFFECT_RELEASING already in the
// log, appended by this process, before anything left.
func TestAnEffectGoesOutThroughAConnectedDeliverer(t *testing.T) {
	s, dir := newGatedServer(t)
	client, _ := dial(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := client.DeliverEffects(ctx)
	if err != nil {
		t.Fatalf("opening the delivery stream: %v", err)
	}
	if err := stream.Send(&janusv1.DeliverEffectsRequest{
		Message: &janusv1.DeliverEffectsRequest_Register{
			Register: &janusv1.DelivererRegistration{Targets: []string{"tool_payments"}},
		},
	}); err != nil {
		t.Fatalf("registering: %v", err)
	}

	delivered := make(chan *janusv1.DeliverEffectsResponse, 1)
	go func() {
		msg, err := stream.Recv()
		if err != nil {
			return
		}
		delivered <- msg
		_ = stream.Send(&janusv1.DeliverEffectsRequest{
			Message: &janusv1.DeliverEffectsRequest_Receipt{
				Receipt: &janusv1.DeliveryReceipt{
					EffectId: msg.GetEffectId(), Ref: "bank-ref-1",
				},
			},
		})
	}()

	// Wait for the registration to land before anything could need it: the
	// stream is served on another goroutine, and a race here would look like a
	// missing deliverer rather than a slow one.
	waitForDeliverer(t, s, "tool_payments")

	holdAndRunGatedStep(t, s, ctx)
	approve(t, s, dir)

	select {
	case got := <-delivered:
		if got.GetIdemKey() != "idem-notify-1" {
			t.Fatalf("the deliverer was given idem key %q; without the one the target "+
				"recognises, a retry is a second effect", got.GetIdemKey())
		}
		if got.GetAttempt() != 1 {
			t.Fatalf("attempt is %d, want 1 — the deliverer needs to know how many times "+
				"this effect may already have reached the target", got.GetAttempt())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the saga committed and nothing was ever handed to the deliverer; " +
			"an effect held until commit and then held forever is a payment that " +
			"never happens")
	}

	state, err := outbox.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range state.Order {
		if e := state.Effects[id]; e.SagaID == notifySaga {
			if e.State != outbox.StateDelivered {
				t.Fatalf("effect %q is %s, want DELIVERED — the receipt came back but the "+
					"log does not record the delivery", id, e.State)
			}
			return
		}
	}
	t.Fatal("the log holds no effect for this saga at all")
}

// TestAnEffectStaysHeldWhenNothingCanDeliverIt is the other half, and the one
// that must not become a silent success.
//
// A target with no deliverer connected is a refusal the outbox already knows
// how to make: the effect stays held, retryable, with the reason on the record.
// What must never happen is the saga committing and the effect quietly
// vanishing, or the commit being rolled back because a target was down.
func TestAnEffectStaysHeldWhenNothingCanDeliverIt(t *testing.T) {
	s, dir := newGatedServer(t)
	ctx := context.Background()

	holdAndRunGatedStep(t, s, ctx)
	approve(t, s, dir)

	if got := getSaga(t, s, notifySaga); got.GetStatus() != janusv1.SagaState_SAGA_STATE_COMMITTED {
		t.Fatalf("the saga is %s: a target with no deliverer must not stop it committing, "+
			"because the commit is what makes the effect releasable at all", got.GetStatus())
	}
	state, err := outbox.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range state.Order {
		if e := state.Effects[id]; e.SagaID == notifySaga && e.State != outbox.StateHeld {
			t.Fatalf("effect %q is %s with nothing able to deliver it, want HELD", id, e.State)
		}
	}
}

func holdAndRunGatedStep(t *testing.T, s *orchd.Server, ctx context.Context) {
	t.Helper()
	beginGatedPlan(t, s, ctx)
	attempt := prepareStep(t, s, notifySaga, "st_notify")

	// Held before the step reports, which is the order the outbox insists on: a
	// step that sealed while its effect existed only in memory would let the
	// saga commit on the strength of something nobody was holding.
	if _, err := s.HoldEffect(ctx, &janusv1.HoldEffectRequest{
		Effect: &janusv1.EffectHeld{
			EffectId: "ef_notify_1", SagaId: notifySaga, StepId: "st_notify",
			Target: "tool_payments", Action: "notify.email", IdemKey: "idem-notify-1",
			EffectClass: janusv1.EffectClass_EFFECT_CLASS_IRREVERSIBLE_GATED,
		},
	}); err != nil {
		t.Fatalf("holding the effect: %v", err)
	}
	if _, err := s.CompleteStep(ctx, &janusv1.CompleteStepRequest{
		Result: &janusv1.StepResult{
			SagaId: notifySaga, StepId: "st_notify", Attempt: attempt,
			Outcome: &janusv1.Outcome{Status: janusv1.Outcome_STATUS_OK},
		},
	}); err != nil {
		t.Fatalf("reporting the step: %v", err)
	}
}

func approve(t *testing.T, s *orchd.Server, dir string) {
	t.Helper()
	_, err := console.Open(dir).WithRecorder(orchd.NewClient(clientConn(t, s))).
		Answer(context.Background(), console.AnswerRequest{
			SagaID: notifySaga, StepID: "st_notify", RequirementID: "notify-four-eyes",
			Approve: true, Reason: "counterparty verified",
			By: console.Approver{
				Subject: "person:alice@bank", Roles: []string{"credit-officer"},
				AuthRef: "oidc:session-1",
			},
		})
	if err != nil {
		t.Fatalf("approving: %v", err)
	}
}

func waitForDeliverer(t *testing.T, s *orchd.Server, target string) {
	t.Helper()
	for range 200 {
		if s.HasDeliverer(target) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no deliverer registered for %q after two seconds", target)
}
