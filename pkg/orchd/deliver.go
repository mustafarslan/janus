package orchd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/outbox"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Lending the outbox a way to reach a target.
//
// The outbox has always taken a map of target to Deliverer, and every Deliverer
// so far has been compiled in. In a deployment the thing that can reach a
// payments API is a process somewhere else, and the question is which way the
// call goes.
//
// It goes this way: the deliverer connects and waits to be told. Invariant I1
// requires EFFECT_RELEASING to be appended durably before anything is
// attempted, and only this process appends — so the decision to deliver, the
// ordering around it, the retry budget, the circuit breaker and the quarantine
// all stay where they already are. `outbox.Releaser.Release` is not touched:
// what it calls is still a Deliverer, and this is one whose implementation
// happens to be a stream.
//
// A dropped stream mid-delivery is not a new failure mode either. It is the
// case already named for delivery: an attempt was announced and may or may not have
// landed, the effect stays held, and the next attempt is made under the same
// idempotency key the target uses to recognise a repeat.

// deliveryTimeout bounds one attempt.
//
// It exists because a release runs under the saga's own lock: a deliverer that
// accepted an effect and never answered would hold that saga still, and the
// operator would see a stuck saga with no failing component to point at. A
// bounded attempt turns that into an ordinary retryable failure, which the
// breaker and the attempt budget already know what to do with.
const deliveryTimeout = 30 * time.Second

// deliverers is the set of ways to reach a target: streams that connected, and
// whatever the process was constructed with.
type deliverers struct {
	mu       sync.RWMutex
	byTarget map[string]*streamDeliverer
	fixed    map[string]outbox.Deliverer
}

// set registers a deliverer that is not a stream and never goes away.
func (d *deliverers) set(target string, deliverer outbox.Deliverer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fixed == nil {
		d.fixed = map[string]outbox.Deliverer{}
	}
	d.fixed[target] = deliverer
}

func (d *deliverers) register(targets []string, sd *streamDeliverer) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.byTarget == nil {
		d.byTarget = map[string]*streamDeliverer{}
	}
	// Checked before anything is claimed, so a registration that names four
	// targets and collides on the fourth takes none of them.
	for _, t := range targets {
		if _, taken := d.byTarget[t]; taken {
			return status.Errorf(codes.AlreadyExists,
				"target %q already has a deliverer on another stream; two processes "+
					"delivering one target is how an effect goes out twice", t)
		}
	}
	for _, t := range targets {
		d.byTarget[t] = sd
	}
	return nil
}

func (d *deliverers) unregister(targets []string, sd *streamDeliverer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, t := range targets {
		// Compared by identity: a stream that reconnected and re-registered
		// while this one was tearing down must not be evicted by its
		// predecessor's cleanup.
		if d.byTarget[t] == sd {
			delete(d.byTarget, t)
		}
	}
}

// snapshot is the map the Releaser is rebuilt with.
//
// A copy rather than the live map, because the Releaser reads it without a lock
// — it was written when the set of deliverers was fixed at construction — and
// handing it something that can be mutated underneath would be a data race in
// the one code path that must not have one.
func (d *deliverers) snapshot() map[string]outbox.Deliverer {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make(map[string]outbox.Deliverer, len(d.byTarget)+len(d.fixed))
	for t, fixed := range d.fixed {
		out[t] = fixed
	}
	// A connected stream wins over a compiled-in deliverer for the same target.
	// The stream is the one that can actually reach the world; the fixed entry
	// is a test double or a fallback, and silently preferring it would make a
	// deployment look like it was delivering when it was not.
	for t, sd := range d.byTarget {
		out[t] = sd
	}
	return out
}

// streamDeliverer is one connected deliverer, seen as an outbox.Deliverer.
type streamDeliverer struct {
	stream janusv1.OrchestratorService_DeliverEffectsServer

	// sendMu serialises writes: a gRPC stream has one sender, and two
	// concurrent releases to the same target would otherwise interleave.
	sendMu sync.Mutex

	mu      sync.Mutex
	waiting map[string]chan *janusv1.DeliveryReceipt
	closed  bool
}

func newStreamDeliverer(stream janusv1.OrchestratorService_DeliverEffectsServer) *streamDeliverer {
	return &streamDeliverer{
		stream:  stream,
		waiting: map[string]chan *janusv1.DeliveryReceipt{},
	}
}

// Deliver satisfies outbox.Deliverer.
func (s *streamDeliverer) Deliver(ctx context.Context, e outbox.Effect) (outbox.Receipt, error) {
	reply := make(chan *janusv1.DeliveryReceipt, 1)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return outbox.Receipt{Retryable: true}, errors.New("the deliverer for this target " +
			"disconnected before the effect could be handed to it")
	}
	if _, busy := s.waiting[e.ID]; busy {
		s.mu.Unlock()
		return outbox.Receipt{}, fmt.Errorf("effect %q is already in flight to %q", e.ID, e.Target)
	}
	s.waiting[e.ID] = reply
	s.mu.Unlock()
	defer s.forget(e.ID)

	s.sendMu.Lock()
	err := s.stream.Send(&janusv1.DeliverEffectsResponse{
		EffectId: e.ID, SagaId: e.SagaID, StepId: e.StepID,
		Target: e.Target, Action: e.Action, IdemKey: e.IdemKey,
		EffectClass: e.Class, PayloadHash: e.PayloadHash, PayloadRef: e.PayloadRef,
		Attempt: e.Attempts + 1,
	})
	s.sendMu.Unlock()
	if err != nil {
		// Nothing was handed over, so nothing may have happened. Retryable is
		// the honest answer and it is also the safe one.
		return outbox.Receipt{Retryable: true}, fmt.Errorf("sending the effect to its "+
			"deliverer: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()
	select {
	case r := <-reply:
		if msg := r.GetError(); msg != "" {
			return outbox.Receipt{Retryable: r.GetRetryable(), Message: msg}, errors.New(msg)
		}
		return outbox.Receipt{
			Ref: r.GetRef(), Hash: r.GetHash(),
			Duplicate: r.GetDuplicate(), Retryable: r.GetRetryable(),
			Message: r.GetMessage(),
		}, nil
	case <-ctx.Done():
		// The attempt was announced and its outcome is unknown, which is
		// exactly what the attempt counter is for: it counts how many times the
		// effect may have reached the target, not how many times it did.
		return outbox.Receipt{Retryable: true}, fmt.Errorf(
			"the deliverer for %q did not answer within %s; the effect may or may not "+
				"have been applied", e.Target, deliveryTimeout)
	}
}

// deliver routes a receipt back to whoever is waiting for it.
func (s *streamDeliverer) deliver(r *janusv1.DeliveryReceipt) {
	s.mu.Lock()
	ch, ok := s.waiting[r.GetEffectId()]
	s.mu.Unlock()
	if !ok {
		// A receipt for something nobody is waiting on: a late answer to an
		// attempt that already timed out. Dropped rather than treated as an
		// error, because the effect's own record already says the attempt was
		// made and its outcome unknown.
		return
	}
	select {
	case ch <- r:
	default:
	}
}

func (s *streamDeliverer) forget(effectID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.waiting, effectID)
}

// shutdown fails everything still in flight when the stream ends.
func (s *streamDeliverer) shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for id, ch := range s.waiting {
		select {
		case ch <- &janusv1.DeliveryReceipt{
			EffectId: id, Retryable: true,
			Error: "the deliverer disconnected before answering; the effect may or may " +
				"not have been applied",
		}:
		default:
		}
	}
}

// DeliverEffects registers a deliverer and serves it effects.
func (s *Server) DeliverEffects(stream janusv1.OrchestratorService_DeliverEffectsServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	reg := first.GetRegister()
	if reg == nil || len(reg.GetTargets()) == 0 {
		return status.Error(codes.InvalidArgument,
			"the first message must register at least one target; a deliverer that serves "+
				"nothing has nothing to be sent")
	}

	sd := newStreamDeliverer(stream)
	if err := s.deliverers.register(reg.GetTargets(), sd); err != nil {
		return err
	}
	defer func() {
		s.deliverers.unregister(reg.GetTargets(), sd)
		sd.shutdown()
		s.rebuildReleaser()
	}()
	s.rebuildReleaser()

	// Deliver what was already waiting for these targets. A crash between an
	// effect's release being announced and the target answering leaves it
	// pending, and the process that restarts is the one that has to finish it.
	// Without this, an effect stranded by a crash sits held until somebody
	// notices and asks — which is the same failure as never releasing it, only
	// slower and harder to see.
	//
	// In the background so that registering does not block on a sweep, and so
	// the stream is already receiving when the first effect goes down it.
	go s.sweepHeld(reg.GetTargets())

	for {
		msg, err := stream.Recv()
		if err != nil {
			// Including io.EOF: the deliverer went away. Its targets lose their
			// deliverer, which the outbox refuses on rather than holding
			// silently.
			return nil
		}
		if r := msg.GetReceipt(); r != nil {
			sd.deliver(r)
		}
	}
}

// rebuildReleaser swaps in a Releaser that knows the current deliverers.
//
// Rebuilt rather than mutated: the Releaser reads its map without a lock, which
// was correct when the set was fixed at construction and would be a race now.
// Constructing one is cheap, and a release already in flight keeps the releaser
// it started with — which still holds the deliverer it is using.
func (s *Server) rebuildReleaser() {
	next, err := outbox.NewReleaser(outbox.Options{
		Appender:    s.app,
		Participant: s.participant,
		Authority:   outbox.NewLiveLogAuthority(s.dir, s.liveRead),
		// Where a target is, read from the same log the registry is folded
		// from. A daemon whose tenant has pinned a jurisdiction refuses to
		// release an effect to a target that log does not place inside it;
		// an unpinned one never consults it.
		Residency: outbox.NewLiveLogResidency(s.dir, s.liveRead),
		// What mode a saga was admitted under, read from its SAGA_BEGIN in the
		// same log. An exploratory saga's effects reach a declared sandbox and
		// nothing else; a saga in any other mode
		// never notices this.
		Modes:          outbox.NewLogModes(s.dir),
		SandboxTargets: s.sandboxTargets,
		Deliverers:     s.deliverers.snapshot(),
		MaxAttempts:    s.maxAttempts,
		Breakers:       s.breakers,
		// The writer lease, checked again here and not only at seal. Sealing
		// protects history; this protects the world, and an effect that has
		// been delivered cannot be undone by deciding afterwards which log was
		// the real one. Nil-safe: unfenced deployments get nil.
		BeforeRelease: s.fence.CheckOrNil,
	})
	if err != nil {
		// NewReleaser refuses only on a missing appender or authority today,
		// both of which were supplied at construction and cannot have gone
		// away — so this is unreachable. It is logged rather than ignored
		// because the moment somebody adds a refusal to NewReleaser, this path
		// silently keeps the *previous* releaser, and a daemon delivering under
		// options it no longer holds is the kind of thing that is only ever
		// found by reading this function.
		log.Printf("orchd: the releaser could not be rebuilt and the previous one is still "+
			"in use: %v", err)
		return
	}
	s.releaserMu.Lock()
	s.releaser = next
	s.releaserMu.Unlock()
}

// currentReleaser returns the releaser to use for one release.
func (s *Server) currentReleaser() *outbox.Releaser {
	s.releaserMu.RLock()
	defer s.releaserMu.RUnlock()
	return s.releaser
}

// HasDeliverer reports whether anything can currently reach a target.
//
// It is exported because "why is this effect still held" is the question an
// operator asks first, and the answer is usually that the process which serves
// that target is not connected. A console or a health endpoint can say so
// without having to infer it from an effect that is not moving.
func (s *Server) HasDeliverer(target string) bool {
	s.deliverers.mu.RLock()
	defer s.deliverers.mu.RUnlock()
	if _, ok := s.deliverers.byTarget[target]; ok {
		return true
	}
	_, ok := s.deliverers.fixed[target]
	return ok
}

// sweepHeld releases anything already pending for the given targets.
func (s *Server) sweepHeld(targets []string) {
	want := make(map[string]bool, len(targets))
	for _, t := range targets {
		want[t] = true
	}
	state, err := outbox.Load(s.dir)
	if err != nil {
		return
	}

	sagas := map[string]bool{}
	for _, id := range state.Order {
		e := state.Effects[id]
		if e != nil && e.Pending() && want[e.Target] {
			sagas[e.SagaID] = true
		}
	}
	for sagaID := range sagas {
		// Per saga, under that saga's own lock, so a sweep and a live drive of
		// the same saga cannot both be appending. ReleaseAll asks the commit
		// authority itself, so a saga that has not committed is refused here
		// rather than needing to be filtered out first.
		h := s.hostedSaga(sagaID)
		h.driving.Lock()
		_ = s.currentReleaser().ReleaseAll(context.Background(), state, sagaID)
		h.driving.Unlock()
	}
}
