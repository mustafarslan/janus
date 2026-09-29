package orchd

import (
	"sync"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
)

// The watch stream.
//
// A client that had to poll to notice a gate was answered would either poll
// often enough to cost more than the work, or rarely enough that a human's
// approval sat unnoticed. So changes are pushed.
//
// The delivery rule is coalescing, not queueing: a watcher holds at most one
// pending projection per saga, and a newer one replaces the older. That is safe
// only because a projection is a complete statement of the saga at a sequence
// rather than a delta — dropping the middle of three states loses nothing a
// reader can act on, and carrying last_seq is what lets them prove it. A queue
// would instead grow without bound behind a slow consumer, and the thing it
// would be preserving is a history the log already holds.
type watchers struct {
	mu   sync.Mutex
	next int
	set  map[int]*watcher
}

type watcher struct {
	// ids limits the stream. Empty means every saga.
	ids map[string]bool

	mu      sync.Mutex
	pending map[string]*janusv1.SagaProjection
	// signal carries one token to say there is something pending. It is
	// buffered to one and sent non-blockingly, so publishing never waits on a
	// consumer — a slow client must not be able to stall the coordinator that
	// is trying to tell it something.
	signal chan struct{}
	closed bool
	// remove detaches this watcher from the set when its stream ends.
	remove func()
}

func (w *watchers) add(ids []string) *watcher {
	wt := &watcher{
		ids:     map[string]bool{},
		pending: map[string]*janusv1.SagaProjection{},
		signal:  make(chan struct{}, 1),
	}
	for _, id := range ids {
		wt.ids[id] = true
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.set == nil {
		w.set = map[int]*watcher{}
	}
	w.next++
	id := w.next
	w.set[id] = wt
	wt.remove = func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		delete(w.set, id)
	}
	return wt
}

func (w *watchers) publish(p *janusv1.SagaProjection) {
	w.mu.Lock()
	live := make([]*watcher, 0, len(w.set))
	for _, wt := range w.set {
		live = append(live, wt)
	}
	w.mu.Unlock()

	for _, wt := range live {
		wt.offer(p)
	}
}

func (w *watchers) closeAll() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, wt := range w.set {
		wt.close()
	}
	w.set = nil
}

func (wt *watcher) offer(p *janusv1.SagaProjection) {
	if len(wt.ids) > 0 && !wt.ids[p.GetSagaId()] {
		return
	}
	wt.mu.Lock()
	if wt.closed {
		wt.mu.Unlock()
		return
	}
	wt.pending[p.GetSagaId()] = p
	wt.mu.Unlock()

	select {
	case wt.signal <- struct{}{}:
	default:
	}
}

// drain takes everything pending. Returning them together rather than one at a
// time is what makes the coalescing visible to the sender loop: it wakes once
// and sends the current state of every saga that moved.
func (wt *watcher) drain() []*janusv1.SagaProjection {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	if len(wt.pending) == 0 {
		return nil
	}
	out := make([]*janusv1.SagaProjection, 0, len(wt.pending))
	for _, p := range wt.pending {
		out = append(out, p)
	}
	wt.pending = map[string]*janusv1.SagaProjection{}
	return out
}

func (wt *watcher) close() {
	wt.mu.Lock()
	defer wt.mu.Unlock()
	if wt.closed {
		return
	}
	wt.closed = true
	close(wt.signal)
}
