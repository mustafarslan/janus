package outbox

import (
	"sync"
	"time"
)

// Circuit breakers, one per target.
//
// The failure they exist for is specific. Each effect has a small, fixed budget
// of delivery attempts, and after that budget is spent the effect is
// quarantined for a human. If a target goes down for ten minutes, and Janus
// keeps attempting every held effect against it, every one of those effects
// burns its whole budget on an outage and lands in a human's queue — turning a
// transient network problem into a pile of frozen payments that somebody has to
// reconcile by hand.
//
// A breaker converts that into waiting. While the target is known to be
// failing, effects are not attempted, so their budgets stay intact for when it
// comes back.
//
// Breaker state is deliberately in memory and not evidence. It is a belief
// about the present — "this endpoint appears to be down" — not a fact about
// what happened, and a fresh process is right to start with no opinion and find
// out for itself. Everything that did happen is in the log as attempts and
// outcomes.

// BreakerState is a breaker's position.
type BreakerState string

const (
	// BreakerClosed is the normal state: attempts flow.
	BreakerClosed BreakerState = "CLOSED"
	// BreakerOpen means the target is failing and attempts are withheld.
	BreakerOpen BreakerState = "OPEN"
	// BreakerHalfOpen lets exactly one attempt through to find out whether the
	// target has recovered.
	BreakerHalfOpen BreakerState = "HALF_OPEN"
)

// BreakerConfig tunes the breakers.
type BreakerConfig struct {
	// Threshold is how many consecutive failures open a breaker. Defaults to 3.
	Threshold int
	// Cooldown is how long a breaker stays open before allowing a trial
	// attempt. Defaults to 30s.
	Cooldown time.Duration
	// Now supplies the current time, so tests do not have to sleep. Defaults to
	// time.Now.
	Now func() time.Time
}

// Breakers holds one breaker per target.
type Breakers struct {
	cfg BreakerConfig
	mu  sync.Mutex
	per map[string]*breaker
}

type breaker struct {
	state    BreakerState
	failures int
	openedAt time.Time
	// trialOut is true while a half-open trial attempt is outstanding, so only
	// one attempt probes a recovering target rather than every effect at once.
	trialOut bool
}

// NewBreakers builds a breaker set.
func NewBreakers(cfg BreakerConfig) *Breakers {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 3
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Breakers{cfg: cfg, per: map[string]*breaker{}}
}

// Allow reports whether an attempt against a target may proceed, and reserves
// the trial slot when the breaker is half-open.
func (b *Breakers) Allow(target string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	br := b.get(target)

	switch br.state {
	case BreakerClosed:
		return true
	case BreakerOpen:
		if b.cfg.Now().Sub(br.openedAt) < b.cfg.Cooldown {
			return false
		}
		// The cooldown has passed. Let exactly one attempt through.
		br.state = BreakerHalfOpen
		br.trialOut = true
		return true
	case BreakerHalfOpen:
		// A trial is already in flight. Sending more would defeat the purpose:
		// the point of half-open is to spend one effect's attempt finding out,
		// not all of them.
		return !br.trialOut
	}
	return true
}

// Success records a delivery that worked.
func (b *Breakers) Success(target string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	br := b.get(target)
	br.state = BreakerClosed
	br.failures = 0
	br.trialOut = false
}

// Failure records a delivery that did not.
func (b *Breakers) Failure(target string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	br := b.get(target)
	br.failures++
	br.trialOut = false

	// A failed trial reopens immediately rather than counting toward the
	// threshold again: the target has just told us it is still broken, and the
	// cooldown should restart from now.
	if br.state == BreakerHalfOpen || br.failures >= b.cfg.Threshold {
		br.state = BreakerOpen
		br.openedAt = b.cfg.Now()
	}
}

// State reports a target's breaker position, for operators and tests.
func (b *Breakers) State(target string) BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.get(target).state
}

func (b *Breakers) get(target string) *breaker {
	br, ok := b.per[target]
	if !ok {
		br = &breaker{state: BreakerClosed}
		b.per[target] = br
	}
	return br
}
