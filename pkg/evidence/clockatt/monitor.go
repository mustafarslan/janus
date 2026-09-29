package clockatt

import (
	"context"
	"sync"
	"time"
)

// Monitor takes attestations on a schedule and keeps the most recent one, so
// that events can point at a statement about the clock that timestamped them
// without every append paying for a network round trip.
//
// The reference an event carries is therefore approximate in time: it names the
// most recent attestation, not one taken at that instant. That is the right
// trade, and it is why the attestation records its own TakenAt — an auditor can
// see how stale the claim was rather than having to assume.
type Monitor struct {
	sources  []Source
	interval time.Duration
	// Tolerance is the offset a deployment claims to hold the clock within.
	// Crossing it fires OnBreach.
	tolerance time.Duration

	// OnAttestation is called for every attestation, and is how the monitor is
	// wired to the evidence log.
	onAttestation func(Attestation)
	// OnBreach is called when the clock leaves tolerance or cannot be checked.
	onBreach func(Attestation)

	mu        sync.RWMutex
	latest    Attestation
	latestRef string
}

// Config configures a Monitor.
type Config struct {
	// Sources are tried in order until one answers. Listing several is how a
	// deployment survives one server being down without losing attestation.
	Sources []Source
	// Interval between attestations. Defaults to five minutes, which keeps the
	// reference fresh without turning clock checking into traffic.
	Interval time.Duration
	// Tolerance is the claimed synchronisation bound. Defaults to one second,
	// the RTS 25 figure for activity other than high-frequency trading.
	Tolerance time.Duration
	// OnAttestation receives every attestation, including failures.
	OnAttestation func(Attestation)
	// OnBreach receives attestations that fall outside tolerance.
	OnBreach func(Attestation)
}

// New builds a monitor.
func New(cfg Config) (*Monitor, error) {
	if len(cfg.Sources) == 0 {
		return nil, ErrNoSources
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.Tolerance <= 0 {
		cfg.Tolerance = time.Second
	}
	return &Monitor{
		sources:       cfg.Sources,
		interval:      cfg.Interval,
		tolerance:     cfg.Tolerance,
		onAttestation: cfg.OnAttestation,
		onBreach:      cfg.OnBreach,
	}, nil
}

// Attest takes one attestation now, trying each source until one succeeds.
//
// A failure from every source still produces an attestation — the last error is
// carried — because a deployment that cannot check its clock needs that on the
// record, not omitted.
func (m *Monitor) Attest(ctx context.Context) Attestation {
	var last Attestation
	for _, src := range m.sources {
		att := src.Attest(ctx)
		last = att
		if att.Synchronised {
			break
		}
	}

	// The tolerance travels with the attestation, so the record says what bound
	// this deployment claimed to be holding rather than leaving it in a flag
	// nobody reading the log can see. It is stamped here, not by the Source: a
	// source measures the clock, and the claim about what the clock is supposed
	// to be good enough for belongs to the deployment that configured it.
	last.ToleranceNanos = m.tolerance.Nanoseconds()

	m.mu.Lock()
	m.latest = last
	m.mu.Unlock()

	if m.onAttestation != nil {
		m.onAttestation(last)
	}
	if m.onBreach != nil && !last.WithinTolerance(m.tolerance) {
		m.onBreach(last)
	}
	return last
}

// Latest returns the most recent attestation and whether one has been taken.
func (m *Monitor) Latest() (Attestation, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.latest, !m.latest.TakenAt.IsZero()
}

// SetRef records the evidence reference of the most recent attestation event,
// so appends can point at it.
func (m *Monitor) SetRef(ref string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latestRef = ref
}

// Ref returns the evidence reference of the most recent attestation, or the
// empty string when none has been recorded.
func (m *Monitor) Ref() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.latestRef
}

// Tolerance returns the claimed synchronisation bound.
func (m *Monitor) Tolerance() time.Duration { return m.tolerance }

// Run takes attestations until the context is cancelled. It attests once
// immediately, so a process never serves events with no clock statement at all.
func (m *Monitor) Run(ctx context.Context) {
	m.Attest(ctx)

	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Attest(ctx)
		}
	}
}
