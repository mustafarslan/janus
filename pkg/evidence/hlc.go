package evidence

import (
	"sync"
	"time"
)

// Clock is a hybrid logical clock (Kulkarni et al.). It packs a physical
// millisecond reading into the high 48 bits and a logical counter into the low
// 16, giving timestamps that are strictly monotonic within a writer, close to
// wall time, and comparable across writers that have exchanged messages.
//
// Janus needs this because wall clocks in a bank move — NTP steps, VM
// migrations, leap smearing — and an evidence log whose order depends on a
// clock that can go backwards is not an audit trail. The wall reading stays in
// the envelope for regulatory timestamping; the HLC is what orders.
//
// Phase 0 provided the local clock only. Attestation is now recorded — see
// pkg/evidence/clockatt: an event's wall reading points at a
// CLOCK_ATTESTATION saying what the clock was disciplined against and how far
// off it was. Attestation is opt-in, so an event with no reference means a
// deployment that configured no time source. PTP discipline is still not here,
// and this comment claimed both for a Phase 1 that closed without either.
type Clock struct {
	mu   sync.Mutex
	last uint64
	now  func() time.Time
}

const (
	// logicalBits is the width of the counter that breaks ties within a
	// millisecond. 16 bits allows 65536 events per millisecond per writer,
	// which is above the 50k events/s/node target by a wide margin.
	logicalBits = 16
	logicalMask = (1 << logicalBits) - 1
)

// NewClock returns a clock reading from the system time.
func NewClock() *Clock { return &Clock{now: time.Now} }

// Wall is this clock's plain wall-clock reading, used for the timestamp an
// event carries when the caller supplies none.
//
// It exists so that an appender reads *one* clock. Before it, the HLC came from
// here and the wall time came from `time.Now()` directly, so a caller who
// substituted a clock changed one of the two and not the other — which meant
// nothing could produce a log that is genuinely old, and anything that reasons
// about elapsed time (a periodic revalidation) could only be tested by
// faking the reader's "now" instead of the record's.
func (c *Clock) Wall() time.Time { return c.now().UTC() }

// NewClockWithSource returns a clock reading from now, for tests that need to
// drive time explicitly.
func NewClockWithSource(now func() time.Time) *Clock { return &Clock{now: now} }

// Now returns the next HLC timestamp. It never returns the same value twice and
// never goes backwards, even if the underlying wall clock does.
func (c *Clock) Now() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	physical := uint64(c.now().UnixMilli()) << logicalBits
	if physical > c.last {
		c.last = physical
		return c.last
	}
	// The wall clock did not advance (or went backwards): stay ahead by
	// incrementing the logical counter.
	c.last++
	return c.last
}

// Observe merges a timestamp received from another writer, so that causally
// related events order correctly across partitions.
func (c *Clock) Observe(remote uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if remote > c.last {
		c.last = remote
	}
}

// SplitHLC decomposes a packed HLC into its physical time and logical counter.
func SplitHLC(hlc uint64) (physical time.Time, logical uint64) {
	return time.UnixMilli(int64(hlc >> logicalBits)).UTC(), hlc & logicalMask
}
