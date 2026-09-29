// Package fence holds a writer lease in an object store, so that two processes
// writing what claims to be one evidence log can be reduced to one.
//
// Without a fence, a fork is *detected and attributed* and not
// prevented: `syscall.Flock` is per-filesystem, so a promoted replica in one
// region and a partitioned-but-alive primary in another each hold a perfectly
// valid writer lock on their own directory. Both logs verify. `janus-replicad
// compare` can say where they stopped agreeing and cannot say which is right.
//
// A lease moves the arbitration somewhere both writers can see: a single object
// that only one of them can hold, decided by the store's compare-and-swap rather
// than by either writer's opinion of whether the other is alive.
//
// # What this bounds, and what it does not
//
// The lease is checked when a segment is **sealed** and when an effect is
// **released**, never on an append. An append is the most latency-sensitive
// operation in this repository and a per-append round trip to an object store
// would end S4 at any concurrency worth measuring.
//
// The consequence is stated rather than hidden: **a writer that has lost the
// lease can still append to its open segment until it next tries to seal.** The
// fence bounds a fork to one unsealed segment; it does not prevent one byte of
// divergence. What it does prevent is that divergence becoming *sealed history*
// or a *released effect* — the two things that cannot be taken back.
package fence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/objstore"
)

// ErrLost is returned once the lease is known to be held by somebody else. It
// is terminal: a writer that has lost the lease does not try to take it back,
// because the process that holds it may already have sealed history this one
// cannot see.
var ErrLost = errors.New("fence: the writer lease was lost")

// ErrStale is returned when the lease has not been renewed within its TTL,
// which means the store could not be reached. It is not ErrLost — nobody else
// is known to hold the lease — and it stops the writer all the same, because a
// lease nobody can confirm is a lease nobody can rely on.
var ErrStale = errors.New("fence: the writer lease could not be renewed in time")

// Record is the lease document. It is JSON rather than CBOR because nothing in
// `janus-verify`'s import graph reads it and an operator looking at a bucket
// during an incident should be able to read it with `cat`.
type Record struct {
	// Holder names the process that took it, for an operator reading the
	// bucket rather than for the protocol: the protocol is decided by the
	// store's etag, not by this field.
	Holder string `json:"holder"`
	// Epoch is the tenure this writer is serving under. A promotion
	// bumps it, so a revenant primary holding epoch N cannot mistake a newer
	// lease for its own.
	Epoch uint64 `json:"epoch"`
	// Expires is when the lease may be stolen by somebody else.
	//
	// It is also what makes every renewal write *different bytes*, and that is
	// load-bearing rather than incidental: an ETag is derived from content, so a
	// renewal writing an identical document would leave the etag unmoved and an
	// etag some other process had been holding since before it would still
	// match. See TestAnUnchangedRenewalDoesNotMoveTheEtag in pkg/evidence/objstore.
	Expires time.Time `json:"expires"`
	// TakenAt and RenewedAt are for the operator, not the protocol.
	TakenAt   time.Time `json:"taken_at"`
	RenewedAt time.Time `json:"renewed_at,omitempty"`
}

// Config configures a Lease.
type Config struct {
	// Store is the bucket the lease lives in. It must be reachable from every
	// process that could write this log, which is the whole point: a lease in a
	// place only one region can reach fences nothing.
	Store *objstore.Client
	// Key names the lease object.
	Key string
	// Holder names this process.
	Holder string
	// Epoch is the tenure.
	Epoch uint64
	// TTL is how long a lease stays valid without a renewal, and therefore how
	// long a dead writer's lease blocks a takeover. Defaults to 30s.
	TTL time.Duration
	// Interval between renewals. Defaults to TTL/3, which leaves room for two
	// failed attempts before the lease goes stale.
	Interval time.Duration
	// Establish distinguishes a caller *taking* this epoch for the first time
	// from one *serving* it.
	//
	// `janus-replicad promote` establishes: it is recording a handover, and an
	// equal epoch already in the object means another promotion got there, so
	// there is nothing to take however long ago it happened. `janus-orchd`
	// serves: an equal epoch that has expired is its own lease, left behind by
	// the promotion that told the operator to start it or by its own crash, and
	// refusing to reclaim it would turn every restart into an outage.
	//
	// Without this the release at the end of a promotion opens the hole the
	// epoch was added to close: two operators promoting five seconds apart both
	// find an expired record at the epoch they derived, and both steal it.
	Establish bool
	// Now is injectable for tests.
	Now func() time.Time
	// Sleep is injectable for tests, and has to be: Acquire waits out a
	// displaced writer by comparing against Now, so a fake clock with a real
	// time.Sleep spins until the test times out.
	Sleep func(time.Duration)
	// Notify, when set, is called with one human sentence at the only point
	// where this package makes a caller wait: taking the lease from a writer
	// that was still live. A daemon that appears to hang for a TTL during an
	// incident is a daemon somebody kills.
	Notify func(string)
}

// Lease is a held writer lease.
type Lease struct {
	cfg Config

	mu       sync.RWMutex
	etag     string
	held     bool
	lastOK   time.Time
	terminal error
}

// New validates a configuration and returns an unheld lease.
func New(cfg Config) (*Lease, error) {
	if cfg.Store == nil {
		return nil, errors.New("fence: no object store")
	}
	if cfg.Key == "" {
		return nil, errors.New("fence: no lease key")
	}
	if cfg.Holder == "" {
		return nil, errors.New("fence: no holder name")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 30 * time.Second
	}
	if cfg.Interval <= 0 {
		cfg.Interval = cfg.TTL / 3
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = time.Sleep
	}
	return &Lease{cfg: cfg}, nil
}

// Arm probes the bucket and refuses if it does not enforce conditional writes.
//
// **This is not optional and it is not a formality.** When a store does not
// enforce `If-None-Match` and `If-Match`, it does not report an error — it
// accepts every write, and two writers both believe they hold the lease. A
// fence that silently does not fence is worse than no fence, because an operator
// stops looking for the failure it was supposed to prevent.
func (l *Lease) Arm(ctx context.Context) error {
	rows, err := l.cfg.Store.ProbeConditionalWrites(ctx, l.cfg.Key+".probe")
	if err != nil {
		return fmt.Errorf("fence: probing %s: %w", l.cfg.Store.Bucket(), err)
	}
	if ok, why := objstore.ProbeOK(rows); !ok {
		return fmt.Errorf("fence: bucket %s does not enforce conditional writes, so a "+
			"lease in it would not fence: %s", l.cfg.Store.Bucket(), why)
	}
	return nil
}

// Acquire takes the lease, and the epoch decides what it is allowed to take.
//
// # Three answers, not two
//
// The first version of this had two: an unheld or expired lease is taken, an
// unexpired one is refused. That is correct for a crash and wrong for the
// situation a fork actually arises from — a primary partitioned from its clients
// but *not* from the object store. It goes on renewing every Interval forever,
// so the replica the operator promotes can never acquire, and the fence fails
// closed onto the wrong side: no writer at all, until somebody reaches the
// machine that is unreachable by assumption.
//
// [Record.Epoch] is the field that answers it, and until this comment was
// written nothing read it. Each promotion serves a higher epoch than the tenure
// it replaces, so:
//
//	cur.Epoch > mine   refuse, expired or not — this writer has been superseded
//	cur.Epoch == mine  steal only if expired — two of the same tenure is a fork
//	cur.Epoch < mine   steal, expired or not — a promotion outranks its predecessor
//
// The first row is new safety rather than liveness: a revenant primary coming
// back after the promoted writer's lease expired used to steal it and fork.
//
// # Stealing a lease that has not expired means waiting anyway
//
// [Lease.Check] does no I/O, so a writer that has just been stolen from does not
// know it: its next [Lease.Renew] is refused, and until then it goes on sealing
// with a lease that checks out. Returning immediately from a live steal would
// hand the package's stated bound — "a fork is bounded to one unsealed segment"
// — back to whatever Interval the other side happens to use.
//
// So a live steal waits out the displaced writer's own Expires before it
// returns, renewing meanwhile. That bound needs nothing to be known about the
// other side's configuration: by the time its own record says it expired, it has
// either tried to renew (and been refused, terminally) or not tried (and its
// Check reports ErrStale). Either way it has stopped.
//
// The cost is up to one TTL added to start-up, in exactly the case where a live
// writer was displaced — never after a crash, where the lease is already expired
// and the wait is zero.
func (l *Lease) Acquire(ctx context.Context) error {
	now := l.cfg.Now().UTC()
	body, err := json.Marshal(Record{
		Holder: l.cfg.Holder, Epoch: l.cfg.Epoch,
		Expires: now.Add(l.cfg.TTL), TakenAt: now,
	})
	if err != nil {
		return err
	}

	etag, err := l.cfg.Store.PutIfAbsent(ctx, l.cfg.Key, body, objstore.PutOptions{ContentType: "application/json"})
	switch {
	case err == nil:
		l.hold(etag, now)
		return nil
	case !errors.Is(err, objstore.ErrPreconditionFailed):
		return fmt.Errorf("fence: taking %s: %w", l.cfg.Key, err)
	}

	// Somebody holds it, or held it. Read and decide.
	cur, curETag, err := l.read(ctx)
	if err != nil {
		return err
	}
	live := cur.Expires.After(now)
	switch {
	case cur.Epoch > l.cfg.Epoch:
		return fmt.Errorf("fence: %s has moved to epoch %d and this writer serves epoch %d "+
			"(%d < %d): the log was promoted after this writer's tenure, and a superseded "+
			"writer taking the lease back would put it at the head of a log that has gone "+
			"on without it. Last held by %q",
			l.cfg.Key, cur.Epoch, l.cfg.Epoch, l.cfg.Epoch, cur.Epoch, cur.Holder)
	case cur.Epoch == l.cfg.Epoch && l.cfg.Establish:
		return fmt.Errorf("fence: epoch %d of %s was already established by %q at %s: this "+
			"log has already been promoted into that tenure, and promoting again would "+
			"produce a second log claiming to continue from the same sequence. An expired "+
			"lease is not an opening here -- the writer it belongs to may simply not have "+
			"been started yet", l.cfg.Epoch, l.cfg.Key, cur.Holder, cur.TakenAt.Format(time.RFC3339))
	case cur.Epoch == l.cfg.Epoch && live:
		return fmt.Errorf("fence: %s is held by %q (epoch %d) until %s: refusing to start a "+
			"second writer for this log", l.cfg.Key, cur.Holder, cur.Epoch,
			cur.Expires.Format(time.RFC3339))
	}
	// Expired at this epoch, or held at a lower one. Two processes racing here
	// both read the same etag and the store decides which compare-and-swap
	// lands.
	etag, err = l.cfg.Store.PutIfMatch(ctx, l.cfg.Key, body, curETag, objstore.PutOptions{ContentType: "application/json"})
	if err != nil {
		if errors.Is(err, objstore.ErrPreconditionFailed) {
			return fmt.Errorf("fence: lost the race to take %s: another writer got there first",
				l.cfg.Key)
		}
		return fmt.Errorf("fence: taking %s from %q: %w", l.cfg.Key, cur.Holder, err)
	}
	l.hold(etag, now)
	if live {
		return l.waitOutDisplaced(ctx, cur)
	}
	return nil
}

// waitOutDisplaced holds a freshly stolen lease until the writer it was taken
// from can no longer believe it holds one.
//
// Renewing while waiting is not optional: the displaced writer's TTL may be
// longer than this one's, and a lease that went stale while its holder waited
// for somebody else's to expire would be an own goal.
//
// Cancellation is checked once per Interval rather than interrupting the sleep.
// The wait is bounded by the other side's TTL and a start-up that is already
// waiting out a displaced writer has nothing better to do with the difference.
func (l *Lease) waitOutDisplaced(ctx context.Context, displaced Record) error {
	if l.cfg.Notify != nil {
		l.cfg.Notify(fmt.Sprintf("took %s from %q (epoch %d), which was still live; waiting "+
			"until %s for it to find out, so it stops sealing before this writer starts",
			l.cfg.Key, displaced.Holder, displaced.Epoch, displaced.Expires.Format(time.RFC3339)))
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		left := displaced.Expires.Sub(l.cfg.Now().UTC())
		if left <= 0 {
			return nil
		}
		if left > l.cfg.Interval {
			left = l.cfg.Interval
		}
		l.cfg.Sleep(left)
		if !displaced.Expires.After(l.cfg.Now().UTC()) {
			return nil
		}
		if err := l.Renew(ctx); err != nil {
			return fmt.Errorf("fence: renewing while waiting out %q: %w", displaced.Holder, err)
		}
	}
}

// Renew extends the lease. A refusal means somebody else holds it now, which is
// terminal.
func (l *Lease) Renew(ctx context.Context) error {
	l.mu.RLock()
	etag, held, terminal := l.etag, l.held, l.terminal
	l.mu.RUnlock()
	// Terminal first. `lose` clears `held`, so checking that alone would answer
	// a caller looping on Renew with "never acquired" — which reads as a
	// programming error and is in fact the fence having fired.
	if terminal != nil {
		return terminal
	}
	if !held {
		return errors.New("fence: renew called on a lease that was never acquired")
	}

	now := l.cfg.Now().UTC()
	body, err := json.Marshal(Record{
		Holder: l.cfg.Holder, Epoch: l.cfg.Epoch,
		Expires: now.Add(l.cfg.TTL), TakenAt: now, RenewedAt: now,
	})
	if err != nil {
		return err
	}
	next, err := l.cfg.Store.PutIfMatch(ctx, l.cfg.Key, body, etag, objstore.PutOptions{ContentType: "application/json"})
	if err != nil {
		if errors.Is(err, objstore.ErrPreconditionFailed) {
			l.lose(fmt.Errorf("%w: %s moved while this writer held it, so another writer "+
				"has taken over", ErrLost, l.cfg.Key))
			return l.Err()
		}
		// Reachability failure: not lost, not confirmed. Check() decides when
		// the silence has gone on too long.
		return fmt.Errorf("fence: renewing %s: %w", l.cfg.Key, err)
	}
	l.hold(next, now)
	return nil
}

// Check reports whether the lease is still good enough to seal a segment or
// release an effect. It is the call the write path makes, and it does no I/O:
// the renewal goroutine does the I/O, and this reads what it last learned.
//
// No I/O on purpose. A seal that made a network call would put object-store
// latency on the path that closes a segment, and an outbox release that made one
// would put it in front of every effect.
func (l *Lease) Check() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.terminal != nil {
		return l.terminal
	}
	if !l.held {
		return errors.New("fence: the lease was never acquired")
	}
	if age := l.cfg.Now().UTC().Sub(l.lastOK); age > l.cfg.TTL {
		return fmt.Errorf("%w: last confirmed %s ago, TTL is %s", ErrStale, age.Round(time.Millisecond), l.cfg.TTL)
	}
	return nil
}

// Err returns the terminal error, or nil.
func (l *Lease) Err() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.terminal
}

// Run renews until the context is cancelled or the lease is lost.
func (l *Lease) Run(ctx context.Context) {
	t := time.NewTicker(l.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := l.Renew(ctx); err != nil && errors.Is(err, ErrLost) {
				return
			}
		}
	}
}

// Release drops the lease so another writer can take it without waiting out the
// TTL. Best effort: a writer that crashes does not get to call this, which is
// what the TTL is for.
func (l *Lease) Release(ctx context.Context) error {
	l.mu.Lock()
	etag, held := l.etag, l.held
	l.held = false
	l.mu.Unlock()
	if !held {
		return nil
	}
	// Expire it in place rather than delete it: a deleted lease lets the next
	// taker use PutIfAbsent, and an object that briefly does not exist is an
	// object two takers can both create... which PutIfAbsent handles, but
	// leaving the record readable also leaves an operator something to look at.
	now := l.cfg.Now().UTC()
	body, err := json.Marshal(Record{
		Holder: l.cfg.Holder, Epoch: l.cfg.Epoch,
		Expires: now.Add(-time.Second), TakenAt: now, RenewedAt: now,
	})
	if err != nil {
		return err
	}
	if _, err := l.cfg.Store.PutIfMatch(ctx, l.cfg.Key, body, etag, objstore.PutOptions{ContentType: "application/json"}); err != nil {
		return fmt.Errorf("fence: releasing %s: %w", l.cfg.Key, err)
	}
	return nil
}

// Holder returns the configured holder name.
func (l *Lease) Holder() string { return l.cfg.Holder }

func (l *Lease) read(ctx context.Context) (Record, string, error) {
	body, err := l.cfg.Store.Get(ctx, l.cfg.Key)
	if err != nil {
		return Record{}, "", fmt.Errorf("fence: reading %s: %w", l.cfg.Key, err)
	}
	info, err := l.cfg.Store.Head(ctx, l.cfg.Key)
	if err != nil {
		return Record{}, "", fmt.Errorf("fence: heading %s: %w", l.cfg.Key, err)
	}
	var rec Record
	if err := json.Unmarshal(body, &rec); err != nil {
		return Record{}, "", fmt.Errorf("fence: decoding %s: %w", l.cfg.Key, err)
	}
	return rec, info.ETag, nil
}

func (l *Lease) hold(etag string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.etag, l.held, l.lastOK = etag, true, at
}

func (l *Lease) lose(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.terminal == nil {
		l.terminal = err
	}
	l.held = false
}
