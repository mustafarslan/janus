package fence_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/fence"
	"github.com/mustafarslan/janus/pkg/evidence/objstore"
	"github.com/mustafarslan/janus/pkg/evidence/objstore/objstoretest"
)

func leaseKey() string { return fmt.Sprintf("tenure/lease-%d.json", time.Now().UnixNano()) }

func newLease(t *testing.T, c *objstore.Client, key, holder string, epoch uint64, ttl time.Duration) *fence.Lease {
	t.Helper()
	l, err := fence.New(fence.Config{Store: c, Key: key, Holder: holder, Epoch: epoch, TTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// TestASecondWriterIsRefusedWhileTheFirstHoldsIt is the whole point of the
// package, stated as the situation fork detection could only describe afterwards.
func TestASecondWriterIsRefusedWhileTheFirstHoldsIt(t *testing.T) {
	c := objstoretest.Client(t, "janus-fence", false)
	ctx := context.Background()
	key := leaseKey()
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })

	primary := newLease(t, c, key, "primary", 1, time.Minute)
	if err := primary.Acquire(ctx); err != nil {
		t.Fatalf("the first writer could not take an unheld lease: %v", err)
	}
	if err := primary.Check(); err != nil {
		t.Fatalf("a freshly acquired lease does not check out: %v", err)
	}

	revenant := newLease(t, c, key, "revenant", 1, time.Minute)
	err := revenant.Acquire(ctx)
	if err == nil {
		t.Fatal("a second writer acquired a lease the first one holds; this is a fork the verifier " +
			"can only name afterwards, and the fence exists to make it impossible")
	}
	// The refusal has to say who holds it: an operator staring at a daemon that
	// will not start needs to know whether the other side is alive.
	if got := err.Error(); !contains(got, "primary") {
		t.Fatalf("the refusal does not name the holder, so an operator cannot act on it: %v", err)
	}
}

// TestAnExpiredLeaseIsStolen covers the other half: a fence that never let a
// dead writer's log be taken over would turn every crash into an outage.
func TestAnExpiredLeaseIsStolen(t *testing.T) {
	c := objstoretest.Client(t, "janus-fence", false)
	ctx := context.Background()
	key := leaseKey()
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })

	// A TTL in the past: the holder is, as far as the store can tell, gone.
	dead := newLease(t, c, key, "dead-primary", 1, time.Millisecond)
	if err := dead.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)

	promoted := newLease(t, c, key, "promoted-replica", 2, time.Minute)
	if err := promoted.Acquire(ctx); err != nil {
		t.Fatalf("an expired lease could not be stolen, which would make every writer crash "+
			"an outage lasting until somebody deleted an object by hand: %v", err)
	}
	if err := promoted.Check(); err != nil {
		t.Fatalf("the stolen lease does not check out: %v", err)
	}
}

// TestTheStolenFromWriterLosesItsLeaseOnTheNextRenewal is the fence firing.
//
// This is the `FORK=1 make failover` situation in one process: the old primary
// is still running and still believes it is the writer. What it discovers, at
// its next renewal, is that its etag no longer matches — and ErrLost is
// terminal, because the process that took over may already have sealed history
// this one cannot see.
func TestTheStolenFromWriterLosesItsLeaseOnTheNextRenewal(t *testing.T) {
	c := objstoretest.Client(t, "janus-fence", false)
	ctx := context.Background()
	key := leaseKey()
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })

	old := newLease(t, c, key, "old-primary", 1, 20*time.Millisecond)
	if err := old.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)

	promoted := newLease(t, c, key, "promoted", 2, time.Minute)
	if err := promoted.Acquire(ctx); err != nil {
		t.Fatal(err)
	}

	// The old primary, unaware, tries to carry on.
	err := old.Renew(ctx)
	if !errors.Is(err, fence.ErrLost) {
		t.Fatalf("the stolen-from writer was allowed to renew, so both processes now believe "+
			"they hold the lease: %v", err)
	}
	if !errors.Is(old.Check(), fence.ErrLost) {
		t.Fatalf("Check does not report the loss, so the write path would go on sealing: %v", old.Check())
	}
	// Terminal: it does not recover by trying again.
	if !errors.Is(old.Renew(ctx), fence.ErrLost) {
		t.Fatal("a lost lease was recoverable by retrying; the writer that took over may " +
			"already have sealed history this one cannot see")
	}
}

// TestALeaseNobodyCanConfirmStopsTheWriter covers the unreachable-store case,
// which is not the same as losing the lease and stops the writer anyway.
func TestALeaseNobodyCanConfirmStopsTheWriter(t *testing.T) {
	c := objstoretest.Client(t, "janus-fence", false)
	ctx := context.Background()
	key := leaseKey()
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })

	now := time.Now().UTC()
	clock := now
	l, err := fence.New(fence.Config{
		Store: c, Key: key, Holder: "primary", Epoch: 1,
		TTL: time.Second, Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if err := l.Check(); err != nil {
		t.Fatalf("fresh lease: %v", err)
	}

	// No renewal happens and time passes: the lease is not known to be lost,
	// and it is not known to be held either.
	clock = now.Add(2 * time.Second)
	err = l.Check()
	if !errors.Is(err, fence.ErrStale) {
		t.Fatalf("a lease that has not been renewed within its TTL still reported healthy, so "+
			"a writer partitioned from the store would go on sealing: %v", err)
	}
	if errors.Is(err, fence.ErrLost) {
		t.Fatal("an unrenewed lease was reported as lost; nobody is known to hold it, and " +
			"conflating the two would tell an operator to look for a second writer that " +
			"may not exist")
	}
}

// TestArmRefusesABucketThatDoesNotFence is the guard on the guard.
func TestArmRefusesABucketThatDoesNotFence(t *testing.T) {
	c := objstoretest.Client(t, "janus-fence", false)
	l := newLease(t, c, leaseKey(), "primary", 1, time.Minute)
	if err := l.Arm(context.Background()); err != nil {
		t.Fatalf("arming against a store that does enforce conditional writes failed: %v", err)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// TestALaterEpochTakesTheLeaseFromALiveWriter is the case the fence got wrong
// when it was first armed, and the drill could not see.
//
// `make failover-fenced` SIGKILLs the primary, so its renewals stop and the
// lease expires on its own. A partition does not do that: the primary in region
// A is cut off from its clients and still has a route to the bucket, so it goes
// on renewing every Interval indefinitely. With only "steal what has expired",
// the replica the operator promotes can never take the lease — the fence fails
// closed onto the wrong side and the log has no writer at all.
//
// The epoch is what distinguishes the two. A promotion serves a higher one.
func TestALaterEpochTakesTheLeaseFromALiveWriter(t *testing.T) {
	c := objstoretest.Client(t, "janus-fence", false)
	ctx := context.Background()
	key := leaseKey()
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })

	// A long TTL, renewed: as far as the store can tell this writer is fine.
	partitioned := newLease(t, c, key, "partitioned-primary", 0, time.Minute)
	if err := partitioned.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if err := partitioned.Renew(ctx); err != nil {
		t.Fatal(err)
	}

	// The promoted writer must not sit through that minute, and must not return
	// before the displaced writer's own record says it expired.
	// A clock the sleep moves. Faking one without the other is the spin this
	// test found the first time it ran: Acquire compares Expires against Now, so
	// a fake Sleep with a real Now loops on the store until the minute is up for
	// real, and the test passes having measured a busy wait.
	var slept time.Duration
	clock := time.Now().UTC()
	promoted, err := fence.New(fence.Config{
		Store: c, Key: key, Holder: "promoted-replica", Epoch: 1, TTL: time.Minute,
		Now:   func() time.Time { return clock },
		Sleep: func(d time.Duration) { slept += d; clock = clock.Add(d) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := promoted.Acquire(ctx); err != nil {
		t.Fatalf("a promotion at epoch 1 could not take the lease from a live writer at "+
			"epoch 0, so a partitioned primary that can still reach the bucket blocks its "+
			"own replacement forever: %v", err)
	}
	if slept < 50*time.Second {
		t.Fatalf("Acquire returned after waiting %s of the displaced writer's minute. Check() "+
			"does no I/O, so the writer it was taken from goes on sealing with a lease that "+
			"checks out until its next renewal; returning early hands that window to "+
			"whatever Interval the other side happens to use", slept)
	}
	if err := promoted.Check(); err != nil {
		t.Fatalf("the lease taken from a live writer does not check out: %v", err)
	}
	// And the displaced writer finds out, terminally.
	if !errors.Is(partitioned.Renew(ctx), fence.ErrLost) {
		t.Fatal("the displaced writer renewed successfully, so both processes believe they " +
			"hold the lease -- which is the fork, with a fence armed")
	}
}

// TestAnEarlierEpochIsRefusedEvenWhenTheLeaseHasExpired is the other half, and
// it is the one that is safety rather than liveness.
//
// The promoted writer dies too. Its lease expires. The original primary comes
// back — unaware it was replaced, serving the epoch it always served — and under
// "steal what has expired" it takes the lease and writes its own directory,
// which is the fork the fence was armed to prevent, arrived at by waiting.
//
// The lease remembers the highest epoch it has seen, so it can refuse.
func TestAnEarlierEpochIsRefusedEvenWhenTheLeaseHasExpired(t *testing.T) {
	c := objstoretest.Client(t, "janus-fence", false)
	ctx := context.Background()
	key := leaseKey()
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })

	promoted := newLease(t, c, key, "promoted-replica", 1, time.Millisecond)
	if err := promoted.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // and then it dies

	revenant := newLease(t, c, key, "original-primary", 0, time.Minute)
	err := revenant.Acquire(ctx)
	if err == nil {
		t.Fatal("a writer at epoch 0 took a log that had been promoted to epoch 1, because " +
			"the lease it found had expired. It is a fork arrived at by waiting: the " +
			"promoted history exists and this writer continues from before it")
	}
	// The operator reading this has to be able to tell it from "somebody else is
	// alive and holding it", because the two want opposite actions.
	for _, want := range []string{"epoch 1", "epoch 0", "0 < 1"} {
		if !contains(err.Error(), want) {
			t.Fatalf("the refusal does not say %q, so an operator cannot tell a superseded "+
				"writer from a contended one: %v", want, err)
		}
	}
}

// TestTheSameEpochStillCannotTakeALiveLease pins the row in the middle. Two
// processes serving one tenure are the fork whatever they think of each other,
// so equality does not steal — only expiry does.
func TestTheSameEpochStillCannotTakeALiveLease(t *testing.T) {
	c := objstoretest.Client(t, "janus-fence", false)
	ctx := context.Background()
	key := leaseKey()
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })

	first := newLease(t, c, key, "first", 7, time.Minute)
	if err := first.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	second := newLease(t, c, key, "second", 7, time.Minute)
	if err := second.Acquire(ctx); err == nil {
		t.Fatal("two writers at the same epoch both hold the lease; the epoch rule was " +
			"written to let a promotion displace a live writer and it must not let a " +
			"restart of the same tenure do it")
	}
}

// TestASecondPromotionIsRefusedAfterTheFirstReleased is the hole the epoch rule
// left, and it is the one the drill was placed wrongly to see.
//
// `janus-replicad promote` takes the lease, writes the tenure, and releases —
// the process that goes on writing is `janus-orchd`, started separately. So
// between the two there is a record at epoch N marked expired. A second operator
// promoting a second replica derives the same N, meets an equal epoch that is not
// live, and under the plain three-row rule falls straight through to the steal:
// two tenures, two logs, both claiming to continue from the same sequence.
//
// Establish says which of the two a caller is doing. A promotion is
// *establishing* epoch N, so finding N already in the object means somebody
// established it and there is nothing to take. A daemon is *serving* N, so an
// expired N is its own lease to reclaim.
func TestASecondPromotionIsRefusedAfterTheFirstReleased(t *testing.T) {
	c := objstoretest.Client(t, "janus-fence", false)
	ctx := context.Background()
	key := leaseKey()
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })

	establishing := func(holder string) *fence.Lease {
		t.Helper()
		l, err := fence.New(fence.Config{
			Store: c, Key: key, Holder: holder, Epoch: 1, TTL: time.Minute,
			Establish: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		return l
	}

	first := establishing("promote:op_a")
	if err := first.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	// The handover: the promotion is done and janus-orchd has not started yet.
	if err := first.Release(ctx); err != nil {
		t.Fatal(err)
	}

	second := establishing("promote:op_b")
	if err := second.Acquire(ctx); err == nil {
		t.Fatal("a second operator promoted a second replica of the same log, because the " +
			"first promotion had released the lease on its way out. Two tenures now claim " +
			"to continue from the same sequence, which is the two-writer case the fence exists to prevent")
	} else if !contains(err.Error(), "already established") {
		t.Fatalf("the refusal does not say the epoch was already established, so an operator "+
			"cannot tell it from a contended lease: %v", err)
	}

	// And the handover itself still works: the daemon the first promotion told
	// the operator to start serves that epoch and reclaims the released record.
	// Getting this wrong would trade a double promotion for a failover that
	// cannot be completed.
	daemon := newLease(t, c, key, "ag_orchd", 1, time.Minute)
	if err := daemon.Acquire(ctx); err != nil {
		t.Fatalf("the promoted daemon could not take the lease its own promotion released, "+
			"so the fence now blocks the failover it exists to make safe: %v", err)
	}
}
