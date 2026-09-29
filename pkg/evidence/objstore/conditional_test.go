package objstore_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/objstore"
	"github.com/mustafarslan/janus/pkg/evidence/objstore/objstoretest"
)

// TestAConditionalWriteIsDecidedByTheStore is the lease primitive, checked
// against a real object store rather than against the documentation.
//
// The four rows are the four things a fence needs to be true, and they are
// exactly the rows `ProbeConditionalWrites` asks at arm time. They are written
// out here as well so that a change to the probe has to break a test that says
// what the probe is *for*, rather than only a test that says the probe returns
// four rows.
func TestAConditionalWriteIsDecidedByTheStore(t *testing.T) {
	c := objstoretest.Client(t, "janus-conditional", false)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	key := fmt.Sprintf("lease-%d.json", time.Now().UnixNano())
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })

	// 1. Creation is exclusive.
	etag, err := c.PutIfAbsent(ctx, key, []byte(`{"holder":"a"}`), objstore.PutOptions{})
	if err != nil {
		t.Fatalf("taking an unheld lease was refused: %v", err)
	}
	if etag == "" {
		t.Fatal("a successful conditional put returned no etag; a lease cannot be renewed without one")
	}

	// 2. A second taker loses, and loses *distinguishably* — a lease that
	// cannot tell "somebody else holds it" from "the store is broken" would
	// make a writer stop for the wrong reason.
	if _, err := c.PutIfAbsent(ctx, key, []byte(`{"holder":"b"}`), objstore.PutOptions{}); !errors.Is(err, objstore.ErrPreconditionFailed) {
		t.Fatalf("a second taker was not refused with ErrPreconditionFailed: %v", err)
	}

	// 3. The holder renews by proving which version it holds.
	next, err := c.PutIfMatch(ctx, key, []byte(`{"holder":"a","renewed":true}`), etag, objstore.PutOptions{})
	if err != nil {
		t.Fatalf("the holder could not renew with its own etag: %v", err)
	}
	if next == etag {
		t.Fatal("renewal returned the same etag; a holder that cannot tell its versions apart cannot detect a steal")
	}

	// 4. A process whose view is stale is refused — this is the fence.
	if _, err := c.PutIfMatch(ctx, key, []byte(`{"holder":"b"}`), etag, objstore.PutOptions{}); !errors.Is(err, objstore.ErrPreconditionFailed) {
		t.Fatalf("a writer holding a stale etag was allowed to overwrite the lease: %v", err)
	}
}

// TestTheProbeRefusesAStoreThatDoesNotFence checks the arm-time probe reports
// all four, and that ProbeOK agrees.
//
// The probe is the thing standing between "-fence was passed" and "-fence does
// something", so a probe that returns rows nobody grades is the hollow control
// one level up from the one it exists to prevent.
func TestTheProbeRefusesAStoreThatDoesNotFence(t *testing.T) {
	c := objstoretest.Client(t, "janus-conditional", false)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rows, err := c.ProbeConditionalWrites(ctx, fmt.Sprintf("probe-%d.json", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	for _, r := range rows {
		t.Logf("  %-40s want %-14s %v", r.What, r.Want, r.Got)
	}
	ok, why := objstore.ProbeOK(rows)
	if !ok {
		t.Fatalf("this bucket does not enforce conditional writes, so a fence built on it would not fence: %s", why)
	}

	// ProbeOK has to fail when a row fails, or arming would consult an oracle
	// that always says yes.
	broken := append([]objstore.ProbeResult(nil), rows...)
	broken[1].OK, broken[1].Got = false, "accepted"
	if ok, _ := objstore.ProbeOK(broken); ok {
		t.Fatal("ProbeOK passed a probe whose second-taker row was accepted — that store allows two holders")
	}
	if ok, _ := objstore.ProbeOK(rows[:3]); ok {
		t.Fatal("ProbeOK passed a short probe; a row that did not run is not a row that passed")
	}
}

// TestAnUnchangedRenewalDoesNotMoveTheEtag pins the trap that a lease design
// built on compare-and-swap has to know about, and that this package's probe
// walked into before it was written down.
//
// An ETag is derived from content. Writing the same bytes again leaves it
// unchanged — so a holder that "renews" with an identical document has not
// moved anything, and an etag some other process has been holding since before
// that renewal is still *current*. Its compare-and-swap succeeds. **The fence
// is open and nothing reports it**, because every call returned 200 and the
// lease file looks exactly as it should.
//
// The consequence for the lease: `tenure/lease.json` must differ on every write.
// An expiry timestamp does that as a side effect of being useful, which is why
// the lease carries one rather than only a holder id.
func TestAnUnchangedRenewalDoesNotMoveTheEtag(t *testing.T) {
	c := objstoretest.Client(t, "janus-conditional", false)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	key := fmt.Sprintf("etag-%d.json", time.Now().UnixNano())
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })

	same := []byte(`{"holder":"a"}`)
	first, err := c.PutIfAbsent(ctx, key, same, objstore.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.PutIfMatch(ctx, key, same, first, objstore.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Skipf("this store changes the etag for an identical write (%s -> %s); the trap "+
			"below does not apply here, but a store that behaves like S3 still has it",
			first, second)
	}

	// The trap, demonstrated: `first` was taken before a renewal happened, and
	// it still works. On a lease whose bytes never vary, this is a fenced-out
	// writer successfully taking the lease back.
	if _, err := c.PutIfMatch(ctx, key, same, first, objstore.PutOptions{}); err != nil {
		t.Fatalf("expected the pre-renewal etag to still match after an unchanged "+
			"renewal, which is the whole point of this test: %v", err)
	}

	// And the fix, demonstrated: vary the bytes and the etag moves, so the old
	// one is refused.
	moved, err := c.PutIfMatch(ctx, key, []byte(`{"holder":"a","expires":1}`), first, objstore.PutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if moved == first {
		t.Fatal("writing different bytes left the etag unchanged; compare-and-swap cannot work on this store")
	}
	if _, err := c.PutIfMatch(ctx, key, []byte(`{"holder":"b"}`), first, objstore.PutOptions{}); !errors.Is(err, objstore.ErrPreconditionFailed) {
		t.Fatalf("a genuinely stale etag was accepted: %v", err)
	}
}
