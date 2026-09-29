package replica_test

import (
	"context"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/replica"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// counting wraps a Source and counts the round trips a pass makes.
//
// A decorator in the test rather than a counter in the Follower: what is being
// measured is the *shape* of a pass — how many calls it makes and what they
// scale with — and that is a property of the interface, so it is measured at
// the interface. Nothing in production carries a counter for this.
type counting struct {
	inner             replica.Source
	head, segs, reads int
	bytes             int64
}

func (c *counting) Head(ctx context.Context) (replica.Head, error) {
	c.head++
	return c.inner.Head(ctx)
}

func (c *counting) Segments(ctx context.Context) ([]uint64, error) {
	c.segs++
	return c.inner.Segments(ctx)
}

func (c *counting) Read(ctx context.Context, id uint64, off int64, max int) (replica.Chunk, error) {
	c.reads++
	ch, err := c.inner.Read(ctx, id, off, max)
	c.bytes += int64(len(ch.Bytes))
	return ch, err
}

func (c *counting) reset() { c.head, c.segs, c.reads, c.bytes = 0, 0, 0, 0 }

// settle waits for the primary's directory to stop changing.
//
// A rotation swaps in a segment file that was created *in the background*
// (creating it on the writer goroutine cost about a third of
// throughput), so an Append can be acknowledged before the file for the segment
// after it exists. A count taken without waiting pins whichever of the two the
// race produced, which is how a test ends up asserting a number that is right
// most of the time.
func settle(t *testing.T, dir string) []uint64 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	prev, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		now, err := segment.ScanDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(now) == len(prev) {
			return now
		}
		prev = now
	}
	t.Fatalf("the primary's directory was still changing after 5s")
	return nil
}
func (c *counting) trips() int { return c.head + c.segs + c.reads }

// countedFollower mirrors a primary through a counting source.
func countedFollower(t *testing.T, src replica.Source, chunk int) (*replica.Follower, *counting) {
	t.Helper()
	c := &counting{inner: src}
	f, err := replica.New(replica.Options{
		Dir: t.TempDir() + "/replica", Source: c, ChunkBytes: chunk,
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

// A steady-state pass costs the same on a large log as on a small one.
//
// This is the number a production ticker interval is chosen from, and it had
// only ever been estimated — "a pass costs one head call, one segment
// listing and N reads", with the fold's ~1000 unnoticed round trips as the
// warning. The premise was wrong in the direction that matters: N reads is the
// *first* pass. A follower that is caught up reads from its cursor, and the
// cursor is the earliest segment that could still grow, so the segments below
// it are skipped whatever there are of them.
//
// Asserted as a comparison rather than as a constant. A hard 4 would fail for
// reasons that are not defects — a rotation landing mid-pass, a pre-created
// segment — and what has to hold is that the cost does not grow with the log.
func TestASteadyStatePassDoesNotScaleWithTheLog(t *testing.T) {
	cost := func(segments int) (trips int, bytes int64, segs int) {
		app, pdir, src, _ := primary(t, func(o *evidence.Options) {
			o.SegmentTargetBytes = 4 << 10
		})
		appendN(t, app, segments*8)
		ids := settle(t, pdir)
		f, c := countedFollower(t, src, 0)
		ctx := context.Background()
		if err := f.Follow(ctx); err != nil {
			t.Fatal(err)
		}
		c.reset()
		if err := f.Follow(ctx); err != nil {
			t.Fatal(err)
		}
		return c.trips(), c.bytes, len(ids)
	}

	small, smallBytes, smallSegs := cost(5)
	large, largeBytes, largeSegs := cost(250)
	t.Logf("idle pass: %d segments -> %d round trips, %d bytes; %d segments -> %d round trips, %d bytes",
		smallSegs, small, smallBytes, largeSegs, large, largeBytes)

	if largeSegs < smallSegs*4 {
		t.Fatalf("the two logs are %d and %d segments; the comparison needs them to differ",
			smallSegs, largeSegs)
	}
	if large != small {
		t.Fatalf("an idle pass costs %d round trips on %d segments and %d on %d: a pass that "+
			"grows with the log is a ticker interval that has to grow with it too",
			small, smallSegs, large, largeSegs)
	}
	// Pinned exactly, not bounded. A cap of "no more than a few" passes when
	// somebody adds one call per pass, which is how a count test ends up
	// measuring nothing — and this one did, until a break that should have gone
	// red did not. The four are: one Head, one Segments, one Read on the cursor
	// segment that comes back empty, and one Read of the segment the writer
	// pre-created for the next rotation.
	//
	// That last one re-fetches the same 32 bytes on every pass, forever, and
	// is left alone deliberately: followSegment resumes at a known offset only
	// for the cursor segment, and giving every segment a remembered offset
	// touches the truncate-if-longer path, which is the follower's hardest
	// rule. 32 bytes a pass is a price worth naming rather than paying a risk
	// to remove.
	const perPass = 4
	if large != perPass {
		t.Fatalf("an idle pass costs %d round trips, and it cost %d when this was measured "+
			"and written down. A call added to a pass is a cost multiplied by the ticker "+
			"rate on every follower", large, perPass)
	}
}

// A first pass scales with bytes, not with segments — which is where the
// unthrottled read actually lives.
//
// Halving the chunk doubles the reads over the same log. That is the whole
// point of stating it: 16 MiB segments and a 1 MiB default chunk make a first
// pass roughly 16 reads per segment, so a 100 GiB log is ~100,000 round trips
// and 100 GiB pulled as fast as the follower can ask for it. A throttle belongs
// there and nowhere else; the steady state above needs none.
func TestAFirstPassScalesWithBytesNotSegments(t *testing.T) {
	app, pdir, src, _ := primary(t, func(o *evidence.Options) {
		o.SegmentTargetBytes = 1 << 20
	})
	appendN(t, app, 6000)
	ids := settle(t, pdir)
	if len(ids) < 3 {
		t.Fatalf("the primary wrote %d segment(s); this needs several", len(ids))
	}

	first := func(chunk int) (reads int, bytes int64) {
		f, c := countedFollower(t, src, chunk)
		if err := f.Follow(context.Background()); err != nil {
			t.Fatal(err)
		}
		return c.reads, c.bytes
	}

	wide, wideBytes := first(256 << 10)
	narrow, narrowBytes := first(64 << 10)
	t.Logf("first pass over %d segments: %d reads at 256 KiB chunks, %d reads at 64 KiB — %d bytes either way",
		len(ids), wide, narrow, wideBytes)

	if wideBytes != narrowBytes {
		t.Fatalf("the two passes copied %d and %d bytes; they are the same log and the "+
			"comparison is only meaningful if the same bytes moved", wideBytes, narrowBytes)
	}
	// More than doubled, not quadrupled: the chunk is quartered, but each
	// segment's last read is a partial one whatever the chunk is, so the ratio
	// sits below four and moves with where the rotation boundaries fell. The
	// measured pair is 8 and 24; asserting 24 > 24 would be a threshold with no
	// margin, which fails on a log that scales perfectly.
	if narrow < wide*2 {
		t.Fatalf("quartering the chunk took the reads from %d to %d, and it should more than "+
			"double them; a first pass that does not scale with bytes is not reading in "+
			"chunks at all, and the throttle this measurement is for would be sized "+
			"against the wrong number", wide, narrow)
	}
	if wide <= len(ids) {
		t.Fatalf("a first pass over %d segments made %d reads: at %d KiB chunks over 1 MiB "+
			"segments it should take several reads per segment", len(ids), wide, 256)
	}
}
