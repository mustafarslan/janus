package saga_test

import (
	"context"
	"errors"
	"os"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/saga"
)

// A coordinator resuming a saga reads the log while its own appender is
// running, and the appender creates the next segment ahead of time so that a
// rotation does not stall writes. The reader can therefore see a file
// that is part-way through becoming a segment.
//
// It has to skip it rather than refuse. Nothing was ever acknowledged on the
// authority of a segment with no header, so there is no record to miss — and
// refusing would mean a healthy log became unreadable for as long as it took to
// create a file. This was found by the saga chaos suite on Linux, where a
// SIGKILL landed inside that window; the state is built by hand here because a
// test that depends on losing a race only fails on the machines that lose it.
func TestReadingSkipsASegmentThatIsNotASegmentYet(t *testing.T) {
	app, dir, _ := newLog(t)
	ctx := context.Background()
	r := saga.NewRunner(app, evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1", Principal: "pr_1"})
	if _, err := r.Begin(ctx, &janusv1.SagaBegin{
		SagaId: "sg_probe", Plan: []*janusv1.PlannedStep{
			{StepId: "s1", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PrepareStep(ctx, &janusv1.StepPrepare{SagaId: "sg_probe", StepId: "s1"}); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	before, err := saga.LoadEvents(dir, "sg_probe")
	if err != nil {
		t.Fatal(err)
	}

	ids, err := segment.ScanDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	next := segment.Path(dir, ids[len(ids)-1]+1)

	// Every length a partially-created segment can have, including zero.
	for _, size := range []int{0, 1, 8, segment.HeaderSize - 1} {
		if err := os.WriteFile(next, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := saga.LoadEvents(dir, "sg_probe")
		if err != nil {
			t.Fatalf("a %d-byte placeholder made the log unreadable: %v", size, err)
		}
		if len(got) != len(before) {
			t.Fatalf("a %d-byte placeholder changed the history: %d events, want %d",
				size, len(got), len(before))
		}
	}

	// A file that *is* long enough to be a segment must still be inspected
	// rather than skipped, or a truncated segment would be silently ignored.
	if err := os.WriteFile(next, make([]byte, segment.HeaderSize+16), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := saga.LoadEvents(dir, "sg_probe"); err == nil {
		t.Fatal("a header-sized file of zeroes was accepted as a valid segment")
	}
}

// A torn tail is reported through a sentinel a caller can test for, not only as
// a sentence.
//
// The distinction matters because the two things that produce a torn tail are
// not the same event. One is a crash, and the log genuinely needs recovering.
// The other is a reader arriving while the appender is mid-write: `segment.Writer`
// buffers through a bufio.Writer that flushes when its buffer fills, at a byte
// boundary rather than a record boundary, so a concurrent reader can see half a
// record in a log that is entirely healthy. `janus-latency` reproduces the
// second reliably at concurrency 8.
//
// Reading past either is unsafe, so both still refuse; what the sentinel buys is
// a caller able to say which situation it is in rather than telling an operator
// to run recovery on a log that does not need it. This test exists because the
// wrap is a single `%w` that a later edit to the message would silently drop,
// and the callers relying on it would go back to matching a string.
func TestATornTailIsReportedAsTheSentinel(t *testing.T) {
	app, dir, _ := newLog(t)
	ctx := context.Background()
	r := saga.NewRunner(app, evidence.ParticipantRef{ID: "ag_1", ManifestVersion: "1", Principal: "pr_1"})
	if _, err := r.Begin(ctx, &janusv1.SagaBegin{
		SagaId: "sg_torn", Plan: []*janusv1.PlannedStep{
			{StepId: "s1", EffectClass: janusv1.EffectClass_EFFECT_CLASS_PURE},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PrepareStep(ctx, &janusv1.StepPrepare{SagaId: "sg_torn", StepId: "s1"}); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	// Lop a few bytes off the end, which is what a reader sees when it arrives
	// between a partial flush and the rest of the record.
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := segment.Path(dir, ids[len(ids)-1])
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()-4); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"LoadEvents", func() error { _, err := saga.LoadEvents(dir, "sg_torn"); return err }},
		{"ReplayAll", func() error { _, err := saga.ReplayAll(dir); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("a torn segment was read without complaint")
			}
			if !errors.Is(err, segment.ErrTornTail) {
				t.Fatalf("a torn tail did not carry segment.ErrTornTail, so a caller "+
					"cannot tell it apart from any other replay failure: %v", err)
			}
		})
	}
}
