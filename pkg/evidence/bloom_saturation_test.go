package evidence

import (
	"fmt"
	"log"
	"math"
	"strings"
	"testing"
)

// The estimate matches a measured false-positive rate, at the sizes the
// argument for deferring sidecars rests on.
//
// The filter's decay is the reason to build per-segment saga-id lists one
// day, and an earlier estimate put a number on it: "at roughly a
// million distinct saga ids the rate is about 1%". It is 1.76%, and the shape
// past that is what matters — 16.4% at two million, 77.1% at five, where the
// filter agrees with almost every question and the fallback scan is the common
// path again.
//
// Two things are asserted. That `fill^k` is what an operator can act on, which
// is what lets the appender report a rate without counting insertions it does
// not see (the filter is rebuilt from the log, not from this process's
// appends). And the three numbers themselves, so the entry's arithmetic cannot
// drift again without a test saying so.
func TestTheFilterReportsARateThatMatchesItsRealOne(t *testing.T) {
	for _, tc := range []struct {
		ids       int
		wantFPR   float64
		tolerance float64
	}{
		{1_000_000, 0.0176, 0.004},
		{2_000_000, 0.1638, 0.01},
	} {
		t.Run(fmt.Sprintf("%d", tc.ids), func(t *testing.T) {
			b := newBloom(bloomBits, bloomHashes)
			for i := range tc.ids {
				b.add(fmt.Sprintf("sg_%d", i))
			}
			fill, estimated := b.saturation()

			const trials = 100_000
			fp := 0
			for i := range trials {
				if b.mayContain(fmt.Sprintf("never_%d", i)) {
					fp++
				}
			}
			measured := float64(fp) / float64(trials)
			t.Logf("%d ids: fill %.4f, estimated %.4f, measured %.4f", tc.ids, fill, estimated, measured)

			if math.Abs(estimated-measured) > tc.tolerance {
				t.Fatalf("the filter estimates %.4f and really answers %.4f: the number the "+
					"appender warns on is not the number an operator would measure",
					estimated, measured)
			}
			if math.Abs(measured-tc.wantFPR) > tc.tolerance {
				t.Fatalf("%d ids give a false-positive rate of %.4f, and %.4f is what the sizing "+
					"analysis and the size constant were written against", tc.ids, measured, tc.wantFPR)
			}
		})
	}
}

// The decay is said out loud, once per threshold.
//
// This is the whole point: a filter that fills produces no wrong answers and no
// errors, so without a line somewhere the first symptom is an incident. A
// warning that repeats is a warning that gets filtered, so each threshold is
// reported once — and a filter that has not decayed says nothing at all, which
// is the half that keeps the first half readable.
func TestTheFilterSaysWhenItHasDecayed(t *testing.T) {
	var sb strings.Builder
	restore := captureLog(t, &sb)

	x := newSagaIndex(1024)
	// 5% is fill^5, so a fill of 0.549, which is about 1.34M ids: the loop runs
	// past that and not much past it.
	for i := range 1_500_000 {
		x.append(fmt.Sprintf("sg_%d", i), Location{Segment: 1, Offset: int64(i)})
	}
	restore()

	out := sb.String()
	if n := strings.Count(out, "saga filter is"); n != 1 {
		t.Fatalf("the locator warned %d time(s) crossing one threshold, want 1:\n%s", n, out)
	}
	if !strings.Contains(out, "full") || !strings.Contains(out, "false-positive rate") {
		t.Fatalf("the warning does not say how full or how wrong: %q", out)
	}

	var quiet strings.Builder
	restore = captureLog(t, &quiet)
	y := newSagaIndex(1024)
	for i := range 200_000 {
		y.append(fmt.Sprintf("sg_%d", i), Location{Segment: 1, Offset: int64(i)})
	}
	restore()
	if quiet.Len() != 0 {
		t.Fatalf("a filter at %.2f%% fill warned anyway: %q — a line that appears on a "+
			"healthy log is a line nobody reads on a decayed one",
			mustFill(y)*100, quiet.String())
	}
}

func mustFill(x *sagaIndex) float64 {
	fill, _ := x.Saturation()
	return fill
}

// captureLog redirects the standard logger and returns the restore.
func captureLog(t *testing.T, into *strings.Builder) func() {
	t.Helper()
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(into)
	log.SetFlags(0)
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	}
	t.Cleanup(restore)
	return restore
}
