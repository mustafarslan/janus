package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// The incremental checks replaced ones that read the whole log every round. That
// trade is only sound if the cheaper checks still refuse everything the
// expensive ones refused, so each of these breaks the log in a specific way and
// requires the refusal — a check nobody has watched fail is not a check.

func writeLog(t *testing.T, events int, segBytes int64) (string, *keys.Signer) {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	a, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, SegmentTargetBytes: segBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range events {
		if _, err := a.Append(context.Background(), evidence.Request{
			Kind:        evidence.KindStepResult,
			SagaID:      "sg_soak",
			Participant: evidence.ParticipantRef{ID: "ag"},
			Payload:     fmt.Appendf(nil, `{"i":%d,"pad":"%060d"}`, i, i),
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, signer
}

func newTestEpoch(t *testing.T, dir string, signer *keys.Signer) *epoch {
	t.Helper()
	e, err := newEpoch(1, filepath.Dir(dir), keys.PublicKeySet{signer.KeyID(): signer.Public()}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// newEpoch derives the directory name; the fixture already chose it.
	e.dir = dir
	return e
}

func TestAScanCountsEveryRecordExactlyOnce(t *testing.T) {
	dir, signer := writeLog(t, 300, 2048)
	e := newTestEpoch(t, dir, signer)

	if err := e.scanNew(); err != nil {
		t.Fatalf("a clean log was refused: %v", err)
	}
	first := e.events
	if first == 0 {
		t.Fatal("the scan found no events in a log that has 300")
	}

	// Scanning again with nothing new must not move the counters. Double-counting
	// here would inflate every figure the soak reports for the rest of the run.
	if err := e.scanNew(); err != nil {
		t.Fatalf("re-scanning an unchanged log was refused: %v", err)
	}
	if e.events != first {
		t.Fatalf("re-scanning an unchanged log counted its records again: %d then %d", first, e.events)
	}
}

func TestAGapInTheSequenceIsRefused(t *testing.T) {
	dir, signer := writeLog(t, 400, 2048)
	e := newTestEpoch(t, dir, signer)

	ids, err := segment.ScanComplete(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) < 3 {
		t.Fatalf("the fixture needs several segments to lose one from the middle, got %d", len(ids))
	}
	// Lose a segment from the middle: every sequence it held goes with it.
	if err := os.Remove(segment.Path(dir, ids[len(ids)/2])); err != nil {
		t.Fatal(err)
	}

	err = e.scanNew()
	if err == nil {
		t.Fatal("a log missing a whole segment from the middle was accepted; " +
			"the incremental check is not equivalent to the full one it replaced")
	}
	if !strings.Contains(err.Error(), "INTEGRITY VIOLATION") {
		t.Fatalf("the refusal does not name what it found: %v", err)
	}
}

// TestALogThatResumesBehindWhereItLeftOffIsRefused covers the other half of the
// contiguity argument. The count check catches records missing from the middle
// of the new range; this catches a new range that does not begin where the last
// one ended — records already counted being presented as new, which is the shape
// a recovery that resumed from the wrong point produces.
//
// The assertion is on the message, not just on failure, because a weakened
// version still fails here for the wrong reason: with the lower bound gone, the
// count check subtracts a larger head from a smaller one and refuses on unsigned
// underflow. Refusing by accident is not the same as refusing, and the next
// person to touch this needs to see which guard fired.
func TestALogThatResumesBehindWhereItLeftOffIsRefused(t *testing.T) {
	dir, signer := writeLog(t, 200, 2048)
	e := newTestEpoch(t, dir, signer)

	e.highSeq = 500
	err := e.scanNew()
	if err == nil {
		t.Fatal("a log that starts again behind the previous round's head was accepted")
	}
	if !strings.Contains(err.Error(), "resumes at") {
		t.Fatalf("the lower-bound guard did not fire; something else refused this: %v", err)
	}
}

func TestADuplicateSequenceIsRefused(t *testing.T) {
	dir, signer := writeLog(t, 400, 2048)
	e := newTestEpoch(t, dir, signer)

	ids, err := segment.ScanComplete(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) < 3 {
		t.Fatalf("the fixture needs several segments, got %d", len(ids))
	}
	// Replay an early segment's records under a later segment's name — the shape
	// a recovery that resumed from the wrong point would leave behind.
	blob, err := os.ReadFile(segment.Path(dir, ids[0]))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segment.Path(dir, ids[len(ids)-1]+1), blob, 0o600); err != nil {
		t.Fatal(err)
	}

	err = e.scanNew()
	if err == nil {
		t.Fatal("a log holding the same sequence number twice was accepted")
	}
	if !strings.Contains(err.Error(), "appears twice") {
		t.Fatalf("the refusal does not name what it found: %v", err)
	}
}

func TestAnAcknowledgementBeyondTheLogIsRefused(t *testing.T) {
	dir, signer := writeLog(t, 200, 2048)
	e := newTestEpoch(t, dir, signer)

	if err := e.scanNew(); err != nil {
		t.Fatal(err)
	}

	// The parent saw an acknowledgement for a sequence the log does not hold.
	// That is an append having returned success for an event that did not
	// survive, which is the one failure this whole harness exists to catch.
	e.ackedHigh = e.highSeq + 1
	_, err := e.check(context.Background(), 0)
	if err == nil {
		t.Fatal("an acknowledged sequence past the head of the log was accepted")
	}
	if !strings.Contains(err.Error(), "DURABILITY VIOLATION") {
		t.Fatalf("the refusal does not name what it found: %v", err)
	}
}

// TestTheSweepOutpacesTheLogItIsSweeping is the arithmetic that decides whether
// history is checked at all. The sweep is chasing a target that is still moving:
// if a round's slice is no bigger than what a round adds, the cursor gains
// nothing and a full pass never lands.
func TestTheSweepOutpacesTheLogItIsSweeping(t *testing.T) {
	const (
		segments = 1000
		rounds   = 50
		elapsed  = 50 * time.Second // one second per round
		period   = 10 * time.Second
	)
	growth := segments / rounds // 20 segments per round

	size := sweepSlice(segments, period, elapsed, rounds)
	if size <= growth {
		t.Fatalf("a slice of %d segments cannot outpace %d new ones per round, "+
			"so the sweep would crawl and history would go unverified", size, growth)
	}

	// And it must actually finish inside the period: ten rounds fit in ten
	// seconds, and in those the cursor has to cover the log plus what arrives.
	roundsPerSweep := int(period / (elapsed / rounds))
	if covered := size * roundsPerSweep; covered < segments+growth*roundsPerSweep {
		t.Fatalf("in %d rounds the sweep covers %d segments, short of the %d it needs "+
			"to finish a pass over a log growing by %d a round",
			roundsPerSweep, covered, segments+growth*roundsPerSweep, growth)
	}
}

func TestTheSweepIsSkippedWhenItIsTurnedOff(t *testing.T) {
	if got := sweepSlice(1000, 0, time.Minute, 50); got != 0 {
		t.Fatalf("-sweep-period 0 must disable the sweep, got a slice of %d", got)
	}
}

// TestAnEpochRotationDoesNotSwallowSweepPasses is the regression test for the
// bug that made the 72-hour gate run report a 13h30m8s detection latency
// against a 15m0s ask.
//
// The pass counter lives on the epoch's verifier and restarts at zero when the
// epoch is retired. Counting with a single running maximum across the run — the
// obvious implementation, and the one that shipped — therefore records nothing
// from the moment of a rotation until the new epoch has completed more passes
// than the retired one ever did. Both printed figures go wrong together: the
// count loses every swallowed pass, and the wait for the counter to catch up is
// attributed to one pass, which is then printed as how stale a reading of
// history can be.
//
// It fails on the old code for both reasons, which is why both are asserted.
func TestAnEpochRotationDoesNotSwallowSweepPasses(t *testing.T) {
	start := time.Now()
	l := &sweepLedger{last: start}

	// A long-lived first epoch completes sixty passes, one a minute.
	at := start
	for i := uint64(1); i <= 60; i++ {
		at = at.Add(time.Minute)
		l.observe(i, at)
	}
	l.rotate()

	// The next epoch outlives it and completes sixty-two, still one a minute.
	// It has to overtake the retired epoch's total for the latency half of this
	// test to bite: under the old code nothing is recorded until pass 61, and
	// the hour of silence before it is then reported as one very slow pass.
	for i := uint64(1); i <= 62; i++ {
		at = at.Add(time.Minute)
		l.observe(i, at)
	}

	if got := l.total(); got != 122 {
		t.Fatalf("the run completed 122 sweep passes but the ledger counted %d; "+
			"passes made after a rotation are being discarded, and the summary "+
			"understates how often history was re-read", got)
	}
	if got := l.slowest(); got != time.Minute {
		t.Fatalf("every pass took a minute but the slowest is recorded as %s; "+
			"the wait for the new epoch's counter to overtake the old one has "+
			"been billed to a single pass, and that figure is printed as the "+
			"detection latency for tampering with history", got)
	}
}

// TestSweepPassesAreCountedOncePerEpochRotation guards the other direction: the
// ledger must not double-count by adding a live counter to a total that already
// includes it.
func TestSweepPassesAreCountedOncePerEpochRotation(t *testing.T) {
	at := time.Now()
	l := &sweepLedger{last: at}

	at = at.Add(time.Minute)
	l.observe(5, at)
	l.rotate()

	if got := l.total(); got != 5 {
		t.Fatalf("five passes were completed before the rotation, ledger says %d", got)
	}

	// The verifier reports the same number again from a fresh epoch. That is a
	// new epoch's first five passes, not the old epoch's five a second time.
	at = at.Add(time.Minute)
	l.observe(5, at)
	if got := l.total(); got != 10 {
		t.Fatalf("five passes either side of a rotation is ten, ledger says %d", got)
	}
}
