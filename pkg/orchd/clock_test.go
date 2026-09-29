package orchd_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/clockatt"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/orchd"
)

// fakeClock is a time source that answers without a network.
//
// A real NTP query here would make the result depend on somebody else's server
// being up, which is the opposite of what a test of *our* wiring should measure.
type fakeClock struct {
	synced bool
	offset time.Duration
}

func (f fakeClock) Name() string { return "fake" }

func (f fakeClock) Attest(context.Context) clockatt.Attestation {
	return clockatt.Attestation{
		Source:         f.Name(),
		Synchronised:   f.synced,
		OffsetNanos:    int64(f.offset),
		RoundTripNanos: int64(2 * time.Millisecond),
		Stratum:        2,
		TakenAt:        time.Now().UTC(),
	}
}

// clockDaemon starts a daemon with the given time sources.
func clockDaemon(t *testing.T, sources ...clockatt.Source) (*orchd.Server, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)

	policy, err := gate.LoadPolicyFile("../../docs/policy/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: policy,
		ClockSources: sources,
		// Long enough that the only attestation is the one taken at startup: a
		// ticker firing mid-test would make the counts non-deterministic.
		ClockInterval: time.Hour,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}

// TestEventsPointAtAClockAttestation is the check that was missing.
//
// `pkg/evidence/clockatt` was written, tested and connected to nothing, so every
// event Janus wrote carried an empty attestation reference — and every test
// passed, because no test asked. This one asks, and asks properly: the reference
// has to be present *and* resolve to a CLOCK_ATTESTATION that is actually in the
// log. Asserting only that it is non-empty would pass on a reference pointing at
// nothing, which is the same shape of hollow control in a smaller box.
//
// Only events after the first attestation are held to it. The registry history
// is written before the daemon opens the directory, so those records have no
// attestation to point at and saying otherwise would be a lie about ordering.
func TestEventsPointAtAClockAttestation(t *testing.T) {
	s, dir := clockDaemon(t, fakeClock{synced: true, offset: 3 * time.Millisecond})
	beginGatedPlan(t, s, context.Background())

	attestations := map[string]bool{}
	var firstAttestation uint64
	var pointed, unpointed int

	if err := evidence.Walk(dir, func(h evidence.EventHeader, _ segment.Record) error {
		if h.Kind == evidence.KindClockAttestation {
			attestations[h.EventID] = true
			if firstAttestation == 0 {
				firstAttestation = h.Seq
			}
			return nil
		}
		if firstAttestation == 0 || h.Seq < firstAttestation {
			return nil
		}
		if h.TS.ClockAttestationRef == "" {
			unpointed++
			t.Errorf("event %s (%s) at seq %d carries no attestation reference",
				h.EventID, h.Kind, h.Seq)
			return nil
		}
		pointed++
		if !attestations[h.TS.ClockAttestationRef] {
			t.Errorf("event %s (%s) names attestation %q, which is not in the log",
				h.EventID, h.Kind, h.TS.ClockAttestationRef)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if len(attestations) == 0 {
		t.Fatal("no CLOCK_ATTESTATION was recorded: the monitor is not wired to the log")
	}
	if pointed == 0 {
		t.Fatal("no event points at a clock attestation — which is exactly the state " +
			"this wiring exists to end, and what every earlier test tolerated")
	}
	if unpointed != 0 {
		t.Errorf("%d events appended after the first attestation carry no reference to it",
			unpointed)
	}
}

// TestALaterAttestationPointsAtTheOneBeforeIt pins behaviour the prose got wrong
// on the first attempt.
//
// The appender stamps the current reference on every event in a batch, with no
// exemption by kind — so the *first* attestation carries none and every later
// one points at its predecessor. The design originally claimed attestations carried
// no reference at all, which was a statement about intent rather than about the
// code. This test is here so the next person reads the behaviour rather than the
// intention, and so a kind-exemption cannot be added without something failing.
func TestALaterAttestationPointsAtTheOneBeforeIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifest(t, dir, signer)
	policy, err := gate.LoadPolicyFile("../../docs/policy/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: policy,
		ClockSources:  []clockatt.Source{fakeClock{synced: true}},
		ClockInterval: 20 * time.Millisecond,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Let the ticker fire a few times, then close before reading: the log is
	// only walked once nobody is writing to it, so this test says nothing about
	// live reads and cannot fail for their reasons.
	time.Sleep(300 * time.Millisecond)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	var attestations []evidence.EventHeader
	if err := evidence.Walk(dir, func(h evidence.EventHeader, _ segment.Record) error {
		if h.Kind == evidence.KindClockAttestation {
			attestations = append(attestations, h)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if len(attestations) < 2 {
		t.Fatalf("only %d attestations after 300ms at a 20ms interval: the monitor is not ticking",
			len(attestations))
	}
	if attestations[0].TS.ClockAttestationRef != "" {
		t.Errorf("the first attestation points at %q; nothing precedes it",
			attestations[0].TS.ClockAttestationRef)
	}
	if got := attestations[1].TS.ClockAttestationRef; got != attestations[0].EventID {
		t.Errorf("the second attestation points at %q, want the first (%s)",
			got, attestations[0].EventID)
	}
}

// TestAnUnreachableClockIsRecordedRatherThanOmitted is the honest-failure half.
//
// A deployment whose time source is down must still say so on the record. The
// failure guarded against is a daemon that treats an unreachable source as "no
// attestation needed", which reads in a log exactly like a deployment that was
// never configured to check its clock at all.
func TestAnUnreachableClockIsRecordedRatherThanOmitted(t *testing.T) {
	_, dir := clockDaemon(t, fakeClock{synced: false})

	var found bool
	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		if h.Kind == evidence.KindClockAttestation {
			found = true
			if len(rec.Payload) == 0 {
				t.Error("the attestation has no payload, so it states nothing")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("an unsynchronised clock recorded nothing: an absent attestation is " +
			"indistinguishable from one nobody bothered to take")
	}
}

// TestNoClockSourceRecordsNoAttestation keeps the default honest.
//
// Configuring no source must mean no attestation and no reference, rather than a
// quiet default pointing at somebody's NTP server. The negative earns
// a test because the failure would be silent and would put an external
// dependency in the write path of every air-gapped deployment.
func TestNoClockSourceRecordsNoAttestation(t *testing.T) {
	s, dir := clockDaemon(t)
	beginGatedPlan(t, s, context.Background())

	if err := evidence.Walk(dir, func(h evidence.EventHeader, _ segment.Record) error {
		if h.Kind == evidence.KindClockAttestation {
			t.Errorf("an attestation was recorded with no source configured")
		}
		if h.TS.ClockAttestationRef != "" {
			t.Errorf("event %s names attestation %q with no source configured",
				h.EventID, h.TS.ClockAttestationRef)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
