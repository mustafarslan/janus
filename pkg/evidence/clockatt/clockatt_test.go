package clockatt_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/clockatt"
)

// fakeNTP serves synthetic NTP responses so the parsing and the offset
// arithmetic can be tested without depending on a public time server — which
// would make the suite flaky and, worse, would leave the sign convention
// untested because the real offset is always near zero.
type fakeNTP struct {
	conn *net.UDPConn
	// skew is how far ahead of the local clock the fake server claims to be.
	skew time.Duration
	// leap and stratum let a test produce an unusable response.
	leap    byte
	stratum byte
	wg      sync.WaitGroup
}

func startFakeNTP(t *testing.T, skew time.Duration, leap, stratum byte) *fakeNTP {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeNTP{conn: conn, skew: skew, leap: leap, stratum: stratum}
	f.wg.Add(1)
	go f.serve()
	t.Cleanup(func() {
		_ = conn.Close()
		f.wg.Wait()
	})
	return f
}

func (f *fakeNTP) addr() string { return f.conn.LocalAddr().String() }

func (f *fakeNTP) serve() {
	defer f.wg.Done()
	buf := make([]byte, 48)
	for {
		n, peer, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 48 {
			continue
		}
		now := time.Now().Add(f.skew)
		resp := make([]byte, 48)
		resp[0] = f.leap<<6 | 4<<3 | 4 // leap, version 4, mode 4 (server)
		resp[1] = f.stratum
		copy(resp[12:16], []byte("GPS "))
		writeNTPTime(resp[32:40], now) // receive
		writeNTPTime(resp[40:48], now) // transmit
		if _, err := f.conn.WriteToUDP(resp, peer); err != nil {
			return
		}
	}
}

const ntpEpochOffset = 2208988800

func writeNTPTime(b []byte, t time.Time) {
	secs := uint32(t.Unix() + ntpEpochOffset)
	frac := uint32((int64(t.Nanosecond()) << 32) / 1e9)
	binary.BigEndian.PutUint32(b[0:4], secs)
	binary.BigEndian.PutUint32(b[4:8], frac)
}

// TestOffsetSignAndMagnitude pins the convention. Getting the sign backwards
// would be invisible in production, where the real offset is near zero, and
// would then mislead whoever eventually reads an attestation during an
// investigation.
func TestOffsetSignAndMagnitude(t *testing.T) {
	// The server claims to be two seconds ahead, so the local clock is two
	// seconds behind and the reported offset should be about -2s.
	srv := startFakeNTP(t, 2*time.Second, 0, 2)
	src := clockatt.NTPSource{Server: srv.addr(), Timeout: 2 * time.Second}

	att := src.Attest(context.Background())
	if !att.Synchronised {
		t.Fatalf("attestation failed: %s", att.Err)
	}
	off := att.Offset()
	if off > -1900*time.Millisecond || off < -2100*time.Millisecond {
		t.Fatalf("offset is %s, want about -2s (local behind a server that is ahead)", off)
	}
	if att.Stratum != 2 {
		t.Fatalf("stratum is %d, want 2", att.Stratum)
	}
	if att.RoundTripNanos < 0 {
		t.Fatalf("round trip is negative: %d", att.RoundTripNanos)
	}
	if att.TakenAt.IsZero() {
		t.Fatal("attestation has no timestamp")
	}
}

func TestOffsetWhenLocalIsAhead(t *testing.T) {
	srv := startFakeNTP(t, -3*time.Second, 0, 3)
	src := clockatt.NTPSource{Server: srv.addr(), Timeout: 2 * time.Second}

	att := src.Attest(context.Background())
	if !att.Synchronised {
		t.Fatalf("attestation failed: %s", att.Err)
	}
	if off := att.Offset(); off < 2900*time.Millisecond || off > 3100*time.Millisecond {
		t.Fatalf("offset is %s, want about +3s (local ahead of the reference)", off)
	}
}

// TestUnreachableServerIsRecordedNotThrown: a deployment that cannot reach a
// time source needs that on the record, so the failure has to produce an
// attestation rather than an error.
func TestUnreachableServerIsRecordedNotThrown(t *testing.T) {
	// Port 1 on loopback: nothing listens, and the reply never arrives.
	src := clockatt.NTPSource{Server: "127.0.0.1:1", Timeout: 200 * time.Millisecond}
	att := src.Attest(context.Background())

	if att.Synchronised {
		t.Fatal("an unreachable server produced a synchronised attestation")
	}
	if att.Err == "" {
		t.Fatal("no reason was recorded for the failure")
	}
	if att.TakenAt.IsZero() {
		t.Fatal("a failed attestation still has to say when it was attempted")
	}
	if !strings.Contains(att.Summary(), "UNSYNCHRONISED") {
		t.Fatalf("summary does not flag the failure: %s", att.Summary())
	}
}

// TestServerThatDisclaimsSynchronisationIsRejected: leap indicator 3 means the
// server itself is not synchronised, so its time is not evidence.
func TestServerThatDisclaimsSynchronisationIsRejected(t *testing.T) {
	srv := startFakeNTP(t, 0, 3, 2)
	src := clockatt.NTPSource{Server: srv.addr(), Timeout: 2 * time.Second}

	att := src.Attest(context.Background())
	if att.Synchronised {
		t.Fatal("accepted time from a server that reports itself unsynchronised")
	}
	if !strings.Contains(att.Err, "unsynchronised") {
		t.Fatalf("error does not explain the rejection: %s", att.Err)
	}
}

// TestKissOfDeathIsRejected: stratum 0 is a control response, not a time.
func TestKissOfDeathIsRejected(t *testing.T) {
	srv := startFakeNTP(t, 0, 0, 0)
	src := clockatt.NTPSource{Server: srv.addr(), Timeout: 2 * time.Second}

	att := src.Attest(context.Background())
	if att.Synchronised {
		t.Fatal("accepted a stratum 0 response as a time source")
	}
	if !strings.Contains(att.Err, "stratum") {
		t.Fatalf("error does not name the reason: %s", att.Err)
	}
}

// TestWithinToleranceCountsUncertaintyAgainstItself: a compliance claim should
// not depend on a measurement being luckier than it can prove to be.
func TestWithinToleranceCountsUncertaintyAgainstItself(t *testing.T) {
	att := clockatt.Attestation{
		Synchronised:   true,
		OffsetNanos:    int64(800 * time.Millisecond),
		RoundTripNanos: int64(600 * time.Millisecond), // ±300ms
	}
	// 800ms + 300ms = 1.1s, so a 1s tolerance is not met even though the
	// measured offset alone is inside it.
	if att.WithinTolerance(time.Second) {
		t.Fatal("tolerance was met by ignoring the measurement uncertainty")
	}
	if !att.WithinTolerance(1200 * time.Millisecond) {
		t.Fatal("tolerance was not met when offset plus uncertainty fits")
	}

	// Negative offsets count the same.
	att.OffsetNanos = -int64(800 * time.Millisecond)
	if att.WithinTolerance(time.Second) {
		t.Fatal("a negative offset escaped the tolerance check")
	}

	unsynced := clockatt.Attestation{Synchronised: false}
	if unsynced.WithinTolerance(time.Hour) {
		t.Fatal("an unsynchronised clock was reported as within tolerance")
	}
}

// TestUnavailableSourceRecordsTheFact: an air-gapped install genuinely cannot
// reach NTP, and the honest artefact says so rather than being absent.
func TestUnavailableSourceRecordsTheFact(t *testing.T) {
	src := clockatt.UnavailableSource{Reason: "air-gapped deployment, no time source"}
	att := src.Attest(context.Background())

	if att.Synchronised {
		t.Fatal("the unavailable source claimed synchronisation")
	}
	if !strings.Contains(att.Err, "air-gapped") {
		t.Fatalf("the stated reason was lost: %s", att.Err)
	}
	if att.TakenAt.IsZero() {
		t.Fatal("no timestamp on the attestation")
	}

	// And with no reason given, it still says something useful.
	bare := clockatt.UnavailableSource{}.Attest(context.Background())
	if bare.Err == "" {
		t.Fatal("an unavailable source with no configured reason recorded nothing")
	}
}

// TestMonitorFallsBackToTheNextSource: listing several servers is how a
// deployment survives one being down without losing attestation entirely.
func TestMonitorFallsBackToTheNextSource(t *testing.T) {
	good := startFakeNTP(t, 0, 0, 2)
	m, err := clockatt.New(clockatt.Config{
		Sources: []clockatt.Source{
			clockatt.NTPSource{Server: "127.0.0.1:1", Timeout: 200 * time.Millisecond},
			clockatt.NTPSource{Server: good.addr(), Timeout: 2 * time.Second},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	att := m.Attest(context.Background())
	if !att.Synchronised {
		t.Fatalf("the monitor did not fall back to the working source: %s", att.Err)
	}
	latest, ok := m.Latest()
	if !ok || !latest.Synchronised {
		t.Fatal("the monitor did not retain the successful attestation")
	}
}

// TestMonitorRecordsFailureWhenEverySourceIsDown.
func TestMonitorRecordsFailureWhenEverySourceIsDown(t *testing.T) {
	var seen []clockatt.Attestation
	var breaches int
	m, err := clockatt.New(clockatt.Config{
		Sources: []clockatt.Source{
			clockatt.NTPSource{Server: "127.0.0.1:1", Timeout: 150 * time.Millisecond},
			clockatt.NTPSource{Server: "127.0.0.1:2", Timeout: 150 * time.Millisecond},
		},
		OnAttestation: func(a clockatt.Attestation) { seen = append(seen, a) },
		OnBreach:      func(clockatt.Attestation) { breaches++ },
	})
	if err != nil {
		t.Fatal(err)
	}

	att := m.Attest(context.Background())
	if att.Synchronised {
		t.Fatal("all sources were down but the attestation claims synchronisation")
	}
	if len(seen) != 1 {
		t.Fatalf("OnAttestation fired %d times, want 1", len(seen))
	}
	if breaches != 1 {
		t.Fatalf("OnBreach fired %d times; a clock that cannot be checked is a breach", breaches)
	}
}

func TestMonitorRequiresASource(t *testing.T) {
	if _, err := clockatt.New(clockatt.Config{}); err == nil {
		t.Fatal("a monitor was built with nothing to query")
	}
}

func TestMonitorRefRoundTrip(t *testing.T) {
	m, err := clockatt.New(clockatt.Config{
		Sources: []clockatt.Source{clockatt.UnavailableSource{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Ref() != "" {
		t.Fatal("a fresh monitor reported an attestation reference")
	}
	m.SetRef("ev_0001")
	if m.Ref() != "ev_0001" {
		t.Fatalf("reference is %q, want ev_0001", m.Ref())
	}
}

// TestRunAttestsImmediately: a process must never serve events with no clock
// statement at all while waiting for the first tick.
func TestRunAttestsImmediately(t *testing.T) {
	srv := startFakeNTP(t, 0, 0, 2)
	m, err := clockatt.New(clockatt.Config{
		Sources:  []clockatt.Source{clockatt.NTPSource{Server: srv.addr(), Timeout: time.Second}},
		Interval: time.Hour, // far longer than the test runs
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()

	deadline := time.After(3 * time.Second)
	for {
		if _, ok := m.Latest(); ok {
			break
		}
		select {
		case <-deadline:
			cancel()
			t.Fatal("Run did not take an attestation before its first tick")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop when its context was cancelled")
	}
}

func TestAttestationPayloadIsStable(t *testing.T) {
	att := clockatt.Attestation{
		Source: "ntp:pool.example", Synchronised: true,
		OffsetNanos: 1234, RoundTripNanos: 5678, Stratum: 2,
		ReferenceID: "GPS", TakenAt: time.Unix(1753430400, 0).UTC(),
	}
	first, err := att.Payload()
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, err := att.Payload()
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatal("the attestation payload does not encode deterministically, so it cannot be chained")
		}
	}
	if !strings.Contains(string(first), "ntp:pool.example") {
		t.Fatalf("payload lost the source: %s", first)
	}
}

// TestTheMonitorRecordsTheDeclaredTolerance.
//
// The bound a deployment claims to be holding was configuration and nothing
// else: `janus-orchd -clock-tolerance` reached the monitor, fired OnBreach, and
// never touched the record. A log therefore could not say what its operator
// claimed, and a reader could only fall back to RTS 25's one-second ceiling —
// so a deployment that declared 100 ms read as satisfied without that figure
// ever having been tested.
func TestTheMonitorRecordsTheDeclaredTolerance(t *testing.T) {
	srv := startFakeNTP(t, 0, 0, 2)
	m, err := clockatt.New(clockatt.Config{
		Sources:   []clockatt.Source{clockatt.NTPSource{Server: srv.addr(), Timeout: time.Second}},
		Tolerance: 250 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	att := m.Attest(context.Background())
	if !att.Synchronised {
		t.Fatalf("the fake server did not answer: %s", att.Err)
	}
	tol, ok := att.DeclaredTolerance()
	if !ok || tol != 250*time.Millisecond {
		t.Fatalf("the attestation declares tolerance %s (recorded=%v), want 250ms", tol, ok)
	}
	// The point is the record, not the struct: what reaches the log is the
	// payload, and a field the monitor sets but Payload drops would be the same
	// gap with an extra step in it.
	payload, err := att.Payload()
	if err != nil {
		t.Fatal(err)
	}
	var back clockatt.Attestation
	if err := json.Unmarshal(payload, &back); err != nil {
		t.Fatal(err)
	}
	if got, ok := back.DeclaredTolerance(); !ok || got != 250*time.Millisecond {
		t.Fatalf("the payload carries tolerance %s (recorded=%v), want 250ms: %s", got, ok, payload)
	}
	// Latest is what a caller reads back, and it has to agree with what was
	// handed to OnAttestation.
	if latest, ok := m.Latest(); !ok || latest.ToleranceNanos != att.ToleranceNanos {
		t.Fatalf("Latest declares %d, the returned attestation %d",
			latest.ToleranceNanos, att.ToleranceNanos)
	}
}

// TestAnAttestationWithNoRecordedToleranceIsNotADeclaredZero.
//
// Every attestation written before the field existed decodes with zero, and a
// reader that treated that as a declaration would grade the whole history of
// this project's logs against a bound of nothing — every one of them a breach,
// none of them a real finding.
func TestAnAttestationWithNoRecordedToleranceIsNotADeclaredZero(t *testing.T) {
	var old clockatt.Attestation
	if err := json.Unmarshal([]byte(`{"source":"ntp:x","synchronised":true,`+
		`"offset_nanos":1000,"round_trip_nanos":2000,"taken_at":"2025-07-25T08:00:00Z"}`),
		&old); err != nil {
		t.Fatal(err)
	}
	if _, ok := old.DeclaredTolerance(); ok {
		t.Fatal("an attestation written before the field existed reported a declared tolerance")
	}
	// And an undeclared tolerance is omitted rather than written as a zero, so
	// a reader of the older payload sees exactly the bytes it saw before.
	payload, err := old.Payload()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "tolerance_nanos") {
		t.Fatalf("an undeclared tolerance was written into the payload: %s", payload)
	}
}
