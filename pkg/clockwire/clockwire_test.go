package clockwire_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/clockwire"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/clockatt"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// fakeSource answers without a network, so what is measured is this wiring
// rather than somebody else's NTP server being up.
type fakeSource struct {
	mu     sync.Mutex
	calls  int
	synced bool
	delay  time.Duration
}

func (f *fakeSource) Name() string { return "fake" }

func (f *fakeSource) Attest(context.Context) clockatt.Attestation {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return clockatt.Attestation{
		Source: f.Name(), Synchronised: f.synced,
		OffsetNanos: int64(time.Millisecond), RoundTripNanos: int64(2 * time.Millisecond),
		Stratum: 2, TakenAt: time.Now().UTC(),
	}
}

func (f *fakeSource) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func logDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "evidence")
}

func openOpts(t *testing.T, dir string) evidence.Options {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return evidence.Options{Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone}
}

// walk splits a log into its attestations and everything else.
func walk(t *testing.T, dir string) (atts []evidence.EventHeader, rest []evidence.EventHeader) {
	t.Helper()
	if err := evidence.Walk(dir, func(h evidence.EventHeader, _ segment.Record) error {
		if h.Kind == evidence.KindClockAttestation {
			atts = append(atts, h)
			return nil
		}
		rest = append(rest, h)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return atts, rest
}

// TestAOneShotCommandsEventsPointAtItsOwnAttestation is what this package was
// built for.
//
// `janus-tier`, `janus-registry` and `janus-keys` append an operator act and
// exit. Before this wiring those records carried no clock attestation reference in
// deployments whose sagas carried one, and the compliance check reported it as
// "a clock source is configured, but these events were appended by something
// that does not record the reference".
func TestAOneShotCommandsEventsPointAtItsOwnAttestation(t *testing.T) {
	dir := logDir(t)
	src := &fakeSource{synced: true}
	app, clk, err := clockwire.Open(context.Background(),
		clockwire.Config{Sources: []clockatt.Source{src}, Tolerance: time.Second},
		openOpts(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Append(context.Background(), evidence.Request{
		Kind: evidence.KindControl, Payload: []byte("{}"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	if got := src.count(); got != 1 {
		t.Fatalf("a one-shot command queried its time source %d times, want exactly 1: it "+
			"appends a record and exits, so it needs one statement and not a schedule", got)
	}
	atts, rest := walk(t, dir)
	if len(atts) != 1 {
		t.Fatalf("%d attestations recorded, want 1", len(atts))
	}
	if len(rest) == 0 {
		t.Fatal("nothing but the attestation was written, so the test proves nothing")
	}
	for _, h := range rest {
		if h.TS.ClockAttestationRef != atts[0].EventID {
			t.Errorf("event %s (%s) points at %q, want the attestation %s",
				h.EventID, h.Kind, h.TS.ClockAttestationRef, atts[0].EventID)
		}
	}
	if !clk.Enabled() {
		t.Error("a clock with a source reported itself disabled")
	}
}

// TestTheAttestationLandsBeforeTheFirstEvent.
//
// The ordering is the whole of it. An event appended while the first attestation
// is still in flight carries no reference — the same defect this exists to
// remove, at a smaller scale — so `Open` must not return until the attestation
// is in the log, and a slow time source must not turn that into a race.
func TestTheAttestationLandsBeforeTheFirstEvent(t *testing.T) {
	dir := logDir(t)
	src := &fakeSource{synced: true, delay: 60 * time.Millisecond}
	app, _, err := clockwire.Open(context.Background(),
		clockwire.Config{Sources: []clockatt.Source{src}}, openOpts(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Append(context.Background(), evidence.Request{
		Kind: evidence.KindControl, Payload: []byte("{}"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	atts, rest := walk(t, dir)
	if len(atts) != 1 || len(rest) != 1 {
		t.Fatalf("%d attestation(s) and %d other event(s), want 1 and 1", len(atts), len(rest))
	}
	if atts[0].Seq > rest[0].Seq {
		t.Fatalf("the attestation is at seq %d and the event at seq %d: the event was "+
			"written first and cannot point at a statement taken after it",
			atts[0].Seq, rest[0].Seq)
	}
	if rest[0].TS.ClockAttestationRef == "" {
		t.Fatal("the first event carries no attestation reference, so Open returned before " +
			"the attestation landed")
	}
}

// TestADaemonKeepsAttestingAndStops: the long-lived shape. A process that runs
// for days needs its later events pointing at a recent statement, not at one
// taken when it started.
func TestADaemonKeepsAttestingAndStops(t *testing.T) {
	dir := logDir(t)
	src := &fakeSource{synced: true}
	clk, err := clockwire.New(clockwire.Config{
		Sources: []clockatt.Source{src}, Interval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := openOpts(t, dir)
	opts.ClockAttestationRef = clk.Ref
	app, err := evidence.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	clk.Bind(app)
	clk.Start(context.Background())
	if src.count() < 1 {
		t.Fatal("Start returned before the first attestation was taken, which is the race " +
			"it exists to close")
	}
	time.Sleep(200 * time.Millisecond)
	clk.Stop()
	// Twice, because a shutdown path is where a second close gets written by
	// accident and a panic there loses the log's clean close.
	clk.Stop()
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	atts, _ := walk(t, dir)
	if len(atts) < 2 {
		t.Fatalf("%d attestation(s) after 200ms at a 20ms interval: the loop is not ticking",
			len(atts))
	}
	before := len(atts)
	time.Sleep(100 * time.Millisecond)
	after, _ := walk(t, dir)
	if len(after) != before {
		t.Errorf("%d attestations after Stop, %d before: the loop is still running",
			len(after), before)
	}
}

// TestNoSourceRecordsNothingAndRefersToNothing keeps the clock opt-in honest in
// the shared wiring.
//
// A default pointing at somebody's NTP server would put a network dependency in
// the write path of every air-gapped install, and here it would do it in
// six binaries at once rather than one.
func TestNoSourceRecordsNothingAndRefersToNothing(t *testing.T) {
	dir := logDir(t)
	app, clk, err := clockwire.Open(context.Background(), clockwire.Config{}, openOpts(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if clk.Enabled() {
		t.Error("a clock with no sources reported itself enabled")
	}
	if _, err := app.Append(context.Background(), evidence.Request{
		Kind: evidence.KindControl, Payload: []byte("{}"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	atts, rest := walk(t, dir)
	if len(atts) != 0 {
		t.Errorf("%d attestation(s) recorded with no source configured", len(atts))
	}
	for _, h := range rest {
		if h.TS.ClockAttestationRef != "" {
			t.Errorf("event %s names attestation %q with no source configured",
				h.EventID, h.TS.ClockAttestationRef)
		}
	}
	// And the no-source path must not deadlock: Start and Stop are called on
	// every daemon's path whether or not a source was configured.
	clk.Start(context.Background())
	clk.Stop()
}

// TestAnUnreachableSourceStillRecordsAndDoesNotBlockStartup.
//
// A command whose time source is down must still run: the attestation says
// "unsynchronised", which is a finding an auditor can act on, where refusing to
// start would turn a clock problem into an outage.
func TestAnUnreachableSourceStillRecordsAndDoesNotBlockStartup(t *testing.T) {
	dir := logDir(t)
	app, _, err := clockwire.Open(context.Background(),
		clockwire.Config{Sources: []clockatt.Source{&fakeSource{synced: false}}},
		openOpts(t, dir))
	if err != nil {
		t.Fatalf("a command with an unreachable time source refused to start: %v", err)
	}
	if _, err := app.Append(context.Background(), evidence.Request{
		Kind: evidence.KindControl, Payload: []byte("{}"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	atts, rest := walk(t, dir)
	if len(atts) != 1 {
		t.Fatalf("%d attestation(s): an absent attestation is indistinguishable from one "+
			"nobody bothered to take", len(atts))
	}
	if rest[0].TS.ClockAttestationRef != atts[0].EventID {
		t.Error("the event does not point at the unsynchronised attestation, so the log " +
			"cannot show that the clock was checked and could not be reached")
	}
}

// TestTheDeclaredToleranceReachesTheRecordThroughThisWiring.
//
// The one-shot path has to go through clockatt.Monitor and not call a Source
// directly, because the monitor is what stamps the declared bound. A writer that
// queried its source itself would produce attestations declaring nothing, and
// every record a CLI wrote would silently lose the declared bound.
func TestTheDeclaredToleranceReachesTheRecordThroughThisWiring(t *testing.T) {
	dir := logDir(t)
	app, _, err := clockwire.Open(context.Background(), clockwire.Config{
		Sources: []clockatt.Source{&fakeSource{synced: true}}, Tolerance: 250 * time.Millisecond,
	}, openOpts(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	var found bool
	if err := evidence.Walk(dir, func(h evidence.EventHeader, rec segment.Record) error {
		if h.Kind != evidence.KindClockAttestation {
			return nil
		}
		found = true
		var a clockatt.Attestation
		if err := json.Unmarshal(rec.Payload, &a); err != nil {
			t.Fatal(err)
		}
		if got, ok := a.DeclaredTolerance(); !ok || got != 250*time.Millisecond {
			t.Errorf("the recorded attestation declares %s (recorded=%v), want 250ms", got, ok)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("no attestation was recorded")
	}
}

// TestAnAttestationWithNowhereToGoIsNotSilentlyLost: Bind before the loop, or
// the reference advances to an event that was never written.
func TestAnAttestationWithNowhereToGoIsNotSilentlyLost(t *testing.T) {
	clk, err := clockwire.New(clockwire.Config{
		Sources: []clockatt.Source{&fakeSource{synced: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Never bound to an appender.
	if _, ok := clk.Attest(context.Background()); !ok {
		t.Fatal("an enabled clock reported that it took no attestation")
	}
	if ref := clk.Ref(); ref != "" {
		t.Fatalf("the reference advanced to %q with no appender to record into: an event "+
			"would then point at something that is not in the log", ref)
	}
}

// capture collects what a warning would print, so the two sentences can be
// compared rather than eyeballed.
func capture(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	flags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(prev)
		log.SetFlags(flags)
	}()
	fn()
	return buf.String()
}

// A one-shot with no sources is told which of the two deployments it is in.
//
// This is the foot-gun: `-clock-sources` is per process, so an operator
// who set it on the daemon can forget it on a `janus-tier erase`, and the log
// then holds one unattested event among thousands of attested ones. It is
// visible afterwards — the compliance check says "N of M event(s) point at a
// clock attestation" — and the warning at the moment it happens used to be the
// same sentence a deployment that never configured a clock at all receives.
//
// Both halves are asserted, because a warning that says "you forgot the flag"
// to a deployment that chose not to attest is the same defect with the sign
// flipped, and the air-gapped install is a supported deployment, not an oversight.
func TestAOneShotIsToldWhatTheWriterDeclared(t *testing.T) {
	dir := logDir(t)
	src := &fakeSource{synced: true}

	// A writer that attests opens the directory first — the daemon, in a
	// deployment, and here whatever ran before this command.
	app, _, err := clockwire.Open(context.Background(),
		clockwire.Config{Sources: []clockatt.Source{src}, Tolerance: 250 * time.Millisecond},
		openOpts(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	unconfigured := clockwire.Config{}
	told := capture(t, func() { unconfigured.WarnIfUnattested("janus-tier", dir) })
	if !strings.Contains(told, "fake") {
		t.Fatalf("a one-shot in a directory whose writer attests against \"fake\" was "+
			"warned with: %q — which is the sentence a deployment that attests nowhere "+
			"gets, and telling those two apart is the whole point", told)
	}
	if !strings.Contains(told, "250ms") {
		t.Fatalf("the warning does not name the tolerance the writer declared: %q", told)
	}

	// And the other deployment: no writer here ever attested, so there is
	// nothing to have forgotten and nothing to suggest.
	fresh := logDir(t)
	plain, _, err := clockwire.Open(context.Background(), clockwire.Config{}, openOpts(t, fresh))
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}
	quiet := capture(t, func() { unconfigured.WarnIfUnattested("janus-tier", fresh) })
	if strings.Contains(quiet, "Pass -clock-sources ") {
		t.Fatalf("a deployment that attests nowhere was told to pass a source list it "+
			"never chose: %q — an air-gapped install acquires no network dependency "+
			"by being warned about one", quiet)
	}
	if !strings.Contains(quiet, "no clock source configured") {
		t.Fatalf("a deployment that attests nowhere was not warned at all: %q", quiet)
	}
}

// The declaration is a hint and never a configuration.
//
// A writer with no sources of its own must not acquire them by opening a
// directory somebody else attested in: `-clock-sources` is per process on
// purpose (an air-gapped install acquires no network dependency it did not ask
// for), and a source list read from a file could be a month stale. The
// declaration survives such an open — dropping it would erase the hint at the
// moment it is being given — and changes nothing about what the process does.
func TestTheDeclarationIsNotInheritedByTheNextWriter(t *testing.T) {
	dir := logDir(t)
	src := &fakeSource{synced: true}
	app, _, err := clockwire.Open(context.Background(),
		clockwire.Config{Sources: []clockatt.Source{src}}, openOpts(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	before := src.count()

	// A second process, given nothing.
	plain, clk, err := clockwire.Open(context.Background(), clockwire.Config{}, openOpts(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Append(context.Background(), evidence.Request{
		Kind: evidence.KindControl, Payload: []byte(`{}`),
		Participant: evidence.ParticipantRef{ID: "janus-tier"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}

	if clk.Enabled() {
		t.Fatal("a process given no sources acquired one from the directory: the flag is " +
			"per process, and a file that configures the write path is the network " +
			"dependency the clock wiring refuses to add by default")
	}
	if got := src.count(); got != before {
		t.Fatalf("the declared source was queried %d more time(s) by a process that was "+
			"given none", got-before)
	}
	sources, _, ok, err := evidence.WriterClockDeclaration(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(sources) == 0 {
		t.Fatal("the declaration was erased by an unattested writer opening the directory, " +
			"so the next one-shot gets the generic warning again")
	}
}
