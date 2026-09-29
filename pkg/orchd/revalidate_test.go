package orchd_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/orchd"
	"github.com/mustafarslan/janus/pkg/registry"
	"google.golang.org/protobuf/proto"
)

// The daemon schedules a periodic revalidation that has come due.
//
// This is the test that fails if the wiring is deleted, which is the check this
// repository has had to learn five times: `Cadence.Due` can be perfectly
// correct and the ticker never call it, and every unit test would still pass.
//
// The history is written by an appender whose clock is a year in the past, so
// the anchor the cadence counts from is genuinely old and the daemon's own
// `time.Now()` is what makes the review overdue. Nothing here manipulates the
// daemon's clock; the log is old, which is the real situation.
func TestTheDaemonSchedulesAPeriodicRevalidation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifestAt(t, dir, signer, time.Now().AddDate(-1, 0, 0), []string{registry.TriggerPeriodic})

	s := revalidationServer(t, dir, signer, &registry.Cadence{ByTier: map[uint32]uint32{2: 90}})
	defer func() { _ = s.Close() }()

	waitFor(t, 5*time.Second, "the daemon to record the periodic revalidation", func() bool {
		return owesPeriodic(t, dir)
	})
}

// A version whose review is not yet due is left alone, so the test above is not
// passing because the daemon schedules everything it sees.
func TestAReviewThatIsNotDueIsLeftAlone(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	// Evaluated a week ago, on a ninety-day cadence.
	registerManifestAt(t, dir, signer, time.Now().AddDate(0, 0, -7), []string{registry.TriggerPeriodic})

	s := revalidationServer(t, dir, signer, &registry.Cadence{ByTier: map[uint32]uint32{2: 90}})
	defer func() { _ = s.Close() }()

	time.Sleep(500 * time.Millisecond)
	if owesPeriodic(t, dir) {
		t.Fatal("a version evaluated a week ago was put on the hook for a review " +
			"its ninety-day cadence does not ask for yet")
	}
}

// With no cadence configured, nothing is scheduled — which is the documented
// default and has to be the observed one.
func TestWithNoCadenceNothingIsScheduled(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifestAt(t, dir, signer, time.Now().AddDate(-1, 0, 0), []string{registry.TriggerPeriodic})

	s := revalidationServer(t, dir, signer, nil)
	defer func() { _ = s.Close() }()

	time.Sleep(500 * time.Millisecond)
	if owesPeriodic(t, dir) {
		t.Fatal("a revalidation was scheduled with no cadence configured")
	}
}

// The debt is recorded once, however many times the ticker fires.
func TestThePeriodicDebtIsRecordedOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifestAt(t, dir, signer, time.Now().AddDate(-1, 0, 0), []string{registry.TriggerPeriodic})

	s := revalidationServer(t, dir, signer, &registry.Cadence{ByTier: map[uint32]uint32{2: 90}})
	defer func() { _ = s.Close() }()

	waitFor(t, 5*time.Second, "the daemon to record the periodic revalidation", func() bool {
		return owesPeriodic(t, dir)
	})
	// Many more ticks at 20ms.
	time.Sleep(600 * time.Millisecond)

	if n := countRevalidationEvents(t, dir); n != 1 {
		t.Fatalf("the periodic debt was recorded %d times; an inventory would list "+
			"the same overdue review once per tick", n)
	}
}

func revalidationServer(t *testing.T, dir string, signer *keys.Signer,
	cad *registry.Cadence) *orchd.Server {

	t.Helper()
	// A minimal policy with a rule in it: these tests run no sagas, but an
	// empty policy is refused because it would refuse every effectful step.
	p := &gate.Policy{
		ID: "orchd.revalidation.test",
		Rules: []gate.Rule{{
			ID:    "irreversible-needs-a-person",
			Match: gate.Match{EffectClasses: []string{"IRREVERSIBLE_GATED"}},
			Require: []gate.Requirement{{
				ID: "four-eyes", Gate: gate.GateHuman, Phase: gate.PhasePreRelease,
				Human: &gate.HumanSpec{Roles: []string{"credit-officer"}, Quorum: 1},
			}},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	s, err := orchd.New(orchd.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone, Policy: p,
		Cadence: cad, TickInterval: 20 * time.Millisecond,
		Participant: evidence.ParticipantRef{
			ID: "ag_orchd", ManifestVersion: "1.0.0", Principal: testPrincipal, Kind: "AGENT",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// owesPeriodic reports whether the active version owes a periodic revalidation,
// read back through an ordinary fold of the log.
func owesPeriodic(t *testing.T, dir string) bool {
	t.Helper()
	reg, err := registry.Replay(dir)
	if err != nil {
		return false
	}
	e, ok := reg.Active("tool_payments")
	if !ok {
		return false
	}
	for _, tr := range e.PendingTriggers {
		if tr == registry.TriggerPeriodic {
			return true
		}
	}
	return false
}

func countRevalidationEvents(t *testing.T, dir string) int {
	t.Helper()
	events, err := registry.LoadEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, ev := range events {
		var msg janusv1.RegistryEvent
		if err := proto.Unmarshal(ev.Payload, &msg); err != nil {
			t.Fatal(err)
		}
		if msg.GetKind() == janusv1.RegistryEvent_KIND_REVALIDATION_REQUIRED {
			n++
		}
	}
	return n
}

// Every read the daemon makes of its own directory names the head it requires.
//
// This is here because the miss was invisible. `registry.LoadEvents` became
// variadic when live torn-tail handling landed, so `registry.LoadEvents(s.dir)` kept compiling
// with the *offline* default — refuse any incomplete record — on the admission
// path of a daemon writing that directory. A Begin could then fail with
// "recover the log" because the writer was mid-flush, which is exactly the
// operator-facing harm naming the head exists to prevent.
//
// The test tears the log the way a concurrent flush does and then asks the
// daemon to do the two things that fold the registry: admit a saga, and run the
// revalidation schedule. A strict reader fails both.
func TestTheDaemonAdmitsAgainstALogItIsWriting(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	registerManifestAt(t, dir, signer, time.Now().AddDate(-1, 0, 0), []string{registry.TriggerPeriodic})

	s := revalidationServer(t, dir, signer, &registry.Cadence{ByTier: map[uint32]uint32{2: 90}})
	defer func() { _ = s.Close() }()

	// Wait until the daemon has written something of its own, so the segment
	// torn below is the one it is actually appending to.
	waitFor(t, 5*time.Second, "the daemon to write to its own segment", func() bool {
		return owesPeriodic(t, dir)
	})

	// A partial record at the tail, which is what a reader sees mid-flush. The
	// daemon's own appender has acknowledged nothing beyond it, so a live read
	// is entitled to read up to it and no further.
	tearLastRecord(t, dir)

	if _, err := s.RegistryFoldForTest(); err != nil {
		t.Fatalf("the daemon could not fold the registry out of the log it is "+
			"writing: %v", err)
	}
}

// tearLastRecord appends bytes that do not form a whole record, which is what a
// bufio flush boundary leaves behind mid-write.
func tearLastRecord(t *testing.T, dir string) {
	t.Helper()
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(ids) - 1; i >= 0; i-- {
		path := segment.Path(dir, ids[i])
		insp, err := segment.Inspect(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(insp.Records) == 0 || insp.Sealed() {
			continue
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		// A length prefix promising far more than follows: a torn tail.
		if _, err := f.Write([]byte{0xff, 0x00, 0x00, 0x00, 0x01}); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("no unsealed segment with records to tear")
}
