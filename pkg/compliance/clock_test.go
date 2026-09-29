package compliance_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/compliance"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/clockatt"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// clockLog writes a log whose events carry a clock attestation reference, or do
// not, and returns the directory.
//
// The reference is produced the way the daemon produces it — through
// `Options.ClockAttestationRef` — rather than stamped by the test, so what is
// exercised is the same wiring the daemon uses.
func clockLog(t *testing.T, atts []clockatt.Attestation, attach bool, events int) string {
	t.Helper()
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "evidence")
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var latest string
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		ClockAttestationRef: func() string {
			if !attach {
				return ""
			}
			return latest
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range atts {
		payload, perr := a.Payload()
		if perr != nil {
			t.Fatal(perr)
		}
		ref, aerr := app.Append(ctx, evidence.Request{
			Kind: evidence.KindClockAttestation, Payload: payload,
		})
		if aerr != nil {
			t.Fatal(aerr)
		}
		latest = ref.EventID
	}
	for range events {
		if _, err := app.Append(ctx, evidence.Request{
			Kind: evidence.KindControl, Payload: []byte("{}"),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func goodAttestation() clockatt.Attestation {
	return clockatt.Attestation{
		Source: "ntp://time.example", Synchronised: true,
		OffsetNanos: int64(2 * time.Millisecond), RoundTripNanos: int64(4 * time.Millisecond),
		Stratum: 2, TakenAt: time.Now().UTC(),
	}
}

func clockSubject(t *testing.T, dir string) compliance.Subject {
	t.Helper()
	c, err := compliance.ClockTraceabilityOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	return compliance.Subject{Clock: c}
}

// TestAnAttestedLogDemonstratesTraceability is the satisfied case: every event
// points at an attestation and every attestation found the clock synchronised.
func TestAnAttestedLogDemonstratesTraceability(t *testing.T) {
	dir := clockLog(t, []clockatt.Attestation{goodAttestation()}, true, 3)
	got := compliance.Run("business_clocks_are_traceable_to_utc", clockSubject(t, dir))
	if !got.Satisfied {
		t.Fatalf("an attested log does not demonstrate traceability: %s", got.Detail)
	}
	// The finding has to say what it graded against, or a reader assumes their
	// own tolerance was the one checked.
	if !strings.Contains(got.Detail, "one second") {
		t.Errorf("the finding does not say which tolerance it used: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "ntp://time.example") {
		t.Errorf("the finding does not name the time source: %s", got.Detail)
	}
}

// TestADeploymentWithNoClockSourceIsExposed is the failure the check exists to
// catch, and it is the realistic one: a daemon started without -clock-sources
// writes events that point at nothing. Item 43 says the events do not lie about
// it — they carry no reference — and this is what makes that visible.
func TestADeploymentWithNoClockSourceIsExposed(t *testing.T) {
	dir := clockLog(t, nil, false, 3)
	got := compliance.Run("business_clocks_are_traceable_to_utc", clockSubject(t, dir))
	if got.Satisfied || got.Unknown {
		t.Fatalf("a log with no attestations at all reported satisfied=%v unknown=%v: %s",
			got.Satisfied, got.Unknown, got.Detail)
	}
	if !strings.Contains(got.Detail, "no clock source configured") {
		t.Errorf("the finding does not say what to do about it: %s", got.Detail)
	}
}

// TestAConfiguredClockWithUnattestedEventsSaysSoRatherThanBlamingTheConfig.
//
// Found by running the real command rather than by thinking. A log written by
// janus-orchd with -clock-sources set holds attestations; append one event with
// janus-tier without that flag and every event in the log points at nothing
// while four attestations sit beside them. The check's first version reported
// "this deployment runs with no clock source configured", which was false and
// would have sent an operator to add a flag they already had.
//
// When this was written the gap was structural — only janus-orchd wired the
// monitor. Every writing binary now has the flag, so what is left is an
// invocation that was not given it: -clock-sources is per process, and an
// operator who set it on the daemon can still forget it on a one-shot command.
// The finding has to keep saying which of the two it is.
func TestAConfiguredClockWithUnattestedEventsSaysSoRatherThanBlamingTheConfig(t *testing.T) {
	// Attestations present; events written without the reference attached.
	dir := clockLog(t, []clockatt.Attestation{goodAttestation()}, false, 2)
	got := compliance.Run("business_clocks_are_traceable_to_utc", clockSubject(t, dir))
	if got.Satisfied || got.Unknown {
		t.Fatalf("satisfied=%v unknown=%v: %s", got.Satisfied, got.Unknown, got.Detail)
	}
	if strings.Contains(got.Detail, "no clock source configured") {
		t.Errorf("the finding blames the configuration on a log that holds attestations, "+
			"which would send an operator to add a flag they already have: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "a clock source is configured") {
		t.Errorf("the finding does not say a source is configured: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "was not given one") {
		t.Errorf("the finding does not say what is actually wrong: %s", got.Detail)
	}
}

// TestAPartiallyAttestedLogIsExposed: events written before the first
// attestation carry no reference, and traceability cannot be demonstrated for
// them. Reporting the whole log as satisfied because most of it is attested
// would be the kind of pass this package exists not to produce.
func TestAPartiallyAttestedLogIsExposed(t *testing.T) {
	dir := clockLog(t, nil, false, 2)
	// Reopen and add an attested tail.
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var latest string
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		ClockAttestationRef: func() string { return latest },
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := goodAttestation().Payload()
	if err != nil {
		t.Fatal(err)
	}
	ref, err := app.Append(context.Background(), evidence.Request{
		Kind: evidence.KindClockAttestation, Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	latest = ref.EventID
	if _, err := app.Append(context.Background(), evidence.Request{
		Kind: evidence.KindControl, Payload: []byte("{}"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	got := compliance.Run("business_clocks_are_traceable_to_utc", clockSubject(t, dir))
	if got.Satisfied {
		t.Fatalf("a partly attested log reported satisfied: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "2 do not") {
		t.Errorf("the finding does not count the unattested events: %s", got.Detail)
	}
}

// TestAnUnreachableTimeSourceIsExposed: an attestation that could not reach a
// source still gets recorded, saying so. That is the honest behaviour and it is
// also a window in which nothing is demonstrated.
func TestAnUnreachableTimeSourceIsExposed(t *testing.T) {
	dir := clockLog(t, []clockatt.Attestation{{
		Source: "ntp://time.example", Synchronised: false,
		Err: "dial udp: i/o timeout", TakenAt: time.Now().UTC(),
	}}, true, 2)
	got := compliance.Run("business_clocks_are_traceable_to_utc", clockSubject(t, dir))
	if got.Satisfied {
		t.Fatalf("an unsynchronised attestation reported satisfied: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "could not reach a time source") {
		t.Errorf("the finding does not say the source was unreachable: %s", got.Detail)
	}
}

// TestAClockOutsideToleranceIsExposed: checked, and found wrong. The only one of
// the three failures where the log establishes an actual divergence.
func TestAClockOutsideToleranceIsExposed(t *testing.T) {
	dir := clockLog(t, []clockatt.Attestation{{
		Source: "ntp://time.example", Synchronised: true,
		OffsetNanos:    int64(3 * time.Second),
		RoundTripNanos: int64(4 * time.Millisecond),
		TakenAt:        time.Now().UTC(),
	}}, true, 2)
	got := compliance.Run("business_clocks_are_traceable_to_utc", clockSubject(t, dir))
	if got.Satisfied {
		t.Fatalf("a clock three seconds out reported satisfied: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "outside tolerance") {
		t.Errorf("the finding does not say the clock was out of tolerance: %s", got.Detail)
	}
}

// TestAnUnreadLogIsUnknownRatherThanSatisfied. Unknown is not a milder pass: a
// subject with no clock summary means nobody looked, and reporting that as
// satisfied is how a report claims more than anybody established.
func TestAnUnreadLogIsUnknownRatherThanSatisfied(t *testing.T) {
	got := compliance.Run("business_clocks_are_traceable_to_utc", compliance.Subject{})
	if !got.Unknown {
		t.Fatalf("a subject with no clock summary reported satisfied=%v: %s",
			got.Satisfied, got.Detail)
	}
	empty := clockLog(t, nil, false, 0)
	got = compliance.Run("business_clocks_are_traceable_to_utc", clockSubject(t, empty))
	if !got.Unknown {
		t.Fatalf("an empty log reported satisfied=%v rather than unknown: %s",
			got.Satisfied, got.Detail)
	}
}

// TestAnAttestationDoesNotCountAsAnEventNeedingOne. An attestation cannot point
// at itself, so counting them among the events that should carry a reference
// would make a log of nothing but attestations read as entirely unattested —
// a finding that is both alarming and false.
func TestAnAttestationDoesNotCountAsAnEventNeedingOne(t *testing.T) {
	dir := clockLog(t, []clockatt.Attestation{goodAttestation(), goodAttestation()}, true, 1)
	c, err := compliance.ClockTraceabilityOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Events != 1 {
		t.Errorf("counted %d event(s) needing an attestation; the log holds one plus two "+
			"attestations, which cannot attest themselves", c.Events)
	}
	if c.Attestations != 2 {
		t.Errorf("counted %d attestation(s), want 2", c.Attestations)
	}
}

// TestTheClockCheckIsReachableFromThePack is the reachability proof, and it is
// the one that matters: a check no pack references is unreachable, which is the
// reason a check and its pack mapping arrive together.
func TestTheClockCheckIsReachableFromThePack(t *testing.T) {
	dir := clockLog(t, nil, false, 3)
	subject := clockSubject(t, dir)

	var found []string
	for _, f := range compliance.Lint(subject, packs(t)).Findings {
		if f.PackID != "rts-25" {
			continue
		}
		found = append(found, f.ArticleID)
		if f.Status != compliance.StatusExposed {
			t.Errorf("rts-25 %s is %s on a log with no attestations; the pack does not "+
				"reach the check", f.ArticleID, f.Status)
		}
	}
	if len(found) != 2 {
		t.Fatalf("the shipped rts-25 pack produced %d finding(s) (%v), want 2 — the pack "+
			"is not being loaded, so nothing here proves the mapping", len(found), found)
	}
}

// declaring returns an attestation with an offset and a declared tolerance, so
// a test can put the two out of step deliberately.
func declaring(offset, tolerance time.Duration) clockatt.Attestation {
	a := goodAttestation()
	a.OffsetNanos = int64(offset)
	a.RoundTripNanos = 0
	a.ToleranceNanos = int64(tolerance)
	return a
}

// TestADeclaredToleranceIsCheckedRatherThanAssumed is a gap attestation left
// open and this closes: a deployment that declared 100 ms and held 500 ms is inside
// RTS 25 Art. 2(2)'s second and outside its own claim. Before the tolerance
// reached the log the only bound a reader could apply was the article's, and
// this log read as satisfied — a pass earned by the stricter figure being
// unreadable rather than by the clock being good.
func TestADeclaredToleranceIsCheckedRatherThanAssumed(t *testing.T) {
	dir := clockLog(t, []clockatt.Attestation{
		declaring(500*time.Millisecond, 100*time.Millisecond),
	}, true, 2)
	got := compliance.Run("business_clocks_are_traceable_to_utc", clockSubject(t, dir))
	if got.Satisfied {
		t.Fatalf("a clock five times its declared bound reported satisfied: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "outside the tolerance its own record declares") {
		t.Errorf("the finding does not say which bound was broken: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "100ms") {
		t.Errorf("the finding does not name the declared bound: %s", got.Detail)
	}
	// And it must not read as an article breach, because it is not one: an
	// operator sent to fix a one-second divergence would find none.
	if strings.Contains(got.Detail, "found the clock outside tolerance") {
		t.Errorf("a breach of the declared bound was reported as an article breach: %s", got.Detail)
	}
}

// TestADeclarationWiderThanTheArticleIsItselfTheFinding.
//
// Art. 2(2)'s second is a maximum, not a default an operator can raise by
// typing a bigger number. A deployment running -clock-tolerance=5s has a daemon
// that will not report a divergence the regulation forbids, and the clock being
// fine today does not make that configuration compliant.
func TestADeclarationWiderThanTheArticleIsItselfTheFinding(t *testing.T) {
	dir := clockLog(t, []clockatt.Attestation{
		declaring(2*time.Millisecond, 5*time.Second),
	}, true, 2)
	got := compliance.Run("business_clocks_are_traceable_to_utc", clockSubject(t, dir))
	if got.Satisfied {
		t.Fatalf("a deployment declaring five seconds reported satisfied: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "wider than RTS 25 Art. 2(2) permits") {
		t.Errorf("the finding does not say the declaration is the problem: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "5s") {
		t.Errorf("the finding does not name the declaration: %s", got.Detail)
	}
}

// TestADeclaredToleranceThatIsHeldIsSatisfiedAndSaysWhatItChecked.
func TestADeclaredToleranceThatIsHeldIsSatisfiedAndSaysWhatItChecked(t *testing.T) {
	dir := clockLog(t, []clockatt.Attestation{
		declaring(2*time.Millisecond, 100*time.Millisecond),
	}, true, 2)
	got := compliance.Run("business_clocks_are_traceable_to_utc", clockSubject(t, dir))
	if !got.Satisfied {
		t.Fatalf("a clock inside both bounds reported a finding: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "the tolerance each attestation declares (100ms)") {
		t.Errorf("the finding does not say the declared bound was the one checked: %s", got.Detail)
	}
}

// TestALogThatDeclaresNoToleranceSaysWhatItCouldNotCheck.
//
// Every log this project has written so far is this one. The verdict is the
// same as it was, and the sentence has to keep saying that a stricter figure
// could not be checked — a reader who assumes the declared bound was tested
// gets a stronger claim than the log supports.
func TestALogThatDeclaresNoToleranceSaysWhatItCouldNotCheck(t *testing.T) {
	dir := clockLog(t, []clockatt.Attestation{goodAttestation()}, true, 2)
	got := compliance.Run("business_clocks_are_traceable_to_utc", clockSubject(t, dir))
	if !got.Satisfied {
		t.Fatalf("a log without declarations changed verdict: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "no attestation here records the tolerance") {
		t.Errorf("the finding does not say the declared bound was unreadable: %s", got.Detail)
	}
}

// TestAMixedLogCountsTheAttestationsThatDeclareNothing: an operator who
// upgraded mid-life has both kinds in one log, and reporting only the declared
// bound would claim every attestation was graded against it.
func TestAMixedLogCountsTheAttestationsThatDeclareNothing(t *testing.T) {
	dir := clockLog(t, []clockatt.Attestation{
		goodAttestation(),
		declaring(2*time.Millisecond, 100*time.Millisecond),
	}, true, 2)
	got := compliance.Run("business_clocks_are_traceable_to_utc", clockSubject(t, dir))
	if !got.Satisfied {
		t.Fatalf("a mixed log reported a finding: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "1 of 2 record none") {
		t.Errorf("the finding does not count the undeclared attestations: %s", got.Detail)
	}
}

// TestAToleranceIsGradedPerAttestationNotPerLog.
//
// An operator who tightened -clock-tolerance across a restart writes a log with
// two declarations in it, and each attestation is answerable for the bound that
// was in force when it was taken. Grading the whole log against the strictest
// would invent breaches nobody claimed; against the loosest, it would forgive
// one somebody did.
func TestAToleranceIsGradedPerAttestationNotPerLog(t *testing.T) {
	dir := clockLog(t, []clockatt.Attestation{
		declaring(200*time.Millisecond, 500*time.Millisecond), // held its bound
		declaring(2*time.Millisecond, 10*time.Millisecond),    // held its own, stricter
	}, true, 2)
	c, err := compliance.ClockTraceabilityOf(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.OutOfDeclared != 0 {
		t.Fatalf("%d attestation(s) reported outside a bound they both held: grading is "+
			"not per attestation", c.OutOfDeclared)
	}
	if len(c.Declared) != 2 || c.Declared[0] != 10*time.Millisecond ||
		c.Declared[1] != 500*time.Millisecond {
		t.Fatalf("declared bounds %v, want [10ms 500ms] ascending", c.Declared)
	}
}
