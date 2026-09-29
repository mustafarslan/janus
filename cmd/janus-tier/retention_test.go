package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/crypto"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/retention"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// scheduleFile writes a schedule whose longest minimum is `years`.
func scheduleFile(t *testing.T, years int) string {
	t.Helper()
	s := retention.DefaultSchedule()
	s.Policies[0].MinRetention = retention.Duration(
		time.Duration(years) * 365 * 24 * time.Hour)
	blob, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "schedule.json")
	if err := os.WriteFile(path, blob, 0o640); err != nil {
		t.Fatal(err)
	}
	// Assert the fixture: if the edited policy is not the longest, this proves
	// nothing about deriving the longest.
	loaded, err := retention.LoadSchedule(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Duration(years) * 365 * 24 * time.Hour; loaded.LongestMinimum() != want {
		t.Fatalf("the fixture's longest minimum is %s, want %s; the edited policy is not "+
			"the longest and this test would not exercise deriving one",
			loaded.LongestMinimum(), want)
	}
	return path
}

// TestTheArchiveLockComesFromTheSchedule is the fix for a number that was typed
// rather than derived.
//
// `worm.Config.Retention` says what it needs — "the longest any record in the
// log could require" — and the flag defaulted to six years, which matched the
// built-in schedule by coincidence. An operator running a schedule with a longer
// floor archived under a shorter lock and was told nothing.
func TestTheArchiveLockComesFromTheSchedule(t *testing.T) {
	sf := &storageFlags{schedule: scheduleFile(t, 9)}
	got, source, err := sf.lockDuration()
	if err != nil {
		t.Fatal(err)
	}
	if want := 9 * 365 * 24 * time.Hour; got != want {
		t.Errorf("derived a %s lock, want %s (the schedule's longest minimum)", got, want)
	}
	if !strings.Contains(source, "longest minimum") {
		t.Errorf("the source does not say where the number came from: %q", source)
	}
}

// TestALockShorterThanTheScheduleIsRefused is the fail-closed direction, and the
// reason it must be a refusal rather than a warning: Object Lock in COMPLIANCE
// mode cannot be shortened after the fact, so a segment locked for too little
// becomes deletable before the schedule permits and no later correction reaches
// back to it.
func TestALockShorterThanTheScheduleIsRefused(t *testing.T) {
	sf := &storageFlags{
		schedule:  scheduleFile(t, 9),
		retention: 6 * 365 * 24 * time.Hour,
	}
	_, _, err := sf.lockDuration()
	if err == nil {
		t.Fatal("a lock shorter than the schedule requires was accepted")
	}
	for _, want := range []string{"shorter than", "cannot be shortened later"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
}

// TestALongerLockIsAllowed: the schedule is a floor, not a ceiling. An operator
// keeping evidence longer than required is doing something legitimate.
func TestALongerLockIsAllowed(t *testing.T) {
	sf := &storageFlags{
		schedule:  scheduleFile(t, 6),
		retention: 11 * 365 * 24 * time.Hour,
	}
	got, source, err := sf.lockDuration()
	if err != nil {
		t.Fatal(err)
	}
	if want := 11 * 365 * 24 * time.Hour; got != want {
		t.Errorf("got %s, want the operator's %s", got, want)
	}
	if source != "-retention" {
		t.Errorf("source %q should name the flag the operator set", source)
	}
}

// TestTheRetentionReportSaysWhatEnforcesIt is the regression for a false claim.
//
// The command's help said it printed "the retention schedule in force". Nothing
// enforces the maximums: no daemon evaluates the schedule and nothing disposes
// of a record when its ceiling passes. A compliance officer reading a `personal`
// row with a 10-year maximum and a `crypto-shred` disposal mode would reasonably
// conclude that both happen.
//
// The legal-hold line moved the other way and is the reason this test is worth
// keeping rather than deleting once it passes. It used to read "LEGAL HOLDS
// cannot be placed at all", which was true and is now false, and this test
// caught the stale sentence the moment holds became records. A report that
// understates what the software does is the same defect as one that overstates
// it — both leave a reader's belief wrong — so the claims are pinned in both
// directions.
func TestTheRetentionReportSaysWhatEnforcesIt(t *testing.T) {
	out, err := capture(t, func() error { return showRetention(nil) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"MAXIMUMS are enforced by NOTHING",
		"MINIMUMS are enforced for archived segments",
		// What a hold now is, and the exact extent of what it stops. Naming
		// `erase` is the load-bearing half: a reader told only that holds exist
		// would assume they freeze disposal generally, and nothing else
		// disposes of anything.
		"LEGAL HOLDS are records in the log and survive a restart",
		"janus-tier erase, which refuses a held subject",
		"It stops nothing else, because nothing else disposes of anything",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "schedule in force") {
		t.Error("the report still claims the schedule is 'in force'")
	}
	// The superseded claim must be gone, not merely joined by its replacement.
	if strings.Contains(out, "cannot be placed at all") {
		t.Error("the report still says legal holds cannot be placed; they can, and " +
			"understating what the software does misleads a reader as surely as " +
			"overstating it")
	}
}

// TestTheReportQuotesTheLockItActuallyUses keeps the two halves from drifting:
// the footer states a duration, and `archive` must use that same one.
func TestTheReportQuotesTheLockItActuallyUses(t *testing.T) {
	out, err := capture(t, func() error { return showRetention(nil) })
	if err != nil {
		t.Fatal(err)
	}
	sf := &storageFlags{}
	lock, _, err := sf.lockDuration()
	if err != nil {
		t.Fatal(err)
	}
	quoted := retention.Duration(lock).String()
	if !strings.Contains(out, "COMPLIANCE mode for "+quoted) {
		t.Errorf("the report does not quote the lock archive would apply (%s):\n%s", quoted, out)
	}
}

// TestLongestMinimumIsTheLongest, directly, because the archive's correctness
// rests on it and a max/min slip would be invisible in the output above.
func TestLongestMinimumIsTheLongest(t *testing.T) {
	var s retention.Schedule
	blob, err := retention.DefaultSchedule().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(blob, &s); err != nil {
		t.Fatal(err)
	}
	longest := s.LongestMinimum()
	for _, p := range s.Policies {
		if time.Duration(p.MinRetention) > longest {
			t.Errorf("policy %s requires %s, longer than the reported %s",
				p.Class, p.MinRetention, longest)
		}
	}
	if longest == 0 {
		t.Fatal("the built-in schedule reports no minimum at all")
	}
}

// eraseFixture lays out the directories `erase` and `holdCmd` expect: an
// evidence log with a sibling keys/writer.key, and a keyring root.
//
// The layout matters rather than being incidental. Both commands default their
// writer key to `<evidence>/../keys/writer.key` and refuse to open without a
// readable one, because opening without it mints a fresh key: the command would
// look like it succeeded and the log would stop verifying against the key set
// the auditor holds.
func eraseFixture(t *testing.T) (evidenceDir, keyringRoot string) {
	t.Helper()
	root := t.TempDir()
	evidenceDir = filepath.Join(root, "evidence")
	keyringRoot = filepath.Join(root, "keyring")
	if err := os.MkdirAll(filepath.Join(root, "keys"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(keyringRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.Save(filepath.Join(root, "keys", "writer.key")); err != nil {
		t.Fatal(err)
	}
	// One event, so the directory is a log rather than an empty path.
	a, err := evidence.Open(evidence.Options{
		Dir: evidenceDir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Append(context.Background(), evidence.Request{
		Kind: evidence.KindControl, Payload: []byte("{}"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	// A live key for the subject, so that erasure would otherwise *succeed*.
	// Without it every erase in these tests fails on "subject unknown" and a
	// hold check that did nothing at all would still leave them looking red for
	// the right reason. The hold has to be the thing standing in the way.
	master, err := crypto.LoadOrCreateMasterKey(filepath.Join(keyringRoot, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	ring, err := crypto.NewFileKeyRing(filepath.Join(keyringRoot, "ring"), master)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ring.EnsureKey("cust_42"); err != nil {
		t.Fatal(err)
	}
	if got := ring.State("cust_42"); got != crypto.KeyLive {
		t.Fatalf("the fixture's subject is %s, not live; an erase would fail for that "+
			"reason rather than for the hold", got)
	}
	return evidenceDir, keyringRoot
}

// eraseArgs builds the flags `erase` demands, so a test says only what it is
// varying.
func eraseArgs(dir, keyring, subject string) []string {
	return []string{
		"-evidence", dir,
		"-keyring", filepath.Join(keyring, "ring"),
		"-master-key", filepath.Join(keyring, "master.key"),
		"-writer-key", filepath.Join(dir, "..", "keys", "writer.key"),
		"-subject", subject,
		"-reason", "GDPR Art. 17 request 2026-114",
		"-approved-by", "dpo@bank",
		"-confirm",
	}
}

// TestErasureIsRefusedWhileASubjectIsUnderLegalHold.
//
// This is the reason the legal hold became a record rather than staying a map
// entry. `erase` destroys a subject's data encryption key permanently — its own
// output says no privilege recovers the content afterwards — so a hold that did
// not stop it would be a hold in name only: a court tells the deployment to
// preserve records, the next Art. 17 request destroys them, and nothing in the
// log says the hold was ever considered.
//
// The refusal has to come first, before the keyring is opened. A held subject
// whose key is missing must be refused for the hold, because "subject unknown"
// sends an operator to fix their setup and try again.
func TestErasureIsRefusedWhileASubjectIsUnderLegalHold(t *testing.T) {
	dir, keyring := eraseFixture(t)

	placeErr := holdCmd([]string{"place",
		"-evidence", dir,
		"-writer-key", filepath.Join(dir, "..", "keys", "writer.key"),
		"-id", "hold_bafin", "-matter", "BaFin enquiry 2026/17",
		"-by", "compliance@bank", "-subject", "cust_42",
	})
	if placeErr != nil {
		t.Fatal(placeErr)
	}

	err := erase(eraseArgs(dir, keyring, "cust_42"))
	if err == nil {
		t.Fatal("a subject under legal hold was erased; the key is gone and no privilege " +
			"recovers the content")
	}
	// The refusal has to be about the hold, and it has to say enough for the
	// person reading it to act: which hold, what matter, who placed it.
	for _, want := range []string{"legal hold", "hold_bafin", "BaFin enquiry 2026/17", "compliance@bank"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
	// And it must not be the keyring's refusal wearing a hold's clothes.
	if strings.Contains(err.Error(), "not live") {
		t.Errorf("erase refused for the keyring rather than the hold, which sends an "+
			"operator to fix their setup and try again: %v", err)
	}

	// Released, and the hold no longer stands in the way. This half matters as
	// much: a hold that could not be lifted would make erasure impossible
	// forever, which is its own compliance failure.
	if err := holdCmd([]string{"release",
		"-evidence", dir,
		"-writer-key", filepath.Join(dir, "..", "keys", "writer.key"),
		"-id", "hold_bafin", "-by", "compliance@bank", "-reason", "enquiry closed",
	}); err != nil {
		t.Fatal(err)
	}
	if err := erase(eraseArgs(dir, keyring, "cust_42")); err != nil {
		t.Errorf("erasure failed after its hold was released: %v", err)
	}
}

// TestAnUnheldSubjectIsNotBlocked guards the other direction. A check that
// refused everything would pass the test above and make erasure impossible.
func TestAnUnheldSubjectIsNotBlocked(t *testing.T) {
	dir, keyring := eraseFixture(t)
	if err := holdCmd([]string{"place",
		"-evidence", dir,
		"-writer-key", filepath.Join(dir, "..", "keys", "writer.key"),
		"-id", "hold_other", "-matter", "unrelated matter",
		"-by", "compliance@bank", "-subject", "cust_99",
	}); err != nil {
		t.Fatal(err)
	}
	if err := erase(eraseArgs(dir, keyring, "cust_42")); err != nil {
		t.Errorf("a hold on cust_99 blocked the erasure of cust_42: %v", err)
	}
}

// TestAHoldRefusesToBeWrittenWithoutAnAccountablePerson: a hold nobody is
// accountable for cannot later be justified or lifted, so it is not a hold.
func TestAHoldRefusesToBeWrittenWithoutAnAccountablePerson(t *testing.T) {
	dir, _ := eraseFixture(t)
	base := []string{"place", "-evidence", dir,
		"-writer-key", filepath.Join(dir, "..", "keys", "writer.key")}

	for name, args := range map[string][]string{
		"no person": {"-id", "h", "-matter", "m"},
		"no id":     {"-matter", "m", "-by", "p"},
		"no matter": {"-id", "h", "-by", "p"},
	} {
		if err := holdCmd(append(append([]string{}, base...), args...)); err == nil {
			t.Errorf("%s: the hold was accepted", name)
		}
	}
	held, err := retention.FoldHolds(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(held.All()) != 0 {
		t.Fatalf("%d refused hold(s) reached the log", len(held.All()))
	}
}
