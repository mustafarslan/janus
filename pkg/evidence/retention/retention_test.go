package retention_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence/retention"
)

func mustEngine(t *testing.T, s retention.Schedule) *retention.Engine {
	t.Helper()
	e, err := retention.NewEngine(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func dur(t *testing.T, s string) retention.Duration {
	t.Helper()
	d, err := retention.ParseDuration(s)
	if err != nil {
		t.Fatal(err)
	}
	return retention.Duration(d)
}

var epoch = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// TestDefaultScheduleIsValid: the shipped default has to be self-consistent, or
// every deployment starts from a broken schedule.
func TestDefaultScheduleIsValid(t *testing.T) {
	s := retention.DefaultSchedule()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, class := range retention.AllClasses() {
		if _, err := s.Lookup(class, "DE"); err != nil {
			t.Errorf("default schedule does not cover class %q: %v", class, err)
		}
	}
}

// TestUncoveredRecordIsAnError: disposing of something no rule mentions is the
// exact mistake a schedule exists to prevent, so an unmatched record must not
// fall through to a permissive default.
func TestUncoveredRecordIsAnError(t *testing.T) {
	e := mustEngine(t, retention.Schedule{
		Version: 1,
		Policies: []retention.Policy{
			{Class: retention.ClassTransaction, MinRetention: dur(t, "6y"), Mode: retention.DisposeNone},
		},
	})
	_, err := e.Evaluate(retention.Record{Class: retention.ClassPersonal, CreatedAt: epoch}, epoch.AddDate(50, 0, 0))
	if !errors.Is(err, retention.ErrNoPolicy) {
		t.Fatalf("got %v, want ErrNoPolicy", err)
	}
}

func TestMinimumRetentionIsAFloor(t *testing.T) {
	e := mustEngine(t, retention.Schedule{
		Version: 1,
		Policies: []retention.Policy{{
			Class: retention.ClassPersonal, MinRetention: dur(t, "6y"), MaxRetention: dur(t, "10y"),
			Mode: retention.DisposeCryptoShred,
		}},
	})
	rec := retention.Record{Class: retention.ClassPersonal, CreatedAt: epoch}

	for _, at := range []time.Time{epoch, epoch.AddDate(1, 0, 0), epoch.AddDate(5, 11, 0)} {
		d, err := e.Evaluate(rec, at)
		if err != nil {
			t.Fatal(err)
		}
		if d.Disposable {
			t.Fatalf("record was disposable at %s, inside its six-year minimum", at.Format(time.RFC3339))
		}
		if d.EligibleAt.IsZero() {
			t.Fatal("no eligibility date was reported")
		}
	}
}

func TestDisposableOnlyPastTheMaximum(t *testing.T) {
	e := mustEngine(t, retention.Schedule{
		Version: 1,
		Policies: []retention.Policy{{
			Class: retention.ClassPersonal, MinRetention: dur(t, "6y"), MaxRetention: dur(t, "10y"),
			Mode: retention.DisposeCryptoShred,
		}},
	})
	rec := retention.Record{Class: retention.ClassPersonal, CreatedAt: epoch}

	between, err := e.Evaluate(rec, epoch.AddDate(8, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if between.Disposable {
		t.Fatal("record was disposable between the minimum and the maximum")
	}

	after, err := e.Evaluate(rec, epoch.AddDate(11, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !after.Disposable {
		t.Fatalf("record was not disposable past its maximum: %s", after.Reason)
	}
	if after.Mode != retention.DisposeCryptoShred {
		t.Fatalf("disposal mode is %q, want crypto-shred", after.Mode)
	}
}

// TestNoMaximumMeansKeep: most evidence classes have a floor and no ceiling, and
// the absence of a ceiling must never be read as permission to delete.
func TestNoMaximumMeansKeep(t *testing.T) {
	e := mustEngine(t, retention.Schedule{
		Version: 1,
		Policies: []retention.Policy{{
			Class: retention.ClassTransaction, MinRetention: dur(t, "6y"), Mode: retention.DisposeDelete,
		}},
	})
	d, err := e.Evaluate(retention.Record{Class: retention.ClassTransaction, CreatedAt: epoch}, epoch.AddDate(100, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if d.Disposable {
		t.Fatal("a policy with no maximum allowed disposal a century later")
	}
}

// personalSchedule is the one-policy schedule the hold tests reason about.
func personalSchedule(t *testing.T) retention.Schedule {
	t.Helper()
	return retention.Schedule{
		Version: 1,
		Policies: []retention.Policy{{
			Class: retention.ClassPersonal, MinRetention: dur(t, "1y"), MaxRetention: dur(t, "2y"),
			Mode: retention.DisposeCryptoShred,
		}},
	}
}

// heldEngine places holds through the real path -- a recorder appending to a
// log, then a cold fold -- and loads the result into an engine.
//
// It goes the long way round on purpose. Every hold test below used to call a
// method that put an entry in a map, which is precisely the defect
// here: those tests passed against an engine whose holds died with the
// process. Routing them through the log means they now fail if the recording,
// the fold, or the engine's loading of it breaks.
func heldEngine(t *testing.T, s retention.Schedule, place ...retention.LegalHold) (*retention.Engine, string, *retention.Recorder) {
	t.Helper()
	dir, rec := holdLog(t)
	for _, h := range place {
		if err := rec.Place(context.Background(), dir, h); err != nil {
			t.Fatalf("placing %s: %v", h.ID, err)
		}
	}
	e := mustEngine(t, s)
	held, err := retention.FoldHolds(dir)
	if err != nil {
		t.Fatal(err)
	}
	e.LoadHolds(held)
	// The recorder comes back with the engine because one process writes a
	// directory: a test needing a second write has to reuse this
	// appender rather than open another.
	return e, dir, rec
}

// reload folds the log again and reinstalls the holds, as a restarted process
// would.
func reload(t *testing.T, e *retention.Engine, dir string) {
	t.Helper()
	held, err := retention.FoldHolds(dir)
	if err != nil {
		t.Fatal(err)
	}
	e.LoadHolds(held)
}

// TestLegalHoldOutranksTheSchedule is the rule that matters most: a matter under
// investigation freezes disposal even when the schedule says the record should
// have gone.
func TestLegalHoldOutranksTheSchedule(t *testing.T) {
	// The timeline runs to now rather than from a fixed epoch, because a hold's
	// placement time is the wall clock of the event that placed it. There is no
	// way to backdate one, which is the right property for a legal hold and the
	// reason these tests cannot use a synthetic past.
	now := time.Now().UTC()
	created := now.AddDate(-5, 0, 0)
	rec := retention.Record{Class: retention.ClassPersonal, Subject: "cust_42", CreatedAt: created}
	at := now.Add(time.Minute)

	plain := mustEngine(t, personalSchedule(t))
	before, err := plain.Evaluate(rec, at)
	if err != nil {
		t.Fatal(err)
	}
	if !before.Disposable {
		t.Fatalf("setup: record should be disposable without a hold: %s", before.Reason)
	}

	e, dir, rec2 := heldEngine(t, personalSchedule(t), retention.LegalHold{
		ID: "hold_1", Matter: "BaFin enquiry 2025/17", PlacedBy: "compliance@bank",
		PlacedAt: now,
		Scope:    retention.Scope{Subjects: []string{"cust_42"}},
	})

	during, err := e.Evaluate(rec, at)
	if err != nil {
		t.Fatal(err)
	}
	if during.Disposable {
		t.Fatal("a legal hold did not stop disposal")
	}
	if len(during.HeldBy) != 1 || during.HeldBy[0] != "hold_1" {
		t.Fatalf("decision did not name the hold: %+v", during.HeldBy)
	}

	// Releasing the hold restores the schedule's answer -- and, like placing it,
	// the release has to survive the fold.
	if err := rec2.Release(context.Background(), dir, "hold_1",
		"compliance@bank", "enquiry closed", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	reload(t, e, dir)
	after, err := e.Evaluate(rec, time.Now().UTC().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !after.Disposable {
		t.Fatalf("record stayed frozen after its hold was released: %s", after.Reason)
	}
}

// TestHoldScopeDoesNotFreezeEverything: an investigation into one customer must
// not stop disposal of unrelated personal data, which would itself be a
// data-protection failure.
func TestHoldScopeDoesNotFreezeEverything(t *testing.T) {
	now := time.Now().UTC()
	created := now.AddDate(-5, 0, 0)
	at := now.Add(time.Minute)

	e, _, _ := heldEngine(t, personalSchedule(t), retention.LegalHold{
		ID: "hold_1", Matter: "matter", PlacedBy: "compliance", PlacedAt: now,
		Scope: retention.Scope{Subjects: []string{"cust_42"}},
	})

	held, err := e.Evaluate(retention.Record{
		Class: retention.ClassPersonal, Subject: "cust_42", CreatedAt: created}, at)
	if err != nil {
		t.Fatal(err)
	}
	other, err := e.Evaluate(retention.Record{
		Class: retention.ClassPersonal, Subject: "cust_99", CreatedAt: created}, at)
	if err != nil {
		t.Fatal(err)
	}
	if held.Disposable {
		t.Fatal("the held subject was disposable")
	}
	if !other.Disposable {
		t.Fatalf("an unrelated subject was frozen by a scoped hold: %s", other.Reason)
	}
}

func TestHoldIsNotActiveBeforeItWasPlaced(t *testing.T) {
	now := time.Now().UTC()
	e, _, _ := heldEngine(t, personalSchedule(t), retention.LegalHold{
		ID: "recent", Matter: "m", PlacedBy: "c", PlacedAt: now,
	})
	// Asked about a moment before the hold was placed. A record disposable then
	// was disposable then, and a hold placed afterwards does not reach back and
	// make a past disposal retrospectively wrong.
	d, err := e.Evaluate(
		retention.Record{Class: retention.ClassPersonal, CreatedAt: now.AddDate(-5, 0, 0)},
		now.AddDate(-1, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Disposable {
		t.Fatalf("a hold froze a record at a time before the hold existed: %s", d.Reason)
	}
}

func TestHoldLifecycleValidation(t *testing.T) {
	ctx := context.Background()
	dir, rec := holdLog(t)
	now := time.Now().UTC()
	valid := retention.LegalHold{ID: "h", Matter: "m", PlacedBy: "p", PlacedAt: now}

	for name, h := range map[string]retention.LegalHold{
		"no id":     {Matter: "m", PlacedBy: "p", PlacedAt: now},
		"no matter": {ID: "h", PlacedBy: "p", PlacedAt: now},
		"no person": {ID: "h", Matter: "m", PlacedAt: now},
		"no time":   {ID: "h", Matter: "m", PlacedBy: "p"},
	} {
		if err := rec.Place(ctx, dir, h); err == nil {
			t.Errorf("%s: hold was accepted", name)
		}
	}

	if err := rec.Place(ctx, dir, valid); err != nil {
		t.Fatal(err)
	}
	if err := rec.Place(ctx, dir, valid); err == nil {
		t.Fatal("the same hold id was accepted twice")
	}
	if err := rec.Release(ctx, dir, "h", "", "", now); err == nil {
		t.Fatal("a hold was released with nobody accountable")
	}
	if err := rec.Release(ctx, dir, "nonexistent", "p", "", now); err == nil {
		t.Fatal("releasing an unknown hold succeeded")
	}
	if err := rec.Release(ctx, dir, "h", "p", "", now); err != nil {
		t.Fatal(err)
	}
	if err := rec.Release(ctx, dir, "h", "p", "", now); err == nil {
		t.Fatal("a hold was released twice")
	}

	// A refused placement must not have reached the log. Validating after the
	// append would leave the log carrying history the fold then refuses, which
	// is worse than the refusal it was meant to be.
	held, err := retention.FoldHolds(dir)
	if err != nil {
		t.Fatalf("the log does not fold, so a refused hold was written anyway: %v", err)
	}
	if len(held.All()) != 1 {
		t.Fatalf("the log holds %d hold(s); one was placed and the rest were refused",
			len(held.All()))
	}
}

// TestJurisdictionOverridesGlobal: a schedule states a baseline and raises it
// where a regime is stricter.
func TestJurisdictionOverridesGlobal(t *testing.T) {
	s := retention.Schedule{
		Version: 1,
		Policies: []retention.Policy{
			{Class: retention.ClassPersonal, MinRetention: dur(t, "1y"), MaxRetention: dur(t, "2y"), Mode: retention.DisposeCryptoShred},
			{Class: retention.ClassPersonal, Jurisdiction: "TR", MinRetention: dur(t, "10y"), Mode: retention.DisposeNone},
		},
	}
	e := mustEngine(t, s)
	at := epoch.AddDate(5, 0, 0)

	global, err := e.Evaluate(retention.Record{Class: retention.ClassPersonal, Jurisdiction: "DE", CreatedAt: epoch}, at)
	if err != nil {
		t.Fatal(err)
	}
	if !global.Disposable {
		t.Fatalf("the global policy should permit disposal by now: %s", global.Reason)
	}

	turkish, err := e.Evaluate(retention.Record{Class: retention.ClassPersonal, Jurisdiction: "TR", CreatedAt: epoch}, at)
	if err != nil {
		t.Fatal(err)
	}
	if turkish.Disposable {
		t.Fatal("the stricter jurisdiction policy was not applied")
	}
}

func TestScheduleValidationRejectsContradictions(t *testing.T) {
	for name, s := range map[string]retention.Schedule{
		"empty": {Version: 1},
		"max below min": {Version: 1, Policies: []retention.Policy{{
			Class: retention.ClassPersonal, MinRetention: dur(t, "10y"), MaxRetention: dur(t, "1y"),
			Mode: retention.DisposeCryptoShred,
		}}},
		"duplicate": {Version: 1, Policies: []retention.Policy{
			{Class: retention.ClassPersonal, MinRetention: dur(t, "1y"), Mode: retention.DisposeNone},
			{Class: retention.ClassPersonal, MinRetention: dur(t, "2y"), Mode: retention.DisposeNone},
		}},
		"unknown class": {Version: 1, Policies: []retention.Policy{
			{Class: "invented", MinRetention: dur(t, "1y"), Mode: retention.DisposeNone},
		}},
		"unknown mode": {Version: 1, Policies: []retention.Policy{
			{Class: retention.ClassPersonal, MinRetention: dur(t, "1y"), Mode: "incinerate"},
		}},
		"no mode": {Version: 1, Policies: []retention.Policy{
			{Class: retention.ClassPersonal, MinRetention: dur(t, "1y")},
		}},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: schedule was accepted", name)
		}
	}
}

// TestDisposalRecordRequiresPermission: the disposal record is the audit trail's
// account of a deletion, so it must not be constructible for a deletion the
// policy never allowed.
func TestDisposalRecordRequiresPermission(t *testing.T) {
	e := mustEngine(t, retention.DefaultSchedule())
	d, err := e.Evaluate(retention.Record{Class: retention.ClassTransaction, CreatedAt: epoch}, epoch.AddDate(1, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retention.NewDisposalRecord(d, []string{"seg:1"}, "officer", epoch); err == nil {
		t.Fatal("a disposal record was built for a record that may not be disposed of")
	}
}

func TestDisposalRecordNamesAnApprover(t *testing.T) {
	e := mustEngine(t, retention.Schedule{
		Version: 1,
		Policies: []retention.Policy{{
			Class: retention.ClassPersonal, MinRetention: dur(t, "1y"), MaxRetention: dur(t, "2y"),
			Mode: retention.DisposeCryptoShred, Authority: "GDPR Art. 17",
		}},
	})
	d, err := e.Evaluate(retention.Record{
		Class: retention.ClassPersonal, Subject: "cust_7", CreatedAt: epoch,
	}, epoch.AddDate(5, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Disposable {
		t.Fatalf("setup: expected the record to be disposable: %s", d.Reason)
	}

	if _, err := retention.NewDisposalRecord(d, []string{"cas://blake3:aa"}, "", epoch); err == nil {
		t.Fatal("a disposal was recorded with nobody accountable")
	}

	rec, err := retention.NewDisposalRecord(d, []string{"cas://blake3:aa"}, "dpo@bank", epoch.AddDate(5, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Count != 1 || rec.Mode != retention.DisposeCryptoShred || rec.ApprovedBy != "dpo@bank" {
		t.Fatalf("disposal record is missing detail: %+v", rec)
	}
	if rec.Authority == "" {
		t.Fatal("disposal record does not cite the rule that permitted it")
	}

	// The payload is hashed into the chain, so it must encode identically each
	// time.
	first, err := rec.Payload()
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, err := rec.Payload()
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(first) {
			t.Fatal("the disposal payload does not encode deterministically")
		}
	}
}

func TestParseDurationAcceptsScheduleShorthand(t *testing.T) {
	cases := map[string]time.Duration{
		"6y":    6 * 365 * 24 * time.Hour,
		"180d":  180 * 24 * time.Hour,
		"2160h": 2160 * time.Hour,
		"0.5y":  time.Duration(0.5 * 365 * 24 * float64(time.Hour)),
	}
	for in, want := range cases {
		got, err := retention.ParseDuration(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"", "  ", "six years", "5x", "y"} {
		if _, err := retention.ParseDuration(bad); err == nil {
			t.Errorf("%q was accepted as a duration", bad)
		}
	}
}

// TestScheduleRoundTripsThroughAFile: the schedule is meant to be read and
// edited by a compliance function, so it has to survive a file round trip in a
// form a person can review.
func TestScheduleRoundTripsThroughAFile(t *testing.T) {
	original := retention.DefaultSchedule()
	blob, err := original.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(blob) {
		t.Fatal("marshalled schedule is not valid JSON")
	}
	// Durations must be readable, not nanosecond counts.
	if !strings.Contains(string(blob), `"6y"`) && !strings.Contains(string(blob), `"52560h0m0s"`) {
		t.Fatalf("durations are not human-readable in the file:\n%s", blob)
	}

	path := filepath.Join(t.TempDir(), "retention.json")
	if err := os.WriteFile(path, blob, 0o640); err != nil {
		t.Fatal(err)
	}
	loaded, err := retention.LoadSchedule(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Policies) != len(original.Policies) {
		t.Fatalf("loaded %d policies, wrote %d", len(loaded.Policies), len(original.Policies))
	}
	for i := range loaded.Policies {
		if loaded.Policies[i] != original.Policies[i] {
			t.Fatalf("policy %d changed across the round trip:\n got %+v\nwant %+v",
				i, loaded.Policies[i], original.Policies[i])
		}
	}
}

func TestLoadScheduleRejectsInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"policies":[]}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := retention.LoadSchedule(path); err == nil {
		t.Fatal("an empty schedule was loaded")
	}
	if _, err := retention.LoadSchedule(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("a missing schedule file loaded successfully")
	}
}
