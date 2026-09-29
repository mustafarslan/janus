package retention_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/retention"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
)

// holdLog gives a test its own evidence directory and a recorder over it.
//
// The appender is closed and reopened on each use rather than held, because the
// property under test is what survives a process, and a test that kept one
// appender open for its whole life would never exercise that.
func holdLog(t *testing.T) (dir string, rec *retention.Recorder) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "evidence")
	return dir, recorderFor(t, dir)
}

// recorderFor opens an appender on a directory and closes it when the test ends.
func recorderFor(t *testing.T, dir string) *retention.Recorder {
	t.Helper()
	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Close() })
	return retention.NewRecorder(app, evidence.ParticipantRef{ID: "janus-tier"})
}

// TestAHoldSurvivesTheProcessThatPlacedIt.
//
// This is the test that had never been
// possible, and it is the whole point of the change. `Engine.holds` was an
// in-memory map: a hold placed by an accountable person for a named matter
// ceased silently when the process restarted, and nothing anywhere recorded
// that it had ever existed. For a configuration flag that is a limitation; for
// a litigation hold it is an incident.
//
// So: place a hold, close the appender entirely, open the directory cold, and
// require the hold to still be there with everything a lawyer would ask about
// it.
func TestAHoldSurvivesTheProcessThatPlacedIt(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "evidence")
	placed := time.Now().UTC()

	func() {
		signer, err := keys.Generate()
		if err != nil {
			t.Fatal(err)
		}
		app, err := evidence.Open(evidence.Options{
			Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
		})
		if err != nil {
			t.Fatal(err)
		}
		rec := retention.NewRecorder(app, evidence.ParticipantRef{ID: "janus-tier"})
		if err := rec.Place(ctx, dir, retention.LegalHold{
			ID: "hold_bafin", Matter: "BaFin enquiry 2026/17", PlacedBy: "compliance@bank",
			PlacedAt: placed,
			Scope:    retention.Scope{Subjects: []string{"cust_42"}},
		}); err != nil {
			t.Fatal(err)
		}
		// The process ends here. Everything below is a different one.
		if err := app.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	held, err := retention.FoldHolds(dir)
	if err != nil {
		t.Fatal(err)
	}
	all := held.All()
	if len(all) != 1 {
		t.Fatalf("a cold read of the log found %d hold(s), want 1; the hold did not "+
			"survive the process that placed it", len(all))
	}
	h := all[0]
	// Every field a lawyer would ask about has to come back, not just the id.
	// "Something was held" is not an answer to "what was held, for what, by whom,
	// and from when".
	if h.ID != "hold_bafin" || h.Matter != "BaFin enquiry 2026/17" || h.PlacedBy != "compliance@bank" {
		t.Errorf("the folded hold lost its identity: %+v", h)
	}
	if len(h.Scope.Subjects) != 1 || h.Scope.Subjects[0] != "cust_42" {
		t.Errorf("the folded hold lost its scope: %+v", h.Scope)
	}
	if h.PlacedAt.IsZero() {
		t.Error("the folded hold has no placement time, so nobody can say when disposal stopped")
	}
	if !h.Active(time.Now().UTC()) {
		t.Error("the folded hold is not active")
	}

	// And the release survives too, which is the other half: the fact a lawyer
	// needs second is when destruction was allowed to resume.
	if err := recorderFor(t, dir).Release(ctx, dir, "hold_bafin",
		"compliance@bank", "enquiry closed", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	reread, err := retention.FoldHolds(dir)
	if err != nil {
		t.Fatal(err)
	}
	after := reread.All()
	if len(after) != 1 {
		t.Fatalf("the released hold vanished from the log; %d remain", len(after))
	}
	if after[0].ReleasedAt == nil || after[0].ReleasedBy != "compliance@bank" {
		t.Errorf("the release did not survive the fold: %+v", after[0])
	}
	if after[0].Active(time.Now().UTC().Add(time.Minute)) {
		t.Error("a released hold is still active")
	}
	// Released, not forgotten: "this was held until March" is what explains why
	// records outlived their ceiling.
	if len(reread.Active(time.Now().UTC().Add(time.Minute))) != 0 {
		t.Error("a released hold is still counted as in force")
	}
}

// TestAnUnscopedHoldCoversEverySubject.
//
// An empty scope freezes everything, which is occasionally what a supervisor
// demands. The subject lookup has to honour that rather than looking for a name
// in an empty list and finding none — the failure mode being an unscoped hold
// that reads as the broadest possible and enforces nothing.
func TestAnUnscopedHoldCoversEverySubject(t *testing.T) {
	ctx := context.Background()
	dir, rec := holdLog(t)
	if err := rec.Place(ctx, dir, retention.LegalHold{
		ID: "everything", Matter: "supervisory freeze", PlacedBy: "compliance@bank",
		PlacedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	held, err := retention.FoldHolds(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := held.CoveringSubject("anybody", time.Now().UTC()); len(got) != 1 {
		t.Fatalf("an unscoped hold covers %d subject-level holds, want 1; it is supposed "+
			"to freeze everything", len(got))
	}
}

// TestACompoundScopeStillFreezesItsSubject.
//
// This is why CoveringSubject is not `Scope.Matches(Record{Subject: s})`, and
// the case is narrow enough to be worth stating exactly. `Matches` is an AND
// over every non-empty dimension, evaluated against a *record*: a hold scoped
// to saga sg_1 **and** subject cust_42 does not match a bare
// `Record{Subject: "cust_42"}`, because that record's saga id is empty and so
// fails the saga clause.
//
// For a record being considered for disposal that is right. For an erasure it
// is wrong, and dangerously so, because erasure is not per-record: destroying
// cust_42's data encryption key destroys every record of theirs, including the
// ones in sg_1 that the hold names. So the question "is this person frozen" is
// an OR over the subject dimension alone, and a hold naming them freezes their
// erasure however else it is scoped.
func TestACompoundScopeStillFreezesItsSubject(t *testing.T) {
	ctx := context.Background()
	dir, rec := holdLog(t)
	if err := rec.Place(ctx, dir, retention.LegalHold{
		ID: "saga_and_subject", Matter: "matter", PlacedBy: "compliance@bank",
		PlacedAt: time.Now().UTC(),
		Scope: retention.Scope{
			SagaIDs:  []string{"sg_1"},
			Subjects: []string{"cust_42"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	held, err := retention.FoldHolds(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := held.CoveringSubject("cust_42", time.Now().UTC()); len(got) != 1 {
		t.Fatalf("a hold naming cust_42 does not freeze their erasure (%d holds); "+
			"erasing them destroys the key for every record of theirs, sg_1's included",
			len(got))
	}
	// And it still must not freeze somebody the hold does not name.
	if got := held.CoveringSubject("cust_99", time.Now().UTC()); len(got) != 0 {
		t.Errorf("the hold froze an unnamed subject: %+v", got)
	}
}

// TestAHoldScopedElsewhereDoesNotFreezeASubject: a hold naming only sagas says
// nothing about any person's erasure.
func TestAHoldScopedElsewhereDoesNotFreezeASubject(t *testing.T) {
	ctx := context.Background()
	dir, rec := holdLog(t)
	if err := rec.Place(ctx, dir, retention.LegalHold{
		ID: "one_saga", Matter: "matter", PlacedBy: "compliance@bank",
		PlacedAt: time.Now().UTC(),
		Scope:    retention.Scope{SagaIDs: []string{"sg_1"}},
	}); err != nil {
		t.Fatal(err)
	}
	held, err := retention.FoldHolds(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := held.CoveringSubject("cust_42", time.Now().UTC()); len(got) != 0 {
		t.Errorf("a hold scoped to saga sg_1 froze the erasure of cust_42: %+v", got)
	}
}
