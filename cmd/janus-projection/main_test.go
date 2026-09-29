package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/projection"
	"github.com/mustafarslan/janus/pkg/saga"
)

// The command is the projection's operator surface: `Projector.Rebuild` existed
// and there was no way to invoke it without writing Go. These drive the command
// functions the way the binary does, because that glue is what the command adds
// and nothing else touches it.

func scopedDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("JANUS_PG_DSN")
	if dsn == "" {
		if os.Getenv("JANUS_PG_REQUIRED") != "" {
			t.Fatal("JANUS_PG_REQUIRED is set but JANUS_PG_DSN is not, so the projection " +
				"command would have gone untested")
		}
		t.Skip("set JANUS_PG_DSN to exercise janus-projection")
	}
	ctx := context.Background()
	schema := "cli_" + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, strings.ToLower(t.Name()))
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	for _, q := range []string{`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`, `CREATE SCHEMA ` + schema} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	_ = admin.Close(ctx)
	t.Cleanup(func() {
		a, err := pgx.Connect(ctx, dsn)
		if err != nil {
			return
		}
		_, _ = a.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		_ = a.Close(ctx)
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "options=-c%20search_path%3D" + schema
}

// oneSaga writes a small committed saga so the log has a head to be behind.
func oneSaga(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "evidence")
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
	events := []saga.FixtureEvent{
		{Kind: "SAGA_BEGIN", Payload: []byte(`{"saga_id":"sg1","mode":"supervised",` +
			`"intent":{"intent_id":"in1","principal":"pr_bank"},` +
			`"plan":[{"step_id":"st","participant":"tool","action":"a",` +
			`"effect_class":"EFFECT_CLASS_PURE"}]}`)},
		{Kind: "STEP_PREPARE", Payload: []byte(`{"saga_id":"sg1","step_id":"st"}`)},
		{Kind: "STEP_RESULT", Payload: []byte(`{"saga_id":"sg1","step_id":"st",` +
			`"outcome":{"status":"STATUS_OK"}}`)},
	}
	replayable, err := saga.Fixture{Name: "sg1", Events: events}.Replayable()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range replayable {
		if _, err := app.Append(t.Context(), evidence.Request{
			Kind: e.Kind, SagaID: "sg1", Payload: e.Payload,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestStatusReportsTheGapAndRebuildClosesIt.
func TestStatusReportsTheGapAndRebuildClosesIt(t *testing.T) {
	dsn := scopedDSN(t)
	dir := oneSaga(t)

	// Nothing has folded, so the projection is behind by the whole log.
	if err := status([]string{"-evidence", dir, "-projection", dsn}); err != nil {
		t.Fatalf("status on an unfolded projection: %v", err)
	}
	if err := rebuild([]string{"-evidence", dir, "-projection", dsn}); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	ctx := context.Background()
	store, err := projection.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	projected, _, err := store.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	head, err := projection.LogHead(dir)
	if err != nil {
		t.Fatal(err)
	}
	if projected != head || head == 0 {
		t.Fatalf("after rebuild the projection is at %d and the log at %d", projected, head)
	}
}

// TestRebuildReportsWhatItFoldedAndWhatItCost.
//
// The restore drill reads this file to put the projection rebuild beside the
// restore and the sweep. `kept` is the field that
// earns its place: a rebuild over a log whose records the projector keeps none
// of finishes fast and reports the right head, so head alone cannot tell a fold
// from a skim.
func TestRebuildReportsWhatItFoldedAndWhatItCost(t *testing.T) {
	dsn := scopedDSN(t)
	dir := oneSaga(t)
	out := filepath.Join(t.TempDir(), "rebuild.json")

	if err := rebuild([]string{"-evidence", dir, "-projection", dsn, "-json", out}); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	blob, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Head    uint64 `json:"head"`
		TookNS  int64  `json:"took_ns"`
		Scanned uint64 `json:"scanned"`
		Kept    uint64 `json:"kept"`
		Phases  struct {
			ReadNS   int64 `json:"read_ns"`
			ApplyNS  int64 `json:"apply_ns"`
			CommitNS int64 `json:"commit_ns"`
			FoldNS   int64 `json:"fold_ns"`
		} `json:"phases"`
	}
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("the drill cannot read this: %v", err)
	}

	head, err := projection.LogHead(dir)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Head != head {
		t.Errorf("reported head %d, log head %d", doc.Head, head)
	}
	if doc.Kept == 0 || doc.Kept > doc.Scanned {
		t.Errorf("kept %d of %d scanned", doc.Kept, doc.Scanned)
	}
	if doc.TookNS <= 0 {
		t.Errorf("took_ns is %d", doc.TookNS)
	}
	// Wall time is measured outside the projector and the fold's own total
	// inside it, so the truncate, the pool and the writer lock sit between
	// them. The one that is not the other is the point of reporting both.
	if doc.Phases.FoldNS > doc.TookNS {
		t.Errorf("the fold took %d ns inside a %d ns call", doc.Phases.FoldNS, doc.TookNS)
	}
	if doc.Phases.ReadNS+doc.Phases.ApplyNS+doc.Phases.CommitNS > doc.Phases.FoldNS {
		t.Errorf("the three stages exceed the fold they are stages of")
	}
}

// TestARefusedRebuildLeavesTheProjectionWhereItWas.
//
// The refusal below is only worth having if it is one. Until the rebuild
// timing was measured, `rebuildLocked` truncated the store and *then* took the
// writer lock, so an operator running this against a live daemon read "stop it
// before rebuilding" over an already-empty projection: head 3 before, head 0
// after, and every frontier gate reading the store answering from no rows.
//
// This asserts the thing the message claims — that nothing moved — rather than
// the message.
func TestARefusedRebuildLeavesTheProjectionWhereItWas(t *testing.T) {
	dsn := scopedDSN(t)
	dir := oneSaga(t)
	ctx := context.Background()

	holder, err := projection.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	daemon := projection.NewProjector(holder, dir)
	if _, err := daemon.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	before, _, err := holder.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before == 0 {
		t.Fatal("the holder folded nothing, so there is no projection to destroy")
	}

	if err := rebuild([]string{"-evidence", dir, "-projection", dsn}); err == nil {
		t.Fatal("rebuild refolded a store something else was folding")
	}

	after, _, err := holder.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("the refused rebuild moved the projection from %d to %d: it emptied the "+
			"store and then declined to refill it", before, after)
	}

	// And the daemon that was holding the lock carries on. This is the second
	// half of the damage and it is worse than the empty rows: the projector's
	// in-memory working set still holds sg1 SEALED while the store it was
	// truncated out of reports head 0, so the next fold re-reads seq 3 and
	// applies a STEP_RESULT to a sealed saga. Measured, with the lock taken
	// after the truncate: `saga: illegal transition: STEP_RESULT for step "st"
	// in state SEALED`. Twice, because the state that produces it is the
	// projector's own and nothing in a failed fold changes it — the projection
	// does not go stale, it stops, until somebody restarts the daemon.
	for i := range 2 {
		at, err := daemon.CatchUp(ctx)
		if err != nil {
			t.Fatalf("fold %d after the refused rebuild: %v", i+1, err)
		}
		if at != before {
			t.Fatalf("fold %d after the refused rebuild reached %d, not %d", i+1, at, before)
		}
	}
}

// TestRebuildRefusesWhileSomethingElseIsFolding is the refusal that matters.
//
// Two things refolding one store is what the writer lock exists to prevent, and
// an operator running this against a live daemon is the realistic way to reach
// it. The message has to say what is holding it, or the answer looks like a bug
// in the command.
func TestRebuildRefusesWhileSomethingElseIsFolding(t *testing.T) {
	dsn := scopedDSN(t)
	dir := oneSaga(t)
	ctx := context.Background()

	// A "daemon": a store that has folded and is holding the writer lock.
	holder, err := projection.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if _, err := projection.NewProjector(holder, dir).CatchUp(ctx); err != nil {
		t.Fatal(err)
	}

	err = rebuild([]string{"-evidence", dir, "-projection", dsn})
	if err == nil {
		t.Fatal("rebuild refolded a store something else was folding")
	}
	if !errors.Is(err, projection.ErrNotTheWriter) {
		t.Fatalf("expected a writer-lock refusal, got: %v", err)
	}
	if !strings.Contains(err.Error(), "janus-orchd") {
		t.Errorf("the refusal does not say what is likely holding it: %v", err)
	}

	// status is a read and must still work while the lock is held — an operator
	// diagnosing a stuck daemon is exactly who needs it.
	if err := status([]string{"-evidence", dir, "-projection", dsn}); err != nil {
		t.Errorf("status could not read a store being folded: %v", err)
	}
}

// TestStatusRefusesAProjectionFromAnotherLog: a confident number about the wrong
// log is worse than an error.
func TestStatusRefusesAProjectionFromAnotherLog(t *testing.T) {
	dsn := scopedDSN(t)
	mine, theirs := oneSaga(t), oneSaga(t)
	ctx := context.Background()

	store, err := projection.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := projection.NewProjector(store, theirs).CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	store.Close()

	if err := status([]string{"-evidence", mine, "-projection", dsn}); err == nil {
		t.Fatal("status reported on a projection built from a different log")
	} else if !errors.Is(err, projection.ErrWrongLog) {
		t.Fatalf("expected a wrong-log refusal, got: %v", err)
	}
}

// TestTheDSNHasNoDefault: a command silently pointed at a database nobody meant
// to use is worse than a failure.
func TestTheDSNHasNoDefault(t *testing.T) {
	err := status([]string{"-evidence", t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "-projection is required") {
		t.Fatalf("status ran without a projection: %v", err)
	}
}
