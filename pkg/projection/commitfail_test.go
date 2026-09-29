package projection_test

import (
	"path/filepath"
	"testing"

	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/projection"
	"github.com/mustafarslan/janus/pkg/registry"
)

// TestAFailedFoldLeavesNothingBehindInMemory.
//
// The rows and `last_event_seq` move in one transaction, so a fold that fails
// leaves the database exactly as it was. The projector's *in-memory* state has
// to match that, and the registry stream is where it is easiest to get wrong:
// advance it inside the transaction body and a failed commit leaves the
// projector holding events the table does not have. The head has not moved, so
// the next catch-up reads those same events out of the log again, appends them a
// second time, and refolds a stream with every one duplicated — which
// `registry.Apply` refuses as an illegal transition. Every fold after that
// fails, and on the admission path that is a daemon that has stopped admitting
// sagas.
//
// The failure is produced rather than simulated: another session takes an
// exclusive lock on a table the fold has to write, and the connection's
// lock_timeout turns the wait into an error.
func TestAFailedFoldLeavesNothingBehindInMemory(t *testing.T) {
	store, ctx, dsn := newStoreDSN(t)

	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.Close() }()

	trust := registry.TrustStore{}
	trust.Trust("pr_bank", signer.Public())
	rec := registry.NewRecorder(app, evidence.ParticipantRef{
		ID: "ag_operator", Principal: "pr_bank", Kind: "AGENT", ManifestVersion: "1.0.0",
	}, registry.New(), trust)

	register := func(id string) {
		t.Helper()
		m := testManifest(id, "1.0.0", "COMPENSABLE")
		sig, err := registry.Sign(m, signer)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rec.Register(ctx, m, sig); err != nil {
			t.Fatal(err)
		}
		if err := rec.Evaluate(ctx, id, "1.0.0", &janusv1.EvaluationReport{
			Passed: true, HarnessVersion: "test", Sandbox: "double",
			TriggersCovered: m.Risk.RevalidationTriggers,
		}); err != nil {
			t.Fatal(err)
		}
		if err := rec.Activate(ctx, id, "1.0.0"); err != nil {
			t.Fatal(err)
		}
	}

	proj := projection.NewProjector(store, dir)
	register("tool_first")
	if _, err := proj.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}

	// Now make the next fold fail, and fail it at the *end* of the transaction.
	// Where it fails is the whole point: the projector advances its in-memory
	// registry stream after writing the rows and before updating the head, so a
	// failure earlier than that proves nothing about the ordering. Holding the
	// single projection_meta row makes the head update -- the last statement
	// before the commit -- time out.
	register("tool_second")

	blocker := connect(t, ctx, dsn)
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var held string
	if err := tx.QueryRow(ctx, `SELECT log_id FROM projection_meta WHERE only_row FOR UPDATE`).Scan(&held); err != nil {
		t.Fatal(err)
	}

	if _, err := proj.CatchUp(ctx); err == nil {
		_ = tx.Rollback(ctx)
		t.Fatal("the fold succeeded while another session held the table it had to write")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// The failed fold must have left the projection where it was, and the
	// projector able to try again.
	head, err := proj.CatchUp(ctx)
	if err != nil {
		t.Fatalf("the projector could not recover from a failed fold: %v", err)
	}

	fromLog, err := registry.Replay(dir)
	if err != nil {
		t.Fatal(err)
	}
	fromProjection, err := proj.Registry(ctx, head)
	if err != nil {
		t.Fatal(err)
	}
	if want, got := describeRegistry(t, fromLog), describeRegistry(t, fromProjection); want != got {
		t.Errorf("after a failed fold and a retry the registry differs from the log's.\n"+
			"--- log ---\n%s\n--- projection ---\n%s", want, got)
	}
	if len(fromLog.Participants()) != 2 {
		t.Fatalf("expected two participants in the log, got %d", len(fromLog.Participants()))
	}
}
