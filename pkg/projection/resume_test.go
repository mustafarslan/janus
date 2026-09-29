package projection_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/projection"
)

// connect opens a direct connection to a projection schema.
func connect(t *testing.T, ctx context.Context, dsn string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	return conn
}

// dumpRows renders every projected row in a stable order.
//
// Comparing the rows rather than the answers is deliberate here. Two folds can
// agree on every frontier question and still differ in a column no current
// caller reads, and the next caller to read it would inherit a discrepancy
// nobody introduced on purpose.
func dumpRows(t *testing.T, ctx context.Context, dsn string) string {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()

	var b strings.Builder
	for _, q := range []string{
		`SELECT saga_id, tenant, status, mode, intent_ref, last_seq, terminal
		   FROM sagas ORDER BY saga_id`,
		`SELECT saga_id, step_id, ordinal, participant, effect_class, status, attempt
		   FROM steps ORDER BY saga_id, step_id`,
		`SELECT resource_id, saga_id, step_id, mode, frontier_seq
		   FROM resource_touches ORDER BY resource_id, saga_id, step_id, mode, frontier_seq`,
	} {
		rows, err := conn.Query(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			vals, err := rows.Values()
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&b, "%v\n", vals)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		b.WriteString("--\n")
	}
	return b.String()
}

// TestFoldingInStagesMatchesFoldingAtOnce is the resume property.
//
// Each stage uses a *new* projector against the same database, which is what a
// restart looks like: the durable rows survive, the in-memory working set does
// not, and the fold has to pick up from `last_event_seq` by recovering the
// unfinished sagas from the log. A projector that skipped that recovery would
// fold the next event of a live saga onto a blank projection — losing its
// earlier touches, which is a frontier check that cannot see a contending saga,
// and those pass.
//
// The comparison is against a single uninterrupted fold of the same log, so the
// claim is not "resume produces something plausible" but "resume produces
// exactly what never stopping would have".
func TestFoldingInStagesMatchesFoldingAtOnce(t *testing.T) {
	staged, ctx, stagedDSN := newStoreDSN(t)

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

	// The sagas whose histories straddle a stage boundary are the whole point.
	// `sg-straddle-*` begins and touches its resource in one stage and finishes
	// in a later one, so the projector that folds the ending has never seen the
	// beginning and must recover it from the log. Sagas that fit inside a single
	// stage exercise nothing: the fold starts them from blank either way, which
	// is why an earlier version of this test passed with the recovery disabled.
	straddleA := contenderEvents(t, contender{
		id: "sg-straddle-a", resource: "acct:A", write: true, end: "commit"})
	straddleB := contenderEvents(t, contender{
		id: "sg-straddle-b", resource: "acct:B", write: true, end: "quarantine"})

	// Split after the STEP_RESULT, so the half that is folded first carries the
	// resource touch and the half that is folded second carries the ending. A
	// projector that lost the first half would produce a saga with no touches --
	// invisible to every frontier query, which is the direction that fails open.
	const firstHalf = 3

	var heads []uint64
	catchUp := func(stage int) {
		t.Helper()
		// A brand new projector each time. Nothing carries over but the
		// database, which is what a restart leaves behind.
		h, err := projection.NewProjector(staged, dir).CatchUp(ctx)
		if err != nil {
			t.Fatalf("stage %d: %v", stage, err)
		}
		heads = append(heads, h)
	}

	appendContender(t, app, contender{id: "sg-a", resource: "acct:A", write: true, end: "commit"})
	appendEvents(t, app, "sg-straddle-a", straddleA[:firstHalf])
	appendEvents(t, app, "sg-straddle-b", straddleB[:firstHalf])
	catchUp(0)

	appendContender(t, app, contender{id: "sg-c", resource: "acct:A", write: true})
	appendEvents(t, app, "sg-straddle-b", straddleB[firstHalf:])
	catchUp(1)

	appendEvents(t, app, "sg-straddle-a", straddleA[firstHalf:])
	appendContender(t, app, contender{id: "sg-f", resource: "acct:C", write: false})
	catchUp(2)

	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	for i := 1; i < len(heads); i++ {
		if heads[i] <= heads[i-1] {
			t.Fatalf("stage %d did not advance the head: %d then %d", i, heads[i-1], heads[i])
		}
	}

	// The same log, folded once, into a different schema.
	atOnce, _, atOnceDSN := newStoreDSN(t)
	onceHead, err := projection.NewProjector(atOnce, dir).CatchUp(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if onceHead != heads[len(heads)-1] {
		t.Errorf("folding at once reached sequence %d, folding in stages reached %d",
			onceHead, heads[len(heads)-1])
	}

	if want, got := dumpRows(t, ctx, atOnceDSN), dumpRows(t, ctx, stagedDSN); want != got {
		t.Errorf("folding in stages produced different rows.\n--- at once ---\n%s\n--- in stages ---\n%s",
			want, got)
	}
}

// TestRebuildIsTheFallback: a projection that has been scribbled on comes back
// to exactly what the log says, and does so without being told what was wrong.
//
// This is the property every doc comment in this package leans on. "If it is
// suspect, rebuild it" is only an answer if a rebuild is a rederivation rather
// than a repair, and the way to show that is to damage the rows in a way no
// reconciliation could detect and confirm the result is byte-for-byte what an
// undamaged fold produces.
func TestRebuildIsTheFallback(t *testing.T) {
	store, ctx, dsn := newStoreDSN(t)
	dir, _ := contendingLog(t)

	proj := projection.NewProjector(store, dir)
	if _, err := proj.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	good := dumpRows(t, ctx, dsn)

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Exactly the damage that makes an unsettled saga look settled -- the
	// corruption a frontier check cannot survive, and the one no constraint
	// would catch.
	if _, err := conn.Exec(ctx, `UPDATE sagas SET status = 'COMMITTED', terminal = true`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `DELETE FROM resource_touches WHERE mode = 'MODE_WRITE'`); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)

	if damaged := dumpRows(t, ctx, dsn); damaged == good {
		t.Fatal("the damage did not take, so the rebuild below proves nothing")
	}

	if _, err := projection.NewProjector(store, dir).Rebuild(ctx); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if got := dumpRows(t, ctx, dsn); got != good {
		t.Errorf("a rebuild did not restore the projection the log describes.\n"+
			"--- want ---\n%s\n--- got ---\n%s", good, got)
	}
}
