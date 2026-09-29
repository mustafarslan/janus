package projection

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	janusv1 "github.com/mustafarslan/janus/gen/go/janus/v1"
	"github.com/mustafarslan/janus/pkg/saga"
)

// touchStore opens a schema-scoped store, so this test writes the real tables
// through the real statements rather than asserting on a string of SQL.
func touchStore(t *testing.T) (*Store, context.Context, string) {
	t.Helper()
	dsn := os.Getenv("JANUS_PG_DSN")
	if dsn == "" {
		if os.Getenv("JANUS_PG_REQUIRED") != "" {
			t.Fatal("JANUS_PG_REQUIRED is set but JANUS_PG_DSN is not")
		}
		t.Skip("set JANUS_PG_DSN to run the projection tests against a real Postgres")
	}
	ctx := context.Background()
	schema := "up_" + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, strings.ToLower(t.Name()))

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to %s: %v", dsn, err)
	}
	for _, q := range []string{
		`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`,
		`CREATE SCHEMA ` + schema,
	} {
		if _, err := admin.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	_ = admin.Close(ctx)

	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	scoped := dsn + sep + "options=-c%20search_path%3D" + schema
	store, err := Open(ctx, scoped)
	if err != nil {
		t.Fatalf("open projection: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store, ctx, scoped
}

// writeOnce runs one saga's rows through the batch the fold uses, in its own
// transaction, exactly as a fold would.
func writeOnce(t *testing.T, ctx context.Context, store *Store, s saga.State) {
	t.Helper()
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var b rowBatch
	if err := queueSaga(&b, s, "bank_x", 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := b.send(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestATouchListIsStillClearedBeforeItIsRewritten.
//
// The other half of the DELETE family stays, and the reason is in the schema:
// `resource_touches` has no primary key on purpose, because a step's touch list
// may legally carry the same resource, mode and sequence twice and a uniqueness
// constraint would turn that history into a projector crash. With no conflict
// target there is nothing to upsert against, so a second write of the same list
// would accumulate rather than replace.
//
// **This test exists because the measurement made removing it tempting.** The
// DELETE family is 40% of the commit's statements (docs/bench/README.md), which
// reads as an invitation; the steps half was tried, measured a wash, and
// reverted, and this half cannot be removed at all without a schema change.
// Nothing on the real path would have noticed the duplicates.
func TestATouchListIsStillClearedBeforeItIsRewritten(t *testing.T) {
	store, ctx, dsn := touchStore(t)

	s := saga.State{
		SagaID: "sg_touch", Status: saga.StatusRunning, Order: []string{"one"},
		Steps: map[string]*saga.Step{"one": {
			ID: "one", Participant: "ag_a", Status: saga.StepCommitted,
			Touches: []saga.Touch{
				{Resource: "acct:a", Mode: janusv1.ResourceTouch_MODE_WRITE, Seq: 1},
				// The same resource, mode and sequence twice: legal, and the
				// reason the table has no primary key.
				{Resource: "acct:a", Mode: janusv1.ResourceTouch_MODE_WRITE, Seq: 1},
			},
		}},
	}

	writeOnce(t, ctx, store, s)
	writeOnce(t, ctx, store, s)

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()

	var rows int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM resource_touches`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Fatalf("%d touch rows after folding the same two-touch list twice, want 2: "+
			"either the clearing DELETE is gone and duplicates are accumulating, or a "+
			"legal repeated touch is being collapsed", rows)
	}
}
