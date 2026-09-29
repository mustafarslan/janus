package projection_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/keys"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/gate"
	"github.com/mustafarslan/janus/pkg/projection"
	"github.com/mustafarslan/janus/pkg/saga"
)

const fixtureDir = "../saga/testdata/fixtures"

// storeSeq makes each store's schema name unique within a run.
var storeSeq int

// newStore gives each test its own Postgres schema.
//
// A schema rather than a shared set of tables, so tests do not have to be
// serialised and a failure cannot leave rows behind that make the next run
// disagree with this one for reasons nobody can see.
//
// JANUS_PG_REQUIRED mirrors JANUS_S3_REQUIRED in the object-storage tests and
// exists for the same reason: without it, a CI job whose database never came up
// reports a clean run while the projection goes entirely untested.
func newStore(t *testing.T) (*projection.Store, context.Context) {
	store, ctx, _ := newStoreDSN(t)
	return store, ctx
}

// newStoreDSN is newStore, also handing back the schema-scoped connection string
// so a test can read the projected rows directly rather than only through the
// package that wrote them.
func newStoreDSN(t *testing.T) (*projection.Store, context.Context, string) {
	t.Helper()
	dsn := os.Getenv("JANUS_PG_DSN")
	if dsn == "" {
		if os.Getenv("JANUS_PG_REQUIRED") != "" {
			t.Fatal("JANUS_PG_REQUIRED is set but JANUS_PG_DSN is not, so these tests " +
				"would have been skipped and the projection would be untested")
		}
		t.Skip("set JANUS_PG_DSN to run the projection tests against a real Postgres")
	}
	ctx := context.Background()

	// Each call gets its own schema, not one per test. Two stores in one test is
	// how "a second projector" and "a cold fold of the same log" are written,
	// and sharing a schema between them would have them contend for the writer
	// lock -- which is correct behaviour being triggered by the harness rather
	// than by the thing under test.
	storeSeq++
	schema := fmt.Sprintf("t%d_", storeSeq) + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, strings.ToLower(t.Name()))
	if len(schema) > 60 {
		schema = schema[:60]
	}

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to %s: %v", dsn, err)
	}
	if _, err := admin.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	_ = admin.Close(ctx)

	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	// lock_timeout as well as the schema: a test that deadlocks against a lock
	// somebody else holds should fail in half a second rather than hang until
	// the suite times out, and one test below takes such a lock on purpose.
	scoped := dsn + sep + "options=-c%20search_path%3D" + schema + "%20-c%20lock_timeout%3D500ms"

	store, err := projection.Open(ctx, scoped)
	if err != nil {
		t.Fatalf("open projection: %v", err)
	}
	t.Cleanup(func() {
		store.Close()
		a, err := pgx.Connect(ctx, dsn)
		if err != nil {
			return
		}
		_, _ = a.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		_ = a.Close(ctx)
	})
	return store, ctx, scoped
}

// corpusLog writes every fixture in the corpus into one evidence directory.
//
// One directory rather than twenty is the point: a frontier gate is a question
// about *other* sagas, so a corpus in which every saga lives alone would
// exercise the only case where the answer is trivially "nothing contends".
// Appending them together makes the fixtures contend for whatever resources they
// happen to share, and re-numbers their sequences into one total order, which is
// what the log gives a real deployment.
func corpusLog(t *testing.T) (dir string, sagaIDs []string) {
	t.Helper()
	fixtures, err := saga.LoadFixtures(fixtureDir)
	if err != nil {
		t.Fatalf("loading the corpus: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("the corpus is empty, so this proves nothing")
	}

	signer, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(t.TempDir(), "evidence")
	app, err := evidence.Open(evidence.Options{
		Dir: dir, Signer: signer, SyncMode: segment.SyncModeNone,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	for i, f := range fixtures {
		// Every fixture in the corpus was recorded with the saga id "sg",
		// because each was written to be replayed on its own. Appending them
		// into one directory unchanged would interleave twenty unrelated
		// histories into one saga that none of them describes, so each is given
		// its own identity first. The rewrite is keyed on the field name rather
		// than on the value, so a step or resource that happens to be called
		// "sg" is left alone.
		suffix := fmt.Sprintf("-%02d", i)
		for j := range f.Events {
			f.Events[j].Payload = renameSagas(t, f.Events[j].Payload, suffix)
		}

		events, err := f.Replayable()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		st, err := saga.Replay(events)
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		if st.SagaID == "" {
			t.Fatalf("%s: fixture replays to a saga with no id", f.Name)
		}
		if !strings.HasSuffix(st.SagaID, suffix) {
			t.Fatalf("%s: the saga id rewrite did not take: replayed as %q", f.Name, st.SagaID)
		}
		sagaIDs = append(sagaIDs, st.SagaID)
		for _, ev := range events {
			if _, err := app.Append(ctx, evidence.Request{
				Kind: ev.Kind, SagaID: st.SagaID, Payload: ev.Payload,
			}); err != nil {
				t.Fatalf("%s: append %s: %v", f.Name, ev.Kind, err)
			}
		}
	}
	if err := app.Close(); err != nil {
		t.Fatalf("close the log: %v", err)
	}
	return dir, sagaIDs
}

// TestProjectionAnswersAsTheLogDoes is the claim the whole package rests on:
// the scoped index built from the projection gives the same frontier answer as
// the index built by replaying every saga in the log.
//
// If this ever fails, the projection is not a faster way of asking the question;
// it is a different question.
func TestProjectionAnswersAsTheLogDoes(t *testing.T) {
	store, ctx := newStore(t)
	dir, sagaIDs := corpusLog(t)

	proj := projection.NewProjector(store, dir)
	head, err := proj.CatchUp(ctx)
	if err != nil {
		t.Fatalf("catch up: %v", err)
	}
	if head == 0 {
		t.Fatal("the projection folded nothing, so the comparison below is vacuous")
	}

	fromLog := gate.IndexFromLog(dir)
	states, err := saga.ReplayAll(dir)
	if err != nil {
		t.Fatal(err)
	}

	compared := 0
	withBlockers := 0
	for _, id := range sagaIDs {
		subject, ok := states[id]
		if !ok {
			t.Fatalf("saga %q is in the log but ReplayAll did not return it", id)
		}

		whole, err := fromLog(subject)
		if err != nil {
			t.Fatalf("%s: build the whole-log index: %v", id, err)
		}
		scoped, err := store.FrontierIndex(ctx, subject, head)
		if err != nil {
			t.Fatalf("%s: build the scoped index: %v", id, err)
		}

		want := describeBlockers(whole.Blockers(id))
		got := describeBlockers(scoped.Blockers(id))
		if want != got {
			t.Errorf("saga %s blockers differ.\n  whole log: %s\n  projection: %s", id, want, got)
		}
		if len(whole.Blockers(id)) > 0 {
			withBlockers++
		}

		// Frontier and Claims are asked only about the subject's own resources,
		// so the scoped index must agree there too. Checking them is what makes
		// this an equivalence rather than a spot check on one method.
		for _, r := range resourcesOf(subject) {
			if w, g := whole.Frontier(r), scoped.Frontier(r); w != g {
				t.Errorf("saga %s frontier on %s: whole log %d, projection %d", id, r, w, g)
			}
		}
		if w, g := len(whole.Claims(id)), len(scoped.Claims(id)); w != g {
			t.Errorf("saga %s claim count: whole log %d, projection %d", id, w, g)
		}
		compared++
	}

	if compared == 0 {
		t.Fatal("no sagas were compared")
	}
	t.Logf("compared %d sagas, %d of which the whole-log index reported blockers for", compared, withBlockers)
}

func describeBlockers(bs []saga.Blocker) string {
	if len(bs) == 0 {
		return "(none)"
	}
	parts := make([]string, 0, len(bs))
	for _, b := range bs {
		parts = append(parts, fmt.Sprintf("%s/%s<-%s/%s@%d/%s",
			b.Resource, b.BlockedStep, b.BlockingSaga, b.BlockingStep, b.BlockingSeq, b.BlockingStatus))
	}
	return strings.Join(parts, " ")
}

func resourcesOf(s saga.State) []string {
	seen := map[string]bool{}
	var out []string
	for _, stepID := range s.Order {
		st := s.Steps[stepID]
		if st == nil {
			continue
		}
		for _, tch := range st.Touches {
			if !seen[tch.Resource] {
				seen[tch.Resource] = true
				out = append(out, tch.Resource)
			}
		}
	}
	return out
}

// renameSagas suffixes every saga-id-valued field in a fixture payload.
//
// It walks the JSON rather than doing a textual substitution, and it acts on
// `saga_id` and `authorized_by` only — the two fields in the corpus that hold a
// saga id. A blind string replacement would also rewrite a step, participant or
// resource that shared the name, which would change what the fixture means
// while leaving it looking untouched.
func renameSagas(t *testing.T, raw json.RawMessage, suffix string) json.RawMessage {
	t.Helper()
	if len(raw) == 0 {
		return raw
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode fixture payload: %v", err)
	}
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			for k, sub := range x {
				if s, ok := sub.(string); ok && (k == "saga_id" || k == "authorized_by") && s != "" {
					x[k] = s + suffix
					continue
				}
				x[k] = walk(sub)
			}
			return x
		case []any:
			for i, sub := range x {
				x[i] = walk(sub)
			}
			return x
		default:
			return v
		}
	}
	out, err := json.Marshal(walk(doc))
	if err != nil {
		t.Fatalf("re-encode fixture payload: %v", err)
	}
	return out
}

// TestAColumnAddedToAShippedTableReachesAnExistingDatabase.
//
// Every CREATE in schema.sql says IF NOT EXISTS, which is what makes the file
// safe to re-run and is also the trap: on a database that already has `sagas`,
// the CREATE is a no-op and a column added to it never arrives. The bumped
// fingerprint then forces a rebuild, the rebuild refolds, and the fold's INSERT
// names a column that is not there.
//
// No other test can catch this, and that is the reason this one is written the
// way it is. Every test database in this suite is created fresh, so it gets the
// column from the CREATE and passes whether or not the ALTER exists. Only an
// upgrade fails — which means the failure would first be seen by somebody
// running one, on a deployment, with the projection refusing to fold.
//
// So the upgrade is staged rather than described: take the current schema, drop
// the column back off to get exactly the table an older build left behind, and
// require the reopen to repair it and the fold to succeed. Dropping rather than
// hand-writing the old DDL keeps this honest as more columns are added — it is
// always the real previous shape, never a copy of it that drifted.
func TestAColumnAddedToAShippedTableReachesAnExistingDatabase(t *testing.T) {
	store, ctx, dsn := newStoreDSN(t)
	store.Close()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx,
		`ALTER TABLE sagas DROP COLUMN quarantined_effects`); err != nil {
		t.Fatalf("staging the pre-upgrade table: %v\nIf quarantined_effects is no longer "+
			"the newest column on sagas, point this test at whichever one is. Deleting it "+
			"leaves the upgrade path with nothing checking it.", err)
	}
	var has bool
	mustHaveColumn := func(want bool, when string) {
		t.Helper()
		if err := conn.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM information_schema.columns
			               WHERE table_name = 'sagas' AND column_name = 'quarantined_effects'
			                 AND table_schema = current_schema())`).Scan(&has); err != nil {
			t.Fatal(err)
		}
		if has != want {
			t.Fatalf("%s: sagas.quarantined_effects present = %v, want %v", when, has, want)
		}
	}
	mustHaveColumn(false, "after staging the pre-upgrade table")

	// The upgrade: a new binary opens a database an older one built.
	upgraded, err := projection.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("opening a database built by an older schema: %v", err)
	}
	t.Cleanup(upgraded.Close)
	mustHaveColumn(true, "after the new schema was applied")

	// And the fold has to run against it, which is the thing that actually
	// breaks: the INSERT names every column, so a missing one is an error at
	// the first saga rather than a wrong number later.
	dir, _ := corpusLog(t)
	head, err := projection.NewProjector(upgraded, dir).CatchUp(ctx)
	if err != nil {
		t.Fatalf("folding into an upgraded database: %v", err)
	}
	if head == 0 {
		t.Fatal("the fold wrote nothing, so it never exercised the INSERT this is about")
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
