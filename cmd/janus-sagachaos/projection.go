package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Running the chaos suite against a projection-backed daemon.
//
// The suite kills a coordinator at every transition and restarts it on the same
// evidence directory. With `-projection`, that coordinator answers its frontier
// gates from the projection tables instead of by replaying the log — so what gets
// killed is a *process* holding a projection mid-fold, and what restarts is a
// projector resuming from a `last_event_seq` some other process wrote.
//
// That is the part `TestFrontierAgreesAtEveryInterruptionPoint` cannot reach: it
// interrupts between folds, not inside one, and the transaction is what defends
// the inside.
//
// # One schema per crash point, and why it is per *point*
//
// A projection belongs to one log and every crash point is a fresh
// directory, so each needs its own schema. The schema is derived from the
// directory, which means a child restarted on the same crash point lands on the
// same schema and resumes rather than starting clean — which is the whole reason
// to run this here rather than in a unit test.
//
// The run id is in the name so a crashed run cannot leave a schema that a later
// run silently folds a different log into.

// schemaFor names the schema a crash point's projection lives in.
//
// Hashed rather than composed from the path: a scenario name plus a crash point
// is longer than PostgreSQL's 63-character identifier limit once a temp
// directory is in it, and a truncated name would collide two crash points onto
// one projection without saying so.
func schemaFor(dir string) string {
	sum := sha256.Sum256([]byte(dir))
	return "chaos_" + runID + "_" + hex.EncodeToString(sum[:6])
}

// scopedDSN points a connection at one crash point's schema, creating it.
func scopedDSN(ctx context.Context, dir string) (string, error) {
	if projectionDSN == "" {
		return "", nil
	}
	schema := schemaFor(dir)
	conn, err := pgx.Connect(ctx, projectionDSN)
	if err != nil {
		return "", fmt.Errorf("connecting to the projection: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS `+schema); err != nil {
		return "", fmt.Errorf("creating schema %s: %w", schema, err)
	}

	sep := "?"
	if strings.Contains(projectionDSN, "?") {
		sep = "&"
	}
	return projectionDSN + sep + "options=" + url.QueryEscape("-c search_path="+schema), nil
}

// dropRunSchemas removes every schema this run created.
//
// Best effort and reported rather than fatal: the run's result is about the
// sagas, and a suite that failed because it could not tidy up would be reporting
// the wrong thing. A schema left behind costs nothing but a name.
func dropRunSchemas() {
	if projectionDSN == "" || runID == "" {
		return
	}
	if keepAlways {
		// Evidence kept without the projection folded from it would be half a
		// picture: the frontier decisions in that log were made from these
		// tables, so somebody reading the one wants the other.
		fmt.Printf("projection schemas kept: chaos_%s_*\n", runID)
		return
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, projectionDSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not clean up this run's projection schemas: %v\n", err)
		return
	}
	defer func() { _ = conn.Close(ctx) }()

	rows, err := conn.Query(ctx,
		`SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE $1`,
		"chaos_"+runID+"_%")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not list this run's projection schemas: %v\n", err)
		return
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err == nil {
			names = append(names, n)
		}
	}
	rows.Close()
	for _, n := range names {
		if _, err := conn.Exec(ctx, `DROP SCHEMA IF EXISTS `+n+` CASCADE`); err != nil {
			fmt.Fprintf(os.Stderr, "could not drop schema %s: %v\n", n, err)
		}
	}
	if len(names) > 0 {
		fmt.Printf("dropped %d projection schema(s) from this run\n", len(names))
	}
}
