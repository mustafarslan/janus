package main

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
)

// scopedDSN points a connection at a schema of its own, creating it and
// clearing anything a previous run left in it.
//
// One schema per configuration because a projection belongs to one log
// and every configuration writes a fresh evidence directory. Sharing
// a schema would either wedge on the log-binding check or, worse, fold two logs
// into one set of tables and produce a frontier index for a history that never
// happened.
//
// Dropped and recreated rather than reused: a benchmark that resumed a
// half-folded projection from an earlier run would measure a catch-up whose
// size nobody chose.
// withoutPoolParams strips the pgxpool-only query parameters from a DSN.
func withoutPoolParams(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	q := u.Query()
	for k := range q {
		if strings.HasPrefix(k, "pool_") {
			q.Del(k)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func scopedDSN(ctx context.Context, dsn, name string) (string, error) {
	schema := "latency_" + strings.NewReplacer("-", "_", ".", "_").Replace(name)
	// The admin connection is a plain one, so it must not carry pgxpool's own
	// parameters: pgx hands anything it does not recognise to the server as a
	// runtime setting, and the server refuses `pool_max_conns` by name.
	conn, err := pgx.Connect(ctx, withoutPoolParams(dsn))
	if err != nil {
		return "", fmt.Errorf("connecting to the projection: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`); err != nil {
		return "", fmt.Errorf("dropping schema %s: %w", schema, err)
	}
	if _, err := conn.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		return "", fmt.Errorf("creating schema %s: %w", schema, err)
	}

	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "options=" + url.QueryEscape("-c search_path="+schema), nil
}

// tailLengths records how far behind the log the projection was each time a
// frontier decision asked it a question.
//
// The quantity is `log head - folded head` at the moment of the call: the
// records a decision would have to read and account for itself if it stopped
// waiting for a whole fold. No design exists for deciding without waiting for
// a fold, and the reason the design
// was never attempted is that nobody knew how much work it would be — the
// number was inferred from fold duration rather than measured.
//
// Kept as every observation rather than a running mean. A mean tail would hide
// the shape that decides the question: a decision arriving just after a fold
// sees almost nothing, one arriving just before sees a whole fold's worth, and
// what a design has to survive is the second.
type tailLengths struct {
	mu sync.Mutex
	n  []uint64
}

func (t *tailLengths) add(n uint64) {
	t.mu.Lock()
	t.n = append(t.n, n)
	t.mu.Unlock()
}

// summary returns the count, mean, p50, p99 and max of what was observed.
func (t *tailLengths) summary() (count int, mean, p50, p99, max float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.n) == 0 {
		return 0, 0, 0, 0, 0
	}
	sorted := append([]uint64(nil), t.n...)
	slices.Sort(sorted)
	var sum uint64
	for _, v := range sorted {
		sum += v
	}
	// The same definition the latency rows above use, so p99 on this line and
	// p99 on those means the same thing.
	at := func(q float64) float64 { return float64(sorted[percentileIndex(len(sorted), q)]) }
	return len(sorted), float64(sum) / float64(len(sorted)),
		at(0.50), at(0.99), float64(sorted[len(sorted)-1])
}
