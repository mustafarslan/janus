// Package projection maintains the relational projections of the evidence log,
// and answers from them the questions that used to require replaying the
// whole evidence log.
//
// # What this package is not
//
// It is not a cache and it is not a source of truth. The evidence log is the
// system of record, and every row here is derived from it. The
// distinction that makes that more than a slogan is `last_event_seq`: every read
// says which point in the log it reflects, so a caller that needs to *act* on an
// answer can insist the projection has caught up and refuse when it has not,
// while a caller that only needs to *show* an answer can say "as of sequence N"
// on the page. A cache cannot make either promise, which is why a cache is
// ruled out and this is admitted.
//
// The recovery story is the same everywhere: if the projection is wrong or
// suspect, rebuild it from the log. Nothing is ever reconciled, merged, or
// repaired in place.
package projection

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zeebo/blake3"
)

//go:embed schema.sql
var schemaSQL string

// schemaFingerprint identifies the code that derives the rows, not the DDL.
//
// It is bumped by hand whenever a change to the projector would make new rows
// disagree with rows an older build wrote — a new column, a different status
// mapping, a corrected fold. Open() compares it against what the database
// records and refuses to fold new events onto rows built by different logic,
// because a projection that is half one derivation and half another is wrong in
// a way no single query reveals. The remedy is Rebuild, which is cheap in the
// only sense that matters: it cannot be wrong.
const schemaFingerprint = "6b.2 sagas+steps+resource_touches+registry+quarantine"

// Store is a handle on the projection database.
type Store struct {
	pool *pgxpool.Pool
	// lockConn holds the writer lock and is used for nothing else. See
	// takeWriterLock for why it cannot come from the pool on demand.
	lockConn *pgxpool.Conn
}

// ErrStale is returned by a read that required the projection to be caught up
// to a point in the log and found it behind.
//
// It is a distinct error because the caller's response differs from every other
// failure: a frontier gate that gets this must refuse the step, not retry it
// forever and not decide without the index.
var ErrStale = errors.New("projection is behind the log")

// ErrNotTheWriter is returned when a projector cannot take the store's writer
// lock because another one holds it.
//
// It is distinct from a connection failure because the response is different:
// there is nothing wrong with the database, and retrying will not help until the
// other projector goes away. A deployment seeing this has two processes trying
// to fold one store, which is a configuration to fix rather than a fault to
// absorb.
var ErrNotTheWriter = errors.New("another projector holds this store's writer lock")

// ErrWrongLog is returned when a store's rows were folded from a different
// evidence directory than the one now being folded into it.
//
// Two logs sharing a projection would interleave into a history neither of them
// has, and would do it silently. There is no safe merge; the store belongs to
// one log.
var ErrWrongLog = errors.New("this projection was built from a different log")

// Open connects to the projection database and applies the schema.
//
// The DSN is a libpq connection string. There is no default: a projection
// silently pointing at a database nobody meant to use is worse than a startup
// failure, and the only caller that has one is a daemon whose configuration
// says so.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("projection: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("projection: connect: %w", err)
	}
	s := &Store{pool: pool}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("projection: apply schema: %w", err)
	}
	return s, nil
}

// Close releases the connection pool.
func (s *Store) Close() {
	if s == nil {
		return
	}
	if s.lockConn != nil {
		// Releasing the connection returns it to the pool, which drops the
		// session and with it the advisory lock. Closing the pool would do the
		// same, but doing it explicitly means the lock is gone before the next
		// projector looks, rather than whenever the pool gets round to it.
		_, _ = s.lockConn.Exec(context.Background(), `SELECT pg_advisory_unlock_all()`)
		s.lockConn.Release()
		s.lockConn = nil
	}
	if s.pool != nil {
		s.pool.Close()
	}
}

// Head is the highest evidence sequence folded into the projection, together
// with the fingerprint of the code that folded it.
func (s *Store) Head(ctx context.Context) (seq uint64, builtBy string, err error) {
	var got int64
	err = s.pool.QueryRow(ctx,
		`SELECT last_event_seq, built_by FROM projection_meta WHERE only_row`).Scan(&got, &builtBy)
	if err != nil {
		return 0, "", fmt.Errorf("projection: read head: %w", err)
	}
	return uint64(got), builtBy, nil
}

// Truncate empties every projected table and resets the head to zero.
//
// This is the first half of a rebuild and is not exported as a way to "clear"
// anything: a store that has been truncated and not refolded answers every
// question with "nothing is here", and nothing here treats an empty projection
// as an empty world. Rebuild is the operation callers want.
func (s *Store) truncate(ctx context.Context, tx pgx.Tx) error {
	// sagas cascades into steps and resource_touches; participants cascades
	// into manifest_versions. registry_events has no parent and is listed in its
	// own right — a rebuild that left the registry stream behind would refold a
	// registry from events the sagas beside them no longer match.
	if _, err := tx.Exec(ctx,
		`TRUNCATE sagas, participants, registry_events CASCADE`); err != nil {
		return fmt.Errorf("projection: truncate: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE projection_meta SET last_event_seq = 0, built_by = $1, log_id = '', updated_at = now()
		 WHERE only_row`, schemaFingerprint); err != nil {
		return fmt.Errorf("projection: reset head: %w", err)
	}
	return nil
}

// writerLockKey is the advisory-lock key a projector takes on a store.
//
// Advisory locks are namespaced per database rather than per schema, and this
// store is identified by its search_path, so the key is derived from the schema
// the connection actually resolves to. Two projectors on one schema contend; two
// on different schemas of one database do not.
const writerLockKeySalt = "janus.projection.writer"

// takeWriterLock claims the store for one projector, on a connection held for as
// long as the claim lasts.
//
// The dedicated connection is the whole mechanism and it is easy to get wrong. A
// PostgreSQL advisory lock is *session*-scoped: it belongs to a connection, not
// to a transaction or to a client. Taken through a pool, the pool is free to
// recycle that connection back into general use, and the lock goes with it while
// the projector carries on believing it is the writer. So the lock lives on a
// connection this store owns and does nothing else with, and losing the
// connection is the same event as losing the lock -- which is the behaviour
// wanted, because a projector that cannot prove it is the writer must stop
// being one.
func (s *Store) takeWriterLock(ctx context.Context) error {
	if s.lockConn != nil {
		return nil
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("projection: acquire a connection for the writer lock: %w", err)
	}
	var schema string
	if err := conn.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil {
		conn.Release()
		return fmt.Errorf("projection: read the current schema: %w", err)
	}
	sum := blake3.Sum256([]byte(writerLockKeySalt + "\x00" + schema))
	key := int64(binary.BigEndian.Uint64(sum[:8]))

	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil {
		conn.Release()
		return fmt.Errorf("projection: take the writer lock: %w", err)
	}
	if !got {
		conn.Release()
		return fmt.Errorf("%w: schema %s", ErrNotTheWriter, schema)
	}
	s.lockConn = conn
	return nil
}

// bindToLog records which log this store was folded from, or checks it.
//
// First fold writes the identity; every later one compares. An empty stored
// identity means the store has never been folded, which is the only state in
// which adopting a log is right.
// It runs in its own transaction, before any events are read, and that ordering
// is the point rather than a detail. Checking it inside the fold would only
// check it when the fold had something to write — and the case this exists to
// catch produces no events at all. A store folded to sequence 40 from one log,
// pointed at a *different* log whose sequences also stop around 40, sees every
// record as already folded, writes nothing, opens no transaction and reports
// success. The rows would then describe the first log while the projector
// believed it was following the second, and nothing anywhere would say so.
func (s *Store) bindToLog(ctx context.Context, logID string) error {
	// The overwhelmingly common case is a store already bound to this log, and
	// it is answered with a plain read: no transaction, and no row lock. Taking
	// `FOR UPDATE` here would serialise every catch-up behind a lock it does not
	// need, and would hold the one row the fold itself has to update at the end.
	var stored string
	if err := s.pool.QueryRow(ctx,
		`SELECT log_id FROM projection_meta WHERE only_row`).Scan(&stored); err != nil {
		return fmt.Errorf("projection: read the log binding: %w", err)
	}
	switch {
	case stored == logID:
		return nil
	case stored != "":
		return fmt.Errorf("%w: these rows came from log %s, this projector is folding %s",
			ErrWrongLog, stored, logID)
	}

	// Unbound, so claim it. Only this path needs the lock, and the re-read
	// inside it is what makes the claim safe: the writer lock already makes two
	// projectors racing here impossible, and this costs nothing to keep correct
	// if that ever stops being true.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("projection: begin the log binding: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx,
		`SELECT log_id FROM projection_meta WHERE only_row FOR UPDATE`).Scan(&stored); err != nil {
		return fmt.Errorf("projection: read the log binding: %w", err)
	}
	if stored != "" && stored != logID {
		return fmt.Errorf("%w: these rows came from log %s, this projector is folding %s",
			ErrWrongLog, stored, logID)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE projection_meta SET log_id = $1 WHERE only_row`, logID); err != nil {
		return fmt.Errorf("projection: record the log binding: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("projection: commit the log binding: %w", err)
	}
	return nil
}
