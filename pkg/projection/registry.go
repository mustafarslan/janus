package projection

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/registry"
)

// Registry returns the registry as the log now stands, catching the projection
// up first and refusing if it cannot reach the sequence the caller requires.
//
// This is the replacement for `registry.LoadEvents` + `registry.Fold`, which
// `janus-orchd` ran on every saga admission — a walk of the whole segment
// directory to answer a question about a few hundred manifests. What is
// returned is folded by the same state machine from the same events; only where
// the events were read from has changed.
//
// The staleness contract is the same one the frontier index
// keeps, for a sharper reason here. `admitAgainstRegistry` exists because a
// manifest can be suspended between one saga and the next, so a stale answer
// would admit a plan against a version that had been withdrawn — which is
// precisely the check it is. Requiring the head is what stops the projection
// being the cache that comment rules out.
//
// The returned Registry is a snapshot and is never mutated afterwards. Callers
// may hold it.
func (p *Projector) Registry(ctx context.Context, requireSeq uint64) (*registry.Registry, error) {
	head, err := p.CatchUp(ctx)
	if err != nil {
		return nil, err
	}
	if head < requireSeq {
		return nil, fmt.Errorf("%w: projected to sequence %d, the log is at %d",
			ErrStale, head, requireSeq)
	}
	reg := p.reg.Load()
	if reg == nil {
		// No registry events have ever been folded. An empty registry is the
		// right answer — a log with no registrations has none — and it must be
		// a real one rather than nil, so that a caller resolving against it gets
		// "not found" instead of a panic.
		return registry.New(), nil
	}
	return reg, nil
}

// RegistryAsOf folds the registry as it stood at a sequence.
//
// This is what invariant I8 actually asks for: not whether a pin is active now,
// but whether it was resolvable and active *when the saga started*. It is the
// question `registry.FoldUntil` answers and it is answered by calling exactly
// that function — the events come from the projection instead of from a segment
// scan, and nothing else differs.
//
// It reads the events from the store rather than from the projector's memory so
// that a process which only reads the projection can ask it too.
func (s *Store) RegistryAsOf(ctx context.Context, until, requireSeq uint64) (*registry.Registry, error) {
	head, _, err := s.Head(ctx)
	if err != nil {
		return nil, err
	}
	if head < requireSeq {
		return nil, fmt.Errorf("%w: projected to sequence %d, the log is at %d",
			ErrStale, head, requireSeq)
	}
	events, err := s.registryEvents(ctx)
	if err != nil {
		return nil, err
	}
	return registry.FoldUntil(events, until)
}

// registryEvents reads the registry stream out of the store, in sequence order.
func (s *Store) registryEvents(ctx context.Context) ([]registry.Event, error) {
	rows, err := s.pool.Query(ctx, `SELECT seq, payload FROM registry_events ORDER BY seq`)
	if err != nil {
		return nil, fmt.Errorf("projection: read the registry stream: %w", err)
	}
	defer rows.Close()
	var out []registry.Event
	for rows.Next() {
		var seq int64
		var payload []byte
		if err := rows.Scan(&seq, &payload); err != nil {
			return nil, fmt.Errorf("projection: read the registry stream: %w", err)
		}
		out = append(out, registry.Event{Seq: uint64(seq), Payload: payload})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("projection: read the registry stream: %w", err)
	}
	return out, nil
}

// loadRegistryEvents fills the projector's copy of the stream from the store.
func (p *Projector) loadRegistryEvents(ctx context.Context) error {
	if p.regLoaded {
		return nil
	}
	events, err := p.store.registryEvents(ctx)
	if err != nil {
		return err
	}
	p.regEvents = events
	p.regLoaded = true
	return p.refoldRegistry()
}

// refoldRegistry rebuilds the published snapshot from the whole stream.
//
// Whole rather than incremental. `registry.Registry` hands out pointers into its
// own state and has no deep copy, so applying an event to a registry a reader
// already holds would change what that reader sees mid-read. Folding a fresh one
// and swapping the pointer makes every published snapshot immutable, and the
// stream is short enough that this is not a cost worth avoiding.
func (p *Projector) refoldRegistry() error {
	reg, err := registry.Fold(p.regEvents)
	if err != nil {
		return fmt.Errorf("projection: fold the registry: %w", err)
	}
	p.reg.Store(reg)
	return nil
}

// writeInventory replaces the inventory rows with the folded registry's.
//
// Nothing folds from these rows and nothing decides from them: they exist so
// that "what does this deployment run, and where does each version stand" is a
// query rather than a replay. A reader that needs an Entry — or needs one as of
// a sequence — folds the event stream.
func writeInventory(ctx context.Context, tx pgx.Tx, reg *registry.Registry) error {
	if _, err := tx.Exec(ctx, `TRUNCATE participants CASCADE`); err != nil {
		return fmt.Errorf("projection: clear the inventory: %w", err)
	}
	for _, pid := range reg.Participants() {
		active := ""
		if entry, ok := reg.Active(pid); ok {
			active = entry.Version
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO participants (participant_id, active_version) VALUES ($1, $2)`,
			pid, active); err != nil {
			return fmt.Errorf("projection: write participant %q: %w", pid, err)
		}
		for ordinal, entry := range reg.Versions(pid) {
			// A nil slice arrives as SQL NULL, and the column is NOT NULL with
			// an empty-array default -- which is the right shape, because "owes
			// no triggers" and "we do not know what it owes" must not look the
			// same to an inventory report.
			triggers := entry.PendingTriggers
			if triggers == nil {
				triggers = []string{}
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO manifest_versions (participant_id, version, state, content_address,
					ordinal, registered_seq, activated_seq, last_seq, pending_triggers)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
				pid, entry.Version, string(entry.State), entry.ContentAddress, ordinal,
				int64(entry.RegisteredSeq), int64(entry.ActivatedSeq), int64(entry.LastSeq),
				triggers,
			); err != nil {
				return fmt.Errorf("projection: write %s@%s: %w", pid, entry.Version, err)
			}
		}
	}
	return nil
}

// logIdentity names the log in a directory by the chain hash of its first
// record.
//
// A chain hash commits to the payload, the header and every event before it, so
// the first one is unique to a log and never changes. The directory path would
// have been easier and is not an identity: the same log is at different paths in
// a container and on a laptop, and two different logs can occupy the same path
// on two machines.
//
// An empty directory has no identity yet, which is reported as the empty string
// rather than an error — a projector may legitimately be pointed at a log before
// anything is written to it.
func logIdentity(dir string) (string, error) {
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		return "", err
	}
	for _, id := range ids {
		insp, err := segment.Inspect(segment.Path(dir, id))
		if err != nil {
			return "", fmt.Errorf("projection: inspect segment %d: %w", id, err)
		}
		if len(insp.Records) == 0 {
			continue
		}
		return hex.EncodeToString(insp.Records[0].Chain[:]), nil
	}
	return "", nil
}

// CheckLogBinding refuses a store that was folded from a different evidence
// directory than the one given.
//
// The binding itself is written and checked by the projector, which is
// enough for the daemon. It is not enough for a reader: a console never folds,
// so it never reaches that check, and a console pointed at another deployment's
// database would render that deployment's sagas under this one's heading — with
// no error anywhere, because both halves are internally consistent.
//
// A reader calls this once, at startup, and fails loudly. That is the right
// moment: the alternative is discovering it from a page of unfamiliar saga ids,
// and the alternative to *that* is not discovering it.
//
// An unbound store is accepted. It has folded nothing, so it belongs to no log
// yet and will bind to the first one folded into it.
func CheckLogBinding(ctx context.Context, s *Store, dir string) error {
	var stored string
	if err := s.pool.QueryRow(ctx,
		`SELECT log_id FROM projection_meta WHERE only_row`).Scan(&stored); err != nil {
		return fmt.Errorf("projection: read the log binding: %w", err)
	}
	if stored == "" {
		return nil
	}
	mine, err := logIdentity(dir)
	if err != nil {
		return err
	}
	if mine == "" {
		return fmt.Errorf("%w: this projection was built from log %s and %s has no events "+
			"to compare it against", ErrWrongLog, stored, dir)
	}
	if mine != stored {
		return fmt.Errorf("%w: this projection was built from log %s, and %s is log %s",
			ErrWrongLog, stored, dir, mine)
	}
	return nil
}

// LogHead is the highest sequence in an evidence directory.
//
// It walks the segments and reads headers, which is cheap next to verification
// and is what an operator asking "how far behind is the projection" needs the
// other half of. It deliberately does not verify: this is a status question, and
// a status command that ran the verifier would be slow enough that nobody would
// run it when they were in a hurry — which is when they need it.
func LogHead(dir string) (uint64, error) {
	ids, err := segment.ScanComplete(dir)
	if err != nil {
		return 0, err
	}
	var head uint64
	for _, id := range ids {
		insp, err := segment.Inspect(segment.Path(dir, id))
		if err != nil {
			return 0, fmt.Errorf("projection: inspect segment %d: %w", id, err)
		}
		for _, rec := range insp.Records {
			h, err := evidence.DecodeHeader(rec.Header)
			if err != nil {
				return 0, fmt.Errorf("projection: segment %d: %w", id, err)
			}
			if h.Seq > head {
				head = h.Seq
			}
		}
	}
	return head, nil
}
