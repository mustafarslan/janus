package projection

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/mustafarslan/janus/pkg/evidence"
	"github.com/mustafarslan/janus/pkg/evidence/segment"
	"github.com/mustafarslan/janus/pkg/outbox"
	"github.com/mustafarslan/janus/pkg/registry"
	"github.com/mustafarslan/janus/pkg/saga"
	"github.com/mustafarslan/janus/pkg/tenancy"
)

// Projector folds an evidence directory into a Store.
//
// # Why it holds state in memory
//
// Folding an event needs the saga's projection *before* that event, and
// `saga.Apply` is the only implementation of that transition anywhere in this
// repository. Re-deriving a saga's status from event kinds in SQL would be a
// second state machine, and two state machines for one set of rules diverge —
// slowly, silently, and in the direction nobody tests. So the projector holds
// `saga.State` for the sagas that are still live and calls the real one.
//
// That memory is not durable and does not need to be: on a cold start the
// projector replays the sagas the database says are unfinished, straight from
// the log. The number of those is the concurrency of the deployment, not the
// length of its history, and re-deriving them is the same "rebuild it, don't
// trust it" move the rest of this package makes.
type Projector struct {
	store *Store
	dir   string
	// scan lists the log's complete segments without re-stat-ing every file on
	// every fold. The daemon folds on a five-second ticker whether or not
	// anything asked a question, so this listing is a background cost as well
	// as a per-decision one — which is why it is removed here
	// rather than deferred.
	scan *segment.Scanner

	// mu guards everything below. A projector is consulted from the gate
	// decision path, which a coordinator may run for several sagas at once, and
	// two folds interleaving would apply the same event twice to one saga's
	// held projection.
	mu sync.Mutex

	// live holds the projection of every saga that has not reached a terminal
	// state, keyed by saga id. A terminal saga is dropped: nothing can move it
	// again, so its rows are final and keeping it would make the working set
	// grow with history rather than with concurrency.
	live map[string]saga.State

	// fromSegment is the lowest segment id that may still contain unfolded
	// records. Segments below it were read to the end and sealed segments never
	// change, so a steady-state catch-up inspects the tail of the log rather
	// than all of it. This is what stops a projection-backed gate decision
	// costing the same full pass it was built to avoid.
	//
	// It is the segment holding the highest record actually seen, never simply
	// the highest id the directory listed. Those differ: an open appender
	// pre-creates the next segment, so `segment.ScanComplete` reports an empty
	// one beyond the one being written, and that file is removed again when the
	// writer closes or rotates. Resuming from it meant resuming from a segment
	// id that no longer existed, and every later scan skipped the whole log —
	// the projector silently stopped folding, and the staleness contract then
	// turned that into every frontier gate refusing. Advance this only past
	// records, never past filenames.
	fromSegment uint64

	// warmed records that the live map has been reconciled with the database's
	// idea of which sagas are unfinished. It is false after a rebuild and on a
	// fresh projector.
	warmed bool

	// regEvents is every registry event folded so far, in sequence order. A
	// registry is small by construction -- a bank's model inventory is hundreds
	// of manifests changing a few times a year -- so keeping the stream costs
	// little and makes the refold below trivial.
	regEvents []registry.Event
	// regLoaded records that regEvents has been read back from the table.
	regLoaded bool
	// reg is the current folded registry, published for readers.
	//
	// It is replaced wholesale, never mutated. `registry.Registry` holds
	// pointers to entries and has no deep copy, so a reader holding one while
	// the next fold applied an event would see entries change underneath it --
	// a race no single-threaded test would show. Refolding into a fresh
	// Registry and swapping the pointer is cheaper to get right than making
	// incremental application safe, and the stream is short enough that the
	// cost is not worth measuring.
	reg atomic.Pointer[registry.Registry]

	// logID identifies the log this projector folds, cached after the first read.
	logID string

	// held is the outbox as this projector has folded it, used for one thing:
	// counting how many of a saga's effects are still outstanding, for the
	// console's overview.
	//
	// It is private and stays private. Effect state is commit authority
	// (invariant I1) and `outbox.LogAuthority` reads it from the log every time
	// for that reason; a projection that offered it would eventually be asked to
	// decide a release. Only a count leaves this struct, and there is no way to
	// get an effect id out of the tables.
	held outbox.State

	// fold lets concurrent readers share one catch-up rather than queue behind
	// one another.
	fold coalescer

	// phase accumulates where fold time goes, so "the fold is slow" can be
	// turned into a statement about which part. Written under mu, which the
	// fold already holds.
	phase FoldPhases
	// lastScanned is how many records the last read() framed and decoded.
	lastScanned int
	// fromOffset is where in fromSegment the last pass stopped.
	//
	// Without it a pass resumes at a whole segment and re-decodes everything
	// written to the open one since it was created — measured at 90% of the
	// records a fold looked at, and 38% of its time. That share grows as the
	// open segment fills and resets at rotation, so it is a sawtooth a
	// benchmark starting on a fresh segment barely sees.
	fromOffset int64
}

// NewProjector returns a projector for an evidence directory.
func NewProjector(store *Store, dir string) *Projector {
	return &Projector{
		store: store, dir: dir, live: map[string]saga.State{},
		scan: segment.NewScanner(dir),
	}
}

// Rebuild empties the projection and folds the whole log into it again.
//
// This is the answer to every question of the form "is the projection right?".
// It is not a repair — nothing here is repaired — it is a rederivation from the
// only thing that was ever authoritative.
func (p *Projector) Rebuild(ctx context.Context) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rebuildLocked(ctx)
}

func (p *Projector) rebuildLocked(ctx context.Context) (uint64, error) {
	// The writer lock comes before the truncate, and the order is the whole
	// safety of this function. Taking it afterwards — which is what this did
	// until measuring the rebuild's timing went looking — produces
	// the worst shape a control can have: an operator who runs `janus-projection
	// rebuild` against a live daemon reads "something else is folding this
	// projection, stop it before rebuilding" and believes nothing happened,
	// while the rows are already gone. A refusal that has destroyed what it
	// refuses to touch is not a refusal.
	if err := p.store.takeWriterLock(ctx); err != nil {
		return 0, err
	}
	tx, err := p.store.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("projection: begin rebuild: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := p.store.truncate(ctx, tx); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("projection: commit truncate: %w", err)
	}
	p.live = map[string]saga.State{}
	p.fromSegment, p.fromOffset = 0, 0
	p.warmed = true // an empty projection has no unfinished sagas to recover.
	p.regEvents = nil
	p.regLoaded = true // ... and no registry stream to read back.
	p.held = outbox.State{}
	p.reg.Store(registry.New())
	return p.catchUpLocked(ctx)
}

// CatchUp folds every event the projection has not seen and returns the
// sequence it now stands at.
//
// The rows and `last_event_seq` move in one transaction. A projector killed
// part way through leaves the database at the sequence it was at before, which
// is the only state a resume can start from without either skipping an event or
// applying one twice.
func (p *Projector) CatchUp(ctx context.Context) (uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.catchUpLocked(ctx)
}

func (p *Projector) catchUpLocked(ctx context.Context) (uint64, error) {
	// Timed around everything the fold does, not around the three stages, so
	// that the parts can be checked against the whole. The set-up before the
	// read — the head query, the log binding, `loadRegistryEvents`, `warm` —
	// belongs inside it: it is fold time a caller waits for, and leaving it out
	// would make the three stages sum to 100% of a number that was not the
	// fold.
	tFold := time.Now()
	defer func() { p.phase.Total += time.Since(tFold) }()

	head, builtBy, err := p.store.Head(ctx)
	if err != nil {
		return 0, err
	}
	// Rows derived by different code are not something to fold onto. An empty
	// projection has no derivation yet, so it is adopted rather than rebuilt.
	if builtBy != schemaFingerprint {
		if head != 0 {
			return p.rebuildLocked(ctx)
		}
	}
	// The writer lock comes before anything is written, and before the log
	// binding is checked: a projector that is not the writer has no business
	// deciding which log the store belongs to.
	if err := p.store.takeWriterLock(ctx); err != nil {
		return 0, err
	}
	if p.logID == "" {
		id, err := logIdentity(p.dir)
		if err != nil {
			return 0, err
		}
		p.logID = id
	}
	if p.logID != "" {
		if err := p.store.bindToLog(ctx, p.logID); err != nil {
			return 0, err
		}
	}
	if err := p.loadRegistryEvents(ctx); err != nil {
		return 0, err
	}
	if !p.warmed {
		if err := p.warm(ctx, head); err != nil {
			return 0, err
		}
	}

	tRead := time.Now()
	events, lastSegment, lastOffset, err := p.read(head)
	p.phase.Read += time.Since(tRead)
	if err != nil {
		return 0, err
	}
	p.phase.Scanned += uint64(p.lastScanned)
	p.phase.Kept += uint64(len(events))
	if len(events) == 0 {
		p.fromSegment, p.fromOffset = lastSegment, lastOffset
		return head, nil
	}

	// Apply in log order onto the held projections. This happens before the
	// transaction opens: a decode or state-machine error must leave the
	// database exactly as it was, and the cheapest way to guarantee that is to
	// have written nothing yet.
	tApply := time.Now()
	dirty := map[string]struct{}{}
	tenants := map[string]string{}
	staged := map[string]saga.State{}
	var newRegistry []registry.Event
	// Staged, not applied: the same rule the saga working set and the registry
	// stream follow. A commit that fails must leave every piece of in-memory
	// state exactly where the database is, or the next fold reads the same
	// events again and applies them twice.
	heldStaged := p.held
	for _, pe := range events {
		if pe.kind == evidence.KindRegistry {
			// Registry events are not folded here. They are appended to the
			// stream and the whole registry is refolded once, below -- see
			// refoldRegistry for why that is cheaper to get right than an
			// incremental apply.
			newRegistry = append(newRegistry, registry.Event{Seq: pe.seq, Payload: pe.ev.Payload})
			continue
		}
		prev, ok := staged[pe.sagaID]
		if !ok {
			prev, ok = p.live[pe.sagaID]
		}
		if !ok && pe.ev.Kind != evidence.KindSagaBegin {
			// The projector does not hold this saga and the event is not the one
			// that starts it, so its earlier history has to come back from the
			// log before the event can be folded onto anything.
			//
			// This is reachable in ordinary running, which is what makes it
			// worth the recovery rather than an error. The outbox lifecycle
			// events carry a saga id, so `saga.Apply` sees them; they are
			// delivered *after* the saga commits, by definition; and a committed
			// saga has been evicted from the working set. Applying one to a zero
			// State yields a projection with no saga id, and writing that
			// produces a row keyed on the empty string — a saga that does not
			// exist, in the table a frontier gate reads.
			recovered, rerr := p.recover(pe.sagaID, head)
			if rerr != nil {
				return 0, rerr
			}
			prev = recovered
		}
		next, err := saga.Apply(prev, pe.ev)
		if err != nil {
			return 0, fmt.Errorf("projection: fold saga %q at seq %d: %w", pe.sagaID, pe.seq, err)
		}
		staged[pe.sagaID] = next
		dirty[pe.sagaID] = struct{}{}
		// The outbox lifecycle events reach the saga state machine as
		// non-state-changing, and separately move the held count. One state
		// machine each: `outbox.Apply` is the only thing that decides what an
		// effect event means, here as everywhere.
		switch pe.kind {
		case evidence.KindEffectHeld, evidence.KindEffectReleasing,
			evidence.KindEffectDelivered, evidence.KindEffectQuarantined:
			moved, err := outbox.Apply(heldStaged, outbox.Event{
				Seq: pe.seq, Kind: pe.kind, Wall: pe.ev.Wall, Payload: pe.ev.Payload,
			})
			if err != nil {
				return 0, fmt.Errorf("projection: fold effect at seq %d: %w", pe.seq, err)
			}
			heldStaged = moved
		}
		if pe.tenant != "" {
			if was, seen := tenants[pe.sagaID]; seen && was != pe.tenant {
				// A saga whose events carry two different tenant bindings is
				// not a projection problem to paper over: tenancy makes the
				// tenant a property of the writer, so two of them on one saga
				// means two writers shared a saga id.
				return 0, fmt.Errorf("projection: saga %q carries two tenant bindings, %q and %q",
					pe.sagaID, was, pe.tenant)
			}
			tenants[pe.sagaID] = pe.tenant
		}
	}

	p.phase.Apply += time.Since(tApply)

	newHead := events[len(events)-1].seq

	// Commit covers Begin through Commit. The in-memory moves after it are
	// bookkeeping on already-durable state and are left in the residual rather
	// than attributed here, because attributing them would make Commit read as
	// database time when part of it is not.
	tCommit := time.Now()
	tx, err := p.store.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("projection: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ids := make([]string, 0, len(dirty))
	for id := range dirty {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	// One batch for every saga this fold touched, not one round trip per
	// statement per saga. Same statements, same order, same transaction.
	var rows rowBatch
	for _, id := range ids {
		if err := queueSaga(&rows, staged[id], tenants[id],
			len(outbox.PendingFor(heldStaged, id)),
			len(outbox.QuarantinedFor(heldStaged, id))); err != nil {
			return 0, err
		}
	}
	stmts := uint64(rows.batch.Len())
	if err := rows.send(ctx, tx); err != nil {
		return 0, err
	}
	p.phase.StmtSaga += rows.saga
	p.phase.StmtClear += rows.clear
	p.phase.StmtStep += rows.step
	p.phase.StmtTouch += rows.touch
	// The registry family moves in this transaction too. One head covers every
	// table: a projection whose saga rows and registry rows stood at different
	// sequences would make "as of last_event_seq" mean two different things
	// depending on which table was asked.
	var refolded *registry.Registry
	var mergedRegistry []registry.Event
	if len(newRegistry) > 0 {
		for _, ev := range newRegistry {
			stmts++
			if _, err := tx.Exec(ctx,
				`INSERT INTO registry_events (seq, payload) VALUES ($1, $2)
				 ON CONFLICT (seq) DO NOTHING`, int64(ev.Seq), ev.Payload); err != nil {
				return 0, fmt.Errorf("projection: write registry event at seq %d: %w", ev.Seq, err)
			}
		}
		merged := append(append([]registry.Event{}, p.regEvents...), newRegistry...)
		reg, err := registry.Fold(merged)
		if err != nil {
			return 0, fmt.Errorf("projection: fold the registry: %w", err)
		}
		if err := writeInventory(ctx, tx, reg); err != nil {
			return 0, err
		}
		refolded = reg
		mergedRegistry = merged
	}
	stmts++
	if _, err := tx.Exec(ctx,
		`UPDATE projection_meta SET last_event_seq = $1, built_by = $2, updated_at = now()
		 WHERE only_row`, int64(newHead), schemaFingerprint); err != nil {
		return 0, fmt.Errorf("projection: advance head: %w", err)
	}
	p.phase.Statements += stmts
	tSync := time.Now()
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("projection: commit: %w", err)
	}
	// One reading of the elapsed commit, not two. Calling time.Since twice put
	// tens of nanoseconds between the halves and the whole, so they no longer
	// partitioned it — harmless in the numbers and fatal to the property the
	// split is supposed to have. The test that checks the parts against the
	// whole found it.
	sync := time.Since(tSync)
	spent := time.Since(tCommit)
	p.phase.CommitSync += sync
	p.phase.CommitWrite += spent - sync
	p.phase.Commit += spent

	// Only now that the transaction has committed does the in-memory working
	// set move. If the commit had failed, the held projections would still be
	// the ones the database describes, and the next attempt would redo exactly
	// the same fold.
	// The registry stream moves after the commit, for the same reason the saga
	// working set does. Advancing it inside the transaction meant that a failed
	// commit left the projector holding events the table did not have: the head
	// would not have moved, so the next catch-up would read those same events
	// out of the log again, append them a second time, and refold a stream with
	// every one of them duplicated -- which `registry.Apply` refuses as an
	// illegal transition, wedging every fold after it. On the admission path
	// that is a daemon that stops admitting sagas.
	if refolded != nil {
		p.regEvents = mergedRegistry
		p.reg.Store(refolded)
	}
	p.held = heldStaged
	for _, id := range ids {
		st := staged[id]
		if st.Terminal() {
			delete(p.live, id)
			continue
		}
		p.live[id] = st
	}
	// Both move together and only on success: a pass whose fold failed must
	// re-read what it read, or the records it did not apply are skipped for
	// good.
	p.fromSegment, p.fromOffset = lastSegment, lastOffset
	return newHead, nil
}

// warm reloads the projections of every saga the database says is unfinished,
// as they stood at the sequence the projection was folded to.
//
// A projector that skipped this would fold the next event of a saga onto a zero
// State and get an error, or worse, onto a State missing the earlier touches —
// which is a frontier check that cannot see a contending saga, and those pass.
// # Why it recovers as of a sequence rather than as of now
//
// The obvious implementation replays the saga from the log and takes what it
// gets. That is wrong, and wrong only when the log has moved on since the
// projection last folded — which is every restart that matters. The replay
// returns the saga as it stands *now*; the fold then applies every event after
// `last_event_seq` on top; and each of those events is applied a second time. A
// saga has to be recovered to exactly the point the rest of the projection
// stands at, which is the same as-of-a-sequence question `registry.FoldUntil`
// answers, for the same reason.
func (p *Projector) warm(ctx context.Context, head uint64) error {
	rows, err := p.store.pool.Query(ctx, `SELECT saga_id FROM sagas WHERE NOT terminal`)
	if err != nil {
		return fmt.Errorf("projection: list unfinished sagas: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("projection: list unfinished sagas: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("projection: list unfinished sagas: %w", err)
	}
	for _, id := range ids {
		if _, held := p.live[id]; held {
			continue
		}
		st, err := p.recover(id, head)
		if err != nil {
			return err
		}
		p.live[id] = st
	}
	// The outbox is recovered the same way and to the same point. As of `head`,
	// not as of now -- the sixth place in this package where that distinction
	// matters, and the third where getting it wrong would have folded events
	// twice.
	// AsOf(head) rather than a strict read: the projector reads a directory a
	// daemon is writing, and it is already only folding up to `head`, so a tear
	// beyond that is nothing to it.
	events, err := outbox.LoadEvents(p.dir, evidence.AsOf(head))
	if err != nil {
		return fmt.Errorf("projection: recover the outbox from the log: %w", err)
	}
	asOf := make([]outbox.Event, 0, len(events))
	for _, ev := range events {
		if ev.Seq <= head {
			asOf = append(asOf, ev)
		}
	}
	st, err := outbox.Replay(asOf)
	if err != nil {
		return fmt.Errorf("projection: recover the outbox from the log: %w", err)
	}
	p.held = st

	p.warmed = true
	return nil
}

// pendingEvent is one saga event with the header facts the projection records
// but saga.Event does not carry.
type pendingEvent struct {
	seq    uint64
	kind   evidence.Kind
	sagaID string
	tenant string
	ev     saga.Event
}

// read collects every saga event after a sequence, in log order, and reports the
// highest segment id it looked at.
//
// The records are re-checked against their own hashes before being folded, for
// the same reason saga.LoadEvents does it: a projection derived from unverified
// bytes would let a tampered log dictate what the gate sees, which is the
// opposite of the point.
func (p *Projector) read(after uint64) ([]pendingEvent, uint64, int64, error) {
	ids, err := p.scan.Complete()
	if err != nil {
		return nil, 0, 0, err
	}
	var out []pendingEvent
	// resume is the segment holding the highest-sequence record seen in this
	// pass. Records in segments below it are all accounted for -- either folded
	// now or folded before -- and that segment may still be appended to, so the
	// next pass starts there.
	resume := p.fromSegment
	resumeOffset := p.fromOffset
	var highest uint64
	// How many records this pass framed and decoded, whether or not it kept
	// them: the difference between that and what it kept is re-read.
	scanned := 0
	defer func() { p.lastScanned = scanned }()
	for _, id := range ids {
		if id < p.fromSegment {
			continue
		}
		path := segment.Path(p.dir, id)
		insp, err := segment.Inspect(path)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("projection: inspect %s: %w", path, err)
		}
		// A torn tail stops this pass rather than failing it, for the reason
		// the log readers share: the projector reads a log that is being written, so
		// half a record is what a healthy log looks like from here, and the
		// records before it are whole.
		//
		// Unlike the other log readers this one needs no required sequence,
		// because it never claims to have reached one — it *reports* the
		// sequence it got to, and the caller decides whether that is far enough.
		// If the tear is genuine damage the fold simply stops
		// advancing, `catchUpTo` returns short, and `Store.FrontierIndex`
		// refuses every decision from there on. Fail-closed, and visible as a
		// projection that has stopped moving.
		torn := insp.Torn
		// Records this pass has already accounted for in a previous one are
		// skipped by *offset*, before being decoded. Decoding them and then
		// discarding them on sequence is the same answer at ten times the cost
		// — a header decode is about three quarters of what framing plus
		// decoding costs, and this skips all of it.
		//
		// The offset only applies to the segment the last pass stopped in.
		// Anything below it was seen and either folded or already accounted
		// for, and neither `fromSegment` nor `fromOffset` moves unless the
		// fold that read them committed.
		var floor int64
		if id == p.fromSegment {
			floor = p.fromOffset
		}
		for i, rec := range insp.Records {
			if insp.Offsets[i] < floor {
				continue
			}
			scanned++
			h, err := evidence.DecodeHeader(rec.Header)
			if err != nil {
				return nil, 0, 0, fmt.Errorf("projection: segment %d record %d: %w", id, i, err)
			}
			if h.Seq >= highest {
				highest = h.Seq
				resume = id
				// This record's own offset, not the one after it: the next
				// pass re-decodes exactly this one record and discards it on
				// sequence, which costs a microsecond and saves working out
				// how many bytes a record spans.
				resumeOffset = insp.Offsets[i]
			}
			if h.Seq <= after {
				continue
			}
			// Route by kind. The earlier version dropped every record with no
			// saga id, which is most of the log -- and, once the registry family
			// arrived, exactly the events this needs.
			if h.Kind != evidence.KindRegistry && h.SagaID == "" {
				continue
			}
			if len(rec.Payload) > 0 {
				if got := evidence.HashPayload(rec.Payload); got != h.PayloadHash {
					return nil, 0, 0, fmt.Errorf("projection: segment %d seq %d: payload does not "+
						"match its recorded hash", id, h.Seq)
				}
			}
			if want := evidence.ComputeChainHash(rec.Prev, h.PayloadHash, rec.Header); want != rec.Chain {
				return nil, 0, 0, fmt.Errorf("projection: segment %d seq %d: chain hash mismatch", id, h.Seq)
			}
			out = append(out, pendingEvent{
				seq:    h.Seq,
				kind:   h.Kind,
				sagaID: h.SagaID,
				tenant: tenancy.Of(h.Labels).ID,
				ev: saga.Event{
					Seq: h.Seq, Kind: h.Kind, Wall: h.TS.Wall(), Payload: rec.Payload,
				},
			})
		}
		if torn {
			// Nothing after this point in the directory is readable yet, and a
			// later segment's records would leave a hole in the sequence.
			break
		}
	}
	// Segment ids are assigned in order and records within a segment are
	// appended in order, so this is already sorted. Sorting anyway costs
	// nothing on an ordered slice and means a future change to how segments are
	// enumerated cannot silently reorder a fold.
	sort.SliceStable(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out, resume, resumeOffset, nil
}

// writeSaga replaces a saga's rows with those derived from a projection.
//
// Delete-then-insert rather than a per-row merge: a saga's step list and touch
// list are derived wholes, and a merge would leave behind any row the new
// derivation no longer produces. A stale touch row is a phantom conflict, which
// blocks a commit that should have gone through — the failure that teaches
// operators to route around the safety property.
// queueSaga adds one saga's rows to a batch rather than executing them.
//
// Every statement here used to be its own `tx.Exec`, which is its own round
// trip to Postgres: an upsert, two deletes, and one insert per step and per
// touch — six or so for a one-step saga, times every saga a fold touched. At a
// fold covering 280 events that is on the order of a thousand round trips
// inside one transaction, and it showed up as a per-event cost of 0.107 ms
// that barely moved however much other work was removed. The fold was not
// doing too much; it was talking too often (docs/bench/README.md).
//
// Batching changes nothing about what is written, when, or in what order —
// `pgx.Batch` preserves order and it all still lands in the one transaction
// that advances `last_event_seq`. It changes how many times the fold waits for
// the network.
// rowBatch is a pgx.Batch that remembers what each statement was for, so a
// failure still names the saga rather than an ordinal.
//
// Without it the error from a batched write is "statement 417 of 900 failed",
// which is true and useless. The descriptions cost one string per statement and
// are only read on the path where something has already gone wrong.
type rowBatch struct {
	batch pgx.Batch
	what  []string
	// Counted by family, because "380 statements per fold" does not say which
	// of them to attack. The four families scale differently: saga and clear
	// with the number of sagas a fold touched, step with their total length,
	// touch with how much they contend.
	saga, clear, step, touch uint64
}

func (r *rowBatch) queue(what, sql string, args ...any) {
	r.batch.Queue(sql, args...)
	r.what = append(r.what, what)
}

// send runs the batch and reports the first statement that failed, by name.
//
// Every result is read even after a failure: pgx requires the batch to be
// drained before the connection can be used again, and a fold that left it
// half-read would poison the transaction it is trying to roll back.
func (r *rowBatch) send(ctx context.Context, tx pgx.Tx) error {
	if r.batch.Len() == 0 {
		return nil
	}
	br := tx.SendBatch(ctx, &r.batch)
	var first error
	for i := range r.what {
		if _, err := br.Exec(); err != nil && first == nil {
			first = fmt.Errorf("projection: %s: %w", r.what[i], err)
		}
	}
	if err := br.Close(); err != nil && first == nil {
		first = fmt.Errorf("projection: close the write batch: %w", err)
	}
	return first
}

func queueSaga(b *rowBatch, s saga.State, tenant string, heldEffects, quarantinedEffects int) error {
	if s.SagaID == "" {
		// Nothing should reach here with no id, and the way it happened once was
		// an event folded onto a blank state. A row keyed on the empty string is
		// a saga that does not exist sitting in the table a frontier gate reads,
		// so this refuses rather than inserting it and letting a later query
		// explain it.
		return fmt.Errorf("projection: refusing to write a saga with no id")
	}
	b.saga++
	b.queue("write saga "+s.SagaID, `
		INSERT INTO sagas (saga_id, tenant, status, mode, intent_ref, last_seq, terminal,
			held_effects, quarantined_effects, principal, event_count, reason, parent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (saga_id) DO UPDATE SET
			tenant = EXCLUDED.tenant, status = EXCLUDED.status, mode = EXCLUDED.mode,
			intent_ref = EXCLUDED.intent_ref, last_seq = EXCLUDED.last_seq,
			terminal = EXCLUDED.terminal, held_effects = EXCLUDED.held_effects,
			quarantined_effects = EXCLUDED.quarantined_effects,
			principal = EXCLUDED.principal, event_count = EXCLUDED.event_count,
			reason = EXCLUDED.reason, parent = EXCLUDED.parent`,
		s.SagaID, tenant, string(s.Status), s.Mode, s.IntentID, int64(s.LastSeq), s.Terminal(),
		heldEffects, quarantinedEffects, s.Intent.Principal, int64(s.EventCount),
		saga.TerminalReason(s), parentOf(s))

	// Cleared and rewritten rather than reconciled: the rows must match the
	// state exactly, and working out which steps changed is a second
	// implementation of the state machine's bookkeeping.
	b.clear += 2
	b.queue("clear steps of "+s.SagaID, `DELETE FROM steps WHERE saga_id = $1`, s.SagaID)
	b.queue("clear touches of "+s.SagaID, `DELETE FROM resource_touches WHERE saga_id = $1`, s.SagaID)

	for ordinal, stepID := range s.Order {
		st := s.Steps[stepID]
		if st == nil {
			continue
		}
		b.step++
		b.queue("write step "+stepID+" of "+s.SagaID, `
			INSERT INTO steps (saga_id, step_id, ordinal, participant, effect_class, status,
				attempt, held_by_gate)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			s.SagaID, stepID, ordinal, st.Participant, st.EffectClass.String(),
			string(st.Status), int64(st.Attempt), saga.HeldByGate(st))
		for _, t := range st.Touches {
			b.touch++
			b.queue("write touch on "+t.Resource+" by "+s.SagaID, `
				INSERT INTO resource_touches (resource_id, saga_id, step_id, mode, frontier_seq)
				VALUES ($1, $2, $3, $4, $5)`,
				t.Resource, s.SagaID, stepID, t.Mode.String(), int64(t.Seq))
		}
	}
	return nil
}

// sendSaga writes one saga immediately. It is the single-saga path, used where
// there is nothing to batch with.
// recover rebuilds one saga's projection from the log, as it stood at a
// sequence.
//
// As of a sequence rather than as of now, always. Replaying a saga to its
// current state and then folding the events after `head` on top would apply each
// of those a second time — the same as-of-a-sequence question `registry.FoldUntil`
// answers, and the one this package has now got wrong once.
func (p *Projector) recover(id string, head uint64) (saga.State, error) {
	events, err := saga.LoadEvents(p.dir, id)
	if err != nil {
		return saga.State{}, fmt.Errorf("projection: recover saga %q from the log: %w", id, err)
	}
	asOf := make([]saga.Event, 0, len(events))
	for _, ev := range events {
		if ev.Seq <= head {
			asOf = append(asOf, ev)
		}
	}
	if len(asOf) == 0 {
		// The log has nothing for this saga at or before the sequence the
		// projection stands at, yet something referred to it. The rows and the
		// log disagree about history, and nothing good comes of folding onward
		// from a disagreement.
		return saga.State{}, fmt.Errorf("projection: saga %q has no events at or before "+
			"sequence %d; rebuild the projection", id, head)
	}
	st, err := saga.Replay(asOf)
	if err != nil {
		return saga.State{}, fmt.Errorf("projection: recover saga %q from the log: %w", id, err)
	}
	return st, nil
}

// parentOf names a saga's parent, or the empty string for a root saga.
func parentOf(s saga.State) string {
	if s.Parent == nil {
		return ""
	}
	return s.Parent.SagaID
}
