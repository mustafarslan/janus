-- The relational projections, as far as Phase 6a needs
-- them: the tables a frontier gate reads.
--
-- Every table here is derived. The evidence log is the system of record
-- and nothing in this database is authoritative for anything; if it
-- disagrees with the log, the log wins and the answer is to rebuild, never to
-- reconcile. That is why there is no write path into these tables other than
-- the projector, and why `projection_meta.last_event_seq` is written in the
-- same transaction as the rows it describes.

-- One row, always. `last_event_seq` is the highest evidence sequence folded into
-- the tables below, and it is the only thing that makes a read from this
-- database safe to act on: a caller that needs authority compares it against the
-- head of the log and refuses if it is behind.
CREATE TABLE IF NOT EXISTS projection_meta (
    only_row       boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    last_event_seq bigint      NOT NULL DEFAULT 0,
    -- The schema fingerprint the rows were built under. A projector whose
    -- expectation differs rebuilds rather than folding new events onto rows
    -- that were derived by different code.
    built_by       text        NOT NULL DEFAULT '',
    -- Which log these rows were folded from, as the chain hash of its first
    -- record. The advisory lock stops two projectors folding one store at the
    -- same time; this stops two projectors folding one store at different
    -- times, which is the case a lock cannot see. Two daemons on different
    -- evidence directories pointed at one schema would otherwise interleave two
    -- histories into one projection and report nothing wrong.
    log_id         text        NOT NULL DEFAULT '',
    updated_at     timestamptz NOT NULL DEFAULT now()
);
INSERT INTO projection_meta (only_row) VALUES (true) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS sagas (
    saga_id    text   PRIMARY KEY,
    -- The tenant is a binding on the writer, read back from the event
    -- header labels rather than from anything a caller declared. An evidence
    -- directory carries one tenant, so today this column is constant within a
    -- store; it is here because a query that is not tenant-scoped from the
    -- first day becomes a query nobody dares to scope later.
    tenant     text   NOT NULL DEFAULT '',
    status     text   NOT NULL,
    mode       text   NOT NULL DEFAULT '',
    intent_ref text   NOT NULL DEFAULT '',
    last_seq   bigint NOT NULL,
    -- The rest of what an overview row shows. They are here so that a console
    -- backed by the projection renders the same page as one reading the log,
    -- rather than a quietly poorer one: a row that lost the principal or the
    -- reason a saga is stuck would still look like a row.
    principal   text   NOT NULL DEFAULT '',
    event_count bigint NOT NULL DEFAULT 0,
    reason      text   NOT NULL DEFAULT '',
    parent      text   NOT NULL DEFAULT '',
    -- How many of this saga's effects still owe the world something -- held, or
    -- announced and unconfirmed. Not every effect it owns: that number never
    -- goes down on a mature saga, and it sat under a column headed "held" until
    -- that was corrected. A count and not a table:
    -- the console needs a number, and effect *state* is commit authority
    -- (invariant I1, `outbox.LogAuthority`) which nothing may ever read from a
    -- projection. There is deliberately no way to get an effect id out of here,
    -- so a future release path cannot be tempted to.
    held_effects int NOT NULL DEFAULT 0,
    -- How many of this saga's effects are frozen waiting for a person. It is a
    -- separate number from held_effects and not a subset of it: an effect that
    -- quarantines stops being pending (`outbox.Effect.Pending` is HELD or
    -- RELEASING), so held_effects goes *down* when one freezes and this is the
    -- only thing left in the projection pointing at it.
    --
    -- Under the same rule as held_effects, and it matters more here because the
    -- temptation is stronger: a count, never an effect id. Effect state is
    -- commit authority (invariant I1, `outbox.LogAuthority`), so this column
    -- may say that a saga is worth looking at and may not say what is on it.
    -- The quarantine list is re-derived from the log for the sagas this names
    --. A stale count therefore produces a work list that is missing a
    -- row, never a work list with a wrong row on it.
    quarantined_effects int NOT NULL DEFAULT 0,
    -- Terminal in the `saga.State.Terminal` sense, which includes QUARANTINE:
    -- a state the saga will not leave on its own. It is emphatically NOT the
    -- same as settled -- `saga.Index.settled` excludes QUARANTINE, because a
    -- quarantined saga is frozen with its effects still in the world and must go
    -- on holding the frontier on every resource it touched. Nothing derives
    -- commit safety from this column; it exists so a restart knows which sagas
    -- to recover, and the fold recovers any other saga on demand.
    terminal   boolean NOT NULL
);
CREATE INDEX IF NOT EXISTS sagas_tenant ON sagas (tenant);

CREATE TABLE IF NOT EXISTS steps (
    saga_id      text NOT NULL REFERENCES sagas(saga_id) ON DELETE CASCADE,
    step_id      text NOT NULL,
    -- Position in saga.State.Order. The order a saga declares its steps in is
    -- part of its identity, and a projection that returned them in whatever
    -- order the database chose would make a rebuilt index differ from a
    -- replayed one in a way that is invisible until a tie needs breaking.
    ordinal      int  NOT NULL,
    participant  text NOT NULL DEFAULT '',
    effect_class text NOT NULL DEFAULT '',
    status       text NOT NULL,
    attempt      bigint NOT NULL DEFAULT 0,
    -- Whether this step is stopped at a gate, as `saga.HeldByGate` reports it.
    -- It is that function's answer written down, not a second opinion about it:
    -- the projector calls it while it holds the real projection. What it is for
    -- is choosing which sagas the approval queue has to replay; what each gate
    -- is actually waiting for is decided by `gate.Decide` over real state, never
    -- from a column.
    held_by_gate boolean NOT NULL DEFAULT false,
    PRIMARY KEY (saga_id, step_id)
);

-- `resource_touches`. This is the table that exists to stop
-- `saga.ReplayAll` being called on every frontier decision.
--
-- It has no primary key on purpose. A step's touch list is a recorded fact and
-- nothing in the event schema forbids it from carrying the same resource, mode
-- and sequence twice; a uniqueness constraint here would turn a legal history
-- into a projector crash. The projector deletes a saga's rows and reinserts
-- them whole, so duplicates cannot accumulate across folds.
CREATE TABLE IF NOT EXISTS resource_touches (
    resource_id  text   NOT NULL,
    saga_id      text   NOT NULL REFERENCES sagas(saga_id) ON DELETE CASCADE,
    step_id      text   NOT NULL,
    mode         text   NOT NULL,
    frontier_seq bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS steps_held_by_gate ON steps (held_by_gate) WHERE held_by_gate;

CREATE INDEX IF NOT EXISTS resource_touches_resource ON resource_touches (resource_id);
CREATE INDEX IF NOT EXISTS resource_touches_saga ON resource_touches (saga_id);

-- The registry family (`participants / manifests / manifest_versions`), and why the events themselves are here.
--
-- `pkg/registry`'s own doc comment argues against a table, and it is right about
-- what a table would lose: resolution *as of a sequence*, an auditor rebuilding
-- from a bundle with no service running, and tamper detection from the chain.
-- Only the first of those is this schema's problem, and it is solved by keeping
-- the events rather than by decomposing them.
--
-- `registry_events` is the registry's event stream, copied out of the log in
-- sequence order. Readers fold it with `registry.Fold` and `registry.FoldUntil`
-- -- the same functions, unchanged -- so resolution as of a sequence answers
-- exactly what it answered before, and there is no second implementation of the
-- registry state machine to diverge from the first. What the table removes is
-- the segment scan, which is what the cost always was: `registry.LoadEvents`
-- walks the whole directory, and `janus-orchd` did that on every admission.
--
-- The rule is that projected tables carry structural metadata and never payload
-- content, and this is a deliberate, bounded exception to the letter of it
-- rather than to its reason. The reason is crypto-shredding: a row
-- derived from personal data would outlive the destruction of the subject's DEK.
-- Registry events have no data subject -- `Appender.encrypt` seals a payload only
-- when `Request.Subject` is set, and `registry.Recorder` never sets it -- so they
-- are never encrypted, never shredded, and carry declarations about software
-- rather than facts about people. Nothing that can be shredded may be copied
-- here.
CREATE TABLE IF NOT EXISTS registry_events (
    seq     bigint PRIMARY KEY,
    payload bytea  NOT NULL
);

-- The inventory view: what is registered, and where each version
-- stands *now*. Nothing folds from these -- they exist so that "list what this
-- deployment runs" is a query rather than a replay. A reader that needs an
-- Entry, or needs one as of a sequence, folds `registry_events` instead.
CREATE TABLE IF NOT EXISTS participants (
    participant_id text PRIMARY KEY,
    -- The version that is ACTIVE now, or empty when none is.
    active_version text NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS manifest_versions (
    participant_id  text   NOT NULL REFERENCES participants(participant_id) ON DELETE CASCADE,
    version         text   NOT NULL,
    state           text   NOT NULL,
    content_address text   NOT NULL DEFAULT '',
    -- Registration order, so "the latest version" means the latest registered
    -- rather than the highest string -- the same rule `Registry.order` keeps.
    ordinal         int    NOT NULL,
    registered_seq  bigint NOT NULL DEFAULT 0,
    activated_seq   bigint NOT NULL DEFAULT 0,
    last_seq        bigint NOT NULL DEFAULT 0,
    -- Revalidation triggers no evaluation has covered yet. A version owing any
    -- of these cannot be activated, so it is the column an inventory report is
    -- actually asking about.
    pending_triggers text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (participant_id, version)
);
CREATE INDEX IF NOT EXISTS manifest_versions_state ON manifest_versions (state);

-- ---------------------------------------------------------------------------
-- Columns added after a table shipped.
--
-- Every CREATE above says IF NOT EXISTS, which makes this file safe to re-run
-- and, on a database that already has the table, makes it a no-op that silently
-- skips the new column. The bumped `schemaFingerprint` then triggers a rebuild,
-- the rebuild refolds, and the fold's INSERT names a column that does not
-- exist. A fresh database -- which is every test database -- has the column from
-- the CREATE and passes; only an upgrade fails. So this section is where a
-- column added to an existing table goes, and it is not optional bookkeeping:
-- without it the schema is right for new deployments and broken for real ones.
--
-- The guard around the ALTER is not decoration, and `ADD COLUMN IF NOT EXISTS`
-- on its own is the wrong tool. PostgreSQL takes ACCESS EXCLUSIVE on the table
-- *before* it evaluates IF NOT EXISTS, so the no-op case locks too -- measured:
-- an ALTER whose column already exists still holds AccessExclusiveLock on
-- `sagas` for the length of its transaction. Every `projection.Open` runs this
-- file, and there are several: the daemon's, each console's, `janus-projection
-- status`. That would put a brief exclusive lock on the table the fold writes
-- and the frontier gate reads, every time any of them starts. Checking
-- information_schema first takes no lock at all when there is nothing to do,
-- which is every start after the first.
--
-- The column carries a default because these are projected columns: the default
-- is only ever read between the ALTER and the refold that overwrites it.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name = 'sagas' AND column_name = 'quarantined_effects'
                     AND table_schema = current_schema()) THEN
        ALTER TABLE sagas ADD COLUMN quarantined_effects int NOT NULL DEFAULT 0;
    END IF;
END $$;
