# Support, versions, and what "supported" means here

**There is no LTS branch, no release cadence, and no second maintainer.** Phase 7's
exit gate asks for an LTS policy; this is the honest one. It has two halves, and
they are not equally strong: what holds **mechanically**, enforced by a constant
and a test, and what would need an **organisation**, which does not exist.

Read the second half before relying on the first.

---

## What holds mechanically

These are properties of the code, each with the thing that proves it. None of
them depends on anybody promising anything.

### Your existing log stays readable, or refuses loudly

There are four version gates, and they are not the same rule. The operational
summary is:

| Layer | Today | A **newer** version reaching this build |
|---|---|---|
| Segment file format | `segment.Version = 1` | **Refused** — guessing at the file layout is guessing at record boundaries |
| Event envelope | `evidence.EnvelopeVersion = 1` | **Refused** at `DecodeHeader`; `janus-verify` reports Critical and FAILs |
| Saga semantics | `saga.SemanticsVersion = 2`; 1 and 2 both fold | **Refused** — folding a future saga under today's rules yields an ordinary-looking wrong answer |
| Projection schema | `projection.schemaFingerprint` | **Rebuilt, not refused** — a projection is derived and never the source of truth |

The projection row differs because it is the only layer that can be re-derived.
Everything else *is* the log.

**The honest qualification: one version has been bumped, and only one.** Saga
semantics went to 2, and version 1's reading is now exercised against a
history that version 2 refuses (`TestASwapRecordedUnderVersionOneStillFolds`), so
for that layer the accepting branch has read a genuinely older record. The segment
format and the envelope are still on version 1, the first and only one of each:
older records are accepted there only because "older" and "current" are the same
shape, and there is no dual-read path and no converter.
What is proved for them is the **refusal**, against a committed real-bytes fixture
at `pkg/evidence/testdata/envelope-v2/`. What is not yet proved by anything is the
acceptance.

### Old sagas replay on new builds

`SAGA_BEGIN` pins the semantics version a saga was admitted under, and the runner
stamps it rather than trusting a caller. A recorded history therefore
folds under the rules in force when it began, not the rules of the build reading
it. `make corpus` replays every recorded fixture and fails CI when a change alters
what an old history means — and the fix for a deliberate semantic change is to add
a version and branch, never to regenerate the fixtures.

### A projection upgrade does not need a migration step

`schema.sql` is applied on every `Open` and carries guarded `ALTER TABLE` forward
migrations; a `schemaFingerprint` change makes the next catch-up truncate and
refold from the log. Nothing in those tables is authoritative, so the
worst case is a rebuild, not a data loss. **The cost, stated honestly: the ALTER section can be forgotten and the whole suite will still pass,
because every test database is created fresh.**

### The verifier you were handed is the source you were shown

`make repro` builds `janus-verify` three ways and requires identical bytes,
run in CI as the `repro` job. `make release-verifier` publishes the
matrix with checksums and reproduction instructions.

### Upgrading, operationally

- **Roll forward.** Read the compatibility table above first.
- **A downgrade after any future envelope bump is a hard stop, by design.** The
  build cannot read its own log, deliberately, rather than reading four fifths of
  each record. That is the stated cost.
- Projection rebuilds are automatic and cost one full refold — from the log, so
  the bound is the log's size and not the projection's age. `make latency` reports
  fold cost decomposed into read / apply / commit, and `docs/bench/README.md`
  §"Phase 7: where the fold's other four-fifths go" is where those figures live.
- Nothing here is a rolling upgrade story for multiple writers, because **there is
  only ever one writer** — the writer lock is per-filesystem and
  nothing prevents two.

---

## What would need an organisation, and therefore does not exist

**No LTS branch.** `master` is the only branch. There is no `release-1.x`, no
maintenance window, no end-of-life date — because there is nobody to staff one.
The policy above is deliberately a statement about *your data* rather than about a
branch: what master promises is that a log written under these versions stays
readable or is refused out loud, and that is a property a single branch can
actually keep.

**No backports.** A fix lands on master. If you are on an older commit, you move
forward or you carry the patch.

**No release cadence and no support SLA.** No response time, no severity classes,
no maintenance contract.

**No security response process.** See [SECURITY.md](../SECURITY.md). The short
version: there is no security team. The planned security engineering program
is only partly built, and `SECURITY.md` lists what exists and what does not.

**No `CONTRIBUTING.md`, `GOVERNANCE.md` or `CHANGELOG.md`, on purpose.**

- A `CONTRIBUTING.md` is a promise about review — turnaround, standards, who
  decides. With one maintainer and no second contributor it would be a promise to
  nobody, made by nobody.
- A `GOVERNANCE.md` for a one-person specification is the hollow control this
  project exists to prevent. **JTP v1.0 governance is a Phase 7 exit-gate item and
  it needs an external party** — a public spec repository, a change process, and
  conformance badges somebody other than the author can fail.
- A `CHANGELOG.md` would be one more description of history to keep in step
  with the code.

**Bus factor 1.** One maintainer. This is the load-bearing fact behind every line
above, and no document changes it.

---

## What GA would still be missing

The Phase 7 exit gate is "GA checklist (docs, support runbooks,
security response process, LTS); ≥ 2 external conformant implementations of any
JTP surface."

| Gate item | State |
|---|---|
| Docs | This file, [SECURITY.md](../SECURITY.md), `docs/spec/` |
| Support runbooks | [failover](runbooks/failover.md), [restore](runbooks/restore.md), [replica](runbooks/replica.md) — each marking every step its drill does not execute |
| Security response process | **Absent**, and stated as absent in `SECURITY.md` |
| LTS | **This file.** The policy is "one branch, and here is what it promises about your data" |
| ≥ 2 external conformant implementations | **Absent.** Needs two parties outside this repository. `bin/janus-conformance` and `docs/spec/jtp-v0.9.md` are what they would build against — and the spec is still **v0.9**, since the v1.0 release is a Phase 7 item |

Two of five need people who are not here. That is the accurate GA status, and
writing it down is what this document is for.
