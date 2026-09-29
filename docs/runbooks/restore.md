# Restore: bringing a log back from a backup

**Every step here that `make restore-drill` does not execute is marked
`UNEXERCISED`.** A runbook is prose that reads as a working control; the drill is
what makes it one, and the gap between them belongs on the page rather than in
somebody's confidence.

The drill writes a log, backs it up, restores it, sweeps the restored copy and —
when a DSN is given — rebuilds a projection from it, on one host, into a
temporary directory. **It does not model losing the original.** Every number it
produces is a claim about the size it ran at and nothing else.

---

## The thing to understand before anything else: a restore leaves a window open

A restore checks **the manifest's signature, the segment
digests, and the manifest's own contiguity arithmetic** — and does *not* re-verify
every record's signature and Merkle path. That decision rests on one measured
number: verifying 100M events took **254.5 s against the 300 s RTO**, so
doing it inside the restore would spend the entire budget on it.

The consequence is the sentence an operator needs:

> **Until the sweep in step 5 completes, the restored bytes are trusted on the
> signed manifest and their digests alone.**

That is not "unverified". The chain is checked and the manifest is signed. What
has *not* been re-derived is the per-record signature and Merkle evidence, which
is what an auditor's verification actually consists of. The window is a real
interval with a measured length, and step 5 is what closes it.

**And there is a second window nobody was counting.** The projection comes back
empty, and rebuilding it is the largest number in this whole page — about seven
times the sweep. Until step 6 finishes, the deployment is serving, from the log,
at a frontier-gate latency eight times its own budget. "Restored" therefore
means three different things at three different times, and the table at the
bottom of this page gives all three.

---

## Before anything happens: the two things that must already be true

**1. You have the trusted public key set, from somewhere other than the backup.**
`-keys` is required on `restore` and the tool says why in its own help: *a backup
checked against the keys it carries proves only that it is internally consistent,
which is what a forger also produces.* A backup that vouches for itself vouches
for nothing.

*Exercised by the drill* — it restores with `-keys` written by `janus-keys pub`
from the writer key, held outside the backup.

**2. You have the head, by a route the backup did not travel.** `janus-tier
export` prints it in the form `janus-verify -expect-head` takes. **Neither a
backup nor an audit bundle can prove that records were not dropped from its end —
a valid prefix of a hash chain is a valid hash chain.** The head closes that, and
only if it reached you separately.

*`UNEXERCISED`.* The restore drill compares nothing against an independently
conveyed head; it restores what it just wrote. Evidence bundles are not
anchored, and anchoring is what would close this gap without an out-of-band step.

---

## Restoring

### 1. Decide that you are restoring. `UNEXERCISED`

Nothing automates this and nothing should. **The time this step takes is inside
your real RTO and outside every number below.**

### 2. Confirm the target is empty.

`restore` requires an evidence directory that is **empty or absent** and refuses
otherwise. Restoring on top of an existing log would interleave two histories, so
the check cannot be answered wrongly — but it also means an aborted restore
leaves a directory you must remove before retrying, deliberately, rather than
having the tool decide for you.

*Half exercised.* The drill restores into a fresh directory, so `check_target`
runs and passes on every run — the **refusal** branch is exercised by nothing,
here or in the test suite (`emptyTarget` at `cmd/janus-tier/backup.go:256` has no
caller but this one). `UNEXERCISED` for the case that matters, which is a retry
after a failed restore.

### 3. Restore.

    janus-tier restore -backup <backup dir> -evidence <target dir> \
      -keys <trusted public key set> -json restore.json

It verifies the manifest signature, checks the target, copies the segments, and
checks the manifest's contiguity — in that order, and it stops at the first one
that fails. `-json` writes the per-phase timings, which is what makes the next
section a measurement instead of an impression.

**An unsigned backup is refused.** An unsealed tail segment carries no footer of
its own, so the manifest's signature is the only thing standing over it; a
manifest an attacker can rewrite is a segment list they can shorten.

*Exercised by the drill.*

### 4. Read what it printed.

It names the sweep command and the window in its own output. That is not
decoration — it is the handoff to step 5, on the screen of the person who just
ran step 3.

*Exercised by the drill.*

### 5. Sweep. This is the step that closes the window.

    janus-tier sweep -evidence <target dir> -keys <trusted keys> -json sweep.json

Every record's signature and Merkle path, timed. **Until this exits zero, the
restored log has not been verified in the sense an auditor means.**

*Exercised by the drill*, and it is the drill's headline number. The drill also
**fails** if the sweep verified fewer events than the backup carried — otherwise
the window figure would be a measurement of a sweep that stopped early.

### 6. Rebuild the projection. This is the step that decides your RTO.

    janus-projection rebuild -evidence <target dir> -projection <dsn> -json rebuild.json

A restored evidence directory is the source of truth; the projection is derived,
so it comes back empty or bound to the log you just lost. **This is
the largest number in the whole restore** — at 200,000 events it is 7.5× the
sweep and 46× the restore, and it extrapolates to about half an hour at 100M.

**It can run at the same time as step 5.** Both only read the restored
directory, and the two were run together to check it: 3,439 ms against 4,073 ms
one after the other, both exiting zero. Nothing about them is serial except this
page.

**Run it before you start writers, not after.** `rebuild` takes the projection's
writer lock and refuses while a daemon is folding. The refusal is now a refusal:
until the rebuild was first timed, this truncated the store *and then*
checked the lock, so an operator who read "stop it before rebuilding" had
already lost the rows — and the daemon holding the lock died on its next fold
with `saga: illegal transition`, and the same way on the fold after that,
until restarted.

**Point it at its own schema.** `rebuild` empties whatever the DSN resolves to.

*Exercised by the drill* when `PROJECTION_DSN` is set, which is opt-in: the rest
of `make restore-drill` needs no database and that is worth keeping. The drill
fails if the rebuild reached the log's head having *kept* nothing, because a
rebuild that keeps nothing is a scan and its time is a scan's time.

### 7. Confirm the head against the one you were given separately. `UNEXERCISED`

    janus-verify -keys <trusted keys> -expect-head <head from step 0.2> <target dir>

Without this, a restore of a *truncated* backup succeeds and passes its sweep,
because everything present is genuine.

### 8. Restart writers against the restored directory. `UNEXERCISED`

The drill never starts a writer on the restored copy. Whatever points a daemon,
a load balancer or a DNS record at it is not modelled here and its time is not in
any number below.

---

## What the drill measured, and at what size

**The size is part of the result.** Every phase grows with the log, so each
figure is a claim about one size. From `docs/bench/phase6-restore.json` — which
is written by a drill run *with* `PROJECTION_DSN`; running the drill without one
overwrites that file with a copy that has no `rebuild` key at all:

| | |
|---|---|
| Size | **200,000 events, 59,870,470 bytes, 4 segments** |
| Backup | 338.0 ms |
| Restore, total | **73.5 ms** — of which `copy_segments` 73.1 ms; the manifest signature check 0.27 ms and the contiguity arithmetic 0.0002 ms |
| **The window** (one full sweep) | **453.4 ms**, 200,001 events verified |
| **The projection rebuild** | **3,398.9 ms**, 200,000 of 200,001 records kept — of which the commit half 2,878.8 ms (85%), reading the log 319.2 ms, folding the state machine 120.7 ms |

### Your RTO is three numbers

| | what is true | at 200k | extrapolated to 100M |
|---|---|---|---|
| **Back** | the log is on disk and stands under its signed manifest; a daemon serves from it | 73 ms | ≈ 37 s |
| **Back and verified** | step 5 — every record's signature and Merkle path re-derived | + 453 ms | ≈ 264 s |
| **Back and fast** | step 6 — the frontier gate answers from tables rather than the log | + 3,399 ms | **≈ 29 min** |

Steps 5 and 6 both only read, so they overlap, and that was run rather than
reasoned: together on one restored 200k-event directory they finish in **3,439 ms
against 4,073 ms run one after the other**, both exiting zero, with the rebuild no
slower for the company. The total is the larger, not the sum.

**The five-minute RTO is met at "back and verified" and missed by nearly six
times at "back and fast"**.

The distinction is not academic. A daemon on a restored directory with an empty
projection is *not down* — `gate.IndexFromLiveLog` answers the frontier gate
straight from the log. It answers it at **201.64 ms p50** at concurrency 8 with
2,000 sagas in the log, against the 25 ms gated-effect budget. So the deployment is serving
at "back", and meeting its latency budget only at "back and fast".

### What follows from the shape of it

- **The restore is a file copy plus three cheap checks.** 99.5% of it is
  `copy_segments`. It scales with bytes, not with events, and on other storage
  it will be a different number entirely.
- **The window is six times the restore.** Coming back is fast; being *verified*
  takes longer than coming back did.
- **The rebuild is seven times the window.** And its cost is statements, not
  work: 266,689 of them for 200,000 events, at about 10.8 µs each. Reading the
  log and folding the state machine together are about 13% of it.

**The scaling is measured, not assumed** — three runs at each of 20,000 and
200,000 events: restore ×9.5, sweep ×9.9, rebuild ×8.5 across a tenfold change.
The rebuild's sublinearity is the per-statement cost falling as the batch grows,
not fewer statements: the count is exactly linear at 1.33 per event. **Nothing
here says the RTO is met at your size**, on your storage, against your database:
it says the shape of the curve is known and was checked at two points on it, and
that the 100M column is an extrapolation five hundred times past them.

## What it cannot measure

Losing the original. Storage that is not a local filesystem — the backup target
is a directory, and nothing else is supported yet. A restore under contention with live traffic. An operator deciding, at
three in the morning, whether this is a restore situation at all. And a
projection rebuild against anything but a Postgres on the same host — the
rebuild's cost is dominated by round trips, so a database across a network is
the case most likely to differ and the one nothing here touches.
