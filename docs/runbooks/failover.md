# Failover: promoting a replica

**Every step here that `make failover` does not execute is marked
`UNEXERCISED`.** A runbook is prose that reads as a working control; the drill is
what makes it one, and the gap between them belongs on the page rather than in
somebody's confidence.

Related: [replica.md](replica.md) is the following that precedes a promotion,
and [restore.md](restore.md) is the other way a log comes back.

This is the local-equivalent runbook. The drill runs two processes on one host,
so a SIGKILL leaves the disk behind and the primary's own log is still there —
a luxury a real region loss does not offer.

---

## Before anything happens: the two things that must already be true

**1. The standby key is declared in the log.** `janus-orchd -standby-keys
<public.json>` does it at start-up, and it must happen while the primary is
healthy. Trust extends forward, so a key first declared by the
*promoted* writer dangles from no in-chain declaration: an auditor holding one
root cannot reach it, and would need a second handed to them at exactly the
moment a withheld key and a corrupt segment are hardest to tell apart.

*Exercised by the drill.* Removing `-standby-keys` makes the promoted log report
`UNKNOWN_SIGNING_KEY` on every segment the new writer signed — the drill fails
there, which is how we know the step is load-bearing rather than ceremony.

**If you find out too late**, a follower pointed at the promoted writer refuses
with *"the primary's log is sealed by a key this copy cannot reach from its
roots"* and names the key. That refusal deliberately does not tell you which of
two things happened, because the bytes do not say: a standby that was never
declared, which is this step forgotten, or segments sealed by a key that is not
this log's writer. Find out which the named key is. If it is the promoted
writer's, hand it to the follower's `-keys` — the log could not introduce it, so
it has to arrive out of band — and declare the next standby before the next
failover. If it is not, do not copy that directory; re-seeding takes the same
segments and is refused the same way. Older builds reported this as *"the
primary's log diverges from this copy"*, which sent people hunting a fork that
was not there.

**2. A follower is running and its status is being read.** `janus-replicad`
prints `acknowledged through sequence N` and whether signatures are being
checked. **`signatures NOT checked (no trust root)` means exactly that** — pass
`-keys` or accept that a promotion will be onto bytes nothing verified.

*Exercised by the drill.*

---

## When the primary is lost

### 1. Decide. `UNEXERCISED`

Promotion is an operator act and nothing automates it: a wrong failure
detector produces two writers, which nothing in this system can prevent because
the writer lock is per-filesystem. **The time this step takes is
inside your real RTO and outside every number this drill reports.**

### 2. Stop the follower.

    kill <janus-replicad pid>

Promotion takes the writer lock, and two processes writing one evidence
directory is what the lock exists to refuse. If you forget, promotion fails with
`ErrLocked` naming this step — the check cannot be answered wrongly.

*Exercised by the drill.*

### 3. Note what the follower had acknowledged.

    grep 'acknowledged through sequence' <replicad log> | tail -1

Pass it to `promote -acknowledged N`. Records the replica holds above N were
adopted by recovery and **were never acknowledged to any caller** — the tenure
records both figures so that span is visible rather than silent.

*Exercised by the drill.*

**A follower that dies on its own comes back.** It did not, on builds that
predate the writer marker: once the log had failed over, every replica of it carried the
promotion's tenure, and the follower read that as "this directory is a writer"
and refused to start. Routine process death became a full re-seed.

### 4. Promote.

    janus-replicad promote -dir <replica dir> -key <standby key> \
      -operator <who you are> -reason <why> -acknowledged <N>

*Exercised by the drill.*

**If the deployment is fenced, pass the same `-fence-bucket` you gave the
primary**, and the same endpoint and credentials:

    janus-replicad promote -dir <replica dir> -key <standby key> \
      -operator <who you are> -reason <why> -acknowledged <N> \
      -fence-bucket <bucket> -fence-endpoint <url>

Three things change, and the last one is the step people miss.

- The promotion takes the writer lease before it writes anything, so a second
  operator promoting a second replica of the same log is refused and their
  directory is left untouched — **whether or not the first writer is running**.
  A promotion claims an epoch, and an expired lease at an epoch somebody has
  already claimed is not an opening; it is what their promotion left behind
  while they had not started their daemon yet. *Exercised by the drill, in both
  states of the lease.*
- **If a promotion dies between taking the lease and finishing**, the epoch is
  left claimed and the retry is refused with `already established` naming the
  holder — which will be *you*. Delete the lease object and promote again. This
  is the price of the rule above and it is a manual step on purpose: the
  alternative is a rule that cannot tell your own abandoned attempt from another
  operator's live one. `UNEXERCISED`.
- If the old primary is **alive and still reaching the bucket** — a partition
  rather than a crash — the promotion takes the lease from it anyway and then
  **waits out that writer's TTL before returning**, printing the time it is
  waiting until. That pause is the old primary discovering it has lost, and
  interrupting it puts two writers back on the log. `UNEXERCISED`: one host has
  no network to cut, and the case lives in
  `TestALaterEpochTakesTheLeaseFromALiveWriter`.
- It **records the epoch in the directory's writer marker** and says which one it
  took. You do not pass it to anything: `janus-orchd` reads it from there.
  Do not pass `-fence-epoch` to `promote` either — it refuses the
  flag, because the number decides which writer wins and should not be one
  anybody can mistype.

### 5. Start the writer.

    janus-orchd -dir <replica dir> -key <standby key> -listen <addr> ...

Fenced, and with **no epoch**: the promotion recorded it in this directory and
the daemon reads it.

    janus-orchd -dir <replica dir> -key <standby key> -listen <addr> \
      -fence-bucket <bucket> -fence-endpoint <url>

**Too low and it is refused; too high and it steals a lease somebody legitimately
holds** — which is why it is no longer typed. A daemon that resolves 0 against a
log that has been promoted says so in one line — `has moved to epoch 1 and this
writer serves epoch 0` — which is the same refusal the old primary gets if it
comes back.

`-fence-epoch` still exists for two cases, and a value contradicting the marker
is refused rather than obeyed:

- a directory promoted by an older build, whose marker carries no
  epoch. Pass it once; the daemon records it and the next start needs nothing.
- a marker that has been deleted. The daemon would resolve 0 and the lease would
  refuse it. Pass the epoch the lease's own refusal names; it is recorded once
  the log is open.

*Exercised by the drill*, and the drill's RTO ends at the first *successful
append* rather than at the process listening: a daemon that is up and cannot
write has not recovered anything.

### 6. Point clients at the new address. `UNEXERCISED`

The drill connects to the new port directly. Whatever does this in a deployment
— DNS, a load balancer, a config push — is not modelled here and its time is not
in the RTO number.

---

## Immediately after

### 7. Sweep the promoted log.

    janus-tier sweep -evidence <replica dir> -keys <roots>

**Promotion establishes no integrity of its own.** It records a handover on top
of whatever was there, and a replica that was following without a trust root was
never checking signatures at all. Until this completes, the promoted log is
trusted on its chain and its digests alone.

*`UNEXERCISED` by the failover drill* — `make restore-drill` measures a sweep,
and this drill does not run one. The duration is a function of log size; the
restore drill's figures are the guide.

### 8. Reconcile against the WORM archive. `UNEXERCISED`

Any effect released by the old primary whose evidence the replica lacks is an
RPO violation. The drill *counts* them — it is the number in
`phase6-failover.json` — and reconciling them is a deployment procedure this
repository does not model. The archive is the third copy, in a different failure
domain.

### 9. Give the new primary a replica.

    janus-replicad follow -dir <a fresh dir> -primary <new primary addr> -keys <roots>

**A promoted log can be replicated, and a follower needs only the root you
already had.** The standby key was declared in the log while the old primary was
healthy, so the writer-key chain carries trust across the handover:
one key out of band, across a change of writer.

Two things to know:

- **Into a fresh directory.** A directory an appender has owned refuses to
  become a follower — following would overwrite that writer's history at offsets
  the primary names. A *replica* of a promoted log is not such a directory and
  never was: it can be followed, restarted, and promoted in its turn.
- **A follower that was already running now continues across the promotion.**
  On older builds it returned *"the primary's log diverges from this copy"* — the
  split-brain alarm — because it had verified past the declaration that
  introduced the promoted writer's key, and each range checked trust from the
  configured roots alone. Restarting it made the alarm go away, which is the
  worst possible diagnostic signal. If you are running a build from before that
  fix, a follower crying divergence immediately after a promotion is probably
  this and not a fork; `janus-replicad compare` settles it either way.

**Until this is done the deployment has no replica**, and the RPO = 0 target is a
claim about the failover that already happened rather than the next one.

*Exercised by* `make failover-twice`, which runs a follower against the promoted
writer, kills it, and promotes again — RTO 187 ms against the first failover's
172, RPO 0 of 40 in both, and the twice-promoted log verifying from the original
root alone (`docs/bench/phase6-failover-twice.json`).

**If you are on a build that predates the writer marker, this step does not work.**
`janus-replicad` refuses any replica of a failed-over log with *"this directory
has been promoted to a writer"* — about a directory that has not been — and the
same refusal stops you promoting it later. A restart of the follower hits it
too. There is no workaround but a re-seed, which is why the fix matters.

### 10. Do not restart the old primary against clients — and if it did come back, compare before anything else.

Nothing prevents two writers. If the old primary comes back it holds a
valid writer lock on its own directory and will happily continue its own history.
Both directories stay internally consistent and both pass verification: **a fork
is invisible from inside either log**, because a verifier reading one has nothing
to compare against.

```
janus-replicad compare -a /path/old-primary/evidence -b /path/promoted/evidence
```

It reports the last sequence at which the two agreed, how far each went on after
it, and which side records a promotion. A non-zero exit means they are two logs
now.

**It will not tell you which one to keep, and neither will anybody else's tool.**
Both are valid. The decision is about which effects were released and which
clients were answered, and what the comparison gives you is the sequence to start
reading from. Start at `CommonSeq + 1` on both sides and work forward through the
outbox: an effect already delivered from the old primary cannot be undone by
choosing the other log.

**Exercised** by `FORK=1 make failover`, which brings the old primary back *after*
the promotion and creates this exact situation on one host. What it does not
exercise is the reconciliation — deciding what to do about the divergent records
is a deployment procedure this repository does not model. `UNEXERCISED` from
`CommonSeq + 1` onward.

---

## What the drill measures, and what it cannot

| | |
|---|---|
| RTO | kill → first successful append, **excluding** the decide step and client redirection |
| RPO | acknowledged calls whose evidence is missing from the promoted log. Zero at steady state; about one when killed mid-stream at a 300 ms follower interval |
| Continuity | the promoted log verifies against the **original** writer's key alone |

It cannot measure a region loss, a network partition, DNS propagation, or an
operator at three in the morning.

`FORK=1` adds one more: the split-brain is created for real and named by
`janus-replicad compare`. What follows the naming — deciding which side to keep —
is not measured, because it is not a computation.
