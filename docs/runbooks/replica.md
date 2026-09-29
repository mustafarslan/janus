# Replication: running a follower, and knowing whether it is following

**Every step here that `make replica` does not execute is marked `UNEXERCISED`.**
A runbook is prose that reads as a working control; the drill is what makes it
one, and the gap between them belongs on the page rather than in somebody's
confidence.

**This is the local-equivalent runbook, and the drill is the local equivalent of
a second region — which it is not.** Two processes on one host share a disk, a
kernel, a clock and a power supply. What the drill proves is that the protocol
converges and that the copy stands on its own; what it cannot prove is anything
about a region failing.

Promotion — what you do with a replica after the primary is gone — is
[failover.md](failover.md). This document is only about the following.

---

## The one thing that is silently optional

`janus-replicad` prints one status line, and the signature state is on it:

    acknowledged through sequence N · at segment S offset O · signatures checked through segment M · R records framed
    acknowledged through sequence N · at segment S offset O · signatures NOT checked (no trust root) · R records framed

**Both halves are on one line deliberately** — `describe` in
`cmd/janus-replicad/main.go` says why: a sequence number on its own invites the
reading "verified through here", and without a trust root that is exactly what
has not happened.

**The second line means exactly what it says.** Without `-keys`, the follower copies
bytes and verifies nothing about who wrote them, and a promotion is then onto
bytes nothing checked. It is a warning and not a refusal, because a follower that
will not start is worse than one that is honestly limited — which means **nothing
stops you running this way forever except reading the line.**

*Exercised by the drill*, in the checked direction: it passes `-keys` and then
**fails the whole run** if `signatures checked through segment [1-9]` never
appears, so a green drill cannot mean "verified nothing and finished early".

---

## Setting a follower up

### 1. Publish the writer's public key set.

    janus-keys pub <writer.key> > public.json

This is what `-keys` takes, and it must travel to the follower by a route that
does not go through the thing being replicated.

*Exercised by the drill.*

### 2. Start the primary with its replication surface listening.

    janus-orchd -dir <primary dir> -key <writer.key> -listen <addr> ...

*Exercised by the drill*, which additionally forces `-segment-bytes 2048` so the
primary **rotates** during the run. Rotation is what seals a segment, and a
sealed segment is the only thing signature checking acts on — a drill that never
rotated would report a pass having exercised none of it.

**A real deployment does not want 2048-byte segments.** That flag is there to make
the drill reach the thing it exists to check, and it is the reason step 4's
figures are about a log rotating far more often than yours will.

### 3. Start the follower.

    janus-replicad -primary <addr> -dir <replica dir> \
      -keys public.json -interval 500ms

*Exercised by the drill.*

### 4. Read its status, continuously. `UNEXERCISED` as an ongoing practice

The drill reads the line above once, at the end. **Nothing in this repository alerts on it
going stale** — there is no monitor, no threshold and no page. A follower that
stopped following looks, from the outside, exactly like a follower with nothing
to do. Whatever watches this in a deployment is not modelled here, and the RPO
you actually get is a function of that thing rather than of anything measured
below.

This number is also what [failover.md](failover.md) step 3 asks for, so it is not
only a health signal: it is the input to a promotion.

---

## Confirming the replica is real

These three are the substance of the drill, and they are the checks worth
repeating by hand against a deployment's replica.

### 5. Work must happen on the primary *while* the follower runs.

*Exercised by the drill*, deliberately: it writes 30 records with the follower
live. A copy taken after everything has stopped would not exercise the resume
path, and the resume path is where a replication cursor actually goes wrong.

### 6. Compare the directories, and expect a *prefix*.

    cmp <primary>/<n>.jseg <replica>/<n>.jseg

*Exercised by the drill.* The subtlety it encodes is worth carrying: **the
primary's open segment may have grown after the follower stopped, and that is lag
rather than divergence.** The drill therefore requires the replica to be a
byte-identical prefix, and fails only when it is neither identical nor a prefix.
A comparison that demanded equality would fail every time it was run against a
live primary — which is every time it is useful.

### 7. Verify the replica **offline**, against the writer's key.

    janus-verify -keys public.json -allow-open-tail <replica dir>

*Exercised by the drill*, and this is the one that makes it a replica rather than
a copy: it is run against the **replica**, with the primary stopped. A replica
that only verifies while the primary is present is not a replica.

**`-allow-open-tail` is not a relaxation of the signature check.** A live log's
newest segment has no footer until it rotates or the writer closes, so a faithful
copy of it ends in an unsealed segment too; refusing that would be refusing the
thing being replicated. Every **sealed** segment is still checked against its
signature and its Merkle root.

---

## What the drill establishes, and what it does not

| | |
|---|---|
| The protocol converges under live writes | **Yes** — 30 records written with the follower running; the replica caught up |
| The copy verifies on its own, primary absent | **Yes** — `janus-verify` against the replica alone, `result: PASS`, 5 segments, 3 sealed and signature-checked |
| Sealed segments are signature-checked as they arrive | **Yes**, and the drill fails if none ever was |
| Lag is distinguished from divergence | **Yes** — prefix, not equality |
| Anything about a region failing | **No.** One host, one disk, one kernel, one clock |
| A network partition, or a slow link | **No.** Loopback |
| RPO under load | **No.** [failover.md](failover.md) measures RPO, at one follower interval, on one host |
| Alerting on a stalled follower | **No.** Nothing here watches anything |
| The mirror still being intact an hour later | **No, and the follower is not the thing that would notice.** A poll asks only about segments at or above its cursor, so a sealed segment corrupted on the replica host afterwards does not lower `SignaturesCheckedThrough` — that number says what this follower *copied*. Run `janus-tier watch -evidence <mirror> -keys <roots>` on the replica host: it re-reads history on a schedule and alerts, which is what continuous background verification requires. The drill does not do this |
| Following a log that has already failed over | **Yes** — `make failover-twice`. A replica of a promoted log can be followed, restarted and promoted in its turn; the directory a follower must not target is one an *appender* has owned, which it learns from a node-local marker rather than from the log |
| Two writers | **Prevented only with `-fence-bucket`**. With the fence armed on `promote` and on `janus-orchd`, a second promotion of the same log is refused and a superseded primary refuses to start. Without it — the default — you get two valid logs and `janus-replicad compare` is what names them afterwards |
