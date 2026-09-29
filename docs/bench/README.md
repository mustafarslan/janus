# Phase 0 spike: evidence append path

**Verdict: PASS.** On Linux the append path sustains **195,393 events/s at p99
3.07 ms** with the strongest durability barrier engaged — 3.9× the throughput
target and a third of the latency budget. Phase 0's go/no-go gate
is cleared and the architecture proceeds
unchanged.

Raw reports: `phase0-linux-arm64.json`, `phase0-darwin-arm64.json`.
Reproduce with `make bench` (host) or `make bench-linux` (container).

## What was measured

The whole real path, not a microbenchmark of one part: canonical CBOR encoding
of the envelope → BLAKE3 payload hash → BLAKE3 chain hash → segment record write
→ group-commit durability barrier → RFC 6962 Merkle root → Ed25519 footer
signature at seal. Every run then re-verifies the log it just wrote with
`janus-verify`, because a fast write path that produces unverifiable evidence is
worth nothing. All runs verified clean.

## Targets

| Target | Result (linux, `full`) |
|---|---|
| ≥ 50,000 events/s/node | **195,393/s** at 256 producers |
| p99 append ≤ 10 ms | **3.07 ms** at 256 producers |

## Results

150,000 events per run, 256 B payloads, arm64.

**Linux (fsync) — the deployment-relevant number:**

| Producers | Events/s | Ev/batch | p50 ms | p99 ms |
|---|---|---|---|---|
| 16 | 23,376 | 8.0 | 0.55 | 2.95 |
| 64 | 83,765 | 32.0 | 0.73 | 0.97 |
| 256 | **195,393** | 128.5 | 1.19 | **3.07** |
| 1024 | 315,106 | 857.1 | 2.79 | 14.24 |

**macOS (F_FULLFSYNC):** 1,899/s at 16 producers rising to 106,681/s at 1024,
with p99 never below 13.8 ms.

**A shared GitHub Actions runner** reaches 45,708/s at p99 4.06 ms with 64
producers and 92,977/s at p99 15.80 ms with 256 — that is, it meets one target
or the other but never both. This is not a CI problem to fix; it is what the
write path does on commodity cloud storage, and it is the most likely shape of a
deployment that has not been given fast local disk. The Phase 0 gate is judged
against known hardware, and the CI benchmark step is reported rather than
asserted for exactly this reason. It is worth keeping in view when sizing a
design-partner environment: the storage under the evidence directory is the
single variable that decides whether the 10 ms append budget holds.

## Three things the numbers taught us

**Throughput is bounded by concurrency, not by the write path.** With P appends
in flight and a barrier costing T, no configuration can exceed P/T. The first
run used 16 producers and reported 1,899 events/s, which looked like a failed
gate; it was measuring the load generator. Batch size rises from 8 to 857 events
as producers go from 16 to 1024, which is group commit working exactly as
intended — arrivals queue during the previous sync and are absorbed into the
next one at no extra cost. Any future quote of an events/s figure has to state
the concurrency alongside it, so the benchmark sweeps rather than taking a
single point.

**Past ~256 producers the trade reverses.** Throughput keeps climbing to 315k/s
at 1024 producers but p99 crosses the 10 ms budget (14.24 ms), because queueing
delay now dominates. 256 is where both targets hold simultaneously, so that is
the operating point the gate is judged at. Trading latency away for throughput
is not a pass.

**A darwin `full` result is not a deployment number.** On Linux `full` is
fsync; on darwin it is F_FULLFSYNC, which additionally flushes the drive's write
cache and costs roughly an order of magnitude more. That is why darwin `full`
misses the latency target at every concurrency: a single barrier there costs
8–16 ms, more than the entire p99 budget. The gate is the Linux run. Local
darwin runs are for catching regressions, not for judging targets.

## The rotation outlier, resolved in Phase 1

Phase 0 recorded isolated 130–210 ms outliers in the MAX column and attributed
them to sealing the outgoing segment on the writer goroutine. Phase 1 moved both
halves of a rotation off that goroutine — the seal to a background sealer, the
next segment to a pre-creation step — and **the outlier did not move**:
206 ms before, 206 ms after.

Measuring instead of assuming found the real cause. On macOS the strong barrier
is `F_FULLFSYNC`, which flushes the *device's* write cache rather than one
file's: its cost scales with outstanding dirty data and it stalls all I/O to
that device. No amount of concurrency hides a hardware barrier.

On Linux, where the strong barrier is `fsync`, rotation costs nothing
measurable:

| Linux, sync=data, 16 producers | Events/s | p99 ms | max ms |
|---|---|---|---|
| with rotation (5 segments) | 19,575 | 3.40 | **8.98** |
| without rotation (1 segment) | 24,401 | 3.82 | 37.80 |

So the Phase 0 carryover was a development-machine artefact, not a design flaw.
The asynchronous work was kept anyway: it removes real serialisation, and it is
what let the fault-injection harness exercise sealing, segment creation, and
appending as independently failing operations.

The lesson worth keeping is the one about `F_FULLFSYNC`: a darwin `full` number
measures the device barrier, not Janus.

## Phase 1: 100M-event verification

**Verdict: PASS.** Phase 1's exit gate asks for *"external-style
verification of a 100M-event log < 30 min."* `janus-verify` re-verified a
100,000,001-event, 46 GB, 2,942-segment log in **254.5 s (≈ 4.2 min)** —
**7× inside budget** — at **≈ 393,000 events/s**. Generation (not gated, but
measured because the benchmark does both) sustained 472,754 events/s at
`-sync none`, 256 producers.

Raw report: `phase1-100m.json`. Reproduce with:

```bash
./bin/janus-bench -events 100000000 -payload 256 -producers 256 \
  -sync none -segment-bytes 16777216 -dir /path/with/~60GB/free \
  -json docs/bench/phase1-100m.json
```

The earlier extrapolation from a 500K-event sample (≈ 4 min projected) held
almost exactly — 46 GB measured
against a 47 GB projection, 393k events/s measured against 433k/s projected,
both close enough that the linear-scaling assumption behind the projection is
now a result rather than a claim.

## Phase 1: the 72-hour chaos soak

**Verdict: PASS.** Phase 1's exit gate asks for a *"72-hour chaos soak with
zero integrity violations."* The soak ran **72h1m3s of cumulative chaos time**
over **81,033 kill/recover rounds** and found **zero integrity violations** — no
`VIOLATION` and no `FAIL` line anywhere in the run.

Unlike every other number in this file, this one is not a rate, and it is worth
saying why it belongs here anyway: it is the measurement that says the append
path survives being killed, and the shape of the run is what makes the count
mean something.

| | |
|---|---|
| Platform | native darwin/arm64, APFS — **not** Docker Desktop, whose virtualised disk can report a barrier it did not take |
| Durability | `-sync full` = `F_FULLFSYNC` |
| Segments | 64 KiB |
| Epochs | 5 GiB, rotating; each read end to end before it was retired |
| Rounds | 81,033 across four resumed sessions (8,973 + 17,056 + 19,001 + 36,003) |
| Round cost | 3.441 s average, flat to the end — not climbing, which is what says the run stayed useful |
| Segments per epoch | ≈ 105,400 at rotation |
| History | a full re-verification pass every ≈ 14 minutes; slowest honest pass 19m24s against a 15m0s target |

**The history line is the one to read.** A soak that only ever checks what is new
proves durability and nothing about tampering with the past. The rolling sweep
completed passes continuously — in the final session's report its epoch 3
completed 64 passes across 15h07m18s and its epoch 4 completed 83 across
19h13m24s — so old segments were genuinely re-read. At
roughly 30% over the 15-minute period asked for, the detection latency is a
modest miss rather than a pass, and it is recorded as a miss.

The final session printed `slowest 13h30m8s` for that figure. That was a bug in
the soak harness's own accounting, not a slow sweep. It is fixed, with a
regression test.

Raw evidence — `soak.log`, `soak-report.json`, and one directory per epoch —
lives outside this repository because it is 19 MB before the epoch directories.
Reproduce with:

```bash
make soak DURATION=72h SOAK_SYNC=full SOAK_SEGMENT_BYTES=65536
```

This closes the last open condition of the Phase 1 exit gate.
What it does not do is close the platform question: the run has never been done
on Linux, on amd64, or against `fsync` rather than `F_FULLFSYNC`. That remains
open, and it is deliberately not blocking.

## Phase 6: replay determinism over real sagas

Replay determinism asks for two things and CI only did one. The fixture
corpus replays every saga history ever recorded, on every commit — the CI
half, and proof that the state machine has not changed underneath histories somebody
wrote down. The other half is a production spot-replay daemon that samples
completed sagas continuously, which is about the sagas a deployment actually
ran.

`janus-spotreplay` is that daemon, and `make spotreplay` produces the number.

### What was measured

Both chaos suites were run to completion with `-keep-always`, and every evidence
directory they left behind was checked. That corpus is the richest source of real
sagas this repository can produce, and it is the right one for this question:
**every saga in it was killed and resumed at least once**, so a divergence here
would be a divergence in exactly the histories where it matters — the ones that
were reconstructed rather than merely written.

| | |
|---|---|
| Evidence directories | 243 |
| Completed sagas checked | 287 |
| Agreed | 287 |
| **Rate** | **100.0000%** |

Measured 2026-08-30 on darwin/arm64, over `janus-sagachaos` (129 kills across 12
scenarios) and `janus-sagachaos -hosted` (78 kills across 12 scenarios).

### What each saga was checked for

Three checks, and which ones apply depends on how the saga ended — recorded in
the finding, because a rate whose denominator nobody can see is a number nobody
can audit.

- **`replay-is-stable`** — invariant I5 stated directly: replaying the same
  events twice lands on the same projection. Applies to every saga. This is what
  catches the nondeterminism that actually happens: a map iterated without
  sorting, a decision that reads the clock, a slice shared between two states.
  The fixture corpus cannot catch these, because it compares against a value
  recorded by the same code.
- **`root-agrees`** — the evidence root recorded in the saga's COMMIT against the
  root recomputed from the log. Committed sagas only. This is the strongest of
  the three, because it compares against something *written down at the time by a
  different process* and cited afterwards as the authority for releasing an
  irreversible effect.
- **`commit-seq-agrees`** — the `last_seq` the COMMIT recorded against what the
  replay reaches there. Committed sagas only, and **not a third independent
  anchor**: the coordinator takes that value from its own in-memory state, so on
  a log one coordinator wrote alone the two numbers are equal by construction. It
  is a tripwire for a saga id being written by two things at once — possible,
  because the outbox lifecycle events carry one — kept because it costs nothing.

### What this number is not

The Phase 6 exit gate says "replay sampling **in prod design partner** ≥ 99.99%
deterministic". There is no design partner, so that gate cannot be produced here,
in the same way and for the same reason as Phase 5's mock supervisory inspection.

What exists is the daemon a design partner would run and a rate over this
repository's own logs. 287 sagas is not a production sample; it is enough to say
the machinery works and that nothing in the current state machine is
nondeterministic under the histories the chaos suite generates. Anyone quoting
100% should quote the denominator with it.

### If it ever finds something

A divergence is an integrity alarm, and `janus-spotreplay` deliberately does
nothing about it: it appends nothing, quarantines nothing and holds no lock. It
prints the saga id, the check that failed and what it found, and exits 1.

The three findings mean different things:

- **`replay-is-stable` failed** — the state machine is not a pure function of the
  event sequence any more. This is a code defect and it is the most serious of
  the three, because every other guarantee in the system is stated over a replay.
  Do not "fix" it by regenerating anything.
- **`root-agrees` failed** — the log's bytes may be perfectly intact (run
  `janus-verify` to confirm) and still no longer mean what they meant. Either the
  events for that saga changed, or how a root is computed did. If the latter was
  deliberate, every commit ever recorded now cites a root the current code will
  not reproduce, and that is a migration, not a bug fix.
- **`commit-seq-agrees` failed** alone — most likely an event belonging to the
  saga arrived at a sequence the commit did not expect. Look at what is writing
  to that saga id after it committed.

---

## Phase 6: the decision path

**Verdict: PASS, after three fixes it found.** Every projection-backed
configuration meets the 25 ms p50 budget for a gated side effect and the
50 ms p99 budget for a gate decision — 5.39 ms at concurrency 1 on an empty log,
13.46 ms at concurrency 8 with 2000 sagas in it.

That was not true when this was first measured. **The first sweep failed the gated-effect budget in
three configurations out of four**, and the point of the benchmark is that
nobody knew: neither budget had a number anywhere in the repository, so nothing
was passing or failing them. Three defects are what the sweep found — a reader
that could not tell a live write from a torn tail, a saga that read the whole
log twice, and a projection catch-up that serialized gate decisions — and
closing all three is what turned the verdict.

The `IndexFromLog` fallback still misses both budgets at 2000 sagas, by
construction and as documented.

Until this existed, neither budget had a number anywhere in the repository.
`janus-bench` above proved the *write* path; nothing measured the path a gated
effect actually travels. Three open questions — single-threaded verification,
the cost of small segments, and listing the segment directory on every pass —
were parked waiting on a measurement nobody had taken, and the Phase 6 exit gate — a load test at
10× design-partner peak with SLOs held — had no baseline to hold anything
against.

```
make latency-linux          # the number that counts
make latency                # the same on the host, for iteration
```

### What was measured

`janus-latency` drives single-step IRREVERSIBLE_GATED sagas through the real
coordinator, the real reference policy and a real evidence log, and times four
things per configuration:

| | What it covers |
|---|---|
| `saga_start` | `saga.ResumeSaga` — building a coordinator for one saga |
| `decide_pre_execution` | `Keeper.Decide` at PRE_EXECUTION: SCHEMA, two POLICY gates, RISK_LIMIT |
| `decide_pre_release` | `Keeper.Decide` at PRE_RELEASE: POLICY and FRONTIER — the one that reads the cross-saga index |
| `gated_effect` | `Coordinator.Drive`, begin through commit |

The participant returns instantly and always succeeds, so the time a step takes
*is* the latency Janus added, which is the quantity the gated-effect budget covers.

**What `gated_effect` excludes, so the PASS is not read as more than it is.** It
does not include `saga_start`, which is timed separately and is not free — the
operator-visible cost of one gated effect is the two added together. It stops at
commit, so it excludes the outbox `Hold` append, the release-authority check and
the delivery itself. It excludes human and validator latency, which the
gate-decision budget excludes too. And it is one step: a longer plan pays this per gated step, not
once.

**Why every figure states a concurrency and a background size.** A p99 measured
on an idle node is a figure about an idle node. The background is the number of
committed sagas already in the log when the run starts; the two frontier-index
implementations scale differently in it, and that difference is the entire
argument for the projection.

**Why the frontier decision is always made against a projection that is behind.**
In the reference policy the FRONTIER requirement sits at PRE_RELEASE, decided
immediately after the step's own result is appended — which the projection
cannot already contain. So every `decide_pre_release` sample below pays for the
synchronous catch-up `Projector.FrontierIndex` performs. That is the honest cost
of the staleness contract, not a case that had to be constructed.

### Results — linux/arm64, 16 CPUs, sync=full, 300 samples per configuration

`gated_effect` p50 against the 25 ms gated-effect budget, `decide_pre_release` p99
against the 50 ms gate-decision budget:

| Index | Background | Conc | `saga_start` p50 | `decide_pre_release` p50 / p99 | `gated_effect` p50 | ≤ 25 ms | ≤ 50 ms |
|---|---|---|---|---|---|---|---|
| projection | 0 | 1 | 0.00 | 3.19 / 5.31 | **5.39** | PASS | PASS |
| projection | 0 | 8 | 0.00 | 7.32 / 11.50 | **12.04** | PASS | PASS |
| projection | 2000 | 1 | 0.00 | 3.56 / 5.64 | **5.76** | PASS | PASS |
| projection | 2000 | 8 | 0.00 | 7.19 / 10.30 | **13.46** | PASS | PASS |
| log (fallback) | 0 | 1 | 0.00 | 8.06 / 16.02 | 10.32 | PASS | PASS |
| log (fallback) | 0 | 8 | 0.00 | 16.78 / 28.27 | 23.43 | PASS | PASS |
| log (fallback) | 2000 | 1 | 0.00 | 114.98 / 125.13 | 118.41 | FAIL | **FAIL** |
| log (fallback) | 2000 | 8 | 0.00 | 158.70 / 176.23 | 165.04 | FAIL | **FAIL** |

Run-to-run spread on the projection rows is roughly ±2 ms at concurrency 8 on
this machine, so quote these to the nearest millisecond rather than the
hundredth. The margins that matter — 13 ms against a 25 ms budget, 10 ms against
50 — are wider than the noise.

`decide_pre_execution` — SCHEMA, two POLICY gates and RISK_LIMIT, none of which
read an index — is 0.01–0.02 ms p50 in every row above and never approaches its
budget. Gate evaluation is not the cost. Reading the log is.

The verdict `make latency` exits on is taken over the **projection** row set,
because that is what a deployment runs; the fallback rows are printed with their
budgets beside it. `gate.IndexFromLog` is the no-database option and its O(log)
cost is documented, so holding the whole target red
because the documented fallback behaves as documented would make it a target
nobody runs.

### The fallback index stops being a deployment option between 125 and 250 sagas

`gate.IndexFromLog` replays every saga in the directory to answer one frontier
gate, so its cost is the log's size and nothing in the fixes above changes that —
a frontier gate asks about sagas it cannot name in advance, so there is nothing
to look up. Swept at concurrency 1, same conditions as above:

| Background | `log` `gated_effect` p50 | ≤ 25 ms | `projection` `gated_effect` p50 | ≤ 25 ms |
|---|---|---|---|---|
| 0 | 10.32 | PASS | 5.39 | PASS |
| 125 | 20.67 | PASS | 9.42 | PASS |
| 250 | **28.42** | **FAIL** | 10.25 | PASS |
| 500 | 43.48 | FAIL | 13.15 | PASS |
| 2000 | 118.41 | FAIL | 5.76 | PASS |

At an empty log the fallback beats the projection — replaying nothing is faster
than a Postgres round trip — and then it falls over almost immediately. At 2000
it misses the gate-decision budget by 2.5×. "Runs without Postgres" should be read as a development
and small-installation option, not as a slower way to run a bank: 250 committed
sagas is a few minutes of a working day. This is the fallback's ceiling,
measured.

*(The 125/250/500 rows were measured before the torn-tail and double-read fixes
and are unchanged by them: at concurrency 1 the fallback's cost is the replay,
and the saga-start scan those fixes removed was under 5 ms at those log sizes.)*

### What the three fixes moved

The first sweep is kept here because the differences are the argument.

| `gated_effect` p50, projection | first sweep | now |
|---|---|---|
| empty log, concurrency 1 | 7.87 | **5.39** |
| empty log, concurrency 8 | 31.24 — FAIL | **12.04** — PASS |
| 2000 sagas, concurrency 1 | 31.08 — FAIL | **5.76** — PASS |
| 2000 sagas, concurrency 8 | 44.44 — FAIL | **13.46** — PASS |
| `log` at 2000 / 8 | *could not run* | 165.04 |

**Fix one — a reader could not tell a live write from a torn tail.**
`segment.Writer` flushes on a buffer boundary rather than a record boundary, so
a concurrent reader sees half a record in a healthy log. Every reader treated
that as damage and told the operator to run recovery. The `log 2000/8` row was
`BLOCKED` in the first sweep for exactly this. A live read now names the
sequence it requires, which is what lets it read past a tear it can
prove hid nothing acknowledged — and what stops the tolerance becoming a
fail-open prefix.

**Fix two — a saga read the whole segment directory twice**, once to find its
own history and once at commit to build its evidence root, and the projection
helped with neither. `saga_start` was 23.72 ms at 2000 sagas; it is now 0.00 ms.
The appender indexes each saga's record offsets as it publishes them.
Profiling is what shaped the fix: framing 16,000 records costs 3.0 ms and
decoding all their headers takes it to 13.5 ms, so three quarters of a scan was
decoding headers that were thrown away.

**Fix three — the projection's inline catch-up serialized gate decisions.** After
the first two this was the *only* remaining cause of a gated-effect miss, and cleanly
visible: `decide_pre_release` went 3.27 ms at concurrency 1 to 22.93 ms at
concurrency 8 while `decide_pre_execution`, which reads no index, did not move.
Concurrent readers now share one fold — 22.93 ms → 7.32 ms.

**None of the three was found by reading the code.** The benchmark found the
first two; `-race` on Linux and the hosted chaos suite each found a defect in
the fixes themselves.

### Phase 6j: what a failover costs, and what it loses

`make failover` kills a primary mid-work, promotes its replica, and measures
three things instead of asserting them. Two processes on one host, so a SIGKILL
leaves the disk behind and the primary's log is still there to compare against —
a luxury a real region loss does not offer.

| | Steady state | Killed mid-stream (`SETTLE=0`) |
|---|---|---|
| RTO | **185 ms** | 160 ms |
| RPO violations | **0** of 40 | **1** of 40 |
| Continuity | verifies from the original root | verifies from the original root |

**RTO is measured to the first successful *append*, not to the process
listening.** A daemon that is up and cannot write has not recovered anything. It
**excludes** the operator deciding and the clients being redirected, and the
drill says so rather than quietly counting a machine's reflexes as a recovery.
At 185 ms against the 300,000 ms RTO the machine is not the constraint; the
operator is, and that is the honest reading. The figure moves between runs —
160, 173, 185 and 192 ms across the runs behind this page and
`phase6-failover-twice.json` — and nothing here depends on which of those it is,
which is the point of quoting it against 300,000.

**RPO is framed as the question the RPO = 0 target actually asks.** Not "how far behind was
the replica" — always some — but **"was any effect released whose evidence the
replica lacks?"** Every call that *returned success* before the kill is counted,
and the promoted log must hold them all.

**The mid-stream column is the replication lag's exposure as a number.** One acknowledged
call, at a 300 ms follower interval, was told it had succeeded and its evidence
is not in the promoted log. That is not a defect: it is what "cross-region RPO is
the replication lag, not zero" means when you make it concrete. Zero at steady
state is a real gate; the exposure is measured with `SETTLE=0` and a raised
tolerance, so a measurement run and a gating run cannot be confused.

**Continuity is the crux, and the drill is what proves it in real processes.**
The promoted log is verified against the **original** writer's public key and
nothing else. Remove `-standby-keys` from the primary and the drill fails there:
`UNKNOWN_SIGNING_KEY` on every segment the promoted writer signed. That is the
unit test's finding reproduced end to end, and it is why enrolling the standby
key while the primary is healthy is a constraint rather than ceremony.

**The RTO budget was shown to bite.** `RTO_BUDGET_MS=1` fails the drill. A budget
that is printed rather than enforced is the `janus-tier -jurisdiction` failure
again — a flag accepted and ignored.

**What it cannot measure**, stated because a drill that does not say so invites
the reading that it did: a region loss, a network partition, DNS propagation, or
an operator at three in the morning. `docs/runbooks/failover.md` marks every step
the drill does not execute as `UNEXERCISED`, which is three of nine.

### Phase 6h: what a restore costs, and how long the window lasts

A restore reads no records — the manifest's signature, the
per-file digests, and the manifest's own sequence arithmetic — and leaves
everything per-record to a sweep afterwards. That leaves a window in which the
restored bytes are trusted on the signed manifest and their digests alone.

**Both halves measured, at two sizes**, on darwin/arm64 at `sync=none`
(`make restore-drill`, `EVENTS=` to change the size):

| Size | Backup | Restore | Window (full sweep) |
|---|---|---|---|
| 20,000 events · 9.9 MB · 1 segment | 403 ms | **13 ms** | **53 ms** |
| 200,000 events · 98.9 MB · 6 segments | 506 ms | **129 ms** | **522 ms** |

Ten times the log costs about ten times the restore and ten times the sweep, so
the linear assumption is measured rather than asserted. The restore's
own phases at the larger size: signature 0.3 ms, target check 0.1 ms, **copy and
digest 129.0 ms**, contiguity 0.0 ms. The copy is the whole of it, which is what
"reads no records" means in practice — one blake3 pass over the bytes.

**The extrapolation reproduces a number measured independently, which is the
strongest thing here.** Scaling the 200k window to 100M events gives **≈261 s**.
The Phase 1 run measured 100M-event verification directly at **254.5 s**. Two
different harnesses, one on Linux and one on darwin, agreeing within 3% — so the
sweep really is the full verification, and the extrapolation is not wishful.

**That arithmetic is what justifies the restore's shape rather than merely
motivating it.** At 100M events the restore extrapolates to ≈64 s, comfortably
inside the 300 s RTO. Running the sweep *before* serving would add the ≈261 s and
put the total at **≈325 s — over budget**. The decision to defer the sweep is not
a preference; it is the difference between meeting the RTO and missing it.

**What this does not say.** These are single-node figures on a laptop, at
`sync=none`, with 256-byte payloads. They say the design's shape is right and
they do not say any particular deployment meets the RTO: restore and sweep both
grow with the log, so **the number is a claim about a size**, which is why the
size is stamped into `phase6-restore.json` beside every timing. The
`copy_segments` phase is also a local file copy here; a deployment restoring
across a network pays that phase's cost at network speed instead, and nothing
here measures that.

**The projection rebuild is not in these numbers.** A restored evidence directory
is the source of truth and the projection is derived, so
`janus-projection rebuild` is a separate operator step — and, at scale, the term
that grows fastest. It is not measured here.

### What a restart costs

`saga_start` is 0.00 ms above because the appender's locator has been running
for the whole sweep. A restarted daemon starts cold, and the design claims it pays
**one** scan in total rather than one per saga. Measured, 2000 sagas of 8 events
each:

| | one 16 MB segment | 103 sealed 64 KiB segments |
|---|---|---|
| first read after restart | 18.83 ms | 23.38 ms |
| each of the next 500 | 0.022 ms | 0.022 ms |
| the same 500 with no index | 9.4 s | 11.7 s |

The claim holds, and the number is small: linearly at the 10k-saga target the cold
scan is under 100 ms, once, against the five-minute RTO.

The second column is the more interesting one. **A hundred sealed segments cost
about the same as one** — the scan is dominated by records, not by files — which
is what settles the question of per-segment sidecar indexes: sidecars would
save roughly five milliseconds once per process lifetime. They stay open for a
different reason, which is that they would answer "was this saga ever written?"
exactly instead of probabilistically.

### The ceiling, measured: it is between concurrency 8 and 64

The sweep above stops at 8 because that is where it started. Taking it further
is what the scalability target asks about — 10k concurrent sagas per node — and
the answer is that the decision path falls over two orders of magnitude short of
it. Empty log, 600 samples, `sync=full`:

| Concurrency | `decide_pre_release` p50 | `gated_effect` p50 | ≤ 25 ms |
|---|---|---|---|
| 1 | 5.12 | 7.38 | PASS |
| 8 | 8.38 | 13.45 | PASS |
| 64 | **53.98** | **64.83** | **FAIL** |
| 256 | **152.83** | **163.44** | **FAIL** |

*(These are the numbers as first measured. Batching the fold's writes, below,
moved them: at concurrency 64 the decision is now 17.46 ms and the effect
27.77.)*

The growth is **sub**-linear above 8 — 6.4× for 8× the load from 8 to 64, then
2.8× for 4× from 64 to 256 — and that shape is the useful part. A fold applies
everything pending since the last one, so a longer fold batches more events and
amortises better; the fold's *throughput* is not obviously the problem. What
breaks the budget is that every decision waits for one or two whole folds, and
fold duration grows with the backlog behind it.

**What it is not.** `decide_pre_execution`, which reads no index and touches no
database, stays at 0.01 ms p50 at every concurrency including 256 — so this is
not CPU starvation. `saga_start` stays at 0.00 ms — not the locator. And it is
not the connection pool: `pgxpool` defaults to `max(4, NumCPU)` = 16 here, and
raising it to 64 changed nothing (44.46 → 51.41 ms p50 at concurrency 64, which
is noise in the wrong direction).

**What it is.** Subtracting the decisions from the effect leaves the appends:
about 5 ms at concurrency 8 and about 12 ms at 64 — 2.4× for 8× the load, which
is group commit doing its job. Over the same range the decision went 8.38 ms to
53.98 ms. The projection fold is the whole of it.

The third fix removed the *lock queueing* in front of that fold, and this is a
different thing: one fold now serves everybody, but it has more to apply the
faster the log grows, so its duration rises with the append rate and every
waiter pays it. Coalescing made a fixed cost shared; it did not make a growing
cost smaller.

### The fold is not slow. It is long, and everybody waits for a whole one.

`janus-latency` now reports what the folds cost, because a projection that is
keeping up and one that is the bottleneck look identical from outside — both
answer, both state a sequence. Same runs as above:

| Concurrency | folds | events per fold | mean fold | **ms per event** | `decide_pre_release` p50 |
|---|---|---|---|---|---|
| 1 | 600 | 9.0 | 4.38 ms | **0.487** | 5.09 |
| 8 | 114 | 47.2 | 6.78 ms | **0.144** | 8.79 |
| 64 | 20 | 266.6 | 30.23 ms | **0.113** | 53.80 |
| 256 | 6 | 856.5 | 84.45 ms | **0.099** | 159.22 |

**Per-event apply cost falls by five times as load rises.** The fold amortises
almost perfectly: a busier system gives it more to do per transaction and it
does each event *cheaper*. Whatever is wrong here, the fold's efficiency is not
it, and making it faster would be optimising the one thing that is already
improving.

**What the last two columns say is the whole finding.** A decision's latency
tracks the *duration* of a fold, at a ratio that climbs from 1.16× at
concurrency 1 to 1.89× at 256 — converging on two. That is exactly what the
coalescer promises and no more: a waiter joins the fold in flight, and if that
fold does not reach its required sequence it waits for the next one as well. Two
folds, and a fold now takes 84 ms because it has 856 events in it.

So the cost is **waiting**, and the lever is fold *duration*, not fold
throughput and not the number of projectors.

### Bounded fold batches were tried, and they do not work

The obvious fix from the table above is to commit the fold in bounded batches so
a waiter is released when the batch carrying *its* sequence lands, rather than
when the whole backlog has been applied. `last_event_seq` advances per batch,
which is the same clean-resume property at a finer grain, so it looked cheap and
safe.

It was built, measured, and reverted. Concurrency 64, 600 samples, with each
batch publishing its head so waiters really are woken as batches land:

| Events per batch | ms per event | mean fold | `decide_pre_release` p50 |
|---|---|---|---|
| unbounded (one transaction) | 0.107 | 30.01 ms | **50.16** |
| 256 | 0.119 | 35.27 ms | 60.54 |
| 64 | 0.148 | 56.37 ms | 70.12 |
| 16 | 0.222 | 98.10 ms | 114.43 |

**Monotonic, and in the wrong direction.** Smaller batches are worse at every
step.

**Why, and it is not an implementation detail.** A waiter's required sequence is
the log head read at *its own decision time* — that is the ordering the projection
insists on, so the answer cannot depend on a concurrent append. The fold's
backlog is precisely the events up to that head. So essentially every waiter
needs the **last** batch, and releasing anyone early releases nobody who was
waiting. What the extra transactions do cost is per-event throughput, which
lengthens the fold, which makes every waiter wait longer. The idea is not merely
neutral here; it is actively harmful, and the more finely it is applied the
worse it gets.

The general lesson is worth more than the specific result: **a batching
optimisation only helps when waiters want different points in the stream.**
Every caller of this fold wants the newest one.

### The fold was not doing too much. It was talking too often.

The next hypothesis was that the fold writes rows no decision reads — steps, the
registry inventory, outbox counts — and that folding only the hot tables
synchronously would cut the cost of the thing waiters wait for.

Looking before building found something simpler. `writeSaga` issued **one
`tx.Exec` per statement**: an upsert, two deletes, and one insert per step and
per touch, for every saga a fold touched. A fold covering 280 events across ~200
sagas is on the order of a thousand round trips inside one transaction. At
0.107 ms per event and about five statements per saga, that is ~20 µs per
statement — network, not work.

Batching them with `pgx.Batch` changes nothing about what is written, when, or
in what order. It changes how many times the fold waits for the network.

| Concurrency | ms/event before | after | `decide_pre_release` p50 before | after |
|---|---|---|---|---|
| 1 | 0.487 | 0.481 | 5.09 | 5.25 |
| 8 | 0.144 | **0.089** | 8.79 | **5.81** |
| 64 | 0.113 | **0.048** | 53.80 | **17.46** |
| 256 | 0.099 | **0.038** | 159.22 | **54.93** |

**Three times faster at concurrency 64, and the ceiling moved with it.** The
50 ms p99 for a gate decision now passes at 64 (26.21 ms) where it failed at
63.92. The gated-effect budget is missed at 64 by three milliseconds — 27.77 against 25 — where it
was missed by forty.

At concurrency 1 nothing changes, which is the check that this is what it claims
to be: with nine events in a fold there is nothing to batch.

**The floor this curve is heading for was measured later.** A projection rebuild
is the most favourable fold there is — one pass over the whole log, maximal
amortisation — and `make restore-drill` puts it at **0.017 ms/event** over
200,000 events. So concurrency 256's 0.038 is within about twice the
best this fold shape can do, and the remaining cost is the 1.33 statements each
event still owes.

**What it cost.** `pgx` reports a batch failure by position, so the naive
version says "statement 417 of 900 failed". Each queued statement carries a
description naming its saga, step or resource, and a test asserts one
description per statement — the pairing is not enforced by the type system and
is exactly what a later edit would break.

### Splitting hot from cold tables cannot close the gap either

That was the remaining cheap idea: the fold writes `sagas`, `steps`,
`resource_touches`, the registry stream and its inventory. A frontier decision
reads `sagas` and `resource_touches`. `steps` is read by exactly one query —
the console's approval-queue shortlist — and by no gate decision at all, so it
is genuinely cold with respect to the path being measured.

The upper bound was measured before anything was designed, by simply not writing
`steps` and seeing what the fold cost then. Not a proposal — a ceiling on what
any hot/cold split could deliver:

| | writing `steps` | not writing it | change |
|---|---|---|---|
| ms per event, c=64 | 0.048 | 0.039 | −18% |
| mean fold, c=64 | 12.92 ms | 10.46 ms | −19% |
| `decide_pre_release` p50, c=64 | 17.46 | 14.42 | −17% |
| `gated_effect` p50, c=64 | 27.77 | **26.38** | −5% |
| `decide_pre_release` p50, c=256 | 54.93 | 40.61 | −26% |

**The gated-effect budget still fails at concurrency 64 — 26.38 against 25 — with the cold table not
written at all.** A real split would deliver less than this, because the work
does not vanish: it moves to the ticker and competes for the same database. And
it would cost something real, a second write path and a console table that lags
the decision path, which is a new "as of" question on a page that already
carries one.

So it is not built. The measurement that would have justified it says it would
not have been enough.

### Ninety per cent of what the fold read, it had already read

Decomposing the fold itself — rather than the effect — found the largest single
term, and it was not work at all.

`Projector.read` resumed at a whole *segment*. Within the open one it re-framed
and re-CBOR-decoded every record written since that segment was created, then
discarded all but the tail on sequence: the decode sat *above* the
`h.Seq <= after` skip. Instrumented at concurrency 64: **55,882 records scanned
to keep 5,333 — 90% re-read, and 38% of the fold's time.**

It is also a sawtooth. The waste grows as the open segment fills and resets at
rotation, so a 16 MB segment near full is ~48k records of re-read per fold — and
this benchmark structurally *under*-measures it, because every run starts on a
fresh segment.

The fix is to remember where the last pass stopped and skip below it by offset,
before decoding. `Inspection` already reports each record's offset, so nothing in
`segment` changes.

| Concurrency | mean fold | | `decide_pre_release` p50 | | `gated_effect` p50 | |
|---|---|---|---|---|---|---|
| 1 | 4.35 → **2.13** | | 5.05 → **2.81** | | 7.85 → **5.39** | |
| 8 | 5.72 → **3.57** | | 5.99 → **3.84** | | 11.93 → **9.47** | |
| 64 | 13.02 → **11.42** | | 19.78 → **15.41** | | 29.48 → **25.08** | |
| 256 | 29.94 → **26.82** | | 42.21 → 45.27 | | 58.29 → **55.35** | |

Re-read fell from 90% to under 1%. The win is largest where the fold is smallest
— at concurrency 1 the fold halved, because there the re-read *was* the fold
(82% of its time) — which is the opposite shape to every other fix here and a
good check that it is the thing it claims to be.

**A caveat on the fold captions above, found while instrumenting the appends.**
`janus-latency` printed each configuration's `folds …` and `read …` lines where
they were computed, which put them *above* the next configuration's rows — a
caption attached to the wrong table. The defect is fixed (the lines are returned
and printed under the rows they describe), but the "55,882 / 5,333" pair and the
`mean fold` column below were read from output that had it, so their
*concurrency labels* are not guaranteed. The finding does not rest on them: the
90% ratio holds at every concurrency, `decide_pre_release` and `gated_effect`
come from the rows, which were always labelled correctly, and both halves of the
break were watched turning `TestASecondPassDoesNotRereadTheSegment` red. The
correctly-attributed fold figures are the ones in the next section.

**The gated-effect budget now sits on the line at concurrency 64 rather than forty milliseconds past
it.** Eight runs at the same settings have now given 22.11, 23.04, 23.47, 24.09,
25.04, 25.21, 26.40 and 28.14 ms p50 against a 25 ms budget: it straddles, and
the honest statement is that the budget is *marginal* at 64 — met in most runs,
missed in some — rather than met. The list includes the run whose captions were
misplaced, because that defect never touched the budgeted rows, which is the
same argument used to defend the finding above; dropping the worst observation
because it came from an awkward run is how a budget quietly becomes met.
The gate-decision budget passes comfortably throughout.

### Where the remaining 25 ms actually is

Two halves, and until this was instrumented the split between them was an
estimate. `AppendPhases` now counts a caller's time inside `Append` in three
parts — `Prep` (encryption, hashing, any blob offload, on the caller's
goroutine), `Wait` (queued, until the writer starts the group commit carrying
it) and `Barrier` (chaining, writing, flushing, syncing that commit, which every
append in a batch pays in full).

The split is what discriminates between the two designs that could close the gated-effect budget, and
they are opposites. If the time is `Wait`, the single log is saturated and every
caller is queued behind somebody else's commit — an argument for more logs. If
it is `Barrier`, the writer is idle enough and the cost is the barrier itself,
paid once per append — an argument for a saga making fewer sequential appends,
and no argument for more logs at all.

The counters are always on, for the same reason `FoldPhases` is: one that has to
be enabled is one nobody has when they need it. The cost was measured rather
than assumed — `janus-bench`, 64 producers, `sync=none` so the two `time.Now()`
stamps are as exposed as they will ever be: **404k/412k events/s without them,
403k/406k with**. Noise, at eight times the 50k/s floor.

Projection arm, `sync=full`, 300 samples, nine appends per sample (the
`SAGA_BEGIN` plus the eight a gated effect writes).

*(These are the figures as first measured, with nine separate appends. A later
change has since merged two of the nine into two `AppendPair` calls, so a gated saga
makes **seven** calls and the "per sample" column is 7.81 → 6.59 ms at 2000/64.
`AppendPhases` counts calls rather than records for the same reason — a pair's
two records share one barrier and attributing it twice would report the merge as
free. The shape below is unchanged and the conclusions it supports still hold.)*

| bg | conc | mean batch | wait/append | barrier/append | Append per sample | wait share | `gated_effect` p50 |
|---|---|---|---|---|---|---|---|
| 0 | 1 | 1.0 | 0.00 ms | 0.25 ms | 2.34 ms | 1% | 4.66 |
| 0 | 8 | 5.2 | 0.24 ms | 0.32 ms | 5.08 ms | 43% | 8.71 |
| 0 | 64 | 25.1 | 0.40 ms | 0.51 ms | 8.22 ms | 44% | 22.11 |
| 2000 | 1 | 1.0 | 0.00 ms | 0.23 ms | 2.14 ms | 2% | 4.27 |
| 2000 | 8 | 5.9 | 0.21 ms | 0.28 ms | 4.41 ms | 42% | 8.11 |
| 2000 | 64 | 32.8 | 0.41 ms | 0.59 ms | 9.02 ms | 41% | 24.09 |

**The append half is 9 ms of the 24, not 14 — the fold is the larger half, and
the earlier statement here had it backwards.** At 2000/64 the sample spends
9.0 ms in `Append` and about 14 ms waiting on the projection
(`decide_pre_release` p50 13.99 against a 9.89 ms mean fold, which is the ratio
the fold coalescer predicts: half of an in-flight fold plus your own).

(`saga_start` reads 0.00 ms in this sweep where it was 1.7–3.7 ms before. That
is the appender's saga locator arriving, not a broken timer: `ResumeSaga` on a saga the
log has never seen is answered by the Bloom filter without a directory scan. The
run still asserts `COMMITTED` on all 300 sagas, so the work is real.)

**Group commit is absorbing the load rather than buckling under it.** From
concurrency 1 to 64 the per-append cost goes 0.23 → 0.59 ms — 2.6× for 64× the
callers — while the mean batch a caller rides in goes 1.0 → 32.8.

**`Wait` never exceeds `Barrier`, and that is structural rather than lucky.**
`fill` drains the whole queue each cycle and `MaxBatchEvents` is 4096 against 64
producers, so a caller can be at most about one barrier deep by construction.
That makes the wait share a *ceiling*, not an estimate: **more logs could
recover at most 0.41 × 9 ≈ 3.7 ms of the 24**, and only if nothing else changed.

Something else would change. P logs on one device write the same events in P×
more, smaller batches — the same fsync count arithmetic that group commit exists
to avoid, on the same device. That is a hypothesis and not a measurement, but it
points the wrong way, and the measured ceiling of 3.7 ms is already too small to
justify an evidence-format change. **Log partitioning is not a latency fix.** It
remains what the scalability target calls it: a way to add nodes.

What real append saturation looks like is on the same page, in the fallback arm.
`gate.IndexFromLog` at 2000/64 replays the directory for every decision, and the
reads land on the device the writer is syncing to: wait 6.41 ms and barrier
6.69 ms per append, 118.80 ms per sample. The projection arm's 0.41/0.59 is what
the same machine does when the log is not also being read from end to end.

So the bounded candidate, if the gated-effect budget ever has to be comfortably green rather than
marginal, is **fewer sequential barriers per saga** — nine appends × 1.00 ms is
the whole of what such a fix can win, about 9 ms.

**It was built, and two of the nine were available**. Asking at each
of the eight boundaries whether anything reads the first record's `Ref` before
the second is written gives two: each `DPR` and the `GATE_VERDICT` citing it,
which needs the DPR's *event id* and nothing else. The other six are barriers
somebody is entitled to, and the last is circular — a commit carries the root of
the evidence it commits, computed over a log that must already hold the seal.
Measured over three interleaved pairs: **7.81 → 6.59 ms per sample at 2000/64**,
which shows end to end at concurrency 1 (`gated_effect` p50 4.66 → 3.70 median)
and not at 64, where it sits inside the noise of a ~10 ms fold. **The gated-effect budget at
concurrency 64 was marginal before and is marginal after.** The remaining seven
appends are the product: a provenance record is recorded before the verdict it
explains, so a crash leaves a log that says why nothing was decided.

**The fold's own 10 ms is now the larger and less understood half.** Reading is
only 19–23% of it; the rest — decode, apply, the Postgres commit — has never
been decomposed. That is the next seam, and it is not opened here. One
observation while it is fresh: the projection is rebuildable from the log and
refuses below a required sequence, so `synchronous_commit=off` on its
schema may be legitimate in a way it would not be for the log. It would need an
idempotent-refold check first. Recorded as an observation, not a task.

**Five cheap ideas have now been measured and three of them died**: bounded fold
batches (worse), sealed-segment sidecars (5 ms once per process), and the
hot/cold split (not enough). Two worked, and both were about talking rather than
thinking — batching the fold's SQL (~1000 round trips became one) and not
re-reading the open segment (90% of what was read). Together they moved the
ceiling from 8 to 64.

**Partitioning was what was left, and this measurement takes half of it off the
table.** Splitting the *log* is refuted for latency, above. Splitting the
*projector* attacks the right term — but its hard part is not the obvious
one: a frontier gate asks about *other* sagas' touches, so
every partition still has to reach the decision's required sequence before it
can be answered, which is the coalescer's wait re-created across N of them.

**One undeclared default found on the way**, recorded here so it does not
evaporate: `projection.Open` calls `pgxpool.New` and takes whatever pool size
pgx defaults to — `max(4, NumCPU)`, which is 16 on this machine. It is not the
bottleneck today (raising it to 64 changed nothing), but a pool size nobody
chose is exactly the kind of thing that becomes one. It should become an
explicit option with its default written down when the fold work starts.

### What this does not say

**A PASS here is not a claim about the scalability target.** These are single-node figures on a
16-CPU container against a Postgres in another container on the same host. There is no network between the coordinator
and its projection, which flatters the projection rows, and no other tenant on
the machine, which flatters all of them. The target is 10k concurrent sagas
per node; the sweep above reaches 256, is marginal at 64 and fails above it. The
gap between those is not interpolated anywhere in this document, and the shape of what was found is the
reason not to: **every one of the three defects appeared only above concurrency
1 or above an empty log**, and none was visible by reading the code. The honest
reading of a PASS at 8 is that the budgets are met at 8, and that the next
measurement should be at a concurrency nobody has tried.

A darwin run is not a substitute. `sync=full` on APFS is `F_FULLFSYNC`, a
device-wide barrier that costs 8–16 ms and is not what a deployment pays; the
same lesson as the Phase 0 spike above. `make latency-linux` is the gate.

## Phase 7: where the fold's other four-fifths go

Reading was fixed and stopped being the story. What replaced it was a single
unattributed lump: `FoldPhases` reported `Read`, and at the reference scale that
was about a fifth of a fold. **The other four-fifths were the largest
undecomposed term in the only budget Janus is marginal against** — the 25 ms
gated effect — so "what should be optimised next" was not a question anybody
could answer with a number.

This section is the answer, and its value is mostly in what it **rules out**.

**Reference scale:** `make latency-linux` with `-background 2000 -concurrency 64
-sync full`, six runs, Linux container against the compose Postgres on the same
host. Concurrency 64 is chosen because it is where the gated-effect budget straddles; the split moves
with load and the trend is given below.

### The decomposition

`Read` is framing, header decode, payload hashing and chain recomputation.
`Apply` is the state machines — `saga.Apply`, `outbox.Apply`, and the recovery
read for a saga the working set no longer holds. `Commit` is `Begin` through
`Commit`. `other` is the residual: set-up, `warm`, `loadRegistryEvents`, and the
coalescer lock.

`Total` is measured around the whole fold rather than around the three stages,
so the parts are checked against the whole. A decomposition whose parts sum to
100% of a number smaller than what a caller actually waits for is arithmetically
tidy and operationally wrong.

| run | mean fold | read | apply | commit | other |
|---|---|---|---|---|---|
| 1 | 8.50 ms | 1.84 (22%) | 0.77 (9%) | **5.09 (60%)** | 0.80 (9%) |
| 2 | 9.57 ms | 2.24 (23%) | 0.95 (10%) | **5.99 (63%)** | 0.39 (4%) |
| 3 | 8.91 ms | 1.98 (22%) | 0.82 (9%) | **5.74 (64%)** | 0.38 (4%) |
| 4 | 10.62 ms | 2.01 (19%) | 0.96 (9%) | **6.07 (57%)** | 1.58 (15%) |
| 5 | 9.46 ms | 2.09 (22%) | 1.02 (11%) | **5.85 (62%)** | 0.51 (5%) |
| 6 | 9.45 ms | 1.72 (18%) | 0.95 (10%) | **5.47 (58%)** | 1.30 (14%) |

**The fold is commit-dominated: 57–64%.** Read is 18–23% with under 1% re-read —
the offset-resume work took what was there. Apply is 9–11%.

### What this rules out, and it is most of the candidates

**The Go-side work is refuted.** `Apply` is 0.77–1.02 ms of a 8.5–10.6 ms fold.
Optimising the state machines wins at most a tenth of a fold, and a decision
waits between one and two whole folds. There is no version of that work that
moves the gated-effect budget.

**Durability trades are refuted, and this is the one worth having measured.**
The obvious next move on a commit-dominated fold is to give up a guarantee:
`synchronous_commit = off`, or an unlogged table for something the design already
says is rebuildable from the log. So `Commit` is split into the statements and
the barrier — `tx.Commit` alone:

| run | commit | statements | barrier |
|---|---|---|---|
| 1 | 5.09 ms | 4.85 (95%) | **0.24 (5%)** |
| 2 | 5.99 ms | 5.77 (96%) | **0.21 (4%)** |
| 3 | 5.74 ms | 5.50 (96%) | **0.23 (4%)** |
| 4 | 6.07 ms | 5.77 (95%) | **0.29 (5%)** |
| 5 | 5.85 ms | 5.62 (96%) | **0.23 (4%)** |
| 6 | 5.47 ms | 5.22 (95%) | **0.25 (5%)** |

**The durability barrier is 0.21–0.29 ms — under 3% of the fold.** Trading a
guarantee buys a quarter of a millisecond. It is not close, and without this
measurement it is exactly the change a reasonable person would have made first.

**The round trip is not the cost either.** The statements are *already* one
batch — `pgx.Batch`, one round trip, the 3× win recorded above. Counting them:

| run | statements | per fold | each |
|---|---|---|---|
| 4 | 3,803 | 380.3 | 15 µs |
| 5 | 3,508 | 389.8 | 14 µs |
| 6 | 3,843 | 349.4 | 15 µs |

**~380–420 statements per fold at 14–15 µs each, inside a single round trip.**
That is per-statement server work — parse, plan, execute — not network. Which
leaves two levers rather than one, and it is worth being precise about that:
**fewer statements**, or **fewer and larger ones** (a multi-row
`INSERT ... VALUES (…),(…)` for the step and touch rows, or `COPY`, collapsing
hundreds of parse/plan/execute cycles into a handful). The second is ordinary
engineering; the first is structural.

### Which statements, and it is not the ones anyone assumed

`queueSaga` issues four families, per saga a fold touched: one upsert of the
saga row, two `DELETE`s clearing its steps and touches, then one insert per step
and one per touch. Counted separately, three runs, identical to the point:

| family | share of statements |
|---|---|
| saga upsert | 20% |
| **`DELETE` steps + touches** | **40%** |
| step inserts | 20% |
| touch inserts | 19% |

**The two `DELETE`s are the largest family — twice the step inserts they exist
to make room for.** They are two statements per touched saga regardless of what
that saga contains, and at this scale a saga averages about 1.4 step and touch
rows between them. So 60% of the commit's statements are per-saga overhead and
39% are the rows anyone would say the projection is for.

That reframes the delete-and-rewrite pattern. It is not merely that the fold
rewrites each touched saga's step set from scratch — it is that *clearing* costs
more than *writing*, and it costs the same whether the saga has one step or ten.

**And it corrects the prior this section was about to hand the next person.**
The hot/cold experiment above measured *not writing `steps` at all* and found the gated-effect budget
still failing at concurrency 64 (26.38 vs 25), which reads as "the structural
lever is not enough either". Against these counts it does not: the step inserts
are 20% of statements, so that experiment removed about a fifth of them and
moved the gated-effect figure by roughly what a linear prediction would give. **It is not evidence
against the lever, and it was taken before offset-resume landed in any case.**

So the standing question is open, not closed, and the cheapest thing that would
answer it is the `DELETE` family — the largest, the least examined, and the one
whose removal changes no row the console reads.

> **Answered, in the negative — see "Phase 7: what happens above concurrency 64"
> at the end of this file.** The steps half was built and measured as a wash. The
> family is still 40% of statements, but at concurrency 256 removing *all* of it
> is worth 8.4–16.8 ms against a 40.9 ms gap. This paragraph is left standing
> because it was the honest reading at the time; do not act on it.

### The gated-effect budget at the reference scale, fourteen runs today

`gated_effect` p50 against 25 ms: 22.70, 22.94, 23.72, 24.11, 24.24, 24.34,
24.42, 25.14, 25.59, 25.66, 25.68, 25.73, 26.57, 26.77. Median 24.8; seven of
fourteen over budget.

**Marginal at saturation, unchanged.** Not a regression against the 22.1–28.1
recorded when the offset-resume work landed, and not a clean pass either. The
budget names no concurrency — the 10k-saga figure is a separate target — so the
honest record remains *met at 32, marginal at 64*.

### The steps `DELETE` is not cheaply removable — measured, reverted

The section above names the `DELETE` family as the only lever with headroom, so
the obvious next move is to remove one. Half of it can be removed on an
argument: `steps` is keyed on `(saga_id, step_id)`, a saga's step set is fixed at
`SAGA_BEGIN` — `applyBegin` is the only place `State.Steps` and `State.Order` are
assigned, and nothing removes from either — so `DELETE FROM steps` was clearing
rows about to be reinserted under the same keys, and an
`ON CONFLICT (saga_id, step_id) DO UPDATE` does the same work in one statement.

It was built and measured. **Three interleaved pairs**, baseline and treatment
alternating on the same machine in one sitting, because the earlier baseline was
an hour old and the expected effect is a fraction of the run-to-run spread:

| pair | statements/fold | µs each | statement time | `gated_effect` p50 |
|---|---|---|---|---|
| 1 base | 381.9 | 14 | 5.46 ms | 24.94 |
| 1 treat | 325.5 | 16 | **5.34 ms** | 23.00 |
| 2 base | 376.9 | 14 | 5.36 ms | 24.38 |
| 2 treat | 315.9 | 16 | **4.95 ms** | 21.37 |
| 3 base | 370.8 | 14 | 5.36 ms | 24.40 |
| 3 treat | 346.8 | 16 | **5.45 ms** | 25.43 |

**Statement time: −0.12, −0.41, +0.09 ms. Mean −0.15 ms** on a ~5.4 ms statement
time and a ~9.5 ms fold — 1.5% of a fold, with one pair going the wrong way.
Pair 3's treatment run stalled (p99 156.60 ms against ~29 elsewhere, barrier
0.93 ms against ~0.23) and excluding it gives −0.27 ms. **Both means are under
the 0.3 ms threshold set before the data was seen**, and both are reported
because discarding an inconvenient run after seeing it is the thing pairing
exists to prevent.

**Statement count is not statement cost.** The count fell 15% and the time did
not, because the mix moved: the `DELETE`s removed were the *cheapest* statements
in the batch — `DELETE … WHERE saga_id = $1` with an index hit and usually
nothing to remove — and the plain `INSERT`s became upserts, which add a conflict
probe. 14 → 16 µs is those two effects. A count is a mechanism explanation; the
time is the number.

**The `gated_effect` column is noise, and it is worth saying how that is known
rather than asserted.** Two pairs improved by 1.9 and 3.0 ms. A decision waits
between 1.16 and 1.89 folds, so 0.15 ms of fold time can move `gated_effect` by
at most about 0.3 ms. **A downstream delta larger than the upstream delta can
transmit is not the change; it is the spread** — measured at ±2 ms on this figure
today. The same test applied to the earlier `pgx.Batch` work passes easily:
53.80 → 17.46 ms is far outside any spread this harness produces.

**Reverted, and the null result is not the only reason.** The upsert makes the
correctness of `steps` rows depend on "a step set never shrinks" — an invariant
that holds today because `applyBegin` happens to be the only writer, and that
nothing else in the codebase is told about. Delete-and-rewrite needs no
invariant. Trading robustness for 1.5% of a fold that cannot be seen above the
noise is a bad trade, and it would be a bad trade even if the 1.5% were real.

**What this does and does not settle.** It settles that the *steps* half is not
cheaply removable. It does not settle that the `DELETE` family is the wrong
target — the family is still 40% of the commit's statements and still the only
lever with headroom. The touches half would need a schema change:
`resource_touches` has no primary key on purpose, so an upsert needs a conflict
target, and the candidate is a `(saga_id, step_id, ordinal)` key exploiting the
fact that touch lists are append-only and so ordinals are stable. That is an
`ALTER TABLE`, a fingerprint bump and a rebuild on upgrade (the forward-migration path) for
a predicted ceiling of the same ~0.4 ms. **On these numbers latency does not
justify it**, and it would need a different reason.

`TestATouchListIsStillClearedBeforeItIsRewritten` now guards that `DELETE`,
because the "40%" finding above reads as an invitation to remove it and nothing
on the real path would have noticed the duplicates it prevents.

## Phase 7: what happens above concurrency 64 — and the run that had to be thrown away

Every budget in this file that mentions a concurrency stops at 64. The scalability target is
**10k concurrent sagas per node**, and the gap between those two numbers has
never been interpolated here on purpose. This is the first measurement inside it.

**The headline: the gate-decision budget holds at 64 and fails at 256, and the
gated-effect budget fails at 256 by between 2.5× and 3.2×.** The fold cannot close that, and the arithmetic for why
is below.

### The first three attempts measured something else, and nothing in the output said so

Worth recording before the numbers, because the failure is reproducible and the
next person will otherwise repeat it.

A sweep at `-samples 300 -concurrency 64,256,1024` returned a clean, plausible
story: `gated_effect` p50 of 26.62 → 50.67 → 64.69 ms, a **16× rise in
concurrency for 2.4× the latency**, with the gate-decision p99 flat around 53. It was wrong.

`janus-latency`'s drivers share one counter over `-samples` tasks, so **a slot
that finds the counter exhausted exits without ever running**. At `-concurrency
1024 -samples 300`, 724 of the 1024 slots did exactly that: the run measured 300
drivers, in a single burst, under a column that said 1024. At 256 every slot ran,
but only 1.17 times each — enough to start, not enough to reach steady state.

**The only tell was the fold count**, which fell 10 → 3 → 2 as the "concurrency"
rose. Every other column looked ordinary.

That tell is a rule rather than a coincidence, and it is worth carrying: folds =
events ÷ events-per-fold, and events-per-fold rises with the number of drivers
appending between folds. It checks out on every run here — burst 2544/254.4 = 10
and 1520/760.0 = 2; sustained 6762/281.8 = 24 and 6037/1006.2 = 6. **A fold count
in the low single digits at high concurrency means the run was a burst.** A measurement of a different thing is
not a slow measurement, and this one was indistinguishable from the real one.

**And the burst did not merely mislabel itself — it flattered the system.** At
the same concurrency 64, going from a 300-sample burst to a 3072-sample sustained
run moved the fallback `gated_effect` p50 from 1,263 to **2,105 ms**, and the
mean append batch from 12.9 to **5.8**. When every driver arrives at once, their
appends coincide and group commit batches them; under sustained arrival they
spread out and each pays more. So the discarded numbers were optimistic as well
as mislabelled.

`sustained()` in `cmd/janus-latency/main.go` now refuses any configuration giving
fewer than three samples per slot, in the same posture as the pool check beside
it, with `TestAConcurrencyColumnDescribesWhatWasMeasured` pinning both failure
shapes and the two configurations already in use.

### What could not be measured, and why it is stated rather than estimated

**Concurrency 1024 sustained needs `-samples 3072`, and that run was OOM-killed**
(exit 137) on a 16 GiB machine after completing one point. 3072 samples against a
2000-saga background does not fit. That is a real part of the answer to "why has
nobody taken this number": the honest form of the experiment does not run on this
hardware. **Nothing here extrapolates past 256**, and the 10k-saga target is about 40× beyond a
point that could not be reached — five to six further doublings, not the four an
earlier version of this sentence said.

### The measurement

Three runs, `-samples 768 -background 2000 -resources 4096 -sync full`, on linux
in a container against the compose Postgres. 768 samples is 12 per slot at 64 and
exactly 3 at 256; fold counts of 24–25 and 6–7 confirm sustained load rather than
a burst. The resource pool is 4096 rather than the reference scale's 256, so the
64 column here is **not** the same 64 as the Phase 6 gate's. Less contention for
resources should make it read *easier*, not harder; that it reads 24.61–25.97
against the gate's 23.50 the same morning — both inside the historical
22.70–26.77 band — is consistent with frontier contention not being the term that
matters at 64.

| | concurrency 64 | concurrency 256 |
|---|---|---|
| **Gated effect** `gated_effect` p50 (≤ 25 ms) | 25.74, 24.61, 25.97 — **median 25.74** | 81.05, 63.51, 65.90 — **median 65.90** |
| | *marginal, straddles the budget* | **FAIL, 2.5–3.2×** |
| **Gate decision** `decide_pre_release` p99 (≤ 50 ms) | 20.30, 22.97, 19.88 — **median 20.30** | 73.34, 59.23, 55.87 — **median 59.23** |
| | **PASS**, 2.2× inside | **FAIL** on all three |
| mean fold | 11.78 ms | 31.97 ms |
| events per fold | ≈ 279 | ≈ 954 |
| per-event fold cost | 0.0398–0.0442 ms | 0.0332–0.0341 ms |

**Read the spread before the medians.** At 256 the runs vary 25% on the gated effect and 28% on
the gate decision — three samples of a noisy quantity, and every one of the six fails its
budget, which is what makes the verdict safe despite the spread. At 64 the gated-effect
spread is 5% and it straddles 25: two runs over, one under. **Marginal at 64 is
unchanged**, and consistent with the 22.70–26.77 recorded at the reference scale.

**The system is not falling over.** Per-event fold cost *falls* from 0.0398–0.0442
to 0.0332–0.0341 ms as concurrency quadruples — the fold amortises better under
load, exactly as it did between 1 and 64. `decide_pre_execution` stays at 0.01 ms
p50. What grows is fold *duration* (11.78 → 31.97 ms) because each fold carries
3.4× the events, and a decision waits for one or two whole folds.

### Why the `DELETE` family cannot close this, stated as arithmetic

The section above leaves the `DELETE` family named as "the only lever with
headroom". It still is, and at 256 it is now measurably too small to matter.

At concurrency 256 the gated-effect gap is **65.90 − 25 = 40.9 ms**. Against that:

| | |
|---|---|
| the whole fold | 31.97 ms |
| its commit phase | ≈ 21 ms, of which statements ≈ 20.5 ms |
| `clear` — both `DELETE`s — at 40–42% of statements | **≈ 8.4 ms per fold** |
| a decision waits 1–2 folds, so removing it is worth | **8.4 – 16.8 ms** |

**Against a 40.9 ms gap.** Removing the entire `DELETE` family — both halves,
including the touches schema change this file predicted at ~0.4 ms at the
reference scale — closes at most 41% of it, and that is the ceiling rather than
the estimate.

**How far the fold could go even in principle, stated carefully because the
obvious stronger sentence is wrong.** Removing the *entire commit phase* — all
≈21 ms of it, statements and barrier — is worth 21–42 ms at one to two folds
waited, which **brackets** the 40.9 ms gap: it misses at the one-fold end and
barely closes at the two-fold end. So the most aggressive change anyone could
make to the fold is, at 256, a coin flip against this budget rather than a fix.
**At concurrency 64 the same arithmetic goes the other way** — commit is ≈6.8 ms
of an 11.78 ms fold, worth 6.8–13.7 ms against a 0.74 ms gap — which is why
the gated-effect budget at 64 is *marginal* and at 256 is *out of reach*. The two are not the same
problem at different sizes.

**So the touches schema change should not be built for latency.** The steps half
was already measured as a wash and reverted; this retires the other half for the
same purpose. The family is still 40% of statements, and that is now a fact about
the fold's shape rather than an open lever.

### What is actually left

Two routes. One of them is now measured, and the measurement constrains its
shape rather than choosing it:

- **The frontier decision stops waiting for a whole fold.** Every
  `decide_pre_release` sample pays a synchronous catch-up because the reference
  policy's FRONTIER requirement sits at PRE_RELEASE, immediately after the step's
  own result is appended — which the projection cannot already contain. The cost
  scales with fold duration, and fold duration scales with load. **Measured
  below; the naive form does not survive it.**
- **Adding nodes**, which is what the scalability target itself calls for:
  horizontal partitioning by saga-id, with 10k concurrent sagas per node as a
  **class target**. A single node meeting the gated-effect budget at 64 and missing it at 256 is a sizing input, not a defect, if partitioning
  exists. It does not exist.

Neither is built.

### The tail a decision would have to read, measured

The first route turns on one quantity nobody had taken: the **tail**, meaning
`log head − folded head` at the moment a decision asks. That is what a decision
would have to read and account for itself if it stopped waiting.
`Projector.FoldedThrough` reports the folded head and the harness prints the gap
as `tail at decision time`, beside the fold phases.

| | tail p50 | tail p99 | decisions per fold | records decoded vs folded |
|---|---|---|---|---|
| concurrency 64, three runs | 490 / 558 / 452 | **574 / 576 / 547** | 33 / 55 / 30 | **51–65×** |
| concurrency 256 | 1356 | **2284** | 128 | **221×** |

*(The `max 18005` both rows report is the first decision's cold catch-up over the
whole seeded log, not a tail.)*

**The multiplier is the result, and it is structural.** A fold reads the tail
once and every waiter shares it; a decision that reads its own tail does that
work again for each decision. At 256 that is 769 decisions × ~1713 records ≈
1.3M decodes against the 5,973 the folds actually performed. The tail is the
records written per fold interval and the decisions in that interval are roughly
that tail divided by the records a saga writes — 1713/9 ≈ 190 against 128
measured — so **the duplication is proportional to the tail, and the tail grows
with load**, worse exactly where the budget already fails.

Read plus apply is 0.0057 + 0.0041 ≈ 0.01 ms/event from the fold's own phases at
256, so a per-decision replay is 4.4–5.5 ms at 64 and 16.8 ms at 256 — cheap per
decision, which is what makes the route look attractive. Across the decisions
sharing one fold interval it is **132–301 ms of CPU at 64 and 2.15 s at 256**,
roughly 8–19 ms and 135 ms of wall time on sixteen cores, against fold waits of
~15–17 ms and ~52 ms. Marginal at 64 and losing by 2.6× at 256.

Which half of that carries the weight matters. The per-event constant decides
the comparison at a given load; the duplication decides how it moves with load,
and only the second is structural. At a tenth of the measured constant the 256
case would *win* by about 4×. What does not change is that the duplication went
51–65× → 221× for a 4× rise in concurrency, and the 10k-saga target is about 40× beyond
256.

**So the constraint, not a retirement:** the cost is not the tail, it is reading
the tail N times. A viable version reads it once and shares it, which is a fold
without Postgres rather than a decision without a fold. The named unknown is
merging a saga that is RUNNING at the projection
head and COMMITTED in the tail.

**One run was thrown out of the fold table and kept in the record.** A
concurrency-64 run reported a 38.45 ms mean fold at 77% read against the 19–23%
recorded above. Its `decide_pre_release` p95/p99/p999 were 654.68/655.26/655.28 —
three percentiles within 0.6 ms, which is one stall of about 650 ms across ~38
decisions rather than a property of the fold. Two further runs put the fold back
at 10.55 and 12.22 ms with read at 29% and 25%. The tail numbers from all three
agree to within 100 records, which is why the table above keeps them.
