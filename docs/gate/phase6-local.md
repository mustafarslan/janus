# Phase 6: the local equivalent of the exit gate

**This is the local equivalent of the Phase 6 exit gate. It is not the gate.**

The gate is:

> load test at 10× design-partner peak with SLOs held; region-failover game day;
> replay sampling in prod design partner ≥ 99.99% deterministic.

There is no design partner, so there is no peak to multiply and no production to
sample. There is no second region, so there is nothing to fail over *from*. Those
are not formalities to be worked around; they are the difference between a claim
about a deployment and a claim about a repository.

What follows is the strongest thing this repository can show for each leg, with
what it is and what it is not stated for every one. `make phase6-local` runs all
three and writes `phase6-local.json` beside this file.

---

## Leg 1 — a load test at a stated reference scale

**Is:** the decision path measured at concurrency 64, 2,000 background sagas,
300 samples, `sync=full`, on Linux against a real Postgres.
**Is not:** ten times a design partner's peak. Nobody's peak is known.

The scale is *stated* rather than implied, and it is deliberately the awkward
one: concurrency 64 is where the 25 ms gated-effect budget is marginal.
Running at 8 would have been choosing a number that passes.

| | |
|---|---|
| `gated_effect` p50 | **22.98 ms** against the 25 ms budget |
| `decide_pre_release` p99 | 19.88 ms against the 50 ms budget |

**The gated-effect budget is marginal at this concurrency, not met**, and one
green run does not change that. Nine runs now span **22.1–28.4 ms** against a 25 ms budget: most are
inside it and some are not. The honest record is *met through concurrency 32,
marginal at saturation* — quoting the 22.98 alone would be the "control that
reads as working" this project exists to prevent. The gate-decision budget
passes comfortably throughout.

The fallback index (`gate.IndexFromLog`, for a deployment with no projection
database) is 1,199 ms at this scale and is reported rather than gated: it is
O(log) by construction.

## Leg 2 — a failover drill

**Is:** a primary SIGKILLed mid-work, its replica promoted, on one host.
**Is not:** a region failover. The disk survives the kill, so the primary's own
log is still there — a luxury a lost region does not offer.

| | |
|---|---|
| RTO | **159 ms**, kill → first successful *append* |
| RPO violations | **0 of 40** acknowledged calls at steady state |
| Continuity | the promoted log verifies from the **original** writer's key alone |

RTO **excludes** the operator deciding and the clients being redirected. At 159 ms
against the 300,000 ms RTO the machine is not the constraint — the operator is,
and that time is not measured here by anyone honest.

The RPO figure is zero *at steady state*. Killed mid-stream at a 300 ms follower
interval it is **one in forty**, which is not a defect: it is the documented exposure,
that cross-region RPO is the replication lag rather than zero. `SETTLE=0` on the
drill measures it.

`docs/runbooks/failover.md` marks **three of its nine steps `UNEXERCISED`** —
deciding, redirecting clients, and reconciling against the archive.

## Leg 3 — replay sampling

**Is:** every completed saga the chaos suites produced, re-derived from its log.
**Is not:** sampling in a design partner's production, which is what the gate
asks for.

| | |
|---|---|
| Sagas checked | **327 of 327** |
| Rate | **100.0000%** |

The corpus is the right one for the claim: every saga in it was killed and
resumed at least once, so a divergence here would be a divergence in exactly the
histories where it matters — the ones that were reconstructed rather than merely
written. It is still this repository's logs and not a bank's.

What is missing: spot-replay checks
*everything* rather than sampling, which is right at this size and wrong at a
few thousand sagas a second. A sampling policy wants a load profile to design
against.

---

## What Phase 6 does not have, stated here rather than left to be discovered

- **The gate itself**, for the reasons above. Phase 5's could not be produced
  here either, and Phase 7's cannot be: three consecutive phases end in a
  criterion that needs somebody outside this repository. That is a property of
  how the phases are defined, not a failure of the work, and it should be argued with rather than
  quietly satisfied.
- ~~**An observation of what a promoted writer does with an adopted commit.**~~
  **Closed.** It was observed, and then decided. A promoted daemon
  *does* release on a commit no client was told about, because
  `outbox.LogAuthority` asks only whether the saga is COMMITTED. It is left that
  way — the log is the authority, and an outbox refusing a commit the log
  contains would strand a COMMITTED saga with an effect that can never fire.
  `TestAnAdoptedCommitAuthorisesARelease` keeps it visible: it fails if the
  behaviour ever changes.
- ~~**Cross-log fork attribution.**~~ **Closed.** `CompareLogs` and
  `janus-replicad compare` name where two directories stopped agreeing, how far
  each went, and which side records a promotion — and say plainly that they
  cannot say which is right. `FORK=1 make failover` creates the split-brain for
  real. Nothing *prevents* two writers and nothing here claims to; the fence
  stays deferred.
- **The tenure lease that would prevent a fork rather than name one.** Probed
  against MinIO and buildable — `If-None-Match: *` is enforced — and deferred,
  because its expensive half puts an object-store liveness dependency in the
  append path.
- **Any measurement above concurrency 64.** The target is 10k concurrent
  sagas per node; c=64 saturation is roughly 2,300 sagas/s. The gap is not
  interpolated anywhere, and the reason not to is that **every defect this phase
  found appeared only above the concurrency somebody had previously tried**.
