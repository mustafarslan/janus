# The revalidation cadence

How long a participant's evaluation stays good for before the registry asks for
a fresh one.

```
janus-orchd -revalidation docs/compliance/revalidation.json
```

## Why this is deployment configuration and not a manifest field

A quarterly model review is an expectation a regulator places on an
**institution**, not on a piece of software. The compliance
packs are shaped around that, and so is this: the cadence is keyed by risk tier,
which is the same axis a supervisor uses to say how much scrutiny a model owes.

It also survives what actually happens to a model inventory. A bank re-tiers a
model after an incident, and every schedule that depended on that tier moves
with it — without a single manifest being reissued, and without a migration.

## A manifest may tighten it, never loosen it

`risk.revalidate_after_days` on a manifest is optional. When it is shorter than
the tier's cadence it wins; when it is longer it is ignored.

A vendor can know something the tier does not — a model that drifts in weeks
should not sit on a yearly schedule because its tier permits one. What a vendor
must not be able to do is excuse itself from the institution's floor.

**The shorter of the two is taken when the schedule is computed**, not checked
at registration. That is what makes a re-tiering self-correcting: a manifest
registered under tier 3 and later re-tiered to 1 comes onto the 90-day schedule
immediately, with nothing reissued and nothing to remember.

## The default is to schedule nothing

A tier with no entry here has no periodic schedule, and no cadence file at all
means no participant does. That is deliberate. A guessed default would be a
control that reads as configured and is not — the failure mode this project
exists to prevent — and "nothing was scheduled" is visible in a way that "we
assumed a year" is not.

The file below is the reference, not a recommendation. What the numbers should
be for a given institution is a supervisory question, and the file is where that
answer goes.

| Tier | Days | Reading |
|---|---|---|
| 1 | 90 | highest risk: quarterly |
| 2 | 180 | half-yearly |
| 3 | 365 | annual |
| 4 | *absent* | not on a calendar; changes still trigger revalidation |

Tier 4 is left out on purpose, to make the point that absence is a real setting.
A tier-4 participant still revalidates when its model, actions or limits change
— those triggers are change-driven and derived from the log, and nothing here
affects them.

## What it does when a review comes due

`janus-orchd`'s ticker appends a `KIND_REVALIDATION_REQUIRED` naming the
`periodic` trigger. The version then owes a revalidation, which the registry
already refuses to activate over, and the debt is visible in
`janus-registry inventory`.

**It does not suspend anything.** A scheduler that suspended an ACTIVE
participant on a calendar would stop a production workflow because a review is
overdue, and whether that is the right response is a policy decision belonging
in a compliance pack rather than in the registry. The current semantics are the
conservative half: the debt is recorded and visible, and it blocks the *next*
activation.
