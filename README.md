# Janus

[![arXiv](https://img.shields.io/badge/arXiv-2609.38266-b31b1b.svg)](https://arxiv.org/abs/2609.38266)

**A transactional evidence layer for agentic AI.**

Janus sits between AI agents and the systems they act on, and makes every action
they take a recorded, replayable, tamper-evident transaction: sagas with
compensation for the work, signed manifests for the participants, and a
hash-chained log that answers what happened, when, with what result, and why.

It is not another agent framework. LangGraph, AutoGen, CrewAI, Temporal
workflows, and bespoke agents become *Janus participants* through thin adapters.
Frameworks compete on capability; Janus is the neutral record of what happened
and the machinery to undo it.

The wire vocabulary is specified in [`docs/spec/`](docs/spec/), the measurements
behind every claim below are in [`docs/bench/README.md`](docs/bench/README.md),
and the security posture and known gaps are in [`SECURITY.md`](SECURITY.md).

---

## Status

Janus is a research system: one author, no production deployments. The
design and its evaluation, including a real-model experiment, are in
[`paper/`](paper/); every measurement is in
[`docs/bench/README.md`](docs/bench/README.md), and the model runs, with their
signed logs and public keys, are under [`docs/bench/agentic/`](docs/bench/agentic/).

What works today:

| | |
|---|---|
| **Evidence log** | Append-only segments, deterministic CBOR envelopes, BLAKE3 hash chain, RFC 6962 Merkle roots, Ed25519 segment signatures, group commit, crash recovery |
| **Saga engine** | Pure state machine, DAG scheduling, retry budgets, compensation in reverse topological order, sub-sagas, cross-saga frontier safety, replay |
| **Gates** | Policy resolved at admission and pinned into the saga; schema, expression, risk-limit, frontier, independent-validator and human-approval checks, decided before a step runs and before its effect is released; every verdict re-derivable from the log alone |
| **Four eyes** | Approvals arrive as recorded events; separation of duty is enforced from the log, quorums need distinct people, and a self-approval is refused rather than waited past |
| **Outbox** | Irreversible effects held until the saga commits, released at-least-once under a stable idempotency key, with a truthful attempt count |
| **Verifier** | `janus-verify`: a static binary that checks a log or bundle offline with no Janus service and no network |
| **MCP interception** | `janus-mcpd`: an unmodified MCP tool server, fronted, with every message recorded before it is forwarded |
| **Console** | `janus-console`: saga topology, the queue of what is waiting for a person, and evidence search — a view that holds nothing and decides nothing, read-only until an authenticating layer says who is approving |
| **Registry** | Signed participant manifests with a lifecycle in the log; conformance tests that make a participant demonstrate its declared undo before the claim can be activated; version pinning that cannot be edited under the same name; change events that trigger revalidation |
| **Bundles** | Exportable evidence with Merkle inclusion proofs for a chosen saga |
| **Fault injection** | Disk-full, torn-write, sync-failure and device-death drills through the same seam production uses |
| **Chaos soak** | `janus-soak` kills the writer with SIGKILL on a loop and requires the chain to survive every time |
| **Property tests** | Seeded random histories; a failure prints one number that reproduces it |
| **Payload offload** | Large bodies move to a content-addressed store; the chain still commits to their hash |
| **WORM tier** | Sealed segments archived under S3 Object Lock in compliance mode, with a drill that proves the store refuses to destroy them |
| **Retention** | Schedules as reviewable data, scoped legal holds, disposal recorded as evidence |
| **Crypto-shredding** | Erasure by destroying a per-subject key; the chain commits to ciphertext so nothing survives to fingerprint the erased content |
| **Clock attestation** | SNTP-backed statements about the clock that timestamped the evidence, recorded in the log |
| **Continuous verifier** | Incremental checks on new segments plus a rolling full sweep over history, with an alert on divergence |

What is not built is listed under [Known gaps](#known-gaps) and in [`SECURITY.md`](SECURITY.md).

## Quick start

```bash
make build      # compile everything into bin/
make test       # full suite under the race detector
make skeleton   # the Phase 0 exit gate, end to end
make spike-mcp  # MCP interception against a real subprocess tool server
make bench      # the evidence append benchmark, swept over concurrency
make soak       # chaos: SIGKILL the writer on a loop, verify after every kill
make sagachaos  # chaos: SIGKILL a coordinator at every saga state, resume, compare
make corpus     # replay every recorded saga history (replay determinism)
make policy     # validate the reference gate policy and print its content address
make registry   # register a participant, evaluate it, activate it, change it, audit it
make console EVIDENCE=./janus-evidence   # serve the operator view over a log
make property   # seeded crash-recovery property tests
make dev        # local stack: postgres, and minio with an object-lock bucket
make test-storage  # object-storage and WORM tests against the local stack
```

`make skeleton` runs a saga, replays it from the log and asserts the projection
is identical, exports a bundle, verifies that bundle the way an auditor would,
then flips one byte and confirms the same verifier rejects it.

## Verifying evidence

The verifier is meant to be run by someone who does not trust the system that
produced the log, so it takes the trusted keys separately from the artifact:

```bash
janus-keys pub keys/writer.key > writer-keys.json     # hand this over separately
janus-verify -keys writer-keys.json ./evidence        # PASS or FAIL, with reasons
janus-verify -keys writer-keys.json -list ./evidence  # every event and its labels
```

Without `-keys` a bundle is checked against the keys it carries, which proves it
is internally consistent and nothing more. The report says so rather than
printing a bare PASS.

## Layout

```
proto/janus/v1/      JTP wire vocabulary and the DPR schema
pkg/evidence/        the append path: envelope, chain, segments, keys, bundles, verifier
pkg/saga/            saga state machine (pure), runner, replay
pkg/evidence/cas/    content-addressed store for payloads too large for the chain
pkg/evidence/worm/   write-once archive tier on S3 Object Lock
pkg/evidence/retention/  retention schedules, legal holds, evidenced disposal
pkg/evidence/crypto/     crypto-shredding: per-subject keys, erasure by key destruction
pkg/evidence/clockatt/   clock attestation records
pkg/evidence/continuous/ background re-verification
pkg/gate/            gate policy, admission, the six checks, and the decision audit
pkg/outbox/          irreversible effects held until commit, released once
pkg/registry/        participant manifests, lifecycle, conformance harness, pin audit
pkg/console/         the operator view: topology, the human queue, evidence search
pkg/mcp/             MCP interception proxy and a toy tool server
cmd/                 janus-{bench,verify,skeleton,mcpd,toytool,keys,soak,tier,sagachaos,gate,registry,console}
docs/bench/          gate measurements
docs/compliance/     DPIA input for crypto-shredding
docs/policy/         the reference gate policy
docs/registry/       reference manifests and the sandbox doubles they are evaluated against
sdk/                 the Python SDK, and TypeScript stubs
```

## Design commitments

Four decisions shape everything else.

**The log is the system of record**. Projections are derived and
rebuildable. Two authoritative stores would eventually disagree, and when an
auditor asked which was right there would be no principled answer.

**Evidence before effect**. A side effect is released only after the
evidence describing it is durably chained. Acting first and logging second is
unauditable on crash — the world changed and nothing says so.

**Interception, not reimplementation**. Onboarding an existing MCP
tool server is a command-line change. A bank with working agents will not
re-platform them to gain auditability; it will decline the auditability.

**Fail closed**. If evidence cannot be written, gated effects do not
fire. An agent that keeps acting with the audit trail down produces exactly the
state a regulated institution cannot defend.

## How the durability claim is tested

`make soak` runs the writer under repeated `SIGKILL` and, after each one,
recovers the log, verifies every hash and signature, and checks that **every
sequence number the appender acknowledged is still there**. That last property
is the one that matters: an acknowledgement is the system telling a caller it
may release a side effect, so losing one afterwards would mean an effect backed
by evidence that no longer exists. A 45-second run survives roughly 30 kills and
180,000 events.

`make property` generates random histories — batch sizes, segment sizes,
producer counts, and injected storage faults — and asserts the same invariants.
It found three real recovery bugs during Phase 1, each now pinned as a seed in
`regressionSeeds` so it can never come back unnoticed.

## How the transaction claim is tested

Surviving a crash and *finishing correctly* after one are different properties,
and the second is the Phase 2 exit gate. `make sagachaos` asserts it in the
strongest form available:

> A saga's outcome does not depend on how many times its coordinator died.

It runs each scenario once, uninterrupted, to establish the outcome. Then it
runs it again for every transition in it — sending a real `SIGKILL` after the
first, after the second, and so on — restarting a fresh coordinator each time.
Every resumed run must reach the same terminal state and the same per-step
history: same attempt counts, same outcomes, same compensations, same ordering
of resource touches. Log positions are allowed to shift, because recovery writes
its own records; nothing describing what *happened* is.

The scenarios are chosen for the moments where the state machine makes a
decision it cannot take back — a gate refusing, a retry budget running out, a
compensation failing, and the window between a parent saga committing and its
sub-saga following. That last one is checked at every crash point rather than
only at the end, because it is the window in which a coordinator holds an
obligation that exists nowhere but the log.

This complements `make soak` rather than repeating it. The soak asks whether the
log survives a crash; the chaos suite asks whether the transaction does.

## How the registration claim is tested

A participant declares what each of its actions does to the world, and Janus
gates on that declaration: `IRREVERSIBLE_GATED` is what makes the outbox hold an
effect until the saga commits, `REVERSIBLE` is what lets Janus run an action
optimistically because it believes it can take it back. A declaration nobody
checks is therefore a way to route around the gates by writing a different word.

So registration is not paperwork. `make registry` runs the round trip the Phase
3 exit gate asks for — register, evaluate, activate, pin by a real tool call
through `janus-mcpd`, change the manifest, watch the revalidation fire, and
re-derive the whole registry from the log afterwards — and the conformance
harness behind it turns each claim into something that can fail:

- a `REVERSIBLE` action must demonstrate an inverse that restores the sandbox
  world exactly;
- a `PURE` action must leave it unchanged;
- an effectful action must absorb a duplicate delivery under one idempotency
  key, which is the participant's half of exactly-once;
- and it must refuse an argument above the limit its own manifest declares.

An action nobody can undo is reported as **skipped**, not as passed: a report
that says "checked" about something it did not check is worse than no report.

The other half is `janus-registry audit`, which re-derives the registry from the
log and reports what does not hold — an activation nothing evaluated, a change
record that understates what changed to dodge a revalidation, one version string
registered twice with different content, or a saga pinned to a manifest version
that was not active when it began. It needs nothing but the segments and the
trust store, which travels separately.

## The console, and what it is not allowed to be

`janus-console` shows what the sagas are doing, what is waiting for a person,
and what the evidence says. Three decisions shape it, and all three
are about what it must not become.

**It holds nothing.** Every request re-reads the log. A console with its own
copy of the truth is a second system of record, and the disagreement surfaces as
somebody acting on a screen that was right ten minutes ago.

**It decides nothing.** Approving from the console appends one `GATE_ANSWER` —
the same event a validator produces — and stops. The coordinator composes the
verdict from the log afterwards. So a self-approval submitted from the console
is *recorded* and then refused by the gate, rather than being hidden by the UI:
the attempt is what a supervisor wants to see, and filtering it would leave the
log showing a payment nobody ever tried to self-approve.

**It authenticates nobody.** The approver's identity comes from a header an
authenticating proxy sets, never from the form. Without one, the console is
read-only and says so. An approver who can name themselves can name somebody
else, and four-eyes rests entirely on them not being able to.

The same discipline produced a fix one layer down: an evidence directory now
carries an exclusive lock, so two processes cannot both write it. Before the
console, every writer was a command run on its own; two writers would each
compute the next sequence number from their own start-up scan and chain two
divergent histories into one directory. It is an OS-level `flock` rather than a
pid file, because `make soak` kills writers by the thousand and the successor
has to take the directory immediately.

## Erasure without breaking the chain

A data subject can require erasure; the same records must be kept unaltered for
years. Janus resolves that by encrypting personal-data payloads under a
per-subject key and erasing by destroying the key. The record stays, the chain
still verifies, and the content becomes unrecoverable.

The chain commits to the hash of the **ciphertext**, not the plaintext. A
plaintext hash would outlive the erasure as a permanent oracle: for values drawn
from small spaces — an account number, a date of birth, a name from a customer
list — confirming a guess against it is cheap, and confirmation is itself
disclosure. See the
[DPIA input](docs/compliance/DPIA-crypto-shredding.md), which sets out the
residual risks rather than only the guarantees.

## Known gaps

[`SECURITY.md`](SECURITY.md) lists the known gaps. Phase 1's two exit-gate
measurements passed (see [`docs/bench/README.md`](docs/bench/README.md)):
100M-event verification took 254.5 s against a 30-minute budget, and the
72-hour chaos soak ran 81,033 kill/recover rounds with zero integrity
violations. What the soak left open: its rolling re-verification of history
was slowest at 19m24s against a 15-minute target, recorded as a miss, and it
has only run on darwin/arm64 with `F_FULLFSYNC` — never on Linux, on amd64, or
against `fsync`. Evidence bundles are also not yet anchored, so `janus-verify`
reports every bundle as proving internal consistency rather than completeness.

## What Janus does not promise

Bit-identical regeneration of LLM outputs. Reconstructability here means replay
of *recorded decisions* plus full provenance — the same standard the SEC 17a-4
audit-trail alternative and Temporal-style replay already embody.

## Licence

MIT (see [`LICENSE`](LICENSE)). The specification, schemas, conformance suite, verifier, and SDKs
are the open surface: evidence formats have to be publicly verifiable to be
credible.
