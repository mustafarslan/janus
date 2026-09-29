# Janus Transaction Protocol, v0.9 (draft)

**Status:** draft, for comment. Nothing here is frozen; the version number exists
so that two implementations can say which draft they agree on.

**What this document is.** JTP is an *extension profile*, not a new protocol. It
says how existing agent protocols carry the small amount of extra information
that makes agent work transactional — which saga a message belongs to, what an
action does to the world, and where the evidence for it is. Everything else about
A2A, MCP or HTTP is unchanged, and an implementation that ignores JTP entirely
sees ordinary A2A, ordinary MCP and ordinary HTTP.

**What it is not.** It is not a description of Janus. Janus is one implementation;
the point of writing this down separately is that a second implementation should
be possible from the spec, and checkable by the same conformance suite.

---

## 1. What is implemented, and what is only specified

A spec that reads as though all of it exists is the most expensive kind of
document. This one says which is which, and the table is the first thing in it
for that reason.

| Binding | §  | Status |
|---|---|---|
| HTTP header set | 3 | **Propagation and recording are implemented; origination is not.** `janus-a2ad` carries the framing an agent set and records both halves of the exchange. Nothing in Janus *originates* it — §3 rule 1 is the sender's obligation and an agent discharges it itself |
| A2A extension (`janus.transactions/v1` in the AgentCard) | 4 | **Implemented** — advertised and consumed by `janus-a2ad` |
| MCP metadata convention (`_janus` in tool call params) | 5 | **Specified only.** `janus-mcpd` derives a saga per call instead; nothing yet reads `_janus` |
| Message vocabulary | 6 | **Implemented** — `proto/janus/v1`, and the same messages are the evidence records |
| Saga and step lifecycles | 7 | **Implemented** — `pkg/saga` |
| Invariants | 8 | **Implemented and checked** — `janus-conformance` |

Section 5 is the one to read sceptically. It is what the MCP binding *should*
be, written before there is a caller for it, and it will change when there is.

---

## 2. Design stance

Three commitments shape everything below.

**The wire format and the record share one grammar.** A JTP message is not
translated into an evidence record; it *is* the evidence record's payload. That
removes the class of bug where the thing that was sent and the thing that was
recorded drift apart, and it is why §6 is a protobuf vocabulary rather than a
JSON schema.

**Propagation is not authority.** Every field JTP adds to a message is a claim
by the sender. A saga id on a request says which saga the sender believes this
belongs to; it does not make it so, and no implementation may treat a header,
a metadata field or an AgentCard as permission. What the framing buys is that
two parties and a log agree on what to *call* a piece of work.

**Effect class is the load-bearing declaration.** Every gate matches on it. An
action that understates its class is an action no rule applied to, which is why
§8's conformance requires it to be checked against a signed manifest rather than
believed.

---

## 3. HTTP header set

For plain HTTP services and as the substrate of the A2A binding.

| Header | Meaning |
|---|---|
| `Janus-Saga-Id` | the saga this message belongs to |
| `Janus-Step-Id` | the step within it |
| `Janus-Effect-Class` | `PURE`, `REVERSIBLE`, `COMPENSABLE`, `IRREVERSIBLE_GATED` or `IRREVERSIBLE_IMMEDIATE` |
| `Janus-Idempotency-Key` | the key the receiver uses to recognise a repeat |
| `Janus-Evidence-Ref` | where the sender recorded this |

**Rules.**

1. **A sender making a call from inside a saga MUST set `Janus-Saga-Id` and
   `Janus-Step-Id` on the outbound request**, and an intermediary that records
   an unframed message MUST NOT attribute it to a saga of its own choosing.
   Only the sender knows which saga the call belongs to; a proxy in the path
   does not, and evidence filed under a saga nobody chose reads as an answer.
   What an unframed message loses is larger than the saga: on a concurrent
   conversation with one counterpart, two unframed questions and their two
   answers carry identical metadata, and nothing in the log pairs a question
   with its own answer.
2. A header with no value MUST be omitted rather than sent empty. A present-but-
   empty `Janus-Saga-Id` is a claim that there is a saga and it has no id.
3. A receiver MUST NOT make an authorisation decision from any of these. A
   header is whatever the sender wrote, and a receiver that *records* the saga
   it was given has recorded a claim, which is the propagation this section is
   for — a receiver that *acts* on it has taken the sender's word for
   permission.
4. **An exchange is named by the party that began it, and a response's framing
   MUST NOT override the request's.** A caller that files its record under the
   `Janus-Saga-Id` that came back has let the counterpart rename work the caller
   itself started. A disagreement between the two is worth recording,
   as a discrepancy and never as the name.
5. A receiver that understands JTP SHOULD echo `Janus-Saga-Id` and
   `Janus-Step-Id` on its response. Not for the caller's benefit on a
   request/response round trip, where the caller already knows what it sent and
   rule 4 says so; the echo is for a reader of the wire, and for a caller whose
   response is handled somewhere other than where the request was made.
6. `Janus-Idempotency-Key` is meaningful only for an effectful message. A
   receiver that acts on a repeated key MUST apply the effect once; at-least-once
   delivery plus receiver idempotency is what makes a release effectively
   exactly-once, and neither half is sufficient alone.

---

## 4. A2A binding

An agent governed by JTP advertises the capability `janus.transactions/v1` in
its AgentCard. A counterpart that recognises it may send the §3 headers and may
expect them echoed.

**The AgentCard is not a source of authority, and a conformant implementation
makes that structural rather than advisory.** An AgentCard is an unauthenticated
document served by whoever answers that address; an agent that wanted to be
trusted would serve a card saying it is trusted. So:

1. An implementation MUST NOT make an authorisation or gating decision from an
   AgentCard.
2. An AgentCard SHOULD NOT carry effect classes, idempotency recipes, limits or
   compensations. A field that exists is a field somebody eventually reads.
3. A card SHOULD name the manifest it was projected from — the version and its
   content address — so a reader can ask a registry about *that* declaration
   rather than about whatever is current.
4. Verification of a counterpart MUST consult a registry, not the card.

The Janus manifest — the superset the card points at — MAY be served alongside
the card. Reading a declaration is not checking it.

---

## 5. MCP binding *(specified only; nothing implements this yet)*

A tool call carries JTP framing in a `_janus` object inside `params`, and a
result carries it inside the result object:

```json
{ "method": "tools/call",
  "params": { "name": "payments.wire",
              "arguments": { "amount_minor": 250, "currency": "EUR" },
              "_janus": { "saga_id": "sg_1", "step_id": "st_wire" } } }
```

**Rules.**

1. A server that does not understand `_janus` MUST ignore it, and a client MUST
   NOT depend on it being understood. This is why it is a metadata field rather
   than a new method.
2. `_janus.saga_id` names a saga the *caller* already has. A proxy that receives
   a call with no `_janus` MUST NOT invent a saga id that implies membership of
   one; deriving a fresh single-step saga per call is the conformant behaviour,
   and is what `janus-mcpd` does today.
3. The arguments a call carries are the facts its gates decide against. An
   implementation MUST bind them into the step's prepare record before the call
   is made, so a caller cannot declare one amount and send another.

**Why this is unimplemented.** `janus-mcpd` derives a saga per effectful call,
which needs no cooperation from the agent and is what "config-only onboarding
for an unmodified tool server" means. Joining a saga the agent already has needs
this convention, and it wants designing against a caller that exists — the SDKs
are the first candidate. Specifying it here without implementing it is the
deliberate half of that; implementing it before anyone needs it would be
designing the fields twice.

---

## 6. Message vocabulary

The normative form is `proto/janus/v1`. Summarised:

| Message | What it records |
|---|---|
| `SagaBegin` | the intent, the plan, and the manifest version each participant is pinned to |
| `StepPrepare` | a step is about to run, with the facts it declares |
| `StepResult` | what the participant did, for one attempt |
| `GateVerdict` | a gate's decision, with the provenance record that explains it |
| `SealRequest` | the saga's resource footprint is complete |
| `Commit` | the saga committed; held effects may be released |
| `Compensate` | a step is being undone |
| `Abort`, `Quarantine` | the saga stopped, and whether a human is needed |

Every one of these is also an evidence event. An implementation that stores them
differently from how it sends them is conformant only if the difference is
lossless, and has taken on the drift this design exists to avoid.

---

## 7. Lifecycles

**Saga:** `CREATED → RUNNING → { GATED } → SEALING → COMMITTED`, or
`→ COMPENSATING → { COMPENSATED | QUARANTINE }`.

**Step:** `PLANNED → PREPARED → { GATED } → SEALED → COMMITTED`, or
`→ { REFUSED | FAILED } → COMPENSATED`.

Two states carry more weight than their names suggest.

`QUARANTINE` is terminal until a person acts. It is entered when a compensation
did not succeed, and it exists because a stuck known state beats a guessed clean
one. An implementation that automatically resolved a quarantine would be
guessing.

`REFUSED` is distinct from `FAILED`. A refused step ran and a gate would not let
its effect through; a failed step did not do what it was asked. The difference
decides whether there is anything to undo.

---

## 8. Conformance

An implementation is conformant if evidence it produces satisfies these, and
`janus-conformance` checks each one against a log:

| | Requirement |
|---|---|
| I1 | Evidence before effect: a release is recorded, durably, before it is attempted |
| I2 | Chain integrity: the log verifies offline against the writer's public keys |
| I3 | Every gate decision is re-derivable from the inputs recorded with it |
| I4 | Commit safety: nothing is released except from a committed saga, under a stable idempotency key |
| I5 | Replay determinism: folding the log twice produces the same projection |
| I7 | Compensation order: steps are undone in reverse topological order |
| I8 | Registry pinning: every step's effect class matches the manifest version the saga pinned |

**A conformance run MUST state what the implementation was asked to do.** Every
requirement above holds of a log with nothing in it. A suite that could be
satisfied by an implementation doing nothing measures nothing, so a run is given
the sagas, steps and outcomes expected of it, and refuses to start without them.

---

## 9. What v0.9 does not specify

Stated so that a second implementer is not left guessing which silences are
deliberate.

- **Identity.** How an approver's role claim is established, rather than
  asserted, is out of scope. JTP records the claim and where it came from; it
  does not say what makes it true.
- **Transport security.** Assumed, not specified.
- **Federation.** Cross-organisation sagas — how two logs owned by different
  parties relate, and what a commitment between them looks like — are out of
  scope. They are the hardest part and are deliberately last.
- **Streaming.** A2A streaming tasks and push notifications have no framing here
  yet; §3 covers request/response. An implementation MUST NOT forward a stream
  unrecorded while recording ordinary calls: a log that looks complete and is not
  is worse than an obvious gap.
- **Anchoring.** How an evidence bundle is committed to something outside the
  system, so completeness can be shown rather than asserted.
