# Janus Python SDK

A saga is a class. Its steps are methods that declare which participant runs
them, which registered action they invoke, and what that action does to the
world.

```python
import janus

@janus.saga(name="settle", principal="pr_bank",
            mandate_ref="mandate:payments", scope="settle one invoice")
class Settle:
    @janus.step(participant="tool_payments", action="payments.quote",
                effect=janus.PURE)
    def quote(self, amount_minor: int) -> None:
        ...

    @janus.step(participant="tool_payments", action="payments.wire",
                effect=janus.COMPENSABLE, compensation="payments.refund",
                depends_on=("quote",))
    def wire(self, amount_minor: int, currency: str, approved: bool) -> None:
        ...

    @janus.compensation(for_step="wire")
    def unwire(self) -> None:
        ...

client = janus.connect("127.0.0.1:7777", pins={"tool_payments": "1.0.0"})
result = client.run(Settle(), saga_id="sg_1",
                    amount_minor=250, currency="EUR", approved=True)
```

Two things about that are the point rather than the convenience.

**The arguments a step runs on are the facts its gates decide against.** They
are read from the handler's own signature and bound into the step's prepare
record *before* the method is called. A step cannot declare one amount to Janus
and act on another, because there is only one amount. In the example above, the
reference policy's `effect-approval` rule decides on `approved` at release —
against the value the method was actually called with.

**A declaration the registry contradicts is refused before anything begins.**
The participant's signed manifest says what each action does. A step claiming
`PURE` for an action registered as `COMPENSABLE` raises `DeclarationError` when
the client connects — not at admission, and not at a gate. The daemon re-checks
at admission from the log, and *that* is the enforcement; this is a courtesy
that fails fast.

## What a step says about itself

`Client.step` yields a `StepReport`. A step whose body a model decided attaches
the decision with `report.decided(model=..., temperature=..., output_hash=...,
grounds=[...])` and what it produced with `report.produced(hash=..., ref=...)`.
Both are sent with the step's outcome, **including when the body raises**, and
janus-orchd records the decision immediately before the result, which cites it
. The SDK computes no hash: the algorithm is the deployment's choice.

## What it does not do

It does not answer its own gates. A saga waiting on a person or a validator
raises `WaitingError` naming the requirement, and somebody outside this process
answers it. An SDK that could approve its own payments would be the thing to
attack.

It does not frame an agent's own outbound calls. A step body that calls another
agent over HTTP or A2A sets the Janus headers on that request itself — nothing
in the client or the proxy can, because only the step knows which saga the call
belongs to (JTP §3 rule 1):

```python
headers = {"Janus-Saga-Id": saga_id, "Janus-Step-Id": step_id}
```

A call made without them is still recorded verbatim and still forwarded; what is
lost is the join to the saga, and — where two calls to one counterpart overlap —
the pairing between a question and its own answer.

It does not decide what may run when. The coordinator schedules from the plan's
`depends_on`; this client does what the projection tells it to, one step at a
time. A second scheduler here would be a second answer to the same question.

## Running the tests

```bash
make ci                # includes the `python` job: ruff, mypy --strict, pytest
make sdk-e2e           # the SDK against a real janus-orchd, end to end
```

The unit tests run against a deliberately stupid fake daemon that answers with
whatever the test told it to. It is stupid on purpose: a fake that modelled the
daemon's behaviour would be a second implementation of the contract, and the
interesting failure with two implementations is not that they disagree but that
they agree convincingly while both being wrong. Whether the messages this SDK
builds are messages a real daemon accepts is what `make sdk-e2e` answers, against
a real daemon under the reference gate policy.

## Generated code

`janus/v1/` is generated from `proto/janus/v1/*.proto` by `make gen` and is
committed. It lives inside the package because generated protobuf Python imports
its siblings as `from janus.v1 import ...`, so the package has to *be* `janus`
with `v1` inside it. It is excluded from ruff and mypy — pointing the tools at
the code somebody wrote, not weakening them — and the `proto` CI job diffs it, so
it cannot drift from the protos.
