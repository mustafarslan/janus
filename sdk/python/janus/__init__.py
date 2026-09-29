"""Janus Python SDK: transactional evidence for agent work.

A saga is a class. Its steps are methods that declare which participant runs
them, which registered action they invoke, and what that action does to the
world. Janus turns those declarations into a plan, admits the plan against the
gate policy and the participant registry, and then tells this client which step
is its to run -- one at a time, from a projection it derives from the log.

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
        def wire(self, amount_minor: int, currency: str) -> None:
            ...

        @janus.compensation(for_step="wire")
        def unwire(self) -> None:
            ...

    client = janus.connect("127.0.0.1:7777", pins={"tool_payments": "1.0.0"})
    result = client.run(Settle(), saga_id="sg_1", amount_minor=250, currency="EUR")

Two things about that are worth saying plainly, because they are the difference
between this and a client that merely records.

**The arguments a step runs on are the facts its gates decide against.** They
are read from the handler's own signature and bound into the step's prepare
record before the method is called. A step cannot declare one amount to Janus
and act on another, because there is only one amount.

**A declaration that contradicts the registry is refused before anything
begins.** The participant's signed manifest says what each action does; a step
claiming PURE for an action that moves money is refused when this client
connects, not at admission and not at a gate. The daemon re-checks anyway --
this is a courtesy that fails fast, not the enforcement.
"""

from __future__ import annotations

from janus._callersig import Signer
from janus._client import Client, Result, StepReport, connect, load_signer
from janus._declare import (
    COMPENSABLE,
    IRREVERSIBLE_GATED,
    IRREVERSIBLE_IMMEDIATE,
    PURE,
    REVERSIBLE,
    compensation,
    saga,
    step,
)
from janus.errors import (
    DeclarationError,
    JanusError,
    RefusedError,
    StepError,
    WaitingError,
)

__version__ = "0.1.0"

__all__ = [
    "COMPENSABLE",
    "IRREVERSIBLE_GATED",
    "IRREVERSIBLE_IMMEDIATE",
    "PURE",
    "REVERSIBLE",
    "Client",
    "DeclarationError",
    "JanusError",
    "RefusedError",
    "Result",
    "Signer",
    "StepReport",
    "StepError",
    "WaitingError",
    "compensation",
    "connect",
    "load_signer",
    "saga",
    "step",
    "__version__",
]
