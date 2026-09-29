"""loan-desk, on LangGraph, governed by Janus.

The same four steps as plain.py, and the same four function bodies. What is
added is the declaration of what each step does to the world, a client, and a
wrapper on each graph node.

LangGraph still owns the control flow. Janus does not take it over: the graph
decides which node runs when, and each node, when it runs, is a step that was
prepared with the facts it is about to act on and reported when it is done.

`scripts/measure-integration.sh` diffs this against plain.py. That number is
Phase 4's exit gate, so it is measured rather than claimed.
"""

from __future__ import annotations

import os
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

import janus
from janus.langgraph import govern

ORCHD = os.environ.get("JANUS_ORCHD", "127.0.0.1:7777")
SAGA_ID = os.environ.get("JANUS_SAGA_ID", "sg_loan_desk")


class Application(TypedDict, total=False):
    applicant: str
    amount_minor: int
    currency: str
    approved: bool
    disbursed: bool
    notified: bool


@janus.saga(
    name="loan-desk",
    principal="pr_bank",
    mandate_ref="mandate:loans",
    scope="assess and disburse one loan",
)
class LoanDesk:
    """What each step does to the world, which is what the gates decide on."""

    @janus.step(participant="ag_intake", action="intake.read", effect=janus.PURE)
    def intake(self) -> None: ...

    @janus.step(
        participant="ag_credit_policy", action="credit.assess",
        effect=janus.PURE, depends_on=("intake",),
    )
    def credit_policy(self) -> None: ...

    @janus.step(
        participant="tool_payments", action="payments.disburse",
        effect=janus.COMPENSABLE, compensation="payments.refund",
        depends_on=("credit_policy",),
    )
    def disburse(self) -> None: ...

    @janus.compensation(for_step="disburse")
    def refund(self) -> None: ...

    @janus.step(
        participant="tool_notify", action="notify.email",
        effect=janus.IRREVERSIBLE_GATED, depends_on=("disburse",),
    )
    def notify(self) -> None: ...


def intake(state: Application) -> dict[str, Any]:
    """Read the application. Nothing has happened to the world yet."""
    return {"applicant": state["applicant"], "amount_minor": state["amount_minor"]}


def credit_policy(state: Application) -> dict[str, Any]:
    """The credit-policy validator's opinion: is this within the mandate?"""
    return {"approved": state["amount_minor"] <= 500_000}


def disburse(state: Application) -> dict[str, Any]:
    """Move the money. This is the step with something to take back."""
    if not state.get("approved"):
        return {"disbursed": False}
    return {"disbursed": True}


def notify(state: Application) -> dict[str, Any]:
    """Tell the applicant. Nobody can unsend this."""
    return {"notified": True}


def build(client: janus.Client) -> Any:
    graph = govern(StateGraph(Application), client, SAGA_ID, facts={
        "disburse": lambda s: {"amount_minor": s["amount_minor"], "currency": s["currency"]},
        "notify": lambda s: {"approved": bool(s.get("approved"))},
    })
    graph.add_node("intake", intake)
    graph.add_node("credit_policy", credit_policy)
    graph.add_node("disburse", disburse)
    graph.add_node("notify", notify)
    graph.set_entry_point("intake")
    graph.add_edge("intake", "credit_policy")
    graph.add_edge("credit_policy", "disburse")
    graph.add_edge("disburse", "notify")
    graph.add_edge("notify", END)
    return graph.compile()


def main() -> None:
    client = janus.connect(ORCHD, pins={
        "ag_intake": "1.0.0", "ag_credit_policy": "1.0.0",
        "tool_payments": "1.0.0", "tool_notify": "1.0.0",
    })
    client.answer_as("ag_credit_policy", lambda *q: (q[3]["amount_minor"] <= 500_000, "within the mandate"))
    client.begin(LoanDesk(), saga_id=SAGA_ID)
    result = build(client).invoke(
        {"applicant": "acct_1701", "amount_minor": 250_000, "currency": "EUR"}
    )
    print(f"loan-desk: {result} -> {client.status(SAGA_ID).status}")


if __name__ == "__main__":
    main()
