"""loan-desk, on LangGraph, with no Janus at all.

Four steps: an intake agent reads the application, a credit-policy validator
gives an opinion on it, a payments tool disburses the loan, and a notification
goes to the applicant.

This file exists to be diffed against governed.py. Nothing here is a straw man:
it is the application somebody would write if Janus did not exist, and every
line of it survives into the governed version unchanged. What the diff shows is
the cost of governing it.
"""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, StateGraph


class Application(TypedDict, total=False):
    applicant: str
    amount_minor: int
    currency: str
    approved: bool
    disbursed: bool
    notified: bool


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


def build() -> Any:
    graph = StateGraph(Application)
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
    result = build().invoke(
        {"applicant": "acct_1701", "amount_minor": 250_000, "currency": "EUR"}
    )
    print(f"loan-desk: {result}")


if __name__ == "__main__":
    main()
