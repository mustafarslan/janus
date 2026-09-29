"""The SDK against a real janus-orchd.

It runs under the reference gate policy — the same document a deployment would
use, not a permissive one written for a test. The saga's compensable step is
judged by that policy's `effect-approval` rule at release, against a fact the
step declared from its own signature. That is the property worth showing end to
end: the gate decides on the arguments the step actually ran on.

Everything else in this directory tests what the SDK sends, against a fake that
answers with whatever the test told it to. That is the right shape for those
questions and the wrong shape for this one: whether the messages this SDK builds
are messages a real daemon accepts, admits, gates and commits.

So this test talks to a daemon that a script started, over a real port, against
a real evidence log with a real registered manifest. It is skipped unless
JANUS_ORCHD is set, because it needs that daemon and there is no honest way to
fake one -- a fake that admitted the plan would be answering the question the
test is asking.

Run it with `make sdk-e2e`.
"""

from __future__ import annotations

import os

import pytest

import janus

TARGET = os.environ.get("JANUS_ORCHD", "")

pytestmark = pytest.mark.skipif(
    not TARGET, reason="set JANUS_ORCHD to a running daemon, or run `make sdk-e2e`"
)


@janus.saga(
    name="settle",
    principal="pr_bank",
    mandate_ref="mandate:payments",
    scope="quote and settle one invoice",
)
class Settle:
    def __init__(self) -> None:
        self.ran: list[str] = []

    @janus.step(
        participant="tool_payments", action="payments.quote", effect=janus.PURE
    )
    def quote(self, amount_minor: int) -> None:
        self.ran.append("quote")

    @janus.step(
        participant="tool_payments",
        action="payments.wire",
        effect=janus.COMPENSABLE,
        compensation="payments.refund",
        depends_on=("quote",),
    )
    def wire(self, amount_minor: int, currency: str, approved: bool) -> None:
        self.ran.append("wire")

    @janus.compensation(for_step="wire")
    def unwire(self) -> None:
        self.ran.append("unwire")


@janus.saga(
    name="understated", principal="pr_bank", mandate_ref="mandate:payments", scope="pay"
)
class Understated:
    # The manifest says payments.wire is COMPENSABLE.
    @janus.step(
        participant="tool_payments", action="payments.wire", effect=janus.PURE
    )
    def wire(self, amount_minor: int) -> None: ...


def test_a_declared_saga_runs_to_commit_against_a_real_daemon() -> None:
    settle = Settle()
    client = janus.connect(TARGET, pins={"tool_payments": "1.0.0"})
    result = client.run(
        settle,
        saga_id=os.environ.get("JANUS_SAGA_ID", "sg_sdk_e2e"),
        amount_minor=250,
        currency="EUR",
        # The reference policy's compensable-effects rule decides on this at
        # release. It is a fact the step declared, from its own signature, and
        # bound into the prepare record before the method ran — which is the
        # whole property: the gate judges the arguments the step acts on.
        approved=True,
    )
    assert result.committed, f"saga finished as {result.status}"
    assert settle.ran == ["quote", "wire"], (
        "the daemon schedules from the plan's depends_on, so the order the handlers "
        f"ran in is the order it asked for; got {settle.ran}"
    )


def test_a_contradiction_is_refused_before_the_saga_exists() -> None:
    client = janus.connect(TARGET, pins={"tool_payments": "1.0.0"})
    with pytest.raises(janus.DeclarationError, match="declares PURE"):
        client.run(Understated(), saga_id="sg_sdk_e2e_bad", amount_minor=1)
