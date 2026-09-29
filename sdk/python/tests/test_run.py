"""What the SDK sends while driving a saga.

The fake answers with a script of projections; these tests assert on the
requests, because those are the SDK's own behaviour. How a real daemon responds
to them is a question for a real daemon.
"""

from __future__ import annotations

import pytest
from conftest import projection, step_projection

import janus
from janus.v1 import common_pb2, orchd_pb2


@janus.saga(name="settle", principal="pr_bank", mandate_ref="mandate:x", scope="pay")
class Settle:
    def __init__(self) -> None:
        self.ran: list[str] = []

    @janus.step(participant="tool_payments", action="payments.wire", effect=janus.PURE)
    def wire(self, amount_minor: int, currency: str, urgent: bool) -> None:
        self.ran.append("wire")


ACTIONS = {"payments.wire": ("PURE", "")}


def test_the_facts_a_step_declares_are_the_arguments_it_runs_on(fake) -> None:
    # This is the property that makes a gate worth having. The amount a risk
    # limit compares against is bound into the prepare record before the method
    # is called, from the method's own signature, so a step cannot declare one
    # amount and act on another.
    recorder, configure = fake
    target = configure(
        actions=ACTIONS,
        projections=[
            projection(
                "sg_1",
                common_pb2.SAGA_STATE_RUNNING,
                [step_projection("wire", common_pb2.STEP_STATE_PLANNED, awaiting_participant=True)],
            ),
            projection(
                "sg_1",
                common_pb2.SAGA_STATE_RUNNING,
                [
                    step_projection(
                        "wire",
                        common_pb2.STEP_STATE_PREPARED,
                        awaiting_participant=True,
                        attempt=1,
                    )
                ],
            ),
            projection("sg_1", common_pb2.SAGA_STATE_COMMITTED, []),
        ],
    )
    settle = Settle()
    client = janus.connect(target, pins={"tool_payments": "1.0.0"})
    result = client.run(
        settle, saga_id="sg_1", amount_minor=250, currency="EUR", urgent=True
    )

    assert result.committed
    assert settle.ran == ["wire"], "the step handler was never called"

    facts = {f.key: f for f in recorder.prepares[0].facts}
    assert facts["amount_minor"].number == 250
    assert facts["currency"].text == "EUR"
    assert facts["urgent"].flag is True
    assert facts["urgent"].WhichOneof("value") == "flag", (
        "in Python a bool is an int, so a flag sent as a number is one wrong "
        "isinstance away — and it would then be compared by a rule that meant "
        "something else entirely"
    )


def test_the_reported_result_names_the_attempt_it_belongs_to(fake) -> None:
    # A retry of attempt 2 and a duplicate report of attempt 1 are the same
    # message without it, and only one of them may be recorded.
    recorder, configure = fake
    target = configure(
        actions=ACTIONS,
        projections=[
            projection(
                "sg_2",
                common_pb2.SAGA_STATE_RUNNING,
                [
                    step_projection(
                        "wire",
                        common_pb2.STEP_STATE_PREPARED,
                        awaiting_participant=True,
                        attempt=3,
                    )
                ],
            ),
            projection("sg_2", common_pb2.SAGA_STATE_COMMITTED, []),
        ],
    )
    client = janus.connect(target, pins={"tool_payments": "1.0.0"})
    client.run(Settle(), saga_id="sg_2", amount_minor=1, currency="EUR", urgent=False)

    reported = recorder.completes[0].result
    assert reported.attempt == 3
    assert reported.outcome.status == common_pb2.Outcome.STATUS_OK


def test_a_step_that_fails_reports_which_kind_of_failure(fake) -> None:
    # Retryable and terminal are the caller's distinction to make: a timeout
    # talking to an API is one, a payment the API refused is the other, and
    # retrying a refusal is how a step becomes poison for no reason.
    @janus.saga(name="fails", principal="pr_bank", mandate_ref="mandate:x", scope="pay")
    class Fails:
        @janus.step(participant="tool_payments", action="payments.wire", effect=janus.PURE)
        def wire(self) -> None:
            raise janus.StepError("the counterparty refused", retryable=False)

    recorder, configure = fake
    target = configure(
        actions=ACTIONS,
        projections=[
            projection(
                "sg_3",
                common_pb2.SAGA_STATE_RUNNING,
                [
                    step_projection(
                        "wire",
                        common_pb2.STEP_STATE_PREPARED,
                        awaiting_participant=True,
                        attempt=1,
                    )
                ],
            ),
            projection("sg_3", common_pb2.SAGA_STATE_COMPENSATED, []),
        ],
    )
    client = janus.connect(target, pins={"tool_payments": "1.0.0"})
    client.run(Fails(), saga_id="sg_3")

    assert (
        recorder.completes[0].result.outcome.status
        == common_pb2.Outcome.STATUS_TERMINAL_ERROR
    )


def test_a_saga_waiting_on_a_person_says_so_rather_than_spinning(fake) -> None:
    # An SDK does not answer its own gates -- that is what makes the answer
    # worth something. What it must do is say which requirement is holding it,
    # so the caller knows to go and look at a queue rather than at a bug.
    _, configure = fake
    target = configure(
        actions=ACTIONS,
        projections=[
            projection(
                "sg_4",
                common_pb2.SAGA_STATE_GATED,
                [
                    step_projection(
                        "wire",
                        common_pb2.STEP_STATE_GATED,
                        pending_gates=[
                            orchd_pb2.PendingGate(
                                requirement_id="four-eyes",
                                detail="2 approval(s) from [credit-officer]",
                            )
                        ],
                    )
                ],
            )
        ],
    )
    client = janus.connect(target, pins={"tool_payments": "1.0.0"})
    with pytest.raises(janus.WaitingError, match="four-eyes"):
        client.run(Settle(), saga_id="sg_4", amount_minor=1, currency="EUR", urgent=False)


def test_a_compensation_is_run_when_the_projection_asks_for_it(fake) -> None:
    @janus.saga(name="undo", principal="pr_bank", mandate_ref="mandate:x", scope="pay")
    class Undo:
        def __init__(self) -> None:
            self.undone = False

        @janus.step(
            participant="tool_payments",
            action="payments.wire",
            effect=janus.COMPENSABLE,
            compensation="payments.refund",
        )
        def wire(self) -> None: ...

        @janus.compensation(for_step="wire")
        def unwire(self) -> None:
            self.undone = True

    recorder, configure = fake
    target = configure(
        actions={"payments.wire": ("COMPENSABLE", "payments.refund")},
        projections=[
            projection(
                "sg_5",
                common_pb2.SAGA_STATE_COMPENSATING,
                [
                    step_projection(
                        "wire", common_pb2.STEP_STATE_SEALED, awaiting_compensation=True
                    )
                ],
            ),
            projection("sg_5", common_pb2.SAGA_STATE_COMPENSATED, []),
        ],
    )
    undo = Undo()
    client = janus.connect(target, pins={"tool_payments": "1.0.0"})
    client.run(undo, saga_id="sg_5")

    assert undo.undone, "the compensation handler was never called"
    assert recorder.completes[0].result.step_id == "wire~undo", (
        "a compensation is recorded under the undo step's own id; reporting it as the "
        "step itself would say the step ran a second time"
    )
