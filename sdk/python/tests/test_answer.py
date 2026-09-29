"""What a client that answers gates is shown, and what it sends back.

Before the question carried its facts a validator was asked to approve with the
numbers blanked out, and the only thing it could be was a rubber stamp.
These assert on what `decide` was given and on the
answer the SDK then sent: whether the daemon accepts it is the daemon's test.
"""

from __future__ import annotations

from conftest import projection, step_projection

import janus
from janus.v1 import common_pb2, gate_pb2, orchd_pb2


def _question(amount: int) -> orchd_pb2.SagaProjection:
    return projection(
        "sg_q",
        common_pb2.SAGA_STATE_GATED,
        [
            step_projection(
                "disburse",
                common_pb2.STEP_STATE_GATED,
                pending_gates=[
                    orchd_pb2.PendingGate(
                        requirement_id="credit-opinion",
                        attempt=1,
                        answerable_by=["ag_credit_policy"],
                        facts=[
                            gate_pb2.Fact(key="amount_minor", number=amount),
                            gate_pb2.Fact(key="step.action", text="payments.disburse"),
                            gate_pb2.Fact(key="saga.id", text="sg_q"),
                        ],
                    )
                ],
            )
        ],
    )


def _answered() -> orchd_pb2.SagaProjection:
    return projection(
        "sg_q",
        common_pb2.SAGA_STATE_RUNNING,
        [step_projection("disburse", common_pb2.STEP_STATE_SEALED)],
    )


def test_a_validator_decides_on_the_facts_it_is_shown(fake) -> None:
    recorder, configure = fake
    target = configure(actions={}, projections=[_question(900_000), _answered()])
    client = janus.connect(target, pins={})

    shown: list[dict] = []

    def within_mandate(saga, step, requirement, facts):
        shown.append(facts)
        ok = facts["amount_minor"] <= 500_000
        return ok, f"amount_minor={facts['amount_minor']} against a mandate of 500000"

    client.answer_as("ag_credit_policy", within_mandate)
    client._settle_gates("sg_q")  # noqa: SLF001 - the watcher's own entry point

    assert shown == [
        {"amount_minor": 900_000, "step.action": "payments.disburse", "saga.id": "sg_q"}
    ], "decide was not shown the facts the question carries"
    assert len(recorder.answers) == 1
    answer = recorder.answers[0].answer
    assert answer.verdict == common_pb2.VERDICT_FAIL, (
        "a disbursement over the mandate was approved: the validator never saw the amount"
    )
    assert answer.attempt == 1
    assert "900000" in answer.reason
