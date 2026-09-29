"""The credit-policy validator, as its own participant.

In the LangGraph run the application answers as this validator, because it is
the process that happens to be there. In the raw-MCP run there is no
application in the loop at all — janus-mcpd turns a tool call into a saga and
the agent knows nothing — so the validator has to be what it is in an actual
deployment: a separate process that watches for questions addressed to it and
answers them.

It is not integration code for either application, and it is not counted as
such: nothing in loan-desk changes to accommodate it. It is a participant the
architecture already had.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, "/sdk")

import janus  # noqa: E402
from janus.v1 import orchd_pb2, orchd_pb2_grpc  # noqa: E402

import grpc  # noqa: E402


MANDATE_MINOR = 500_000


def within_mandate(_saga: str, _step: str, _requirement: str, facts: dict) -> tuple[bool, str]:
    """The credit policy's opinion, on the amount the question is about.

    It used to be `lambda *_: (True, ...)`, and not out of laziness: the
    question carried no facts, so there was nothing to read. An amount that
    is absent is refused rather than assumed small.
    """
    amount = facts.get("amount_minor")
    if not isinstance(amount, int):
        return False, "the question does not say how much; nothing to judge a mandate against"
    if amount > MANDATE_MINOR:
        return False, f"amount_minor={amount} exceeds the mandate of {MANDATE_MINOR}"
    return True, f"amount_minor={amount} is within the mandate of {MANDATE_MINOR}"


def main() -> None:
    target = os.environ.get("JANUS_ORCHD", "127.0.0.1:7777")
    watching = os.environ.get("JANUS_SAGAS", "").split(",")
    deadline = time.time() + float(os.environ.get("JANUS_VALIDATOR_SECONDS", "20"))

    channel = grpc.insecure_channel(target)
    rpc = orchd_pb2_grpc.OrchestratorServiceStub(channel)
    client = janus.Client(channel, pins={})
    client.answer_as("ag_credit_policy", within_mandate)

    # Announced, and flushed, so whoever started this can wait for it to be
    # listening rather than sleeping a guess. A validator that is not up yet
    # looks exactly like one that declined to answer.
    def announce(saga: str, step: str, requirement: str, approved: bool) -> None:
        verdict = "pass" if approved else "fail"
        print(f"credit-policy answered {requirement} on {saga}/{step}: {verdict}", flush=True)

    client.on_answer = announce
    print(f"credit-policy validator watching {target}", flush=True)

    while time.time() < deadline:
        answered = False
        for saga_id in watching:
            if not saga_id:
                continue
            try:
                rpc.GetSaga(orchd_pb2.GetSagaRequest(saga_id=saga_id))
            except grpc.RpcError:
                continue
            client._settle_gates(saga_id)  # noqa: SLF001
            answered = True
        if not answered:
            time.sleep(0.2)
        else:
            time.sleep(0.2)


if __name__ == "__main__":
    main()
