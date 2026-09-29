"""The credit-policy validator for the real-model loan-desk, as its own process.

It watches the sagas it is told about and answers every question addressed to
ag_credit_policy from the facts the question carries: the mandate,
applied to the amount the disbursing step proposed. It is deterministic on
purpose. The run's point is a deterministic envelope around a stochastic core,
and a validator that was itself a model would put the core inside the envelope.

It shares nothing with the harness but the daemon's address. The agent does not
know it exists.
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, "/sdk")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import grpc  # noqa: E402

import janus  # noqa: E402
from janus.v1 import orchd_pb2, orchd_pb2_grpc  # noqa: E402
from validator import within_mandate  # noqa: E402  -- the loan-desk validator's rule


def main() -> None:
    target = os.environ.get("JANUS_ORCHD", "127.0.0.1:7777")
    with open(os.environ["JANUS_SAGA_LIST"]) as f:
        watching = [line.strip() for line in f if line.strip()]
    deadline = time.time() + float(os.environ.get("JANUS_VALIDATOR_SECONDS", "3600"))

    channel = grpc.insecure_channel(target)
    rpc = orchd_pb2_grpc.OrchestratorServiceStub(channel)
    # The validator signs its answers with its own key: the daemon
    # refuses an answer "from ag_credit_policy" that ag_credit_policy's key did
    # not sign, so the agent -- which holds only its own keys -- cannot answer
    # in the validator's name.
    signers = {}
    if os.environ.get("JANUS_KEYS_DIR"):
        signers["ag_credit_policy"] = janus.load_signer(
            "ag_credit_policy", os.path.join(os.environ["JANUS_KEYS_DIR"], "ag_credit_policy.key")
        )
    client = janus.Client(channel, pins={}, signers=signers)
    client.answer_as("ag_credit_policy", within_mandate)
    client.on_answer = lambda saga, step, req, ok: print(
        f"answered {req} on {saga}/{step}: {'pass' if ok else 'fail'}", flush=True
    )
    print(f"validator watching {len(watching)} sagas on {target}", flush=True)

    # The stream opens with where each saga stands, then every change. A saga
    # that does not exist yet is watched all the same and arrives when begun.
    stream = rpc.WatchSagas(orchd_pb2.WatchSagasRequest(saga_ids=watching))
    for update in stream:
        if time.time() > deadline:
            break
        if any(
            "ag_credit_policy" in g.answerable_by
            for st in update.saga.steps
            for g in st.pending_gates
        ):
            client._settle_gates(update.saga.saga_id)  # noqa: SLF001


if __name__ == "__main__":
    main()
