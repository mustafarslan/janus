"""A deliberately stupid stand-in for janus-orchd.

It answers with whatever the test told it to answer and records what it was
asked. It does not model the daemon's behaviour, and it must not start to: the
moment a fake here decides what "already recorded" means, or when a gate
resolves, this repository has two implementations of the contract and the
interesting failure is not that they disagree but that they agree convincingly
while both being wrong.

So the tests below assert on what the SDK *sent* -- the plan it built, the facts
it declared, the attempt it named, whether it asked the registry before it
began. Anything about how the daemon *responds* to those messages is tested
against a real daemon, in Go, where the daemon is.
"""

from __future__ import annotations

from concurrent import futures
from dataclasses import dataclass, field
from typing import Any

import grpc
import pytest

from janus.v1 import common_pb2, orchd_pb2, orchd_pb2_grpc


@dataclass
class Recorder:
    """Everything the SDK sent, in order."""

    resolves: list[orchd_pb2.ResolveParticipantRequest] = field(default_factory=list)
    begins: list[orchd_pb2.BeginSagaRequest] = field(default_factory=list)
    prepares: list[orchd_pb2.PrepareStepRequest] = field(default_factory=list)
    completes: list[orchd_pb2.CompleteStepRequest] = field(default_factory=list)
    answers: list[orchd_pb2.RecordAnswerRequest] = field(default_factory=list)


class FakeOrchd(orchd_pb2_grpc.OrchestratorServiceServicer):
    """Canned answers, and a record of the questions."""

    def __init__(self, recorder: Recorder, *, actions: dict[str, Any], projections: list[Any]):
        self.recorder = recorder
        self._actions = actions
        # projections is a script: one SagaProjection per GetSaga call, and the
        # last one repeats. A test says what the saga looks like at each turn.
        self._projections = projections

    def ResolveParticipant(self, request, context):  # noqa: N802 - gRPC naming
        self.recorder.resolves.append(request)
        if not self._actions:
            context.abort(grpc.StatusCode.NOT_FOUND, "not registered")
        return orchd_pb2.ResolveParticipantResponse(
            participant_id=request.participant_id,
            version=request.version,
            state="ACTIVE",
            actions=[
                orchd_pb2.DeclaredAction(
                    name=name,
                    effect_class=common_pb2.EffectClass.Value(f"EFFECT_CLASS_{effect}"),
                    compensation_action=undo,
                )
                for name, (effect, undo) in self._actions.items()
            ],
        )

    def BeginSaga(self, request, context):  # noqa: N802
        self.recorder.begins.append(request)
        return orchd_pb2.BeginSagaResponse(saga_id=request.begin.saga_id)

    def PrepareStep(self, request, context):  # noqa: N802
        self.recorder.prepares.append(request)
        return orchd_pb2.PrepareStepResponse(
            status=orchd_pb2.PREPARE_STATUS_PREPARED, attempt=1
        )

    def CompleteStep(self, request, context):  # noqa: N802
        self.recorder.completes.append(request)
        return orchd_pb2.CompleteStepResponse()

    def RecordAnswer(self, request, context):  # noqa: N802
        self.recorder.answers.append(request)
        return orchd_pb2.RecordAnswerResponse()

    def GetSaga(self, request, context):  # noqa: N802
        nxt = self._projections[0]
        if len(self._projections) > 1:
            self._projections = self._projections[1:]
        return orchd_pb2.GetSagaResponse(saga=nxt)


@pytest.fixture
def fake():
    """Start a fake daemon and hand back (recorder, target, configure)."""
    recorder = Recorder()
    holder: dict[str, Any] = {}

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))

    def configure(*, actions: dict[str, Any], projections: list[Any]) -> str:
        servicer = FakeOrchd(recorder, actions=actions, projections=projections)
        orchd_pb2_grpc.add_OrchestratorServiceServicer_to_server(servicer, server)
        port = server.add_insecure_port("127.0.0.1:0")
        server.start()
        holder["target"] = f"127.0.0.1:{port}"
        return holder["target"]

    yield recorder, configure
    server.stop(None)


def projection(saga_id: str, status, steps) -> orchd_pb2.SagaProjection:
    """A projection, spelled the way the daemon would spell it."""
    return orchd_pb2.SagaProjection(saga_id=saga_id, status=status, steps=steps)


def step_projection(
    step_id: str,
    status,
    *,
    awaiting_participant: bool = False,
    awaiting_compensation: bool = False,
    attempt: int = 0,
    pending_gates=(),
) -> orchd_pb2.StepProjection:
    return orchd_pb2.StepProjection(
        step_id=step_id,
        status=status,
        attempt=attempt,
        awaiting_participant=awaiting_participant,
        awaiting_compensation=awaiting_compensation,
        pending_gates=list(pending_gates),
    )
