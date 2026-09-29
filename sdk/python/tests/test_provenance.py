"""What a step says about what it produced and why.

These assert on what the SDK sent. That the daemon records it -- and refuses a
decision kind that is not a participant's -- is tested against the daemon.
"""

from __future__ import annotations

import pytest
from conftest import projection, step_projection

import janus
from janus.v1 import common_pb2, evidence_pb2


def _settled():
    return projection(
        "sg_p", common_pb2.SAGA_STATE_RUNNING,
        [step_projection("intake", common_pb2.STEP_STATE_SEALED)],
    )


def test_a_step_sends_what_it_produced_and_why_even_when_it_fails(fake) -> None:
    recorder, configure = fake
    target = configure(actions={}, projections=[_settled()])
    client = janus.connect(target, pins={})

    with (
        pytest.raises(janus.StepError),
        client.step("sg_p", "intake", applicant="acct_1") as report,
    ):
        report.decided(
            model="glm-5.3", model_version="cloud", temperature=0.7, seed=17,
            output_hash=b"out", output_ref="cas:out", parse_status="OK",
            grounds=["the application names an amount"],
            inputs=[("SYSTEM", b"prompt", "sha256:p"), ("USER", b"application", "sha256:a")],
        )
        report.produced(hash=b"res", ref="cas:res")
        # The model decided; the tool it chose then failed. That is the
        # provenance most worth having, so it must not be dropped.
        raise janus.StepError("the tool refused", retryable=False)

    assert len(recorder.completes) == 1
    sent = recorder.completes[0]
    assert sent.result.outcome.status == common_pb2.Outcome.STATUS_TERMINAL_ERROR
    assert sent.result.result_hash == b"res" and sent.result.result_ref == "cas:res"
    assert sent.HasField("provenance"), "a failed step's provenance was not sent"
    dpr = sent.provenance
    assert dpr.decision_kind == evidence_pb2.DecisionProvenanceRecord.DECISION_KIND_ACT
    assert (dpr.model.id, dpr.model.temperature, dpr.model.seed) == ("glm-5.3", 0.7, 17)
    assert dpr.output.hash == b"out"
    assert [g.claim for g in dpr.grounds] == ["the application names an amount"]
    assert [(i.role, i.hash) for i in dpr.inputs] == [
        (evidence_pb2.DecisionProvenanceRecord.Input.ROLE_SYSTEM, b"prompt"),
        (evidence_pb2.DecisionProvenanceRecord.Input.ROLE_USER, b"application"),
    ], "what the model was shown is not on the record"


def test_a_step_publishes_what_it_found(fake) -> None:
    recorder, configure = fake
    target = configure(actions={}, projections=[_settled()])
    client = janus.connect(target, pins={})
    with client.step("sg_p", "intake") as report:
        report.publish(approved=True, recommended_minor=250_000)
    sent = {f.key: f for f in recorder.completes[0].result.facts}
    assert sent["approved"].flag is True
    assert sent["recommended_minor"].number == 250_000


def test_a_step_that_says_nothing_sends_no_provenance(fake) -> None:
    recorder, configure = fake
    target = configure(actions={}, projections=[_settled()])
    client = janus.connect(target, pins={})
    with client.step("sg_p", "intake"):
        pass
    assert not recorder.completes[0].HasField("provenance")


def test_an_input_names_a_real_role() -> None:
    with pytest.raises(ValueError, match="role"):
        janus.StepReport().decided(model="m", inputs=[("ATTACKER", b"x", "r")])


def test_a_step_cannot_record_the_gates_decision() -> None:
    with pytest.raises(ValueError, match="PLAN, ACT or ROUTE"):
        janus.StepReport().decided(model="m", kind="VALIDATE")


def test_a_host_learns_which_compensation_is_owed_and_reports_it(fake) -> None:
    recorder, configure = fake
    owed = projection(
        "sg_c", common_pb2.SAGA_STATE_COMPENSATING,
        [
            step_projection("disburse", common_pb2.STEP_STATE_SEALED, awaiting_compensation=True),
            step_projection("notify", common_pb2.STEP_STATE_FAILED),
        ],
    )
    target = configure(actions={}, projections=[owed])
    client = janus.connect(target, pins={})
    assert client.compensations_due("sg_c") == ["disburse"]
    with client.compensate("sg_c", "disburse"):
        pass
    sent = recorder.completes[-1].result
    assert sent.step_id == "disburse~undo"
    assert sent.outcome.status == common_pb2.Outcome.STATUS_OK


def test_a_failed_compensation_is_reported_as_failed(fake) -> None:
    recorder, configure = fake
    target = configure(actions={}, projections=[_settled()])
    client = janus.connect(target, pins={})
    with pytest.raises(janus.StepError), client.compensate("sg_c", "disburse"):
        raise janus.StepError("the refund bounced", retryable=False)
    assert recorder.completes[-1].result.outcome.status == common_pb2.Outcome.STATUS_TERMINAL_ERROR
