"""The check the phase plan calls a trap: a declaration the registry contradicts.

The daemon refuses such a plan at admission, from the log, and that refusal is
the enforcement. What this adds is when: before the saga exists, so the person
who wrote the wrong effect class reads a message about their code rather than a
message about a saga that has been created and refused.
"""

from __future__ import annotations

import pytest
from conftest import projection

import janus
from janus.v1 import common_pb2


@janus.saga(name="honest", principal="pr_bank", mandate_ref="mandate:x", scope="pay")
class Honest:
    @janus.step(participant="tool_payments", action="payments.quote", effect=janus.PURE)
    def quote(self, amount_minor: int) -> None: ...


@janus.saga(name="understated", principal="pr_bank", mandate_ref="mandate:x", scope="pay")
class Understated:
    # The manifest says payments.wire is COMPENSABLE. This says PURE, which is
    # the class no gate is attached to.
    @janus.step(participant="tool_payments", action="payments.wire", effect=janus.PURE)
    def wire(self, amount_minor: int) -> None: ...


def test_a_step_that_understates_its_effect_class_is_refused(fake) -> None:
    recorder, configure = fake
    target = configure(
        actions={"payments.wire": ("COMPENSABLE", "payments.refund")},
        # A projection the run could succeed against, deliberately. If the check
        # below is ever removed this test has to fail on its own assertion —
        # "the saga was begun anyway" — rather than on the fake running out of
        # answers, which would be a failure that says nothing.
        projections=[projection("sg_1", common_pb2.SAGA_STATE_COMMITTED, [])],
    )
    client = janus.connect(target, pins={"tool_payments": "1.0.0"})

    with pytest.raises(janus.DeclarationError, match="declares PURE"):
        client.run(Understated(), saga_id="sg_1", amount_minor=250)

    assert recorder.resolves, "the registry was never asked what the action does"
    assert not recorder.begins, (
        "the saga was begun anyway. Checking after beginning is the daemon's job and "
        "it does it; the whole value of checking here is that nothing exists yet"
    )


def test_a_step_invoking_an_action_the_participant_never_registered_is_refused(fake) -> None:
    recorder, configure = fake
    target = configure(
        actions={"payments.refund": ("REVERSIBLE", "")},
        projections=[projection("sg_2", common_pb2.SAGA_STATE_COMMITTED, [])],
    )
    client = janus.connect(target, pins={"tool_payments": "1.0.0"})

    with pytest.raises(janus.DeclarationError, match="may only be asked for what it registered"):
        client.run(Honest(), saga_id="sg_2", amount_minor=250)
    assert not recorder.begins


def test_a_participant_this_client_does_not_pin_is_refused(fake) -> None:
    _, configure = fake
    target = configure(
        actions={"payments.quote": ("PURE", "")},
        projections=[projection("sg_3", common_pb2.SAGA_STATE_COMMITTED, [])],
    )
    client = janus.connect(target, pins={})

    with pytest.raises(janus.DeclarationError, match="does not pin"):
        client.run(Honest(), saga_id="sg_3", amount_minor=250)


def test_an_honest_declaration_is_accepted_and_the_plan_carries_the_pin(fake) -> None:
    recorder, configure = fake
    target = configure(
        actions={"payments.quote": ("PURE", "")},
        projections=[
            projection("sg_4", common_pb2.SAGA_STATE_COMMITTED, []),
        ],
    )
    client = janus.connect(target, pins={"tool_payments": "1.0.0"})
    result = client.run(Honest(), saga_id="sg_4", amount_minor=250)

    assert result.committed
    begin = recorder.begins[0].begin
    assert begin.manifest_pins["tool_payments"] == "1.0.0", (
        "the plan must record which declaration it relied on, or nothing can be "
        "resolved at replay time"
    )
    assert begin.intent.principal == "pr_bank"


def test_a_suspended_version_is_refused(fake) -> None:
    # A withdrawn version still declares what it declares, so the effect-class
    # check alone would pass. Admission refuses the saga anyway; finding it here
    # is the difference between a message about the pin and a message about a
    # saga that has already been created and rejected.
    class SuspendedFake:
        pass

    recorder, configure = fake
    target = configure(
        actions={"payments.quote": ("PURE", "")},
        projections=[projection("sg_5", common_pb2.SAGA_STATE_COMMITTED, [])],
    )
    client = janus.connect(target, pins={"tool_payments": "1.0.0"})
    # The fake always answers ACTIVE, so this test drives the check directly
    # rather than pretending the fake models lifecycle state -- which is exactly
    # the modelling this suite refuses to put in a fake. The Go side proves the
    # daemon reports SUSPENDED; this proves the SDK acts on it.
    from janus.v1 import orchd_pb2

    resolved = orchd_pb2.ResolveParticipantResponse(
        participant_id="tool_payments", version="1.0.0", state="SUSPENDED"
    )
    client._rpc.ResolveParticipant = lambda _request: resolved  # noqa: SLF001

    with pytest.raises(janus.DeclarationError, match="which is SUSPENDED"):
        client.run(Honest(), saga_id="sg_5", amount_minor=250)
    assert not recorder.begins
