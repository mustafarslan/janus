"""The checks that need nothing but the declaration.

Every one of these fires at import, which is the point: a saga that contradicts
itself should be a mistake somebody reads in a stack trace, not a refusal
somebody reads in a log after a payment did not happen.
"""

from __future__ import annotations

import pytest

import janus


def test_an_effect_class_that_does_not_exist_is_refused() -> None:
    # Every gate matches on the effect class, so a misspelling does not mean
    # "unknown" -- it means "no rule applies", which is silence where a refusal
    # should be.
    with pytest.raises(janus.DeclarationError, match="is not an effect class"):

        @janus.step(participant="tool_payments", action="payments.wire", effect="COMPENSABLE ")
        def wire(self) -> None: ...


def test_a_compensable_step_must_name_its_inverse() -> None:
    with pytest.raises(janus.DeclarationError, match="names no compensation"):

        @janus.saga(
            name="s", principal="pr_bank", mandate_ref="mandate:x", scope="pay"
        )
        class Broken:
            @janus.step(
                participant="tool_payments", action="payments.wire", effect=janus.COMPENSABLE
            )
            def wire(self) -> None: ...


def test_a_declared_compensation_needs_code_to_run_it() -> None:
    # The class promises the effect can be taken back and names the action that
    # takes it, and there is nothing to call. That promise is exactly the kind
    # that reads as a control and is not one.
    with pytest.raises(janus.DeclarationError, match="no code to run it"):

        @janus.saga(
            name="s", principal="pr_bank", mandate_ref="mandate:x", scope="pay"
        )
        class Broken:
            @janus.step(
                participant="tool_payments",
                action="payments.wire",
                effect=janus.COMPENSABLE,
                compensation="payments.refund",
            )
            def wire(self) -> None: ...


def test_a_dependency_on_a_step_that_is_not_there_is_refused() -> None:
    with pytest.raises(janus.DeclarationError, match="not a step of this saga"):

        @janus.saga(
            name="s", principal="pr_bank", mandate_ref="mandate:x", scope="pay"
        )
        class Broken:
            @janus.step(
                participant="tool_payments",
                action="payments.quote",
                effect=janus.PURE,
                depends_on=("nope",),
            )
            def quote(self) -> None: ...


def test_a_saga_without_an_intent_is_refused() -> None:
    # A principal, a mandate and a scope are what a later reader checks the
    # saga was authorised by. A default for any of them would be a claim
    # nobody made.
    with pytest.raises(janus.DeclarationError):

        @janus.saga(name="s", principal="", mandate_ref="mandate:x", scope="pay")
        class Broken:
            @janus.step(
                participant="tool_payments", action="payments.quote", effect=janus.PURE
            )
            def quote(self) -> None: ...


def test_a_well_formed_saga_records_its_steps_in_source_order() -> None:
    @janus.saga(name="s", principal="pr_bank", mandate_ref="mandate:x", scope="pay")
    class Good:
        @janus.step(participant="tool_payments", action="payments.quote", effect=janus.PURE)
        def quote(self) -> None: ...

        @janus.step(
            participant="tool_payments",
            action="payments.wire",
            effect=janus.COMPENSABLE,
            compensation="payments.refund",
            depends_on=("quote",),
        )
        def wire(self) -> None: ...

        @janus.compensation(for_step="wire")
        def unwire(self) -> None: ...

    from janus._declare import declaration_of

    declared = declaration_of(Good)
    assert declared.order() == ["quote", "wire"]
    assert declared.steps["wire"].depends_on == ("quote",)
    assert "wire" in declared.compensations
