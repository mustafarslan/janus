"""What a saga declares about itself, recorded when the module is imported.

The decorators do not talk to anything. They record: this class is a saga, these
methods are its steps, each step runs a named action on a named participant and
claims an effect class. Nothing is checked here, because checking needs the
registry and the registry is behind the service.

That split is deliberate and is the answer to a trap this SDK exists to avoid.
A step that claims PURE for an action the participant's manifest says moves
money is a plan the daemon will refuse at admission -- correctly, but late, and
the person reading the refusal is holding a saga that already exists. So the
declarations are collected at import and checked the moment a client connects,
which is before anything begins and early enough to read as a mistake in the
code rather than an incident.

Fetching the manifest during decorator evaluation would be earlier still, and
would be worse: an import that opens a socket breaks test collection, offline
work, and every tool that imports a module to look at it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

from janus.errors import DeclarationError

# Effect classes, spelled as the manifest and the policy spell them.
PURE = "PURE"
REVERSIBLE = "REVERSIBLE"
COMPENSABLE = "COMPENSABLE"
IRREVERSIBLE_GATED = "IRREVERSIBLE_GATED"
IRREVERSIBLE_IMMEDIATE = "IRREVERSIBLE_IMMEDIATE"

_EFFECT_CLASSES = frozenset(
    {PURE, REVERSIBLE, COMPENSABLE, IRREVERSIBLE_GATED, IRREVERSIBLE_IMMEDIATE}
)

_STEP_ATTR = "__janus_step__"
_COMPENSATION_ATTR = "__janus_compensation_for__"
_SAGA_ATTR = "__janus_saga__"

F = TypeVar("F", bound=Callable[..., Any])


@dataclass(frozen=True)
class StepDeclaration:
    """One step, as its author declared it."""

    step_id: str
    participant: str
    action: str
    effect: str
    depends_on: tuple[str, ...] = ()
    compensation: str = ""
    max_retries: int = 0

    @property
    def needs_compensation(self) -> bool:
        """Whether the class obliges this step to name an inverse.

        REVERSIBLE and COMPENSABLE both promise the effect can be taken back,
        and a promise with nothing behind it is the shape of claim this whole
        system exists to replace. The irreversible classes name no inverse by
        definition; a gate stands in for one.
        """
        return self.effect in (REVERSIBLE, COMPENSABLE)


@dataclass
class SagaDeclaration:
    """A saga class, its steps, and the compensations attached to them."""

    name: str
    principal: str
    mandate_ref: str
    scope: str
    mode: str = "supervised"
    steps: dict[str, StepDeclaration] = field(default_factory=dict)
    # handlers maps a step id to the function that runs it, and compensations
    # to the function that undoes it.
    handlers: dict[str, Callable[..., Any]] = field(default_factory=dict)
    compensations: dict[str, Callable[..., Any]] = field(default_factory=dict)

    def order(self) -> list[str]:
        """Step ids in declaration order.

        Declaration order, not dependency order: the coordinator schedules from
        the plan's depends_on and this SDK must not have a second opinion about
        what may run when. This is only how the plan is written down.
        """
        return list(self.steps)


def saga(
    *,
    name: str,
    principal: str,
    mandate_ref: str,
    scope: str,
    mode: str = "supervised",
) -> Callable[[type], type]:
    """Declare a class as a saga.

    The intent fields are required rather than defaulted. A saga without a
    principal, a mandate and a scope is one nobody can later say was authorised,
    and inventing a plausible default for any of them would put a claim in the
    log that no human made.
    """
    if not name or not principal or not mandate_ref or not scope:
        raise DeclarationError(
            "a saga needs a name, a principal, a mandate_ref and a scope; each of them "
            "is something a later reader has to be able to check, and a default would "
            "be a claim nobody made"
        )

    def decorate(cls: type) -> type:
        declaration = SagaDeclaration(
            name=name, principal=principal, mandate_ref=mandate_ref, scope=scope, mode=mode
        )
        # Walk the class in definition order so the plan reads the way the
        # source does.
        for value in vars(cls).values():
            step_declaration = getattr(value, _STEP_ATTR, None)
            if step_declaration is not None:
                declaration.steps[step_declaration.step_id] = step_declaration
                declaration.handlers[step_declaration.step_id] = value
                continue
            undoes = getattr(value, _COMPENSATION_ATTR, None)
            if undoes is not None:
                declaration.compensations[undoes] = value
        _check_internally_consistent(declaration, cls.__name__)
        setattr(cls, _SAGA_ATTR, declaration)
        return cls

    return decorate


def step(
    *,
    participant: str,
    action: str,
    effect: str,
    step_id: str = "",
    depends_on: tuple[str, ...] = (),
    compensation: str = "",
    max_retries: int = 0,
) -> Callable[[F], F]:
    """Declare a method as a step of the enclosing saga."""
    if effect not in _EFFECT_CLASSES:
        raise DeclarationError(
            f"{effect!r} is not an effect class; it is one of "
            f"{', '.join(sorted(_EFFECT_CLASSES))}. The class is what every gate matches "
            f"on, so a misspelling would silently mean 'no rule applies'"
        )
    if not participant or not action:
        raise DeclarationError("a step needs a participant and an action")

    def decorate(fn: F) -> F:
        setattr(
            fn,
            _STEP_ATTR,
            StepDeclaration(
                step_id=step_id or fn.__name__,
                participant=participant,
                action=action,
                effect=effect,
                depends_on=tuple(depends_on),
                compensation=compensation,
                max_retries=max_retries,
            ),
        )
        return fn

    return decorate


def compensation(*, for_step: str) -> Callable[[F], F]:
    """Declare a method as the compensation for a step."""
    if not for_step:
        raise DeclarationError("a compensation has to say which step it undoes")

    def decorate(fn: F) -> F:
        setattr(fn, _COMPENSATION_ATTR, for_step)
        return fn

    return decorate


def declaration_of(obj: object) -> SagaDeclaration:
    """The declaration attached to a saga class or instance."""
    found = getattr(obj, _SAGA_ATTR, None)
    if not isinstance(found, SagaDeclaration):
        raise DeclarationError(
            f"{obj!r} is not a saga; decorate its class with @janus.saga(...)"
        )
    return found


def _check_internally_consistent(declaration: SagaDeclaration, class_name: str) -> None:
    """Refuse a saga that contradicts itself, before anything external is asked.

    These are the checks that need nothing but the declaration. The one that
    needs the registry -- does the effect class match what the participant says
    the action does -- happens when a client connects, because only then is
    there something to ask.
    """
    if not declaration.steps:
        raise DeclarationError(f"{class_name} is a saga with no steps")

    for step_id, declared in declaration.steps.items():
        for dependency in declared.depends_on:
            if dependency not in declaration.steps:
                raise DeclarationError(
                    f"{class_name}: step {step_id!r} depends on {dependency!r}, which is "
                    f"not a step of this saga"
                )
        if declared.needs_compensation and not declared.compensation:
            raise DeclarationError(
                f"{class_name}: step {step_id!r} is {declared.effect} and names no "
                f"compensation. That class is a promise the effect can be taken back, "
                f"and the promise has to name the action that takes it"
            )
        if declared.compensation and step_id not in declaration.compensations:
            raise DeclarationError(
                f"{class_name}: step {step_id!r} declares the compensating action "
                f"{declared.compensation!r} but nothing is decorated "
                f"@janus.compensation(for_step={step_id!r}), so there is no code to run it"
            )
