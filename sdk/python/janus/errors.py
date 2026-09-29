"""What this SDK refuses, and what it is told."""

from __future__ import annotations


class JanusError(Exception):
    """Base class, so a caller can catch everything this SDK raises."""


class DeclarationError(JanusError):
    """A saga contradicts itself, or contradicts the registry.

    Raised before anything begins. That is the whole point of it: the same
    contradiction found at admission is a refused saga somebody has to explain,
    and found at a gate it is an incident.
    """


class RefusedError(JanusError):
    """The daemon refused something, and said why.

    A refusal is not a transport failure and must not be retried as one. It is
    an answer.
    """


class WaitingError(JanusError):
    """The saga is waiting for somebody outside this process.

    A person, or a validator. It is not an error in the sense of something
    having gone wrong, and it is raised rather than returned because a caller
    that ignored it would sit in a loop waiting for a step it cannot run.
    """


class StepError(JanusError):
    """Raised by a step handler to report that the work did not succeed.

    ``retryable`` is the distinction the saga engine acts on, and it is the
    caller's to make rather than something inferred from the exception type: a
    timeout talking to a payments API is retryable, and a payment the API
    refused is not. Retrying a refusal until the budget runs out is how a step
    becomes poison for a reason nobody chose.
    """

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable
