"""A participant's signature over what it asks Janus to record.

The canonical encodings here are the Go package ``pkg/callersig``'s, byte for
byte: a domain string, then fields each written as their decimal byte length, a
colon, the bytes and a semicolon; lists as a count and their items; facts and
touches sorted first; enums by name. ``tests/callersig_vectors.json`` is the
same file ``pkg/callersig/testdata/vectors.json`` is, and both test suites check
it, so the two languages cannot drift apart without one of them failing.

What is signed is never the protobuf wire bytes: two languages need not
serialise a message alike, and a signature only its own language can check is
one an auditor cannot.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from janus.v1 import common_pb2, gate_pb2, jtp_pb2

_ANSWER = "janus/answer/v1"
_RESULT = "janus/result/v1"
_PREPARE = "janus/prepare/v1"
_BEGIN = "janus/begin/v1"


class _Enc:
    def __init__(self) -> None:
        self.b = bytearray()

    def s(self, v: str | bytes) -> None:
        raw = v.encode() if isinstance(v, str) else v
        self.b += str(len(raw)).encode() + b":" + raw + b";"

    def u(self, v: int) -> None:
        self.s(str(v))

    def x(self, v: bytes) -> None:
        self.s(v.hex())

    def n(self, count: int) -> None:
        self.u(count)

    def facts(self, facts: Iterable[gate_pb2.Fact]) -> None:
        rows: list[tuple[str, str, str]] = []
        for f in facts:
            which = f.WhichOneof("value")
            if which == "text":
                rows.append((f.key, "text", f.text))
            elif which == "number":
                rows.append((f.key, "number", str(f.number)))
            elif which == "flag":
                rows.append((f.key, "flag", "true" if f.flag else "false"))
            else:
                rows.append((f.key, "none", ""))
        rows.sort()
        self.n(len(rows))
        for row in rows:
            for field in row:
                self.s(field)

    def touches(self, touches: Iterable[common_pb2.ResourceTouch]) -> None:
        rows = sorted(
            (t.resource_id, common_pb2.ResourceTouch.Mode.Name(t.mode), str(t.frontier_seq))
            for t in touches
        )
        self.n(len(rows))
        for row in rows:
            for field in row:
                self.s(field)


def answer(a: gate_pb2.GateAnswer) -> bytes:
    e = _Enc()
    e.s(_ANSWER)
    e.s(a.saga_id)
    e.s(a.step_id)
    e.s(a.requirement_id)
    e.u(a.attempt)
    e.s(a.actor.participant.id)
    e.s(a.actor.human_subject)
    e.s(common_pb2.Verdict.Name(a.verdict))
    e.s(a.reason)
    e.n(len(a.roles))
    for r in a.roles:
        e.s(r)
    e.s(a.auth_ref)
    return bytes(e.b)


def result(r: jtp_pb2.StepResult) -> bytes:
    e = _Enc()
    e.s(_RESULT)
    e.s(r.saga_id)
    e.s(r.step_id)
    e.u(r.attempt)
    e.s(common_pb2.Outcome.Status.Name(r.outcome.status))
    e.s(r.outcome.code)
    e.s(r.outcome.message)
    e.x(r.result_hash)
    e.s(r.result_ref)
    e.facts(r.facts)
    e.touches(r.touches)
    return bytes(e.b)


def prepare(
    saga_id: str,
    step_id: str,
    facts: Iterable[gate_pb2.Fact],
    spawns: jtp_pb2.ChildSaga | None,
) -> bytes:
    e = _Enc()
    e.s(_PREPARE)
    e.s(saga_id)
    e.s(step_id)
    e.facts(facts)
    child = spawns if spawns is not None else jtp_pb2.ChildSaga()
    e.s(child.saga_id)
    e.s(common_pb2.ChildCommitMode.Name(child.commit_mode))
    return bytes(e.b)


def begin(b: jtp_pb2.SagaBegin) -> bytes:
    e = _Enc()
    e.s(_BEGIN)
    e.s(b.saga_id)
    i = b.intent
    e.s(i.intent_id)
    e.s(i.principal)
    e.s(i.originator)
    e.s(i.mandate_ref)
    e.s(i.scope)
    e.s(str(i.expires_at_unix_nanos))
    e.s(b.mode)
    e.s(b.parent.saga_id)
    e.s(b.parent.step_id)
    e.s(common_pb2.ChildCommitMode.Name(b.parent.commit_mode))
    e.n(len(b.plan))
    for st in b.plan:
        e.s(st.step_id)
        e.s(st.participant)
        e.s(st.action)
        e.s(common_pb2.EffectClass.Name(st.effect_class))
        e.n(len(st.depends_on))
        for d in st.depends_on:
            e.s(d)
        e.s(st.compensation_action)
        e.u(st.max_retries)
    pins: Mapping[str, str] = b.manifest_pins
    e.n(len(pins))
    for k in sorted(pins):
        e.s(k)
        e.s(pins[k])
    return bytes(e.b)


@dataclass(frozen=True)
class Signer:
    """A participant's signing key: signs as that participant."""

    participant: str
    key: Ed25519PrivateKey

    @classmethod
    def from_seed(cls, participant: str, seed: bytes) -> Signer:
        return cls(participant, Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_key(self) -> str:
        """The key as a manifest declares it: ``ed25519:<hex>``."""
        raw = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return "ed25519:" + raw.hex()

    def sign(self, canonical: bytes) -> common_pb2.ParticipantSignature:
        return common_pb2.ParticipantSignature(
            participant_id=self.participant,
            public_key=self.public_key,
            signature=self.key.sign(canonical),
        )
