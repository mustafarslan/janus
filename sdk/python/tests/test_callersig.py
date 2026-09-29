"""The Python half of the caller-signature contract.

``callersig_vectors.json`` is a byte-for-byte copy of the Go package's
``pkg/callersig/testdata/vectors.json`` (a Go test asserts the two are
identical). If this fails, a signature made by the SDK would not verify in the
daemon, or one in the log would not verify for an auditor using Python.
"""

from __future__ import annotations

import json
from pathlib import Path

from google.protobuf import json_format

from janus import _callersig
from janus.v1 import gate_pb2, jtp_pb2, orchd_pb2

VECTORS = json.loads((Path(__file__).parent / "callersig_vectors.json").read_text())


def _canonical(kind: str, message: dict[str, object]) -> bytes:
    if kind == "answer":
        return _callersig.answer(json_format.ParseDict(message, gate_pb2.GateAnswer()))
    if kind == "result":
        return _callersig.result(json_format.ParseDict(message, jtp_pb2.StepResult()))
    if kind == "prepare":
        p = json_format.ParseDict(message, orchd_pb2.PrepareStepRequest())
        return _callersig.prepare(p.saga_id, p.step_id, p.facts,
                                  p.spawns if p.HasField("spawns") else None)
    if kind == "begin":
        return _callersig.begin(json_format.ParseDict(message, jtp_pb2.SagaBegin()))
    raise AssertionError(kind)


def test_the_canonical_encodings_match_go() -> None:
    for v in VECTORS["vectors"]:
        got = _canonical(v["kind"], v["message"]).hex()
        assert got == v["canonical_hex"], (
            f"{v['kind']}: the SDK encodes this message differently from pkg/callersig, "
            "so its signatures would not verify in the daemon"
        )


def test_the_signatures_match_go() -> None:
    signer = _callersig.Signer.from_seed("ag_credit_policy", bytes.fromhex(VECTORS["seed_hex"]))
    assert signer.public_key == VECTORS["public_key"]
    for v in VECTORS["vectors"]:
        sig = signer.sign(bytes.fromhex(v["canonical_hex"]))
        assert sig.signature.hex() == v["signature_hex"], v["kind"]
        assert sig.participant_id == "ag_credit_policy"
