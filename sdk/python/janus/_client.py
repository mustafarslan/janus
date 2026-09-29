"""Talking to janus-orchd.

The client is thin on purpose. It builds a plan from what a saga declared, hands
it to the daemon, and then does exactly what the projection tells it to: run the
step that is waiting, report what happened, run the compensation that is
waiting, report that. It holds no opinion about what may run when -- the
coordinator schedules from the plan, and a second scheduler here would be a
second answer to the same question.

What it does hold an opinion about is its own declarations. Before anything
begins it asks the registry what each participant says its actions do, and
refuses a saga that contradicts it.
"""

from __future__ import annotations

import contextlib
import inspect
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import grpc

from janus import _callersig
from janus._callersig import Signer
from janus._declare import SagaDeclaration, StepDeclaration, declaration_of
from janus.errors import DeclarationError, RefusedError, StepError, WaitingError
from janus.v1 import common_pb2, evidence_pb2, gate_pb2, jtp_pb2, orchd_pb2, orchd_pb2_grpc

# Terminal saga states: nothing more will happen without a person.
_TERMINAL = frozenset(
    {
        common_pb2.SAGA_STATE_COMMITTED,
        common_pb2.SAGA_STATE_COMPENSATED,
        common_pb2.SAGA_STATE_QUARANTINE,
    }
)

# The driver's bound. A client that could loop forever would turn a coordinator
# bug into a hung process rather than an error somebody can read.
_MAX_TURNS = 2000


@dataclass
class Result:
    """How a saga finished."""

    saga_id: str
    status: str
    abort_reason: str = ""
    quarantine_reason: str = ""

    @property
    def committed(self) -> bool:
        return bool(self.status == common_pb2.SagaState.Name(common_pb2.SAGA_STATE_COMMITTED))


_DECISION_KINDS = {
    "PLAN": evidence_pb2.DecisionProvenanceRecord.DECISION_KIND_PLAN,
    "ACT": evidence_pb2.DecisionProvenanceRecord.DECISION_KIND_ACT,
    "ROUTE": evidence_pb2.DecisionProvenanceRecord.DECISION_KIND_ROUTE,
}


class StepReport:
    """What a step produced and why, filled in by the step's body.

    `Client.step` yields one. Whatever the body attaches is sent with the
    step's outcome -- on every outcome, including a failure: a model that
    decided and a tool that then failed is exactly the provenance somebody
    will want to read later.
    """

    def __init__(self) -> None:
        self.result_hash = b""
        self.result_ref = ""
        self.provenance: evidence_pb2.DecisionProvenanceRecord | None = None
        self.published: dict[str, Any] = {}

    def publish(self, **facts: Any) -> None:
        """Put what the step found on the record, for a later step's gate.

        A later step's gate reads these as `result.<this step>.<key>`, a
        namespace no step can declare into: the step that pays never gets to
        state the approval it is paid on. A model's recommendation is
        exactly such a finding.
        """
        self.published.update(facts)

    def produced(self, *, hash: bytes = b"", ref: str = "") -> None:  # noqa: A002
        """Name what the step produced, by hash and by content-store reference.

        The hash is the caller's to compute; the SDK does not choose an
        algorithm on a deployment's behalf.
        """
        self.result_hash = hash
        self.result_ref = ref

    def decided(
        self,
        *,
        model: str,
        model_version: str = "",
        temperature: float = 0.0,
        top_p: float = 0.0,
        seed: int = 0,
        output_hash: bytes = b"",
        output_ref: str = "",
        schema_id: str = "",
        parse_status: str = "",
        grounds: tuple[str, ...] | list[str] = (),
        inputs: tuple[tuple[str, bytes, str], ...] | list[tuple[str, bytes, str]] = (),
        kind: str = "ACT",
    ) -> None:
        """Record the decision behind this step: which model, how it was
        sampled, what it output, and the claims it rests on.

        This is plan section 10.1's "every model output is an event": the
        daemon records it immediately before the result and the result cites
        it. Its identity is stamped by the daemon, not chosen here.

        `inputs` are what the model was shown, as (role, hash, reference) with
        role one of SYSTEM, CONTEXT, TOOL_RESULT, MEMORY or USER. Without them
        the record says what the model said and not what it was answering --
        and an injected instruction is only attributable if the text that
        carried it is named.
        """
        if kind not in _DECISION_KINDS:
            raise ValueError(f"a step records a PLAN, ACT or ROUTE decision, not {kind!r}")
        roles = evidence_pb2.DecisionProvenanceRecord.Input.Role
        for role, _, _ in inputs:
            if role not in {"SYSTEM", "CONTEXT", "TOOL_RESULT", "MEMORY", "USER"}:
                raise ValueError(f"an input's role is SYSTEM, CONTEXT, TOOL_RESULT, MEMORY or "
                                 f"USER, not {role!r}")
        dpr = evidence_pb2.DecisionProvenanceRecord
        self.provenance = dpr(
            decision_kind=_DECISION_KINDS[kind],
            model=dpr.ModelRef(
                id=model, version=model_version, temperature=temperature,
                top_p=top_p, seed=seed,
            ),
            output=dpr.Output(
                hash=output_hash, cas_ref=output_ref, schema_id=schema_id,
                parse_status=parse_status,
            ),
            grounds=[dpr.Ground(claim=g, source="model") for g in grounds],
            inputs=[
                dpr.Input(role=roles.Value(f"ROLE_{role}"), hash=digest, cas_ref=ref)
                for role, digest, ref in inputs
            ],
        )


class Client:
    """A connection to one janus-orchd."""

    def __init__(
        self,
        channel: grpc.Channel,
        *,
        pins: dict[str, str],
        signers: dict[str, Signer] | None = None,
    ) -> None:
        self._rpc = orchd_pb2_grpc.OrchestratorServiceStub(channel)
        # signers are the participants this client signs as, by id.
        # A daemon checks each signature against the keys the participant's
        # manifest declares and keeps it in the record; a participant whose
        # manifest declares a key is refused unsigned. One process hosting
        # several participants holds one key per participant and signs each
        # call as the participant it is for -- not one key for all of them.
        self._signers = dict(signers or {})
        self._declared: dict[str, SagaDeclaration] = {}
        # pins names the manifest version each participant is pinned to. It is
        # required rather than resolved: a saga records which declaration it
        # relied on, and a client that picked "whatever is active" would record
        # a pin it never checked.
        self._pins = dict(pins)
        self._checked: set[str] = set()
        self._answerers: dict[
            str, Callable[[str, str, str, dict[str, Any]], tuple[bool, str]]
        ] = {}
        # on_answer is a hook for a validator that wants to say what it did.
        # Answering silently is correct for the log and unhelpful for the
        # operator watching a process that is supposed to be doing something.
        self.on_answer: Callable[[str, str, str, bool], None] | None = None

    # ---- declarations -----------------------------------------------------

    def register(self, saga: object) -> None:
        """Check a saga's declarations against the registry.

        This is the check the trap in the phase plan asks for. A step claiming
        PURE for an action the manifest says moves money is a plan the daemon
        will refuse at admission; finding it here means finding it before the
        saga exists, which is the difference between a mistake in the code and
        an incident in the log.

        The daemon still re-checks at admission, from the log. This is a
        courtesy that fails fast, not the enforcement -- a client that treated
        it as permission would be trusting a value it was handed.
        """
        declaration = declaration_of(saga)
        for declared in declaration.steps.values():
            version = self._pins.get(declared.participant)
            if not version:
                raise DeclarationError(
                    f"step {declared.step_id!r} runs on {declared.participant!r}, which "
                    f"this client does not pin. A step whose manifest version is not "
                    f"recorded cannot be resolved at replay time"
                )
            self._check_against_manifest(declared, version)

    def _check_against_manifest(self, declared: StepDeclaration, version: str) -> None:
        key = f"{declared.participant}@{version}/{declared.action}"
        if key in self._checked:
            return
        try:
            resolved = self._rpc.ResolveParticipant(
                orchd_pb2.ResolveParticipantRequest(
                    participant_id=declared.participant, version=version
                )
            )
        except grpc.RpcError as err:
            raise DeclarationError(
                f"cannot resolve {declared.participant}@{version}: {_detail(err)}"
            ) from err

        # A version that is suspended or retired still declares what it
        # declares, and admission will refuse a saga that pins it. Checking here
        # is the same courtesy as the effect-class check and for the same
        # reason: the refusal is more useful before the saga exists than after.
        #
        # This is precisely the case the daemon re-folds the registry for on
        # every call. A client that skipped it would pre-check happily against a
        # manifest that had been withdrawn between one saga and the next.
        if resolved.state != "ACTIVE":
            raise DeclarationError(
                f"step {declared.step_id!r} pins {declared.participant}@{version}, which "
                f"is {resolved.state}; only an active version may be pinned by a new saga"
            )

        actions = {a.name: a for a in resolved.actions}
        found = actions.get(declared.action)
        if found is None:
            raise DeclarationError(
                f"step {declared.step_id!r} invokes {declared.action!r} on "
                f"{declared.participant}@{version}, which declares "
                f"{', '.join(sorted(actions)) or 'nothing'}. A participant may only be "
                f"asked for what it registered"
            )
        want = common_pb2.EffectClass.Value(f"EFFECT_CLASS_{declared.effect}")
        if found.effect_class != want:
            raise DeclarationError(
                f"step {declared.step_id!r} declares {declared.effect} for "
                f"{declared.action!r}, which {declared.participant}@{version} registered "
                f"as {common_pb2.EffectClass.Name(found.effect_class)[len('EFFECT_CLASS_'):]}. "
                f"Janus gates by effect class, so understating it evades a gate and "
                f"overstating it leaves two contradictory accounts of what the action does"
            )
        self._checked.add(key)

    # ---- answering --------------------------------------------------------

    def answer_as(
        self,
        participant: str,
        decide: Callable[[str, str, str, dict[str, Any]], tuple[bool, str]],
    ) -> None:
        """Register this client as able to answer gates for a participant.

        A VALIDATOR gate is answered by the participants the policy names, and
        this is how one of them says so. `decide` is called with the saga, step,
        requirement and the facts the question is about, and returns a verdict
        and a reason.

        The facts are the ones the gate decides on -- what the step proposed or
        ran on, what Janus derives from the saga's record (`step.action`,
        `intent.principal`, ...), and what earlier steps published under
        `result.<step>.<key>`. The answer is bound to exactly these: an answer
        about one proposal is never counted for another. A validator
        that approves without reading them is a rubber stamp, and before they
        were carried here it could not have been anything else.

        The reason is not decoration. A validator that passes an effect without
        saying why leaves a record that is technically complete and useless to
        the person who has to explain the payment later.
        """
        self._answerers[participant] = decide

    def _on_answer(self, saga_id: str, step_id: str, requirement: str, approve: bool) -> None:
        if self.on_answer is not None:
            self.on_answer(saga_id, step_id, requirement, approve)

    def _settle_gates(self, saga_id: str) -> None:
        """Answer any pending gate this client is a named party to.

        Bounded, and deliberately not a wait: this client answers what it can
        and returns. A gate waiting on a person, or on a validator that is not
        this process, stays waiting — an SDK that blocked until somebody
        approved would be a client holding a connection open across a human's
        lunch.
        """
        for _ in range(16):
            projection = self._rpc.GetSaga(orchd_pb2.GetSagaRequest(saga_id=saga_id)).saga
            answered = False
            for step in projection.steps:
                for pending in step.pending_gates:
                    for participant in pending.answerable_by:
                        decide = self._answerers.get(participant)
                        if decide is None:
                            continue
                        approve, reason = decide(
                            saga_id,
                            step.step_id,
                            pending.requirement_id,
                            _facts_as_dict(pending.facts),
                        )
                        answer = gate_pb2.GateAnswer(
                            saga_id=saga_id,
                            step_id=step.step_id,
                            requirement_id=pending.requirement_id,
                            attempt=pending.attempt,
                            actor=common_pb2.Actor(
                                participant=common_pb2.ParticipantRef(id=participant)
                            ),
                            verdict=(
                                common_pb2.VERDICT_PASS if approve else common_pb2.VERDICT_FAIL
                            ),
                            reason=reason,
                        )
                        signer = self._signers.get(participant)
                        if signer is not None:
                            answer.signature.CopyFrom(signer.sign(_callersig.answer(answer)))
                        self._rpc.RecordAnswer(orchd_pb2.RecordAnswerRequest(answer=answer))
                        self._on_answer(saga_id, step.step_id, pending.requirement_id, approve)
                        answered = True
                        break
            if not answered:
                return

    # ---- running ----------------------------------------------------------

    @contextlib.contextmanager
    def step(self, saga_id: str, step_id: str, **facts: Any) -> Iterator[StepReport]:
        """Run one step of a saga that is already under way.

        This is the lower-level path `run` is built on, and it exists for hosts
        that own their own control flow — a LangGraph graph, a workflow engine,
        anything whose loop is not this SDK's to drive. The step is prepared
        with the facts before the body runs and reported after it, which is the
        same order and the same guarantee `run` gives: what a gate decides on is
        what the body was about to do.
        """
        signer = self._signer_for(saga_id, step_id)
        prepared = self._rpc.PrepareStep(
            self._prepare_request(signer, saga_id, step_id, _facts_from(facts))
        )
        if prepared.status == orchd_pb2.PREPARE_STATUS_GATED:
            raise WaitingError(
                f"step {step_id!r} of {saga_id} is waiting for a decision: {prepared.reason}"
            )
        if prepared.status != orchd_pb2.PREPARE_STATUS_PREPARED:
            raise RefusedError(
                f"step {step_id!r} of {saga_id} will not run: {prepared.reason}"
            )

        status = common_pb2.Outcome.STATUS_OK
        report = StepReport()
        try:
            yield report
        except StepError as failure:
            status = (
                common_pb2.Outcome.STATUS_RETRYABLE_ERROR
                if failure.retryable
                else common_pb2.Outcome.STATUS_TERMINAL_ERROR
            )
            raise
        finally:
            self._rpc.CompleteStep(
                orchd_pb2.CompleteStepRequest(
                    result=_signed_result(
                        signer,
                        jtp_pb2.StepResult(
                            saga_id=saga_id,
                            step_id=step_id,
                            attempt=prepared.attempt,
                            outcome=common_pb2.Outcome(status=status),
                            result_hash=report.result_hash,
                            result_ref=report.result_ref,
                            facts=_facts_from(report.published),
                        ),
                    ),
                    provenance=report.provenance,
                )
            )
            self._settle_gates(saga_id)

    def compensations_due(self, saga_id: str) -> list[str]:
        """The steps whose compensation the coordinator is waiting for.

        For a host that drives steps itself: `run` does this on its own. The
        answer comes from the projection, so it survives the host restarting --
        a compensation owed before a crash is still owed after it.
        """
        projection = self._rpc.GetSaga(orchd_pb2.GetSagaRequest(saga_id=saga_id)).saga
        return [s.step_id for s in projection.steps if s.awaiting_compensation]

    @contextlib.contextmanager
    def compensate(self, saga_id: str, step_id: str) -> Iterator[None]:
        """Run one compensation and report how it went.

        The body undoes the step's effect. If it raises StepError the undo is
        reported as failed, which is what puts the saga in QUARANTINE for a
        person rather than claiming an effect was reversed when it was not.
        """
        status = common_pb2.Outcome.STATUS_OK
        try:
            yield
        except StepError:
            status = common_pb2.Outcome.STATUS_TERMINAL_ERROR
            raise
        finally:
            self._rpc.CompleteStep(
                orchd_pb2.CompleteStepRequest(
                    result=_signed_result(
                        self._signer_for(saga_id, step_id),
                        jtp_pb2.StepResult(
                            saga_id=saga_id,
                            step_id=f"{step_id}~undo",
                            outcome=common_pb2.Outcome(status=status),
                        ),
                    )
                )
            )

    def begin(self, saga: object, saga_id: str) -> None:
        """Admit and record a plan without driving it.

        For a host that will run the steps itself through `step` above.
        """
        declaration = declaration_of(saga)
        self.register(saga)
        self._declared[saga_id] = declaration
        try:
            self._rpc.BeginSaga(self._begin_request(declaration, saga_id))
        except grpc.RpcError as err:
            if err.code() is not grpc.StatusCode.ALREADY_EXISTS:
                raise RefusedError(f"beginning {saga_id}: {_detail(err)}") from err

    def status(self, saga_id: str) -> Result:
        """How a saga stands right now."""
        projection = self._rpc.GetSaga(orchd_pb2.GetSagaRequest(saga_id=saga_id)).saga
        return Result(
            saga_id=saga_id,
            status=common_pb2.SagaState.Name(projection.status),
            abort_reason=projection.abort_reason,
            quarantine_reason=projection.quarantine_reason,
        )


    def run(self, saga: object, *, saga_id: str, **arguments: Any) -> Result:
        """Begin a saga and drive it until it can go no further.

        The arguments are matched to each step by name, from the handler's own
        signature, and the ones a step takes become the facts it declares. That
        is not a convenience: the facts a gate decides on are then literally the
        arguments the step runs on, so a step cannot declare one amount and act
        on another.
        """
        declaration = declaration_of(saga)
        self.register(saga)

        self._declared[saga_id] = declaration
        try:
            self._rpc.BeginSaga(self._begin_request(declaration, saga_id))
        except grpc.RpcError as err:
            if err.code() is not grpc.StatusCode.ALREADY_EXISTS:
                raise RefusedError(f"beginning {saga_id}: {_detail(err)}") from err
            # Resuming a saga this client, or its predecessor, already started.

        for _ in range(_MAX_TURNS):
            projection = self._rpc.GetSaga(orchd_pb2.GetSagaRequest(saga_id=saga_id)).saga
            if projection.status in _TERMINAL:
                return Result(
                    saga_id=saga_id,
                    status=common_pb2.SagaState.Name(projection.status),
                    abort_reason=projection.abort_reason,
                    quarantine_reason=projection.quarantine_reason,
                )
            if not self._act_once(saga, declaration, saga_id, projection, arguments):
                _raise_stuck(saga_id, projection)
        raise RefusedError(f"saga {saga_id} did not settle within {_MAX_TURNS} turns")

    def _act_once(
        self,
        saga: object,
        declaration: SagaDeclaration,
        saga_id: str,
        projection: orchd_pb2.SagaProjection,
        arguments: dict[str, Any],
    ) -> bool:
        """Do the single next thing the projection says is this client's to do."""
        for step in projection.steps:
            if step.awaiting_compensation:
                self._compensate(saga, declaration, saga_id, step.step_id)
                return True
            if not step.awaiting_participant:
                continue
            if step.status == common_pb2.STEP_STATE_PREPARED:
                self._report(saga, declaration, saga_id, step, arguments)
                return True
            self._prepare(declaration, saga_id, step, arguments)
            return True
        return False

    def _prepare(
        self,
        declaration: SagaDeclaration,
        saga_id: str,
        step: orchd_pb2.StepProjection,
        arguments: dict[str, Any],
    ) -> None:
        handler = declaration.handlers[step.step_id]
        facts = _facts_for(handler, arguments)
        response = self._rpc.PrepareStep(
            self._prepare_request(self._signers.get(step.participant), saga_id, step.step_id, facts)
        )
        if response.status == orchd_pb2.PREPARE_STATUS_PREPARED:
            return
        if response.status == orchd_pb2.PREPARE_STATUS_GATED:
            raise WaitingError(
                f"step {step.step_id!r} of {saga_id} is waiting for a decision: "
                f"{response.reason}"
            )
        raise RefusedError(
            f"step {step.step_id!r} of {saga_id} will not run: {response.reason}"
        )

    def _report(
        self,
        saga: object,
        declaration: SagaDeclaration,
        saga_id: str,
        step: orchd_pb2.StepProjection,
        arguments: dict[str, Any],
    ) -> None:
        handler = declaration.handlers[step.step_id]
        status = common_pb2.Outcome.STATUS_OK
        try:
            handler(saga, **_call_arguments(handler, arguments))
        except StepError as failure:
            status = (
                common_pb2.Outcome.STATUS_RETRYABLE_ERROR
                if failure.retryable
                else common_pb2.Outcome.STATUS_TERMINAL_ERROR
            )
        self._rpc.CompleteStep(
            orchd_pb2.CompleteStepRequest(
                result=_signed_result(
                    self._signers.get(step.participant),
                    jtp_pb2.StepResult(
                        saga_id=saga_id,
                        step_id=step.step_id,
                        attempt=step.attempt,
                        outcome=common_pb2.Outcome(status=status),
                    ),
                )
            )
        )

    def _compensate(
        self, saga: object, declaration: SagaDeclaration, saga_id: str, step_id: str
    ) -> None:
        handler = declaration.compensations.get(step_id)
        status = common_pb2.Outcome.STATUS_OK
        if handler is None:
            # Declared as compensable with nothing to run it. The declaration
            # check refuses this at import, so reaching it means the saga was
            # begun by something else -- and saying so truthfully is what puts
            # it in QUARANTINE for a person rather than silently claiming the
            # effect was reversed.
            status = common_pb2.Outcome.STATUS_TERMINAL_ERROR
        else:
            try:
                handler(saga)
            except StepError:
                status = common_pb2.Outcome.STATUS_TERMINAL_ERROR
        self._rpc.CompleteStep(
            orchd_pb2.CompleteStepRequest(
                result=_signed_result(
                    self._signers.get(declaration.steps[step_id].participant),
                    jtp_pb2.StepResult(
                        saga_id=saga_id,
                        step_id=f"{step_id}~undo",
                        outcome=common_pb2.Outcome(status=status),
                    ),
                )
            )
        )

    # ---- signing -------------------------------------------------

    def _signer_for(self, saga_id: str, step_id: str) -> Signer | None:
        """The signer for a step's participant, if this client holds one."""
        declaration = self._declared.get(saga_id)
        if declaration is not None and step_id in declaration.steps:
            return self._signers.get(declaration.steps[step_id].participant)
        if not self._signers:
            return None
        projection = self._rpc.GetSaga(orchd_pb2.GetSagaRequest(saga_id=saga_id)).saga
        for step in projection.steps:
            if step.step_id == step_id:
                return self._signers.get(step.participant)
        return None

    def _prepare_request(
        self,
        signer: Signer | None,
        saga_id: str,
        step_id: str,
        facts: list[gate_pb2.Fact],
    ) -> orchd_pb2.PrepareStepRequest:
        request = orchd_pb2.PrepareStepRequest(saga_id=saga_id, step_id=step_id, facts=facts)
        if signer is not None:
            request.signature.CopyFrom(
                signer.sign(_callersig.prepare(saga_id, step_id, facts, None))
            )
        return request

    def _begin_request(
        self, declaration: SagaDeclaration, saga_id: str
    ) -> orchd_pb2.BeginSagaRequest:
        """A saga begun, signed by one of its own participants this client holds."""
        begin = self._plan(declaration, saga_id)
        request = orchd_pb2.BeginSagaRequest(begin=begin)
        for declared in declaration.steps.values():
            signer = self._signers.get(declared.participant)
            if signer is not None:
                request.signature.CopyFrom(signer.sign(_callersig.begin(begin)))
                break
        return request

    def _plan(self, declaration: SagaDeclaration, saga_id: str) -> jtp_pb2.SagaBegin:
        plan = [
            jtp_pb2.PlannedStep(
                step_id=declared.step_id,
                participant=declared.participant,
                action=declared.action,
                effect_class=common_pb2.EffectClass.Value(
                    f"EFFECT_CLASS_{declared.effect}"
                ),
                depends_on=list(declared.depends_on),
                compensation_action=declared.compensation,
                max_retries=declared.max_retries,
            )
            for declared in declaration.steps.values()
        ]
        return jtp_pb2.SagaBegin(
            saga_id=saga_id,
            mode=declaration.mode,
            intent=common_pb2.Intent(
                intent_id=f"in_{saga_id}",
                principal=declaration.principal,
                originator=f"sdk:python/{declaration.name}",
                mandate_ref=declaration.mandate_ref,
                scope=declaration.scope,
            ),
            plan=plan,
            manifest_pins={
                declared.participant: self._pins[declared.participant]
                for declared in declaration.steps.values()
            },
        )


def connect(
    target: str,
    *,
    pins: dict[str, str],
    signers: dict[str, Signer] | None = None,
) -> Client:
    """Connect to a janus-orchd.

    `signers` are the participants this client signs as: who a caller
    is, is established by a signature over what it asks to have recorded, with
    a key the participant's manifest declares -- not by the channel. The
    channel itself is not encrypted; that is a deployment's to add, and a
    channel that quietly claimed to be secure would be worse than one that is
    obviously not.
    """
    return Client(grpc.insecure_channel(target), pins=pins, signers=signers)


def load_signer(participant: str, key_path: str | Path) -> Signer:
    """Load a participant's key from a file `janus-keys gen` wrote."""
    data = json.loads(Path(key_path).read_text())
    if data.get("alg") != "ed25519":
        raise DeclarationError(f"{key_path}: key algorithm {data.get('alg')!r} is not ed25519")
    return Signer.from_seed(participant, bytes.fromhex(data["seed_hex"]))


def _signed_result(signer: Signer | None, result: jtp_pb2.StepResult) -> jtp_pb2.StepResult:
    if signer is not None:
        result.signature.CopyFrom(signer.sign(_callersig.result(result)))
    return result


def _facts_as_dict(facts: Any) -> dict[str, Any]:
    """The facts a question carries, as plain Python values."""
    out: dict[str, Any] = {}
    for f in facts:
        kind = f.WhichOneof("value")
        out[f.key] = getattr(f, kind) if kind else None
    return out


def _facts_from(values: dict[str, Any]) -> list[gate_pb2.Fact]:
    """Facts from an explicit mapping, for the `step` path."""
    facts = []
    for name, value in values.items():
        # bool before int: in Python a bool *is* an int, and a flag sent as a
        # number would be compared by a rule that meant something else.
        if isinstance(value, bool):
            facts.append(gate_pb2.Fact(key=name, flag=value))
        elif isinstance(value, int):
            facts.append(gate_pb2.Fact(key=name, number=value))
        elif isinstance(value, str):
            facts.append(gate_pb2.Fact(key=name, text=value))
    return facts


def _facts_for(handler: Callable[..., Any], arguments: dict[str, Any]) -> list[gate_pb2.Fact]:
    """The facts a step declares: the arguments it is about to run on.

    Only scalars. A gate expression compares numbers, text and flags; a nested
    value has no comparison a policy could make of it, and flattening one would
    invent a naming convention the policy language does not have.
    """
    facts = []
    for name, value in _call_arguments(handler, arguments).items():
        # bool before int: in Python a bool *is* an int, and a flag sent as a
        # number would be compared by a rule that meant something else.
        if isinstance(value, bool):
            facts.append(gate_pb2.Fact(key=name, flag=value))
        elif isinstance(value, int):
            facts.append(gate_pb2.Fact(key=name, number=value))
        elif isinstance(value, str):
            facts.append(gate_pb2.Fact(key=name, text=value))
    return facts


def _call_arguments(handler: Callable[..., Any], arguments: dict[str, Any]) -> dict[str, Any]:
    """The subset of the run's arguments this handler takes, by name."""
    parameters = list(inspect.signature(handler).parameters)[1:]  # drop self
    return {name: arguments[name] for name in parameters if name in arguments}


def _raise_stuck(saga_id: str, projection: orchd_pb2.SagaProjection) -> None:
    """Report a saga this client cannot move, saying which kind of stuck it is."""
    for step in projection.steps:
        for pending in step.pending_gates:
            raise WaitingError(
                f"saga {saga_id} is waiting on {pending.requirement_id!r} at step "
                f"{step.step_id!r}: {pending.detail}. An SDK does not answer its own "
                f"gates -- that is what makes the answer worth something"
            )
    raise RefusedError(
        f"saga {saga_id} is {common_pb2.SagaState.Name(projection.status)} with nothing "
        f"for this client to do"
    )


def _detail(err: grpc.RpcError) -> str:
    details = getattr(err, "details", None)
    return details() if callable(details) else str(err)
