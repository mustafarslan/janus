#!/usr/bin/env bash
# The Python SDK against a real janus-orchd.
#
# The SDK's own tests answer "what does it send", against a fake. This answers
# the other half: are those messages ones a real daemon accepts, admits and
# commits. It needs both toolchains — Go to build and run the daemon, Python to
# run the SDK — which is why it is a script rather than a CI job. `make ci`
# stays one container per job.
#
# It is deliberately not silent about what it did: the output below is the
# evidence, and a run whose daemon refused everything would look identical to a
# passing one if only the exit status were printed.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

PY_IMAGE="${JANUS_PY_IMAGE:-python@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217}"
WORK="$(mktemp -d)"
PORT="${JANUS_ORCHD_PORT:-7912}"
# The guard matters: an unset pid would make this `kill 0`, which signals the
# whole process group — this script included.
cleanup() {
  if [[ -n "${ORCHD_PID:-}" ]]; then kill "$ORCHD_PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "── building"
make build >/dev/null

echo "── registering tool_payments@1.0.0, the way an operator would"
cat > "$WORK/manifest.json" <<'JSON'
{
  "version": "1.0.0",
  "identity": {"participant_id": "tool_payments", "kind": "TOOL", "principal": "pr_bank"},
  "runtime": {"model_id": "none", "prompt_bundle_hash": "blake3:sdk-e2e"},
  "actions": [
    {"name": "payments.quote", "effect_class": "PURE"},
    {"name": "payments.wire", "effect_class": "COMPENSABLE",
     "compensation": {"action": "payments.refund", "max_delay_seconds": 3600,
                      "residual_effects": "the statement line remains"},
     "idempotency": {"key_recipe": "saga_id,step_id"}},
    {"name": "payments.refund", "effect_class": "REVERSIBLE",
     "compensation": {"action": "payments.wire"},
     "idempotency": {"key_recipe": "saga_id,step_id"}}
  ],
  "risk": {"tier": 2, "revalidation_triggers": ["model_change", "action_change"]},
  "jurisdiction": {"deployable_in": ["EU"], "data_residency": "EU"}
}
JSON
cat > "$WORK/doubles.json" <<'JSON'
{"name": "sdk-e2e-sandbox",
 "actions": {"payments.quote": {},
             "payments.wire": {"deltas": {"balance": -100}},
             "payments.refund": {"deltas": {"balance": 100}}}}
JSON
# The reference policy, not a permissive one written for this script. Its rules
# match on IRREVERSIBLE_GATED and this saga's steps are PURE and COMPENSABLE, so
# nothing here is gated — but the daemon is admitting against the same document
# a deployment would use, and an empty policy is refused outright because it
# would refuse every effectful step.
POLICY="$REPO/docs/policy/reference.json"

mkdir -p "$WORK/keys"
./bin/janus-keys gen "$WORK/keys/writer.key" >/dev/null
./bin/janus-keys pub "$WORK/keys/writer.key" > "$WORK/pub.json"
./bin/janus-registry trust pr_bank "$WORK/pub.json" -evidence "$WORK/evidence" -key "$WORK/keys/writer.key" >/dev/null
./bin/janus-registry register -evidence "$WORK/evidence" -key "$WORK/keys/writer.key" "$WORK/manifest.json"
./bin/janus-registry evaluate -evidence "$WORK/evidence" -sandbox "$WORK/doubles.json" tool_payments 1.0.0 >/dev/null
./bin/janus-registry activate -evidence "$WORK/evidence" tool_payments 1.0.0

echo "── starting janus-orchd on 127.0.0.1:$PORT"
./bin/janus-orchd -dir "$WORK/evidence" -policy "$POLICY" \
  -key "$WORK/keys/writer.key" -listen "0.0.0.0:$PORT" -principal pr_bank -sync none \
  > "$WORK/orchd.log" 2>&1 &
ORCHD_PID=$!
for _ in $(seq 1 50); do
  grep -q "serving on" "$WORK/orchd.log" && break
  sleep 0.1
done
grep -q "serving on" "$WORK/orchd.log" || { cat "$WORK/orchd.log"; exit 1; }

echo "── running the SDK against it"
docker run --rm --add-host=host.docker.internal:host-gateway \
  -v "$REPO/sdk/python:/sdk" -w /sdk \
  -e JANUS_ORCHD="host.docker.internal:$PORT" \
  "$PY_IMAGE" bash -euo pipefail -c "
    pip install --quiet --disable-pip-version-check --root-user-action=ignore -r requirements-dev.txt
    python -m pytest -q tests/e2e_test.py
  "

echo
echo "── stopping the daemon so it seals its open segment"
# Verifying while it is still writing reports the open segment as unsealed,
# which is true and is not a finding: a segment with no footer is one nobody has
# finished writing. The point of verifying here is the offline check an auditor
# would run, and they would run it on a log nobody is holding.
kill "$ORCHD_PID"
wait "$ORCHD_PID" 2>/dev/null || true
ORCHD_PID=

echo "── what the daemon recorded, verified offline"
./bin/janus-verify -keys "$WORK/pub.json" "$WORK/evidence" | tail -3

echo
echo "── and checked by the conformance suite, as an adapter"
# The suite is what Phase 4's exit gate turns on, and this is the first adapter
# to be put through it. The expectation is written here rather than derived from
# the log: a suite that read the log to decide what it should contain would
# agree with itself.
cat > "$WORK/expect.json" <<'JSON'
{
  "integration": "python-sdk",
  "sagas": [{
    "saga_id": "sg_sdk_e2e",
    "status": "COMMITTED",
    "steps": [
      {"step_id": "quote", "participant": "tool_payments", "action": "payments.quote",
       "effect_class": "PURE", "status": "COMMITTED"},
      {"step_id": "wire", "participant": "tool_payments", "action": "payments.wire",
       "effect_class": "COMPENSABLE", "status": "COMMITTED"}
    ]
  }]
}
JSON
./bin/janus-conformance -evidence "$WORK/evidence" -expect "$WORK/expect.json" \
  -keys "$WORK/pub.json"
