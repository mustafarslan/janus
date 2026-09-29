#!/usr/bin/env bash
# loan-desk with a real model — the paper's one real-model measurement.
#
# Fifty author-written applications (examples/loan-desk/agentic/applications.json)
# go through a model-backed intake agent and a model-backed underwriter, and then
# through the payment and the notice, twice: governed by a real janus-orchd, and
# plain, on the same recorded model outputs. A separate validator process judges
# the mandate from the facts each question carries. Then the evidence is put
# through the three checks an auditor has: janus-verify (offline, from the public
# key), janus-gate audit (every gate decision re-derived from the log), and
# janus-spotreplay (every terminal saga re-folded).
#
# The model is behind ollama (JANUS_MODEL, default gemma4:31b-cloud) and is
# reached from the containers at host.docker.internal. Sync is FULL — the
# production barrier — so the Janus time it reports is the durable one, on this
# host, one saga at a time.
#
# JANUS_UNSIGNED=1 runs the protocol the way the first runs did: no participant
# declares a key and the daemon takes callers at their word. By default every
# participant signs under a key of its own, and each container is handed only
# the keys of the participants it hosts.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

PY_IMAGE="${JANUS_PY_IMAGE:-python@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217}"
PIP_CACHE="${JANUS_PIP_CACHE:-$HOME/.cache/janus-loan-desk-pip}"
BIN="$REPO/bin"
PORT="${JANUS_AGENTIC_PORT:-7951}"
MODEL="${JANUS_MODEL:-gemma4:31b-cloud}"
STAMP="$(date -u +%Y-%m-%dT%H%M%SZ)"
WORK="${JANUS_AGENTIC_WORK:-$REPO/.agentic-runs/$STAMP}"
RESULTS="${JANUS_AGENTIC_RESULTS:-$REPO/docs/bench/agentic/$STAMP}"
EVIDENCE="$WORK/evidence"
UNSIGNED="${JANUS_UNSIGNED:-}"
# What the containers may read and write. The writer's key, and every key a
# container's participants do not own, stay outside it.
IO="$WORK/io"
mkdir -p "$WORK" "$IO" "$RESULTS" "$PIP_CACHE"

# The tree as the run starts, and again as it ends: a "-dirty" commit says
# something changed, and these say what.
git status --porcelain > "$WORK/git-status-start.txt"

cleanup() {
  docker rm -f janus-agentic-validator >/dev/null 2>&1 || true
  [[ -f "$WORK/orchd.pid" ]] && kill "$(cat "$WORK/orchd.pid")" 2>/dev/null || true
}
trap cleanup EXIT

echo "══ building"
make build >/dev/null

# The always-approve oracle replays a recorded run's intake outputs and calls no
# model; the recorded results.json is copied in so the container can read it.
REPLAY_SRC="${JANUS_REPLAY_INTAKE:-}"
if [[ -n "$REPLAY_SRC" ]]; then
  cp "$REPLAY_SRC" "$IO/replay-intake.json"
fi

echo "══ is the model there"
[[ -n "${JANUS_ORACLE:-}" ]] || curl -sf -m 120 http://localhost:11434/api/chat -d "{\"model\":\"$MODEL\",\"stream\":false,\"messages\":[{\"role\":\"user\",\"content\":\"reply with the word ok\"}]}" \
  | grep -q '"content"' || { echo "the model $MODEL did not answer on localhost:11434"; exit 1; }

# ---- the registry --------------------------------------------------------------

mkdir -p "$WORK/keys"
"$BIN/janus-keys" gen "$WORK/keys/writer.key" >/dev/null
"$BIN/janus-keys" pub "$WORK/keys/writer.key" > "$WORK/pub.json"
"$BIN/janus-registry" trust pr_bank "$WORK/pub.json" -evidence "$EVIDENCE" \
  -key "$WORK/keys/writer.key" >/dev/null

# Each participant signs what it asks the daemon to record with its own key,
# declared in its manifest, and the daemon runs with -require-caller-signatures.
# The keys are generated per run, like the writer's, into one directory per
# container: the agent's holds the four participants it hosts, the validator's
# holds its own, and each container mounts only its own, read-only -- so the
# agent cannot read the key it would need to answer the credit gate in the
# validator's name.
mkdir -p "$WORK/keys-agent" "$WORK/keys-validator"
participant_key() {
  local participant="$1" dir="$WORK/keys-agent"
  [[ "$participant" == ag_credit_policy ]] && dir="$WORK/keys-validator"
  local path="$dir/$participant.key"
  "$BIN/janus-keys" gen "$path" >/dev/null
  # "ed25519:<hex>", the form a manifest declares: the public half of the
  # seed janus-keys wrote.
  "$BIN/janus-keys" pub "$path" | python3 -c 'import json,sys; print("ed25519:" + next(iter(json.load(sys.stdin).values())))'
}

# model_id is what the registry records the agent as running. It is a
# declaration, and a model_change trigger would revalidate on a new one.
register() {
  local participant="$1" kind="$2" model_id="$3" actions="$4" doubles="$5"
  local pubkeys="[]"
  [[ -n "$UNSIGNED" ]] || pubkeys="[\"$(participant_key "$participant")\"]"
  cat > "$WORK/$participant.json" <<JSON
{
  "version": "1.0.0",
  "identity": {"participant_id": "$participant", "kind": "$kind", "principal": "pr_bank",
               "public_keys": $pubkeys},
  "runtime": {"model_id": "$model_id", "prompt_bundle_hash": "blake3:loan-desk-agentic"},
  "actions": $actions,
  "risk": {"tier": 2, "revalidation_triggers": ["model_change", "action_change"]},
  "jurisdiction": {"deployable_in": ["EU"], "data_residency": "EU"}
}
JSON
  echo "$doubles" > "$WORK/$participant-doubles.json"
  "$BIN/janus-registry" register -evidence "$EVIDENCE" -key "$WORK/keys/writer.key" \
    "$WORK/$participant.json" >/dev/null
  "$BIN/janus-registry" evaluate -evidence "$EVIDENCE" \
    -sandbox "$WORK/$participant-doubles.json" "$participant" 1.0.0 >/dev/null
  "$BIN/janus-registry" activate -evidence "$EVIDENCE" "$participant" 1.0.0 >/dev/null
}

register ag_intake AGENT "$MODEL" \
  '[{"name": "intake.read", "effect_class": "PURE"}]' \
  '{"name":"s","actions":{"intake.read":{}}}'
register ag_underwriter AGENT "$MODEL" \
  '[{"name": "underwrite.assess", "effect_class": "PURE"}]' \
  '{"name":"s","actions":{"underwrite.assess":{}}}'
register ag_credit_policy VALIDATOR "none" \
  '[{"name": "credit.assess", "effect_class": "PURE"}]' \
  '{"name":"s","actions":{"credit.assess":{}}}'
register tool_payments TOOL "none" \
  '[{"name": "payments.disburse", "effect_class": "COMPENSABLE",
     "compensation": {"action": "payments.refund", "max_delay_seconds": 3600,
                      "residual_effects": "the statement line remains"},
     "idempotency": {"key_recipe": "saga_id,step_id"}},
    {"name": "payments.refund", "effect_class": "REVERSIBLE",
     "compensation": {"action": "payments.disburse"},
     "idempotency": {"key_recipe": "saga_id,step_id"}}]' \
  '{"name":"s","actions":{"payments.disburse":{"deltas":{"balance":-1}},"payments.refund":{"deltas":{"balance":1}}}}'
register tool_notify TOOL "none" \
  '[{"name": "notify.email", "effect_class": "IRREVERSIBLE_IMMEDIATE",
     "preauthorized_mandate": "mandate:loans",
     "idempotency": {"key_recipe": "recipient,saga_id"}}]' \
  '{"name":"s","actions":{"notify.email":{"deltas":{"sent":1}}}}'

# ---- the daemon, the validator, the agent ---------------------------------------

SIGNED_FLAGS=(-require-caller-signatures)
[[ -z "$UNSIGNED" ]] || SIGNED_FLAGS=()
"$BIN/janus-orchd" -dir "$EVIDENCE" -policy examples/loan-desk/agentic/policy.json \
  -key "$WORK/keys/writer.key" -listen "0.0.0.0:$PORT" -principal pr_bank -sync full \
  ${SIGNED_FLAGS[@]+"${SIGNED_FLAGS[@]}"} \
  > "$WORK/orchd.log" 2>&1 &
echo $! > "$WORK/orchd.pid"
for _ in $(seq 1 100); do grep -q "serving on" "$WORK/orchd.log" && break; sleep 0.1; done
grep -q "serving on" "$WORK/orchd.log" || { cat "$WORK/orchd.log"; exit 1; }

# pyrun KEYS_DIR DOCKER_ARGS...: KEYS_DIR is mounted read-only at /keys and is
# the only key the container can see; "" mounts none.
pyrun() {
  local keys="$1"; shift
  local keymount=() keyenv=()
  if [[ -n "$keys" && -z "$UNSIGNED" ]]; then
    keymount=(-v "$keys:/keys:ro"); keyenv=(-e JANUS_KEYS_DIR=/keys)
  fi
  # Source read-only, and no raw sockets: a container that could rewrite the
  # other's code, or spoof the other's traffic on the shared bridge, would hold
  # the validator's authority without its key.
  docker run --rm --add-host=host.docker.internal:host-gateway --cap-drop NET_RAW \
    -e PYTHONDONTWRITEBYTECODE=1 \
    -v "$REPO/sdk/python:/sdk:ro" -v "$REPO/examples:/examples:ro" -v "$IO:/work" \
    ${keymount[@]+"${keymount[@]}"} ${keyenv[@]+"${keyenv[@]}"} \
    -v "$PIP_CACHE:/root/.cache/pip" -w /examples/loan-desk/agentic \
    -e PYTHONPATH=/sdk -e JANUS_ORCHD="host.docker.internal:$PORT" \
    -e OLLAMA_URL=http://host.docker.internal:11434 -e JANUS_MODEL="$MODEL" \
    -e JANUS_AGENTIC_OUT=/work/out -e JANUS_SAGA_LIST=/work/sagas.txt \
    -e JANUS_AGENTIC_LIMIT="${JANUS_AGENTIC_LIMIT:-}" \
    -e JANUS_CONDITION="${JANUS_CONDITION:-A}" \
    -e JANUS_AGENTIC_ONLY="${JANUS_AGENTIC_ONLY:-}" -e JANUS_FAIL_NOTIFY="${JANUS_FAIL_NOTIFY:-}" \
    -e JANUS_TEMPERATURE="${JANUS_TEMPERATURE:-0.7}" -e JANUS_ORACLE="${JANUS_ORACLE:-}" \
    -e JANUS_REPLAY_INTAKE="${REPLAY_SRC:+/work/replay-intake.json}" \
    "$@"
}
PIP="pip install --quiet --disable-pip-version-check --root-user-action=ignore -r /sdk/requirements-dev.txt >/dev/null 2>&1"

pyrun "" "$PY_IMAGE" bash -c "$PIP; python run.py --list" > "$IO/sagas.txt"
echo "══ $(wc -l < "$IO/sagas.txt" | tr -d ' ') sagas to run"

docker rm -f janus-agentic-validator >/dev/null 2>&1 || true
pyrun "$WORK/keys-validator" -d --name janus-agentic-validator "$PY_IMAGE" \
  bash -c "$PIP; ls /keys 2>/dev/null | sed 's/^/validator holds: /'; python -u watch_validator.py" >/dev/null
for _ in $(seq 1 600); do
  docker logs janus-agentic-validator 2>&1 | grep -q "validator watching" && break
  sleep 0.5
done

echo "══ the run"
pyrun "$WORK/keys-agent" "$PY_IMAGE" \
  bash -c "$PIP; ls /keys 2>/dev/null | sed 's/^/agent holds: /'; python -u run.py" | tee "$WORK/run.log"
docker logs janus-agentic-validator > "$WORK/validator.log" 2>&1 || true
docker rm -f janus-agentic-validator >/dev/null 2>&1 || true
kill "$(cat "$WORK/orchd.pid")"; wait "$(cat "$WORK/orchd.pid")" 2>/dev/null || true
rm -f "$WORK/orchd.pid"

# ---- what an auditor can check, with nothing but the log and a public key -------

echo
echo "══ janus-verify"
"$BIN/janus-verify" -keys "$WORK/pub.json" -json "$EVIDENCE" > "$WORK/verify.json" || true
"$BIN/janus-verify" -keys "$WORK/pub.json" -quiet "$EVIDENCE" | tee "$WORK/verify.txt"
echo "══ janus-gate audit"
"$BIN/janus-gate" audit -keys "$WORK/pub.json" "$EVIDENCE" | tee "$WORK/audit.txt"
echo "══ janus-spotreplay"
"$BIN/janus-spotreplay" -evidence "$EVIDENCE" | tee "$WORK/spotreplay.txt"

git status --porcelain > "$WORK/git-status-end.txt"
cp "$IO/out/results.json" "$WORK/verify.txt" "$WORK/audit.txt" "$WORK/spotreplay.txt" \
  "$WORK/run.log" "$WORK/validator.log" "$WORK/git-status-start.txt" "$WORK/git-status-end.txt" \
  "$RESULTS/"
# The log and the public key, so an auditor can re-run the checks from the
# committed directory alone. Never the key directory.
cp -R "$EVIDENCE" "$RESULTS/evidence"
cp "$WORK/pub.json" "$RESULTS/pub.json"
cat > "$RESULTS/README.md" <<MD
# loan-desk with a real model — run $STAMP

- injected notice failures: ${JANUS_FAIL_NOTIFY:-none}; applications: ${JANUS_AGENTIC_ONLY:-all}
- condition: ${JANUS_CONDITION:-A} (A: the mandate is in the underwriter's prompt and in the policy; B: in the policy only; Bprime: policy only, unit stated)
- oracle: ${JANUS_ORACLE:-none}; intake replayed from: ${REPLAY_SRC:-none (model called)}
- model: \`$MODEL\` via ollama, temperature ${JANUS_TEMPERATURE:-0.7}, seed per saga (recorded in each DPR)
- janus-orchd: \`-sync full\`, one saga at a time, on $(uname -s)/$(uname -m)
- corpus: examples/loan-desk/agentic/applications.json (author-written, synthetic)
- commit: $(git rev-parse --short HEAD)$(git diff --quiet || echo "-dirty"); tracked or untracked changes at the start and end of the run are in \`git-status-start.txt\` and \`git-status-end.txt\` (empty: none)
- caller signatures: $([[ -n "$UNSIGNED" ]] && echo "none (JANUS_UNSIGNED=1: no participant declares a key; the daemon takes callers at their word)" || echo "required (-require-caller-signatures); each container held only its own participants' keys")

\`results.json\` holds the summary and every row. The evidence log is in
\`evidence/\` and the writer's public key in \`pub.json\`, so \`janus-verify -keys
pub.json evidence\` and \`janus-gate audit -keys pub.json evidence\` re-run the auditor's checks
from this directory alone.
MD
echo "results in $RESULTS"
