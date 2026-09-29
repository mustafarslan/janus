#!/usr/bin/env bash
# The Phase 4 exit gate.
#
# loan-desk — intake agent, credit-policy validator, payments tool, notification
# — runs twice: on LangGraph through the Python SDK, and on raw MCP through
# janus-mcpd. For each it prints what Janus cost the application, measured by
# diffing the governed version against a plain one, and then puts the evidence
# through janus-conformance.
#
# Two numbers and two verdicts. The gate asks for under fifty lines each and a
# passing conformance run for both adapters.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

PIP_CACHE="${JANUS_PIP_CACHE:-$HOME/.cache/janus-loan-desk-pip}"
mkdir -p "$PIP_CACHE"
PY_IMAGE="${JANUS_PY_IMAGE:-python@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217}"
BIN="$REPO/bin"
WORK="${JANUS_LOAN_DESK_WORK:-$(mktemp -d)}"
mkdir -p "$WORK"
LG_PORT="${JANUS_LG_PORT:-7941}"
# JANUS_LOAN_DESK_WORK keeps the run's evidence, which is what
# janus-spotreplay needs to be pointed at: the sagas a real reference app
# produced, rather than sagas written by a test to be checked.
cleanup() {
  for pidfile in "$WORK"/*.pid; do
    [[ -f "$pidfile" ]] && kill "$(cat "$pidfile")" 2>/dev/null || true
  done
  if [[ -z "${JANUS_LOAN_DESK_WORK:-}" ]]; then
    rm -rf "$WORK"
  else
    echo "evidence kept in $WORK"
  fi
}
trap cleanup EXIT

echo "══ building"
make build >/dev/null

# ---- the measurement -------------------------------------------------------

echo
./scripts/measure-integration.sh \
  examples/loan-desk/langgraph/plain.py examples/loan-desk/langgraph/governed.py langgraph \
  | tee "$WORK/langgraph.measure"
echo
./scripts/measure-integration.sh \
  examples/loan-desk/mcp/plain.sh examples/loan-desk/mcp/governed.sh raw-mcp \
  | tee "$WORK/mcp.measure"

lg_lines="$(grep -oE '[0-9]+ lines' "$WORK/langgraph.measure" | grep -oE '[0-9]+')"
mcp_lines="$(grep -oE '[0-9]+ lines' "$WORK/mcp.measure" | grep -oE '[0-9]+')"

# ---- a registry both runs are admitted against -----------------------------

setup_registry() {
  local evidence="$1"
  mkdir -p "$WORK/keys"
  [[ -f "$WORK/keys/writer.key" ]] || "$BIN/janus-keys" gen "$WORK/keys/writer.key" >/dev/null
  [[ -f "$WORK/pub.json" ]] || "$BIN/janus-keys" pub "$WORK/keys/writer.key" > "$WORK/pub.json"
  "$BIN/janus-registry" trust pr_bank "$WORK/pub.json" -evidence "$evidence" \
    -key "$WORK/keys/writer.key" >/dev/null
}

register() {
  local evidence="$1" participant="$2" kind="$3" actions="$4" doubles="$5"
  cat > "$WORK/$participant.json" <<JSON
{
  "version": "1.0.0",
  "identity": {"participant_id": "$participant", "kind": "$kind", "principal": "pr_bank"},
  "runtime": {"model_id": "none", "prompt_bundle_hash": "blake3:loan-desk"},
  "actions": $actions,
  "risk": {"tier": 2, "revalidation_triggers": ["model_change", "action_change"]},
  "jurisdiction": {"deployable_in": ["EU"], "data_residency": "EU"}
}
JSON
  echo "$doubles" > "$WORK/$participant-doubles.json"
  "$BIN/janus-registry" register -evidence "$evidence" -key "$WORK/keys/writer.key" \
    "$WORK/$participant.json" >/dev/null
  "$BIN/janus-registry" evaluate -evidence "$evidence" \
    -sandbox "$WORK/$participant-doubles.json" "$participant" 1.0.0 >/dev/null
  "$BIN/janus-registry" activate -evidence "$evidence" "$participant" 1.0.0 >/dev/null
}

# ---- adapter one: LangGraph through the Python SDK --------------------------

echo
echo "══ loan-desk on LangGraph"
LG_EVIDENCE="$WORK/langgraph-evidence"
setup_registry "$LG_EVIDENCE"
register "$LG_EVIDENCE" ag_intake AGENT \
  '[{"name": "intake.read", "effect_class": "PURE"}]' \
  '{"name":"s","actions":{"intake.read":{}}}'
register "$LG_EVIDENCE" ag_credit_policy VALIDATOR \
  '[{"name": "credit.assess", "effect_class": "PURE"}]' \
  '{"name":"s","actions":{"credit.assess":{}}}'
register "$LG_EVIDENCE" tool_payments TOOL \
  '[{"name": "payments.disburse", "effect_class": "COMPENSABLE",
     "compensation": {"action": "payments.refund", "max_delay_seconds": 3600,
                      "residual_effects": "the statement line remains"},
     "idempotency": {"key_recipe": "saga_id,step_id"}},
    {"name": "payments.refund", "effect_class": "REVERSIBLE",
     "compensation": {"action": "payments.disburse"},
     "idempotency": {"key_recipe": "saga_id,step_id"}}]' \
  '{"name":"s","actions":{"payments.disburse":{"deltas":{"balance":-1}},"payments.refund":{"deltas":{"balance":1}}}}'
register "$LG_EVIDENCE" tool_notify TOOL \
  '[{"name": "notify.email", "effect_class": "IRREVERSIBLE_GATED",
     "idempotency": {"key_recipe": "recipient,saga_id"}}]' \
  '{"name":"s","actions":{"notify.email":{"deltas":{"sent":1}}}}'

"$BIN/janus-orchd" -dir "$LG_EVIDENCE" -policy examples/loan-desk/policy.json \
  -key "$WORK/keys/writer.key" -listen "0.0.0.0:$LG_PORT" -principal pr_bank -sync none \
  > "$WORK/lg-orchd.log" 2>&1 &
echo $! > "$WORK/lg-orchd.pid"
for _ in $(seq 1 60); do grep -q "serving on" "$WORK/lg-orchd.log" && break; sleep 0.1; done
grep -q "serving on" "$WORK/lg-orchd.log" || { cat "$WORK/lg-orchd.log"; exit 1; }

docker run --rm --add-host=host.docker.internal:host-gateway \
  -v "$REPO/sdk/python:/sdk" -v "$REPO/examples:/examples" -w /examples/loan-desk/langgraph \
  -e PYTHONPATH=/sdk -e JANUS_ORCHD="host.docker.internal:$LG_PORT" \
  "$PY_IMAGE" bash -euo pipefail -c "
    pip install --quiet --disable-pip-version-check --root-user-action=ignore \
      -r /sdk/requirements-dev.txt langgraph
    python governed.py
  "

kill "$(cat "$WORK/lg-orchd.pid")"; wait "$(cat "$WORK/lg-orchd.pid")" 2>/dev/null || true
rm -f "$WORK/lg-orchd.pid"

cat > "$WORK/langgraph-expect.json" <<'JSON'
{
  "integration": "loan-desk on LangGraph",
  "sagas": [{
    "saga_id": "sg_loan_desk",
    "status": "COMMITTED",
    "steps": [
      {"step_id": "intake", "participant": "ag_intake", "action": "intake.read",
       "effect_class": "PURE", "status": "COMMITTED"},
      {"step_id": "credit_policy", "participant": "ag_credit_policy",
       "action": "credit.assess", "effect_class": "PURE", "status": "COMMITTED"},
      {"step_id": "disburse", "participant": "tool_payments",
       "action": "payments.disburse", "effect_class": "COMPENSABLE", "status": "COMMITTED"},
      {"step_id": "notify", "participant": "tool_notify", "action": "notify.email",
       "effect_class": "IRREVERSIBLE_GATED", "status": "COMMITTED"}
    ]
  }]
}
JSON
echo
"$BIN/janus-conformance" -evidence "$LG_EVIDENCE" -expect "$WORK/langgraph-expect.json" \
  -keys "$WORK/pub.json"

# ---- adapter two: raw MCP through janus-mcpd --------------------------------

echo
echo "══ loan-desk on raw MCP"
MCP_EVIDENCE="$WORK/mcp-evidence"
MCP_PORT="${JANUS_MCP_PORT:-7942}"
setup_registry "$MCP_EVIDENCE"
echo '{"name":"s","actions":{"intake.read":{},"credit.assess":{},"payments.disburse":{"deltas":{"balance":-1}},"payments.refund":{"deltas":{"balance":1}},"notify.email":{"deltas":{"sent":1}}}}' \
  > "$WORK/loan-desk-doubles.json"
register "$MCP_EVIDENCE" ag_credit_policy VALIDATOR \
  '[{"name": "credit.assess", "effect_class": "PURE"}]' \
  '{"name":"s","actions":{"credit.assess":{}}}'

# The validator runs as its own participant, which is what it is in a
# deployment. Nothing in the agent or the tool server changes for it.
cat > "$WORK/start-validator" <<VSH
#!/usr/bin/env bash
set -euo pipefail
docker rm -f janus-loan-desk-validator >/dev/null 2>&1 || true
docker run -d --add-host=host.docker.internal:host-gateway \\
  -v "$REPO/sdk/python:/sdk" -v "$REPO/examples:/examples" \\
  -v "$PIP_CACHE:/root/.cache/pip" -w /examples/loan-desk \\
  -e JANUS_ORCHD="host.docker.internal:$MCP_PORT" \\
  -e JANUS_SAGAS="sg_loan_desk_3,sg_loan_desk_4" \\
  -e JANUS_VALIDATOR_SECONDS=90 \\
  --name janus-loan-desk-validator "$PY_IMAGE" bash -c \\
  "pip install --quiet --disable-pip-version-check --root-user-action=ignore -r /sdk/requirements-dev.txt >/dev/null 2>&1; python validator.py" >/dev/null
# Wait for it to say it is listening rather than sleeping a guess: a validator
# that is not up yet looks exactly like one that declined to answer.
for _ in \$(seq 1 300); do
  docker logs janus-loan-desk-validator 2>&1 | grep -q "validator watching" && break
  sleep 0.5
done
VSH
chmod +x "$WORK/start-validator"

# The measured file is the file that runs. Inlining a copy of the mcpd
# invocation here would mean the number describes one thing and the
# demonstration exercises another, which is the failure this measurement exists
# to avoid.
export BIN EVIDENCE="$MCP_EVIDENCE" KEY="$WORK/keys/writer.key" WORK
export ORCHD="127.0.0.1:$MCP_PORT"
export START_VALIDATOR="$WORK/start-validator"
export JANUS_TOOL_SERVER="$REPO/examples/loan-desk/mcp/toolserver.py"
./examples/loan-desk/mcp/governed.sh || true

# The agent has finished; the validator may still be deciding. Wait for it
# rather than sampling whenever the agent happened to stop — a gate answered
# half a second later is the ordinary case, not a failure.
for _ in $(seq 1 60); do
  docker logs janus-loan-desk-validator 2>&1 | grep -q "answered" && break
  sleep 0.5
done
docker logs janus-loan-desk-validator 2>&1 | grep -E "watching|answered" | sed 's/^/   /' || true
docker rm -f janus-loan-desk-validator >/dev/null 2>&1 || true
if [[ -f "$WORK/mcp-orchd.pid" ]]; then
  kill "$(cat "$WORK/mcp-orchd.pid")" 2>/dev/null || true
  wait "$(cat "$WORK/mcp-orchd.pid")" 2>/dev/null || true
  rm -f "$WORK/mcp-orchd.pid"
fi

cat > "$WORK/mcp-expect.json" <<'JSON'
{
  "integration": "loan-desk on raw MCP",
  "sagas": [
    {"saga_id": "sg_loan_desk_3", "status": "COMMITTED",
     "steps": [{"step_id": "call", "participant": "tool_loan_desk",
                "action": "payments.disburse", "effect_class": "COMPENSABLE",
                "status": "COMMITTED"}]},
    {"saga_id": "sg_loan_desk_4", "status": "COMMITTED",
     "steps": [{"step_id": "call", "participant": "tool_loan_desk",
                "action": "notify.email", "effect_class": "IRREVERSIBLE_GATED",
                "status": "COMMITTED"}]}
  ]
}
JSON
echo
"$BIN/janus-conformance" -evidence "$MCP_EVIDENCE" -expect "$WORK/mcp-expect.json" \
  -keys "$WORK/pub.json"

# ---- the verdict -----------------------------------------------------------

echo
echo "══ Phase 4 exit gate"
echo "   langgraph: $lg_lines lines of integration code"
echo "   raw mcp:   $mcp_lines lines of integration code"
echo "   the gate asks for under 50 each, and a passing conformance run per adapter"
