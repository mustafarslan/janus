#!/usr/bin/env bash
# loan-desk on raw MCP, governed by Janus.
#
# The agent is not changed and does not know: it is the same agent.py, pointed
# at a proxy instead of at the tool server. The tool server is not changed
# either. What Janus costs here is configuration — declaring what the tool
# actually does, registering that declaration, standing up the daemon that owns
# the log, and putting the proxy in front of the server.
#
# Everything below this line is counted as integration code by
# scripts/measure-integration.sh, including the lines that start the daemon and
# the validator. Counting them is the conservative reading: they are what a
# deployment does, not what this application had to be rewritten to do.
#
# It does not stop the daemon. How long the log's owner runs for is the
# deployment's business, and a validator still deciding when the agent happens
# to have finished is the ordinary case rather than a race to lose.
set -euo pipefail
cat > "$WORK/loan-desk-manifest.json" <<'JSON'
{
  "version": "1.0.0",
  "identity": {"participant_id": "tool_loan_desk", "kind": "TOOL", "principal": "pr_bank"},
  "runtime": {"model_id": "none", "prompt_bundle_hash": "blake3:loan-desk"},
  "actions": [
    {"name": "intake.read", "effect_class": "PURE"},
    {"name": "credit.assess", "effect_class": "PURE"},
    {"name": "payments.disburse", "effect_class": "COMPENSABLE",
     "compensation": {"action": "payments.refund", "max_delay_seconds": 3600,
                      "residual_effects": "the statement line remains"},
     "idempotency": {"key_recipe": "saga_id,step_id"}},
    {"name": "payments.refund", "effect_class": "REVERSIBLE",
     "compensation": {"action": "payments.disburse"},
     "idempotency": {"key_recipe": "saga_id,step_id"}},
    {"name": "notify.email", "effect_class": "IRREVERSIBLE_GATED",
     "idempotency": {"key_recipe": "recipient,saga_id"}}
  ],
  "risk": {"tier": 2, "revalidation_triggers": ["model_change", "action_change"]},
  "jurisdiction": {"deployable_in": ["EU"], "data_residency": "EU"}
}
JSON
"$BIN/janus-registry" register -evidence "$EVIDENCE" -key "$KEY" "$WORK/loan-desk-manifest.json" >/dev/null
"$BIN/janus-registry" evaluate -evidence "$EVIDENCE" -sandbox "$WORK/loan-desk-doubles.json" tool_loan_desk 1.0.0 >/dev/null
"$BIN/janus-registry" activate -evidence "$EVIDENCE" tool_loan_desk 1.0.0 >/dev/null
"$BIN/janus-orchd" -dir "$EVIDENCE" -policy examples/loan-desk/policy.json -key "$KEY" \
  -listen "0.0.0.0:${ORCHD##*:}" -principal pr_bank -sync none > "$WORK/mcp-orchd.log" 2>&1 &
echo $! > "$WORK/mcp-orchd.pid"
until grep -q "serving on" "$WORK/mcp-orchd.log"; do sleep 0.1; done
"$START_VALIDATOR"
python3 "$(dirname "$0")/agent.py" \
  "$BIN/janus-mcpd" -evidence "$WORK/mcp-session" -registry "$EVIDENCE" \
  -orchd "$ORCHD" -participant tool_loan_desk -principal pr_bank -session loan_desk -sync none \
  -- "$JANUS_TOOL_SERVER"
