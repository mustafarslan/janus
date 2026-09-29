#!/usr/bin/env bash
# Phase 0 spike 2: MCP interception with real subprocesses.
#
# An agent (this script) speaks MCP to janus-mcpd on stdin/stdout. janus-mcpd
# launches janus-toytool as a child and relays between them. The tool server
# knows nothing about Janus — that is the claim being tested.
#
# Afterwards the evidence log is verified offline with janus-verify, using a
# public key exported separately, the way an auditor would.
set -euo pipefail

BIN="${BIN:-bin}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for b in janus-mcpd janus-toytool janus-verify janus-keys; do
  if [[ ! -x "$BIN/$b" ]]; then
    echo "missing $BIN/$b — run 'make build' first" >&2
    exit 1
  fi
done

# Stands in for the registry: what each tool does to the world. Note that
# unregistered.tool is deliberately absent, to show the fail-closed default.
cat > "$WORK/classes.json" <<'JSON'
{
  "echo": "pure",
  "wire.send": "irreversible_gated"
}
JSON

echo "── the agent talks to janus-mcpd, which fronts janus-toytool"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello from a real agent"}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"wire.send","arguments":{"account":"DE89370400440532013000","amount":250.00}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"unregistered.tool","arguments":{}}}' \
| "$BIN/janus-mcpd" \
    -evidence "$WORK/evidence" \
    -classes "$WORK/classes.json" \
    -session "mcp_spike_0001" \
    -participant "tool_toybox" \
    -sync full \
    -- "$BIN/janus-toytool" \
| sed 's/^/   /'

echo
echo "── export the writer's public key separately, then verify the log offline"
"$BIN/janus-keys" pub "$WORK/keys/writer.key" > "$WORK/writer-keys.json"
"$BIN/janus-verify" -keys "$WORK/writer-keys.json" "$WORK/evidence" | sed 's/^/   /'

echo
echo "── what the evidence itself says about each message"
"$BIN/janus-verify" -keys "$WORK/writer-keys.json" -list "$WORK/evidence" \
  | sed -n '/^SEQ/,/^$/p' | sed 's/^/   /'

# The classification of the unregistered tool is the interesting one: nothing
# declared it, so it was recorded as irreversible rather than waved through.
if ! "$BIN/janus-verify" -keys "$WORK/writer-keys.json" -list -json "$WORK/evidence" \
     | grep -q '"janus.classification": "default"'; then
  echo "spike-mcp: FAIL — expected an unregistered tool to be recorded with the fail-closed default" >&2
  exit 1
fi

echo
echo "spike-mcp: PASS — tool server unmodified, every message recorded, log verifies,"
echo "           and the unregistered tool was classified IRREVERSIBLE_GATED by default"
