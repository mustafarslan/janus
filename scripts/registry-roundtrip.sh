#!/usr/bin/env bash
# The registry half of the Phase 3 exit gate, end to end, through the CLI.
#
# The exit gate: "registry round-trip: register → evaluate → activate → pin
# in saga → change manifest → revalidation triggered."
#
# The pin is demonstrated at the interception edge: janus-mcpd fronts an
# unmodified MCP tool server and classifies every call from that server's active
# manifest, recording the manifest version on each event. Nothing is passed
# between the stages except through the evidence log — every command below
# re-folds the registry out of the segments.
set -euo pipefail

BIN="${BIN:-bin}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for b in janus-registry janus-mcpd janus-toytool janus-keys janus-verify; do
  if [[ ! -x "$BIN/$b" ]]; then
    echo "missing $BIN/$b — run 'make build' first" >&2
    exit 1
  fi
done

EV="$WORK/evidence"

# Every registry command re-folds the projection out of the segments, so the
# evidence directory is the only state passed between the stages below.
reg() { local cmd="$1"; shift; "$BIN/janus-registry" "$cmd" -evidence "$EV" "$@"; }

fail() { echo "registry-roundtrip: FAIL — $1" >&2; exit 1; }

echo "── 0. the manifest, before anything has seen it"
"$BIN/janus-registry" check docs/registry/toybox.json | sed 's/^/   /'

echo
echo "── the principal's signing key, and the trust store that says it may speak for them"
# The key that signs a manifest is not the key that signs the log. Trust in a
# manifest comes from a store the registry operator holds, separately from the
# artifact — a signature checked against keys carried alongside proves nothing.
"$BIN/janus-keys" gen "$WORK/keys/principal.key" >/dev/null
"$BIN/janus-keys" pub "$WORK/keys/principal.key" > "$WORK/principal-keys.json"
"$BIN/janus-registry" trust pr_demo "$WORK/principal-keys.json" > "$WORK/trust.json"
sed 's/^/   /' "$WORK/trust.json"

echo
echo "── 1. register — the manifest enters as DRAFT and may not be pinned"
reg register -key "$WORK/keys/principal.key" -trust "$WORK/trust.json" \
  docs/registry/toybox.json | sed 's/^/   /'

if reg activate tool_toybox 1.0.0 >/dev/null 2>&1; then
  fail "a manifest nothing had evaluated was activated"
fi
echo "   activating it now is refused: nothing has checked what it claims"

echo
echo "── 2. evaluate — the declared classes are run against sandbox doubles"
reg evaluate -sandbox docs/registry/toybox-sandbox.json tool_toybox 1.0.0 | sed 's/^/   /'

echo
echo "── 3. activate"
reg activate tool_toybox 1.0.0 | sed 's/^/   /'
reg inventory | sed 's/^/   /'

echo
echo "── 4. pin — janus-mcpd classifies an unmodified tool server from its manifest"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wire.send","arguments":{"account":"DE89370400440532013000","amount":250.00}}}' \
| "$BIN/janus-mcpd" \
    -evidence "$EV" \
    -registry "$EV" \
    -participant tool_toybox \
    -session "reg_roundtrip_0001" \
    -sync full \
    -- "$BIN/janus-toytool" >/dev/null

"$BIN/janus-keys" pub "$EV/../keys/writer.key" > "$WORK/writer-keys.json"
if ! "$BIN/janus-verify" -keys "$WORK/writer-keys.json" -list -json "$EV" \
     | grep -q '"janus.effect_class": "IRREVERSIBLE_GATED"'; then
  fail "the wire call was not classified from the manifest"
fi
if ! "$BIN/janus-verify" -keys "$WORK/writer-keys.json" -list -json "$EV" \
     | grep -q '"janus.classification": "manifest"'; then
  fail "the classification did not come from the manifest"
fi
if ! "$BIN/janus-verify" -keys "$WORK/writer-keys.json" -list -json "$EV" \
     | grep -q '"manifest_version": "1.0.0"'; then
  fail "the recorded events do not pin the manifest version they ran under (I8)"
fi
echo "   wire.send recorded as IRREVERSIBLE_GATED under manifest version 1.0.0"

echo
echo "── 5. change the manifest — a new prompt bundle, which the version it"
echo "      replaces declared as a revalidation trigger"
sed 's/blake3:1111111111111111111111111111111111111111111111111111111111111111/blake3:2222222222222222222222222222222222222222222222222222222222222222/; s/"version": "1.0.0"/"version": "1.1.0"/' \
  docs/registry/toybox.json > "$WORK/toybox-1.1.0.json"
reg register -key "$WORK/keys/principal.key" -trust "$WORK/trust.json" \
  "$WORK/toybox-1.1.0.json" | sed 's/^/   /'

echo
echo "── 6. revalidation triggered — the evidence that cleared 1.0.0 does not carry over"
if reg evaluate -inherit tool_toybox 1.1.0 >/dev/null 2>&1; then
  fail "a changed prompt inherited the evidence that cleared the old prompt"
fi
if reg activate tool_toybox 1.1.0 >/dev/null 2>&1; then
  fail "a version owing revalidation was activated"
fi
echo "   inheriting the old evidence is refused, and so is activating without new evidence"
reg evaluate -sandbox docs/registry/toybox-sandbox.json tool_toybox 1.1.0 | sed 's/^/   /'
reg activate tool_toybox 1.1.0 | sed 's/^/   /'

echo
echo "── 7. audit — re-derive the whole registry from the log, trusting nothing else"
reg audit -trust "$WORK/trust.json" | sed 's/^/   /'

echo
echo "── 8. and the log the registry lives in still verifies offline"
"$BIN/janus-verify" -keys "$WORK/writer-keys.json" "$EV" | sed 's/^/   /'

echo
echo "registry-roundtrip: PASS — registered, evaluated, activated, pinned by a real"
echo "           tool call, changed, revalidated, and re-derived from the log alone"
