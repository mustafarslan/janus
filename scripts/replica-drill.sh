#!/usr/bin/env bash
# Phase 6g: a replica follows a live primary, in two real processes.
#
# janus-orchd owns an evidence directory and serves the replication surface;
# janus-replicad follows it into a second directory over gRPC. Work happens on
# the primary while the follower is running, so the copy has to keep up rather
# than be taken once and compared.
#
# Afterwards the two directories are compared byte for byte, and the replica is
# verified offline with janus-verify against the primary's public key — the way
# an auditor would, and against the copy rather than the original, because a
# replica that only verifies with the primary present is not a replica.
#
# THIS IS THE LOCAL EQUIVALENT OF A SECOND REGION, AND IT IS NOT ONE. Two
# processes on one host share a disk, a kernel, a clock and a power supply. What
# it proves is that the protocol converges and the copy stands on its own; what
# it cannot prove is anything about a region failing (the same caveat every
# Phase 6 artifact carries).
set -euo pipefail

BIN="${BIN:-bin}"
WORK="$(mktemp -d)"
PORT="${PORT:-17877}"

cleanup() {
  [[ -n "${REPLICA_PID:-}" ]] && kill "$REPLICA_PID" 2>/dev/null || true
  [[ -n "${ORCHD_PID:-}" ]] && kill "$ORCHD_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

for b in janus-orchd janus-replicad janus-keys janus-verify janus-identity; do
  if [[ ! -x "$BIN/$b" ]]; then
    echo "missing $BIN/$b — run 'make build' first" >&2
    exit 1
  fi
done

PRIMARY="$WORK/primary"
REPLICA="$WORK/replica"
mkdir -p "$PRIMARY" "$WORK/keys"

echo "--- writer key"
"$BIN/janus-keys" gen "$WORK/keys/writer.key" >/dev/null
"$BIN/janus-keys" pub "$WORK/keys/writer.key" >"$WORK/keys/public.json"

echo "--- primary on :$PORT"
# A small segment so the primary *rotates* during the drill. Rotation is what
# seals a segment, and a sealed segment is the only thing the follower's
# signature checking acts on — a drill that never rotated would report a pass
# having exercised none of it.
"$BIN/janus-orchd" -dir "$PRIMARY" -key "$WORK/keys/writer.key" \
  -listen "127.0.0.1:$PORT" -sync none -segment-bytes 2048 >"$WORK/orchd.log" 2>&1 &
ORCHD_PID=$!

for _ in $(seq 60); do
  if grep -q "serving on" "$WORK/orchd.log" 2>/dev/null; then break; fi
  sleep 0.2
done
if ! grep -q "serving on" "$WORK/orchd.log" 2>/dev/null; then
  echo "the primary never came up:" >&2
  cat "$WORK/orchd.log" >&2
  exit 1
fi

echo "--- follower"
"$BIN/janus-replicad" -primary "127.0.0.1:$PORT" -dir "$REPLICA" \
  -keys "$WORK/keys/public.json" -interval 500ms >"$WORK/replicad.log" 2>&1 &
REPLICA_PID=$!

# Work on the primary *while* the follower runs. A copy taken after everything
# has stopped would not exercise the resume path, which is where a replication
# cursor actually goes wrong.
echo "--- writing to the primary while the follower runs"
for i in $(seq 30); do
  "$BIN/janus-identity" revoke -addr "127.0.0.1:$PORT" \
    -id "cred_drill_$i" -reason "replication drill" >/dev/null 2>&1 || true
  sleep 0.1
done

echo "--- letting the follower catch up"
sleep 3
kill "$REPLICA_PID" 2>/dev/null || true
wait "$REPLICA_PID" 2>/dev/null || true
REPLICA_PID=""

kill "$ORCHD_PID" 2>/dev/null || true
wait "$ORCHD_PID" 2>/dev/null || true
ORCHD_PID=""

echo "--- the follower's last word"
tail -2 "$WORK/replicad.log"

# The drill is only worth running if it reached the thing it exists to check.
if ! grep -q "signatures checked through segment [1-9]" "$WORK/replicad.log"; then
  echo "FAIL: no sealed segment was ever verified, so this run exercised neither" >&2
  echo "      rotation nor signature checking — the drill passed without doing its job" >&2
  exit 1
fi

echo "--- comparing the two directories byte for byte"
missing=0
for f in "$PRIMARY"/*.jseg; do
  name="$(basename "$f")"
  if [[ ! -f "$REPLICA/$name" ]]; then
    echo "FAIL: $name is missing from the replica" >&2
    missing=1
    continue
  fi
  if ! cmp -s "$f" "$REPLICA/$name"; then
    # The primary's open segment may have grown after the follower stopped,
    # which is a lag rather than a divergence: the replica must be a *prefix*.
    # Arithmetic expansion, because wc pads its output with spaces and a padded
    # number passed to cmp -n is not a number.
    psize=$(( $(wc -c <"$f") ))
    rsize=$(( $(wc -c <"$REPLICA/$name") ))
    # head -c piped into cmp rather than `cmp -n`: BSD cmp has no -n, so the
    # GNU spelling passes on Linux and silently fails on darwin, which is the
    # sort of difference that makes a drill green in CI and red on a laptop.
    if [[ "$rsize" -lt "$psize" ]] && head -c "$rsize" "$f" | cmp -s - "$REPLICA/$name"; then
      echo "  $name: replica holds a $rsize-byte prefix of $psize (lag, not divergence)"
      continue
    fi
    echo "FAIL: $name differs and is not a prefix (primary $psize bytes, replica $rsize)" >&2
    missing=1
  else
    echo "  $name: identical"
  fi
done
[[ "$missing" -eq 0 ]] || exit 1

# -allow-open-tail because the primary is a *live* log: its newest segment has no
# footer until it rotates or the writer closes, so a faithful replica of it ends
# in an unsealed segment too. Refusing that would be refusing the thing being
# replicated. Every sealed segment is still checked against its signature and
# Merkle root, which is what the flag does not relax.
echo "--- verifying the replica offline, against the primary's public key"
"$BIN/janus-verify" -keys "$WORK/keys/public.json" -allow-open-tail "$REPLICA"

echo
echo "janus-replicad: PASS — the copy converged and verifies on its own."
echo
echo "That verification is a moment, not a guard. The follower checks what it"
echo "copies and never re-reads its own history, so damage to a sealed segment"
echo "on this host after it passed by is invisible to it and its status line"
echo "keeps saying 'signatures checked through segment N'. A replica"
echo "host runs 'janus-tier watch' over the mirror for the same reason a primary"
echo "host does: its sweep is the only thing that reads the history again."
echo "This is the local equivalent of a second region and is not one:"
echo "two processes on one host share a disk, a kernel and a clock."
