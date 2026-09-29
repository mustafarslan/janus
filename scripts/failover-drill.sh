#!/usr/bin/env bash
# Phase 6j: a failover drill.
#
# A primary is killed mid-work, its replica is promoted, and three things are
# measured rather than asserted:
#
#   RTO   — from the kill to the first successful append on the promoted writer,
#           with the operator's decision time excluded and that exclusion stated.
#   RPO   — NOT "did the replica have everything", which it never does. The
#           question that actually matters is "was any effect released whose
#           evidence the replica lacks", so every call that *returned success*
#           before the kill is counted, and the promoted log must hold them all.
#   Continuity — the promoted directory verifies end to end against the ORIGINAL
#           writer's public key, with no second root handed over. That is the
#           whole point of enrolling the standby key while the primary was
#           healthy, and this is what proves it in a real process.
#
# THIS IS THE LOCAL EQUIVALENT OF A REGION FAILOVER AND IT IS NOT ONE. Two
# processes on one host share a disk, a kernel, a clock and a power supply. A
# SIGKILL is not a region loss: the disk survives, so the primary's own log is
# still there to compare against, which is a luxury a real failover does not
# have. What this proves is that the protocol works and the promoted log stands
# on its own. What it cannot prove is anything about a region.
set -euo pipefail

BIN="${BIN:-bin}"
WORK="$(mktemp -d)"
PORT="${PORT:-17901}"
PORT2="${PORT2:-17902}"
PORT3="${PORT3:-17903}"
# ROUNDS=2 fails the log over a SECOND time, which nothing has ever exercised.
# Default 1, so the drill and docs/bench/phase6-failover.json are what they were.
ROUNDS="${ROUNDS:-1}"
CALLS="${CALLS:-40}"
# The budget this drill is held to: RTO <= 5 min single-region.
RTO_BUDGET_MS="${RTO_BUDGET_MS:-300000}"
# How many acknowledged calls may be missing from the promoted log before this is
# a failure rather than a measurement.
#
# Zero at steady state, and that is a real gate: with the follower caught up,
# losing an acknowledged call would be a defect. It is *not* zero by
# construction — killing mid-stream (SETTLE=0) loses about one at a 300 ms
# follower interval, and that is the replication lag's exposure rather than a
# bug. Raise the tolerance when measuring the exposure; leave it at zero when
# gating.
RPO_TOLERANCE="${RPO_TOLERANCE:-0}"
OUT="${OUT:-docs/bench/phase6-failover.json}"

# FENCE=1 arms the writer lease on every janus-orchd this drill starts.
#
# Without it, FORK=1 demonstrates the problem: two writers, two valid logs, and a
# comparison that can name the divergence but not resolve it. With it, the same
# sequence must end with the revenant REFUSING TO START -- which is the whole
# claim of the fence and the thing no test in this repository has ever made.
#
# The TTL is deliberately tiny. The primary is SIGKILLed, so it never releases
# its lease and the promoted writer has to wait the TTL out before stealing;
# thirty seconds of that in a drill would be thirty seconds of nothing.
# Expanded as ${FENCE_ARGS[@]+"${FENCE_ARGS[@]}"} at every use: macOS ships bash
# 3.2, where expanding an empty array under `set -u` is an unbound-variable
# error rather than nothing. The drill has to run on a laptop as well as in CI.
FENCE_ARGS=()
if [[ "${FENCE:-0}" == "1" ]]; then
  if [[ -z "${JANUS_S3_ENDPOINT:-}" ]]; then
    echo "FENCE=1 needs an object store: set JANUS_S3_ENDPOINT (and run 'make dev')" >&2
    exit 1
  fi
  FENCE_TTL="${FENCE_TTL:-2s}"
  # Supplied rather than left to the ambient chain: with an endpoint set and no
  # credentials, the SDK falls back to EC2 IMDS and spends its whole timeout
  # discovering there is no instance role, which reads as "the bucket is
  # unreachable" rather than "nobody said who we are".
  FENCE_ARGS=(
    -fence-access-key "${JANUS_S3_ACCESS_KEY:-janus}"
    -fence-secret-key "${JANUS_S3_SECRET_KEY:-januspassword}"
    -fence-bucket "${FENCE_BUCKET:-janus-fence-drill}"
    -fence-key "tenure/drill-$$-$(date +%s).json"
    -fence-ttl "$FENCE_TTL"
  )
fi

cleanup() {
  for p in "${REVENANT_PID:-}" "${PROMOTED2_PID:-}" "${REPLICA2_PID:-}" \
           "${PROMOTED_PID:-}" "${REPLICA_PID:-}" "${ORCHD_PID:-}"; do
    [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null || true
  done
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

echo "--- keys: one for the primary, one held in reserve for whoever is promoted"
"$BIN/janus-keys" gen "$WORK/keys/primary.key" >/dev/null
"$BIN/janus-keys" gen "$WORK/keys/standby.key" >/dev/null
"$BIN/janus-keys" pub "$WORK/keys/primary.key" >"$WORK/keys/primary-pub.json"
"$BIN/janus-keys" pub "$WORK/keys/standby.key" >"$WORK/keys/standby-pub.json"
# A third key for the second failover, declared by the PROMOTED writer while IT
# is healthy -- which is the promotion rule one hop further along the
# writer-key chain than any deployment has been asked to go. The root an auditor holds is still
# only primary-pub.json, and that is what round 2 verifies against.
STANDBY2_ARGS=()
if [[ "$ROUNDS" -ge 2 ]]; then
  "$BIN/janus-keys" gen "$WORK/keys/standby2.key" >/dev/null
  "$BIN/janus-keys" pub "$WORK/keys/standby2.key" >"$WORK/keys/standby2-pub.json"
  STANDBY2_ARGS=(-standby-keys "$WORK/keys/standby2-pub.json")
fi

# -standby-keys declares the reserve key in the log *while the primary is
# healthy*. That is the whole crux of promotion: trust extends forward, so a key
# first declared by the promoted writer would dangle from no in-chain
# declaration and an auditor holding one root could not reach it.
echo "--- primary on :$PORT, declaring the standby key"
"$BIN/janus-orchd" -dir "$PRIMARY" -key "$WORK/keys/primary.key" \
  -listen "127.0.0.1:$PORT" -sync none -segment-bytes 4096 \
  ${FENCE_ARGS[@]+"${FENCE_ARGS[@]}"} \
  -standby-keys "$WORK/keys/standby-pub.json" >"$WORK/orchd.log" 2>&1 &
ORCHD_PID=$!
for _ in $(seq 60); do
  grep -q "serving on" "$WORK/orchd.log" 2>/dev/null && break
  sleep 0.2
done
grep -q "serving on" "$WORK/orchd.log" || { echo "the primary never came up:" >&2; cat "$WORK/orchd.log" >&2; exit 1; }

echo "--- follower"
"$BIN/janus-replicad" -primary "127.0.0.1:$PORT" -dir "$REPLICA" \
  -keys "$WORK/keys/primary-pub.json" -interval 300ms >"$WORK/replicad.log" 2>&1 &
REPLICA_PID=$!

echo "--- $CALLS calls against the primary, counting the ones that returned success"
ACKED=0
for i in $(seq "$CALLS"); do
  if "$BIN/janus-identity" revoke -addr "127.0.0.1:$PORT" \
      -id "cred_drill_$i" -reason "failover drill" >/dev/null 2>&1; then
    ACKED=$((ACKED + 1))
  fi
  sleep 0.05
done
echo "    $ACKED of $CALLS returned success — those are the ones whose evidence must survive"

# How long the follower is given before the kill. The default lets it catch up,
# which is steady state; SETTLE=0 kills it mid-stream, which is where the lag's
# exposure becomes a number rather than an argument.
sleep "${SETTLE:-1}"

# SIGKILL, not a graceful stop: a region does not close its files.
echo "--- killing the primary"
KILL_NS=$(date +%s%N)
kill -9 "$ORCHD_PID" 2>/dev/null || true
wait "$ORCHD_PID" 2>/dev/null || true
ORCHD_PID=""

# The follower is stopped before promotion because promotion takes the writer
# lock, and two processes writing one directory is what the lock refuses. In a
# real failover this is a step in the runbook; here it is a step in the drill,
# and both take operator time that the RTO below excludes.
kill "$REPLICA_PID" 2>/dev/null || true
wait "$REPLICA_PID" 2>/dev/null || true
REPLICA_PID=""

FOLLOWER_SEQ=$(grep -o 'acknowledged through sequence [0-9]*' "$WORK/replicad.log" | tail -1 | grep -o '[0-9]*$' || echo 0)
echo "    the follower had acknowledged through sequence $FOLLOWER_SEQ"

# RTO starts here, and what it excludes is stated rather than hidden: everything
# above is an operator noticing and deciding, which no drill can measure and no
# deployment should pretend to.
RTO_START_NS=$(date +%s%N)

# A second replica of the same log, taken before the promotion, so that the
# fence has something real to refuse later. Two operators each promoting their
# own replica is the case the fence exists for: the tenure records and the
# writer lock cannot see each other, so both promotions succeed and two logs
# claim to continue from the same sequence.
if [[ "${FENCE:-0}" == "1" ]]; then
  RIVAL="$WORK/rival"
  cp -R "$REPLICA" "$RIVAL"
  RIVAL_BEFORE=$(find "$RIVAL" -type f | sort | xargs shasum | shasum | cut -d' ' -f1)
fi

echo "--- promoting the replica"
"$BIN/janus-replicad" promote -dir "$REPLICA" -key "$WORK/keys/standby.key" \
  -operator "op_drill" -reason "primary killed" -node "region-b" \
  -acknowledged "$FOLLOWER_SEQ" \
  ${FENCE_ARGS[@]+"${FENCE_ARGS[@]}"} >"$WORK/promote.log" 2>&1 || {
    echo "promotion failed:" >&2; cat "$WORK/promote.log" >&2; exit 1; }
sed -n '1,4p' "$WORK/promote.log" | sed 's/^/    /'

# No -fence-epoch on the daemon, and that is the assertion rather than a
# convenience: the promotion recorded the epoch in this directory's writer
# marker, and janus-orchd reads it from there. A drill that passed the
# number would pass whether or not that worked.
#
# The epoch the promotion took is still read out of its log, so the negative leg
# below has something to contradict.
PROMOTED_EPOCH=""
if [[ "${FENCE:-0}" == "1" ]]; then
  PROMOTED_EPOCH=$(grep -o 'lease was taken at epoch [0-9]*' "$WORK/promote.log" | tail -1 | grep -o '[0-9]*$' || echo "")
  [[ -n "$PROMOTED_EPOCH" ]] || { echo "the promotion did not say which epoch it took the lease at:" >&2; cat "$WORK/promote.log" >&2; exit 1; }
  echo "    epoch $PROMOTED_EPOCH, recorded in the writer marker rather than printed to be retyped"

  # A daemon told an epoch that contradicts the marker is refused. This is the
  # direction that matters: a stray number one higher would take the log from a
  # writer that legitimately holds it, and the lease cannot arbitrate what it is
  # being told.
  if "$BIN/janus-orchd" -dir "$REPLICA" -key "$WORK/keys/standby.key" \
      -listen "127.0.0.1:$PORT2" -sync none -segment-bytes 4096 \
      ${FENCE_ARGS[@]+"${FENCE_ARGS[@]}"} \
      -fence-epoch "$((PROMOTED_EPOCH + 1))" >"$WORK/orchd-wrong-epoch.log" 2>&1; then
    echo "FAIL: janus-orchd started with -fence-epoch $((PROMOTED_EPOCH + 1)) against a" >&2
    echo "      directory whose marker says $PROMOTED_EPOCH. A writer claiming a promotion" >&2
    echo "      that never happened takes the lease from one that did." >&2
    exit 1
  fi
  grep -q "contradicts this directory's writer marker" "$WORK/orchd-wrong-epoch.log" || {
    echo "FAIL: it was refused, but not by the epoch check:" >&2
    cat "$WORK/orchd-wrong-epoch.log" >&2; exit 1; }
  echo "    a contradicting -fence-epoch is refused, naming both numbers"
fi

echo "--- starting the promoted writer on :$PORT2"
# The drill used to sleep here for the dead primary's TTL, because the promotion
# took no lease and the daemon was the first thing that tried. It is gone: the
# promotion takes the lease now, and displacing a writer that was still live is
# where the wait belongs. The line promote printed above --
# `waiting until ... for it to find out` -- is that wait, and it is real time a
# fenced failover costs. It is inside nobody's RTO number, because the clock for
# that started before the promotion and the drill reports it separately.
#
# The epoch is the promotion's, not the default. A daemon started at 0 here is
# refused by its own log, which is the same refusal the revenant gets below.
"$BIN/janus-orchd" -dir "$REPLICA" -key "$WORK/keys/standby.key" \
  -listen "127.0.0.1:$PORT2" -sync none -segment-bytes 4096 \
  ${FENCE_ARGS[@]+"${FENCE_ARGS[@]}"} \
  ${STANDBY2_ARGS[@]+"${STANDBY2_ARGS[@]}"} \
  >"$WORK/promoted.log" 2>&1 &
PROMOTED_PID=$!
for _ in $(seq 100); do
  grep -q "serving on" "$WORK/promoted.log" 2>/dev/null && break
  sleep 0.1
done
grep -q "serving on" "$WORK/promoted.log" || { echo "the promoted writer never came up:" >&2; cat "$WORK/promoted.log" >&2; exit 1; }

# The RTO ends at the first *successful* append, not at the process starting. A
# daemon that is listening and cannot yet write has not recovered anything.
echo "--- first write against the promoted writer"
for _ in $(seq 100); do
  if "$BIN/janus-identity" revoke -addr "127.0.0.1:$PORT2" \
      -id "cred_after_failover" -reason "first write after promotion" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
RTO_MS=$(( ( $(date +%s%N) - RTO_START_NS ) / 1000000 ))
KILL_TO_WRITE_MS=$(( ( $(date +%s%N) - KILL_NS ) / 1000000 ))
echo "    RTO ${RTO_MS} ms (excluding operator decision time; ${KILL_TO_WRITE_MS} ms since the kill)"

# The second promotion: the case left open after the writer-side fence was
# armed.
#
# A second operator, a second replica of the same log, promoting at the same
# moment. Nothing local can stop it -- the two directories have their own writer
# locks and neither tenure record can see the other -- so before the lease, both
# promotions succeeded and produced two logs each claiming to continue from
# sequence 42.
#
# It is deterministic rather than an actual race, and that is on purpose: the
# promoted writer is up and holding the lease at the same epoch the rival would
# derive, so the rival meets exactly what the loser of a race meets. Equal epochs
# do not displace each other -- only a promotion at a HIGHER epoch does -- which
# is what makes two promotions of one log mutually exclusive.
#
# This is the easy half. The second attempt, further down, is against a lease
# nobody holds at all.
if [[ "${FENCE:-0}" == "1" ]]; then
  echo "--- a second operator promotes a second replica of the same log"
  if "$BIN/janus-replicad" promote -dir "$RIVAL" -key "$WORK/keys/standby.key" \
      -operator "op_rival" -reason "did not know about the first promotion" -node "region-c" \
      ${FENCE_ARGS[@]+"${FENCE_ARGS[@]}"} >"$WORK/rival-promote.log" 2>&1; then
    echo "FAIL: a second promotion of the same log succeeded while the first writer held" >&2
    echo "the lease. Two logs now claim to continue from the same sequence, which is the" >&2
    echo "fork the fence exists to prevent." >&2
    cat "$WORK/rival-promote.log" >&2
    exit 1
  fi
  # "already established" rather than "refusing to start a second writer": for a
  # promotion, the epoch being taken is the whole answer and whether the holder
  # is alive does not enter into it. A daemon asking the same question gets the
  # liveness answer, because an expired lease at its own epoch is its to reclaim.
  grep -q "already established" "$WORK/rival-promote.log" || {
    echo "FAIL: the second promotion failed for some other reason than the fence:" >&2
    cat "$WORK/rival-promote.log" >&2; exit 1; }
  sed -n '1p' "$WORK/rival-promote.log" | sed 's/^/    /'
  # And it recorded nothing. A refusal that had already appended a tenure would
  # leave a directory that is neither a replica nor a writer -- still promotable
  # by the marker, and carrying a handover nobody performed.
  RIVAL_AFTER=$(find "$RIVAL" -type f | sort | xargs shasum | shasum | cut -d' ' -f1)
  if [[ "$RIVAL_BEFORE" != "$RIVAL_AFTER" ]]; then
    echo "FAIL: the refused promotion changed $RIVAL. The lease is taken before the" >&2
    echo "tenure is written precisely so that a promotion which cannot fence records" >&2
    echo "nothing." >&2
    exit 1
  fi
  echo "    and it wrote nothing: the replica is byte-identical and still promotable"
fi

# FORK=1 turns this into the split-brain drill: the old primary is brought back
# up on its own directory while the promoted writer is still serving, which is
# what a partition healing at the wrong moment does.
#
# **The promoted writer is deliberately still running here.** It used to be
# stopped first, which made the drill a sequential restart rather than a
# split-brain: at no point were there two live writers, so the revenant was
# legitimately the only one and a fence had nothing to refuse. The comparison
# still found two logs — the revenant writes its own directory either way — so
# the drill passed while modelling something milder than its own comment
# claimed.
if [[ "${FORK:-0}" == "1" ]]; then
  echo "--- FORK: bringing the old primary back after the promotion"
  "$BIN/janus-orchd" -dir "$PRIMARY" -key "$WORK/keys/primary.key" \
    -listen "127.0.0.1:$((PORT + 10))" -sync none -segment-bytes 4096 \
    ${FENCE_ARGS[@]+"${FENCE_ARGS[@]}"} \
    >"$WORK/revenant.log" 2>&1 &
  REVENANT_PID=$!
  for _ in $(seq 100); do
    grep -qE "serving on|refusing to start" "$WORK/revenant.log" 2>/dev/null && break
    sleep 0.1
  done

  # With the fence armed this is the whole point of the drill: the revenant must
  # not come up at all. Checked positively -- the refusal has to NAME the holder,
  # because an operator staring at a daemon that will not start needs to know
  # whether the other side is alive rather than whether a bucket is misconfigured.
  if [[ "${FENCE:-0}" == "1" ]]; then
    if grep -q "serving on" "$WORK/revenant.log" 2>/dev/null; then
      echo "FAIL: the fence was armed and the old primary started anyway." >&2
      sed 's/^/    /' "$WORK/revenant.log" >&2
      exit 1
    fi
    # Either refusal is the fence; they are not the same refusal, and which one
    # appears says how the revenant lost.
    #
    #   "refusing to start a second writer"  -- somebody else holds the lease
    #                                           right now. Contention: it depends
    #                                           on the other side being alive.
    #   "has moved to epoch N"               -- the log was promoted past this
    #                                           writer's tenure. Supersession: it
    #                                           holds whether or not the promoted
    #                                           writer is up, and it is the one
    #                                           that appears here.
    #
    # The second is the stronger and the drill would once have reported it as a
    # failure, because the check was written when the epoch decided nothing.
    if ! grep -qE "refusing to start a second writer|has moved to epoch" "$WORK/revenant.log" 2>/dev/null; then
      echo "FAIL: the old primary did not start, but not because of the lease --" >&2
      echo "      a drill that passes for the wrong reason proves nothing." >&2
      sed 's/^/    /' "$WORK/revenant.log" >&2
      exit 1
    fi
    echo "    the old primary refused to start:"
    grep -E "refusing to start a second writer|has moved to epoch" "$WORK/revenant.log" | sed 's/^/      /'
  fi
  for i in 1 2 3; do
    "$BIN/janus-identity" revoke -addr "127.0.0.1:$((PORT + 10))" \
      -id "cred_revenant_$i" -reason "the old primary is still writing" >/dev/null 2>&1 || true
  done
  kill "$REVENANT_PID" 2>/dev/null || true
  wait "$REVENANT_PID" 2>/dev/null || true
  REVENANT_PID=""

  echo "--- comparing the two directories"
  if "$BIN/janus-replicad" compare -a "$PRIMARY" -b "$REPLICA" >"$WORK/compare.log" 2>&1; then
    if [[ "${FENCE:-0}" == "1" ]]; then
      sed 's/^/    /' "$WORK/compare.log"
      echo "    the two directories did NOT diverge, because the second writer never wrote."
      echo "    This is the fence: without it the same sequence produces two valid logs"
      echo "    and a comparison that can name the divergence but not resolve it."
    else
      echo "FAIL: two writers each continued the log and the comparison found no fork." >&2
      cat "$WORK/compare.log" >&2
      exit 1
    fi
  elif [[ "${FENCE:-0}" == "1" ]]; then
    echo "FAIL: the fence was armed and the logs diverged anyway." >&2
    cat "$WORK/compare.log" >&2
    exit 1
  else
    sed 's/^/    /' "$WORK/compare.log"
    echo "    (a non-zero exit here is the tool working: these are two logs now)"
  fi
fi

kill "$PROMOTED_PID" 2>/dev/null || true
wait "$PROMOTED_PID" 2>/dev/null || true
PROMOTED_PID=""

# The second promotion again, and this time against a lease nobody holds.
#
# The first attempt above met a LIVE lease, which is the easy half. A promotion
# releases on its way out -- the process that goes on writing is janus-orchd,
# started separately -- so between the two there is a record at the promoted
# epoch, marked expired, that nobody is renewing. A rival promotion derives the
# same epoch, finds it not live, and under the epoch rule alone would steal it
# and write a second tenure. Five seconds of real operator time is all it takes.
#
# That is why a promotion *establishes* its epoch rather than serving it: an
# expired lease at the epoch you are claiming is not an opening, it is what
# somebody else's promotion left behind, and the writer it belongs to may simply
# not have been started yet.
if [[ "${FENCE:-0}" == "1" ]]; then
  echo "--- and again, with nobody holding the lease at all"
  sleep "${FENCE_TTL%s}"   # whatever the daemon left is certainly expired now
  if "$BIN/janus-replicad" promote -dir "$RIVAL" -key "$WORK/keys/standby.key" \
      -operator "op_rival" -reason "and the first writer is not even running" -node "region-c" \
      ${FENCE_ARGS[@]+"${FENCE_ARGS[@]}"} >"$WORK/rival-promote-2.log" 2>&1; then
    echo "FAIL: a second promotion succeeded once the lease was merely expired. The window" >&2
    echo "between a promotion releasing and its daemon starting is exactly when a second" >&2
    echo "operator acts, and two logs now claim to continue from the same sequence." >&2
    cat "$WORK/rival-promote-2.log" >&2
    exit 1
  fi
  grep -q "already established" "$WORK/rival-promote-2.log" || {
    echo "FAIL: the second promotion failed, but not because the epoch was taken:" >&2
    cat "$WORK/rival-promote-2.log" >&2; exit 1; }
  sed -n '1p' "$WORK/rival-promote-2.log" | sed 's/^/    /'
  RIVAL_AFTER_2=$(find "$RIVAL" -type f | sort | xargs shasum | shasum | cut -d' ' -f1)
  [[ "$RIVAL_BEFORE" == "$RIVAL_AFTER_2" ]] || {
    echo "FAIL: the refused promotion changed $RIVAL." >&2; exit 1; }
fi

# Continuity: against the ORIGINAL primary's key and nothing else. If the standby
# key had been declared at promotion rather than in advance, this is where it
# would fail — every segment the promoted writer signed would be unreachable
# from this root.
echo "--- verifying the promoted log against the original root, and nothing else"
"$BIN/janus-verify" -keys "$WORK/keys/primary-pub.json" -allow-open-tail \
  -json "$REPLICA" >"$WORK/verify.json" 2>"$WORK/verify.err" || {
    echo "the promoted log does not verify from the original root:" >&2
    cat "$WORK/verify.err" >&2
    python3 -c "import json;[print('   ',f['severity'],f['code'],'-',f['message']) for f in json.load(open('$WORK/verify.json')).get('findings',[])]" >&2 || true
    exit 1; }
echo "    verifies"

echo "--- RPO: is the evidence for every acknowledged call in the promoted log?"
"$BIN/janus-verify" -keys "$WORK/keys/primary-pub.json" -allow-open-tail -list \
  -json "$REPLICA" >"$WORK/list.json" 2>/dev/null
SURVIVED=$(python3 -c "
import json
d = json.load(open('$WORK/list.json'))
print(sum(1 for e in d.get('event_list', []) if e.get('kind') == 'IDENTITY_TRUST'))
")
# One of them is the post-promotion write, which was not part of the pre-kill
# count and must not be credited to it.
SURVIVED=$((SURVIVED - 1))
echo "    $SURVIVED of $ACKED acknowledged calls have their evidence in the promoted log"

# ---------------------------------------------------------------------------
# Round two: the failover after the failover.
#
# Until the writer marker this could not be run at all, and the reason is worth
# keeping.
# A promotion records a tenure IN THE LOG, and replication copies the log
# faithfully -- so after one failover every replica carries the promotion's
# tenure. Both of the refusals that protect a directory were written against
# that tenure, so both refused every replica of a failed-over log: the follower
# could not be restarted, and no replica could be promoted. A deployment could
# fail over exactly once, and then had no replica it could restart.
#
# What makes this round worth running rather than asserting is the last check in
# it: the twice-promoted log verifies against the ORIGINAL primary's public key
# and nothing else. Two changes of writer, three keys, one root out of band.
if [[ "$ROUNDS" -ge 2 ]]; then
  echo
  echo "=== ROUND 2: failing over a log that has already failed over ==="
  REPLICA2="$WORK/replica2"

  # The promoted writer comes back up -- it was stopped above for the compare --
  # so there is something for the second replica to follow.
  echo "--- the promoted writer again on :$PORT2, so it can be replicated"
  "$BIN/janus-orchd" -dir "$REPLICA" -key "$WORK/keys/standby.key" \
    -listen "127.0.0.1:$PORT2" -sync none -segment-bytes 4096 \
    ${FENCE_ARGS[@]+"${FENCE_ARGS[@]}"} \
    ${STANDBY2_ARGS[@]+"${STANDBY2_ARGS[@]}"} \
  >"$WORK/promoted2.log" 2>&1 &
  PROMOTED_PID=$!
  for _ in $(seq 150); do
    grep -q "serving on" "$WORK/promoted2.log" 2>/dev/null && break
    sleep 0.1
  done
  grep -q "serving on" "$WORK/promoted2.log" || {
    echo "the promoted writer would not restart:" >&2; cat "$WORK/promoted2.log" >&2; exit 1; }

  # -keys is the ORIGINAL primary's key. Follower #2 has never been handed the
  # standby's, and it checks the promoted writer's segment signatures anyway,
  # because the chain reaches them.
  echo "--- follower #2, trusting only the original root"
  "$BIN/janus-replicad" -primary "127.0.0.1:$PORT2" -dir "$REPLICA2" \
    -keys "$WORK/keys/primary-pub.json" -interval 300ms >"$WORK/replicad2.log" 2>&1 &
  REPLICA2_PID=$!

  # Caught up BEFORE the calls start, or the RPO count below would be measuring
  # this follower's cold start rather than what a failover costs.
  # Round one's head, which is a LOWER BOUND on the restarted writer's: it has
  # appended its own clock attestation since. Reaching it means the cold start
  # is over, and SETTLE below is what covers the rest.
  HEAD_NOW=$(python3 -c "
import json,sys
d = json.load(open('$WORK/verify.json'))
print(d.get('last_seq', 0))")
  CAUGHT=0
  for _ in $(seq 100); do
    SEEN=$(grep -o 'acknowledged through sequence [0-9]*' "$WORK/replicad2.log" | tail -1 | grep -o '[0-9]*$' || echo 0)
    if [[ "$SEEN" -ge "$HEAD_NOW" ]]; then CAUGHT=1; break; fi
    sleep 0.2
  done
  [[ "$CAUGHT" == "1" ]] || {
    echo "FAIL: follower #2 never reached sequence $HEAD_NOW; the RPO number below" >&2
    echo "      would be a measurement of a cold start." >&2
    tail -5 "$WORK/replicad2.log" >&2; exit 1; }
  echo "    caught up through sequence $HEAD_NOW"

  echo "--- $CALLS calls against the promoted writer"
  ACKED2=0
  for i in $(seq "$CALLS"); do
    if "$BIN/janus-identity" revoke -addr "127.0.0.1:$PORT2" \
        -id "cred_round2_$i" -reason "second failover drill" >/dev/null 2>&1; then
      ACKED2=$((ACKED2 + 1))
    fi
    sleep 0.05
  done
  echo "    $ACKED2 of $CALLS returned success"
  sleep "${SETTLE:-1}"

  echo "--- killing the promoted writer"
  KILL2_NS=$(date +%s%N)
  kill -9 "$PROMOTED_PID" 2>/dev/null || true
  wait "$PROMOTED_PID" 2>/dev/null || true
  PROMOTED_PID=""
  kill "$REPLICA2_PID" 2>/dev/null || true
  wait "$REPLICA2_PID" 2>/dev/null || true
  REPLICA2_PID=""

  FOLLOWER2_SEQ=$(grep -o 'acknowledged through sequence [0-9]*' "$WORK/replicad2.log" | tail -1 | grep -o '[0-9]*$' || echo 0)
  echo "    follower #2 had acknowledged through sequence $FOLLOWER2_SEQ"

  # The negative, through the binary, before the positive: the directory that
  # WAS promoted stays promoted. This is the marker refusing and not the fence --
  # it runs with whatever FENCE_ARGS are set, and the message has to be the
  # marker's.
  echo "--- the already-promoted directory is still refused"
  if "$BIN/janus-replicad" promote -dir "$REPLICA" -key "$WORK/keys/standby2.key" \
      -operator "op_confused" -reason "promoting the writer itself" -node "region-x" \
      ${FENCE_ARGS[@]+"${FENCE_ARGS[@]}"} >"$WORK/promote-writer.log" 2>&1; then
    echo "FAIL: the directory a writer owns was promoted again. The writer marker narrowed this" >&2
    echo "      refusal from 'holds a tenure' to 'an appender has owned it', and the" >&2
    echo "      second half has to keep refusing or the first was a regression." >&2
    exit 1
  fi
  grep -q "already a writer.s directory" "$WORK/promote-writer.log" || {
    echo "FAIL: it was refused, but not by the writer marker:" >&2
    cat "$WORK/promote-writer.log" >&2; exit 1; }
  sed -n '1p' "$WORK/promote-writer.log" | sed 's/^/    /'

  RTO2_START_NS=$(date +%s%N)
  echo "--- promoting replica #2"
  # No -fence-epoch here either: the epoch is derived, and this is the case that
  # makes the derivation worth having -- a replica of a once-promoted log holds
  # one tenure, so it derives 2 on its own.
  "$BIN/janus-replicad" promote -dir "$REPLICA2" -key "$WORK/keys/standby2.key" \
    -operator "op_drill" -reason "the promoted writer was killed too" -node "region-c" \
    -acknowledged "$FOLLOWER2_SEQ" \
    ${FENCE_ARGS[@]+"${FENCE_ARGS[@]}"} >"$WORK/promote2.log" 2>&1 || {
      echo "the SECOND promotion failed -- this is the thing the writer marker exists to make possible:" >&2
      cat "$WORK/promote2.log" >&2; exit 1; }
  sed -n '1,4p' "$WORK/promote2.log" | sed 's/^/    /'

  if [[ "${FENCE:-0}" == "1" ]]; then
    PROMOTED2_EPOCH=$(grep -o 'lease was taken at epoch [0-9]*' "$WORK/promote2.log" | tail -1 | grep -o '[0-9]*$' || echo "")
    [[ "$PROMOTED2_EPOCH" == "2" ]] || {
      echo "FAIL: the second promotion derived epoch '${PROMOTED2_EPOCH:-none}', want 2." >&2
      echo "      An epoch counts the promotions the LOG has been through, and this log" >&2
      echo "      has now been through two." >&2
      cat "$WORK/promote2.log" >&2; exit 1; }
    echo "    epoch 2, derived rather than given -- and recorded, not retyped"
  fi

  echo "--- starting the twice-promoted writer on :$PORT3"
  "$BIN/janus-orchd" -dir "$REPLICA2" -key "$WORK/keys/standby2.key" \
    -listen "127.0.0.1:$PORT3" -sync none -segment-bytes 4096 \
    ${FENCE_ARGS[@]+"${FENCE_ARGS[@]}"} \
  >"$WORK/promoted3.log" 2>&1 &
  PROMOTED2_PID=$!
  for _ in $(seq 150); do
    grep -q "serving on" "$WORK/promoted3.log" 2>/dev/null && break
    sleep 0.1
  done
  grep -q "serving on" "$WORK/promoted3.log" || {
    echo "the twice-promoted writer never came up:" >&2; cat "$WORK/promoted3.log" >&2; exit 1; }

  for _ in $(seq 100); do
    "$BIN/janus-identity" revoke -addr "127.0.0.1:$PORT3" \
      -id "cred_after_failover_2" -reason "first write after the second promotion" \
      >/dev/null 2>&1 && break
    sleep 0.1
  done
  RTO2_MS=$(( ( $(date +%s%N) - RTO2_START_NS ) / 1000000 ))
  KILL2_TO_WRITE_MS=$(( ( $(date +%s%N) - KILL2_NS ) / 1000000 ))
  echo "    RTO ${RTO2_MS} ms (${KILL2_TO_WRITE_MS} ms since the kill)"

  kill "$PROMOTED2_PID" 2>/dev/null || true
  wait "$PROMOTED2_PID" 2>/dev/null || true
  PROMOTED2_PID=""

  # The headline. Three writer keys, two changes of writer, and the auditor is
  # still holding exactly the one key they were given on day one.
  echo "--- verifying the TWICE-promoted log against the original root, and nothing else"
  "$BIN/janus-verify" -keys "$WORK/keys/primary-pub.json" -allow-open-tail \
    -json "$REPLICA2" >"$WORK/verify2.json" 2>"$WORK/verify2.err" || {
      echo "the twice-promoted log does not verify from the original root:" >&2
      cat "$WORK/verify2.err" >&2
      python3 -c "import json;[print('   ',f['severity'],f['code'],'-',f['message']) for f in json.load(open('$WORK/verify2.json')).get('findings',[])]" >&2 || true
      exit 1; }
  echo "    verifies -- one root, three keys, two promotions"

  echo "--- RPO for round 2"
  "$BIN/janus-verify" -keys "$WORK/keys/primary-pub.json" -allow-open-tail -list \
    -json "$REPLICA2" >"$WORK/list2.json" 2>/dev/null
  SURVIVED2=$(python3 -c "
import json
d = json.load(open('$WORK/list2.json'))
print(sum(1 for e in d.get('event_list', []) if e.get('kind') == 'IDENTITY_TRUST'))")
  # Everything the log holds, minus round one's calls and the two post-promotion
  # writes, is round two's.
  SURVIVED2=$((SURVIVED2 - SURVIVED - 2))
  echo "    $SURVIVED2 of $ACKED2 acknowledged calls have their evidence in the twice-promoted log"
fi

python3 - "$OUT" "$ACKED" "$SURVIVED" "$RTO_MS" "$KILL_TO_WRITE_MS" "$FOLLOWER_SEQ" "$RTO_BUDGET_MS" "$RPO_TOLERANCE" \
  "${ROUNDS}" "${ACKED2:-0}" "${SURVIVED2:-0}" "${RTO2_MS:-0}" "${KILL2_TO_WRITE_MS:-0}" "${FOLLOWER2_SEQ:-0}" <<'PY'
import json, sys, datetime
out, acked, survived, rto, since_kill, follower_seq, budget, tolerance = sys.argv[1:9]
rounds, acked2, survived2, rto2, since_kill2, follower2_seq = sys.argv[9:15]
acked, survived = int(acked), int(survived)
doc = {
    "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "local_equivalent": ("Two processes on one host. A SIGKILL is not a region loss: "
                         "the disk survives."),
    "rto": {
        "ms": int(rto),
        "excludes": "operator decision time, and stopping the follower",
        "ms_since_kill": int(since_kill),
        "budget_ms": int(budget),
        "within_budget": int(rto) <= int(budget),
    },
    "rpo": {
        # The question that matters, not "how far behind was the replica".
        "question": "was any effect released whose evidence the replica lacks",
        "acknowledged_calls": acked,
        "evidence_present": survived,
        "violations": max(0, acked - survived),
    "tolerance": int(tolerance),
        "follower_acknowledged_seq": int(follower_seq),
    },
}
# Round two is absent rather than zeroed when it did not run: a zero RTO in a
# file somebody reads later is a claim, and it would be false.
if int(rounds) >= 2:
    doc["second_failover"] = {
        "why_it_is_separate": ("A promotion's tenure is replicated, so after one failover every "
                               "replica carries one. Until the writer marker that refused every replica: "
                               "the follower could not restart and no replica could be promoted."),
        "rto": {"ms": int(rto2), "ms_since_kill": int(since_kill2),
                "budget_ms": int(budget), "within_budget": int(rto2) <= int(budget)},
        "rpo": {"acknowledged_calls": int(acked2), "evidence_present": int(survived2),
                "violations": max(0, int(acked2) - int(survived2)),
                "tolerance": int(tolerance),
                "follower_acknowledged_seq": int(follower2_seq)},
        "epoch": 2,
        "verified_from": ("the ORIGINAL primary's public key alone -- three writer keys and two "
                          "promotions later"),
    }
json.dump(doc, open(out, "w"), indent=2)
open(out, "a").write("\n")
print(json.dumps(doc["rto"], indent=2))
print(json.dumps(doc["rpo"], indent=2))
if "second_failover" in doc:
    print(json.dumps(doc["second_failover"], indent=2))
PY

FAILED=0
VIOLATIONS=$((ACKED - SURVIVED))
if [[ "$VIOLATIONS" -gt "$RPO_TOLERANCE" ]]; then
  echo "FAIL: $VIOLATIONS acknowledged call(s) have no evidence in the promoted log," >&2
  echo "      against a tolerance of $RPO_TOLERANCE." >&2
  echo "      Something was told it had succeeded and the surviving log does not show it." >&2
  echo "      Under async replication this is possible by construction: the" >&2
  echo "      number is the exposure. At steady state it should be zero, and a non-zero" >&2
  echo "      count here means either the follower was behind or something is wrong." >&2
  FAILED=1
elif [[ "$VIOLATIONS" -gt 0 ]]; then
  echo "    $VIOLATIONS violation(s), within the tolerance of $RPO_TOLERANCE — this is" 
  echo "    the replication lag's exposure being measured, not a guarantee being broken."
fi
if [[ "$RTO_MS" -gt "$RTO_BUDGET_MS" ]]; then
  echo "FAIL: RTO ${RTO_MS} ms exceeds the ${RTO_BUDGET_MS} ms budget" >&2
  FAILED=1
fi
# The drill has to reach what it exists to measure.
if [[ "$ACKED" -eq 0 ]]; then
  echo "FAIL: no call returned success before the kill, so nothing was measured" >&2
  FAILED=1
fi
if ! grep -q "WRITER_TENURE" <(python3 -c "
import json
d = json.load(open('$WORK/list.json'))
print('\n'.join(e.get('kind','') for e in d.get('event_list', [])))
"); then
  echo "FAIL: the promoted log holds no WRITER_TENURE, so no promotion was recorded" >&2
  FAILED=1
fi
if [[ "$ROUNDS" -ge 2 ]]; then
  VIOLATIONS2=$(( ACKED2 - SURVIVED2 ))
  if [[ "$VIOLATIONS2" -gt "$RPO_TOLERANCE" ]]; then
    echo "FAIL: round 2 lost $VIOLATIONS2 acknowledged call(s), against a tolerance of" >&2
    echo "      $RPO_TOLERANCE. The second failover is not held to a weaker bar than the first." >&2
    FAILED=1
  fi
  if [[ "$RTO2_MS" -gt "$RTO_BUDGET_MS" ]]; then
    echo "FAIL: round 2 RTO ${RTO2_MS} ms exceeds the ${RTO_BUDGET_MS} ms budget" >&2
    FAILED=1
  fi
  if [[ "$ACKED2" -eq 0 ]]; then
    echo "FAIL: no call returned success before the second kill" >&2
    FAILED=1
  fi
  # Two tenures, not one: the twice-promoted log has to record both handovers,
  # or the second promotion overwrote rather than continued.
  TENURES2=$(python3 -c "
import json
d = json.load(open('$WORK/list2.json'))
print(sum(1 for e in d.get('event_list', []) if e.get('kind') == 'WRITER_TENURE'))
")
  if [[ "$TENURES2" -ne 2 ]]; then
    echo "FAIL: the twice-promoted log holds $TENURES2 tenure(s), want 2 — a log that has" >&2
    echo "      failed over twice records both handovers or it records neither honestly." >&2
    FAILED=1
  fi
fi

[[ "$FAILED" -eq 0 ]] || exit 1

echo
echo "janus failover-drill: PASS — written to $OUT"
echo
echo "  The promoted log verifies from the ORIGINAL writer's key alone. That is"
echo "  what enrolling the standby key while the primary was healthy bought."
if [[ "$ROUNDS" -ge 2 ]]; then
  echo
  echo "  And so does the log that failed over TWICE — three writer keys, two"
  echo "  promotions, still one root out of band. Round 2 could not be run at all"
  echo "  before the writer marker: a tenure is replicated, so every replica of a"
  echo "  failed-over log read as already promoted."
else
  echo
  echo "  ROUNDS=2 fails the log over a second time, which is the case that could"
  echo "  not run at all until the writer marker."
fi
echo
echo "  This is the local equivalent of a region failover and it is not one:"
echo "  two processes on one host, and a SIGKILL that leaves the disk behind."
