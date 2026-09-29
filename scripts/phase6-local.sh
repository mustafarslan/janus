#!/usr/bin/env bash
# Phase 6's exit gate, in the only form this repository can produce it.
#
# THE GATE IS: "load test at 10x design-partner peak with SLOs held; region-
# failover game day; replay sampling in prod design partner >= 99.99%
# deterministic".
#
# THIS IS NOT THAT. There is no design partner, so there is no peak to multiply
# and no production to sample; there is no second region, so there is no region
# to fail over. What runs here is the local equivalent of each leg, and the
# difference is not a formality:
#
#   - a load test at a *stated reference scale* rather than at 10x anybody's peak
#   - a failover between two processes on one host, where a SIGKILL leaves the
#     disk behind and the primary's own log survives to compare against
#   - replay sampling over this repository's chaos corpus rather than production
#
# Each leg says which of the two it is, in its own output, every time. The point
# of running them together is not to add up to the gate. It is that a phase whose
# gate cannot be produced should still have to show its work, and these are the
# strongest things that can be shown.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

OUT="${OUT:-docs/gate/phase6-local.json}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$(dirname "$OUT")"

# The reference scale. Stated rather than implied, because "the load test
# passed" means nothing without it and because the 25 ms gated-effect budget
# is marginal at exactly this concurrency — running below it would be choosing
# a number that passes.
CONC="${CONC:-64}"
BG="${BG:-2000}"
SAMPLES="${SAMPLES:-300}"

pass=0
fail=0
note() { printf '\n=== %s\n' "$1"; }

note "leg 1 of 3: a load test at a stated reference scale"
echo "    concurrency $CONC, $BG background sagas, $SAMPLES samples, sync=full, on linux"
echo "    (NOT 10x a design partner's peak: there is no design partner)"
if LATENCY_ARGS="-samples $SAMPLES -background $BG -concurrency $CONC -sync full" \
     make latency-linux >"$WORK/latency.log" 2>&1; then
  echo "    PASS"
  pass=$((pass + 1))
else
  echo "    FAIL — see below"
  fail=$((fail + 1))
fi
grep -E "gated_effect|decide_pre_release|verdict" "$WORK/latency.log" | tail -8 | sed 's/^/      /' || true

note "leg 2 of 3: a failover drill"
echo "    two processes on one host (NOT a region: the disk survives the kill)"
if make failover >"$WORK/failover.log" 2>&1; then
  echo "    PASS"
  pass=$((pass + 1))
else
  echo "    FAIL — see below"
  fail=$((fail + 1))
fi
grep -E "RTO |acknowledged calls|verifies" "$WORK/failover.log" | sed 's/^/      /' || true

note "leg 3 of 3: replay sampling"
echo "    over this repository's chaos corpus (NOT a design partner's production)"
if make spotreplay >"$WORK/spotreplay.log" 2>&1; then
  echo "    PASS"
  pass=$((pass + 1))
else
  echo "    FAIL — see below"
  fail=$((fail + 1))
fi
grep -E "sagas|[0-9]+\.[0-9]+%|determinis" "$WORK/spotreplay.log" | tail -4 | sed 's/^/      /' || true

python3 - "$OUT" "$CONC" "$BG" "$SAMPLES" "$pass" "$fail" \
  "docs/bench/phase6-failover.json" <<'PY'
import json, os, sys, datetime
out, conc, bg, samples, npass, nfail, failover_path = sys.argv[1:8]
doc = {
    "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "what_this_is": (
        "The LOCAL EQUIVALENT of the Phase 6 exit gate, not the gate. The gate "
        "asks for a load test at 10x a design partner's peak, a region-failover "
        "game day, and replay sampling in a design partner's production. There "
        "is no design partner and no second region."
    ),
    "legs": {
        "load_test": {
            "is": "a load test at a stated reference scale",
            "is_not": "10x a design partner's peak",
            "concurrency": int(conc), "background_sagas": int(bg), "samples": int(samples),
            "detail": "docs/bench/README.md, section 'Where the remaining 25 ms actually is'",
        },
        "failover_drill": {
            "is": "two processes on one host, primary SIGKILLed",
            "is_not": "a region failover; the disk survives the kill",
            "detail": failover_path,
        },
        "replay_sampling": {
            "is": "a rate over this repository's chaos corpus",
            "is_not": "sampling in a design partner's production",
            "detail": "docs/bench/README.md, spot-replay",
        },
    },
    "legs_passed": int(npass),
    "legs_failed": int(nfail),
}
if os.path.exists(failover_path):
    with open(failover_path) as fh:
        f = json.load(fh)
    doc["legs"]["failover_drill"]["rto_ms"] = f["rto"]["ms"]
    doc["legs"]["failover_drill"]["rpo_violations"] = f["rpo"]["violations"]
json.dump(doc, open(out, "w"), indent=2)
open(out, "a").write("\n")
PY

printf '\n'
if [[ "$fail" -ne 0 ]]; then
  echo "phase6-local: $fail of 3 legs FAILED — written to $OUT" >&2
  exit 1
fi
cat <<EOF
phase6-local: all 3 legs pass — written to $OUT

  This is the local equivalent of the Phase 6 exit gate and it is NOT the gate.
  The gate needs a design partner to have a peak worth multiplying and a
  production worth sampling, and a second region to fail over. None of those
  exist here.

  What these three legs establish is that the machinery works and what it costs.
  What they cannot establish is that a deployment meets its SLOs, because no
  deployment is being measured.
EOF
