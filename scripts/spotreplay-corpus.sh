#!/usr/bin/env bash
# Run janus-spotreplay over every evidence directory a chaos run left behind, and
# report one rate across all of them.
#
# This is how the Phase 6 determinism number is produced in this repository. The
# chaos suite is the richest source of real sagas here: every one of them was
# killed and resumed at least once, so a replay divergence in this corpus would
# be a divergence in exactly the histories where it matters — the ones that were
# reconstructed rather than merely written.
#
#   scripts/spotreplay-corpus.sh                 # run the chaos suites, then check
#   scripts/spotreplay-corpus.sh /path/to/root   # check a directory tree already kept
#
# What it is not: a measurement of a production deployment. The Phase 6 exit gate
# asks for "replay sampling in prod design partner ≥ 99.99% deterministic", and
# there is no design partner. What is produced here is the daemon and a rate over
# this repository's own logs; the docs say which is which.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
BIN="$REPO/bin"

roots=()
if [[ $# -gt 0 ]]; then
  roots=("$@")
else
  make build >/dev/null
  for mode in "" "-hosted"; do
    out="$("$BIN/janus-sagachaos" $mode -keep-always 2>&1 | tail -1)"
    root="${out##*evidence kept at }"
    if [[ ! -d "$root" ]]; then
      echo "could not find the evidence a chaos run kept: $out" >&2
      exit 1
    fi
    roots+=("$root")
  done
fi

checked=0
agreed=0
dirs=0
divergences=()
errored=()

for root in "${roots[@]}"; do
  while IFS= read -r d; do
    [[ -n "$(find "$d" -maxdepth 1 -name '*.jseg' -print -quit)" ]] || continue
    # Exit 1 is "something diverged" and the tally is still on stdout; exit 2 is
    # "the check itself failed" and there is no tally. The two must not be
    # conflated: an errored directory contributing zero to both sides would
    # vanish from the denominator, and "243 directories" has to mean 243
    # checked rather than 243 attempted.
    set +e
    json="$("$BIN/janus-spotreplay" -evidence "$d" -json 2>/dev/null)"
    rc=$?
    set -e
    if [[ $rc -gt 1 || -z "$json" ]]; then
      errored+=("$d")
      continue
    fi
    c="$(printf '%s' "$json" | python3 -c "import json,sys;print(json.load(sys.stdin)['checked'])")"
    a="$(printf '%s' "$json" | python3 -c "import json,sys;print(json.load(sys.stdin)['agreed'])")"
    checked=$((checked + c))
    agreed=$((agreed + a))
    dirs=$((dirs + 1))
    if [[ "$c" != "$a" ]]; then
      divergences+=("$d")
    fi
  done < <(find "$root" -type d | sort)
done

echo
echo "janus-spotreplay over $dirs evidence directories"
echo "  $agreed of $checked completed sagas replay to what the log says they did"
python3 -c "
checked, agreed = $checked, $agreed
print('  rate: %.4f%%' % (100.0 * agreed / checked if checked else 0.0))
"
if [[ ${#errored[@]} -gt 0 ]]; then
  echo
  echo "COULD NOT BE CHECKED (not counted in the rate above):"
  printf '  %s\n' "${errored[@]}"
  exit 1
fi
if [[ ${#divergences[@]} -gt 0 ]]; then
  echo
  echo "DIVERGED:"
  printf '  %s\n' "${divergences[@]}"
  exit 1
fi
if [[ $checked -eq 0 ]]; then
  echo "  nothing was checked, so nothing has been demonstrated" >&2
  exit 1
fi
