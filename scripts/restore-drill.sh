#!/usr/bin/env bash
# Phase 6h: a timed backup and restore, and the window the restore leaves open.
#
# A restore reads no records — signature, digests, and the
# manifest's own arithmetic — and leaves everything per-record to a sweep
# afterwards. That decision rests on one measured number: verifying 100M events
# took 254.5 s against the 300 s RTO budget. It also creates a window in which
# restored bytes are trusted on the signed manifest and their digests alone.
#
# This measures both halves at a stated size: how long a restore takes, and how
# long the window lasts. A runbook that cannot state the second says "wait a
# while".
#
# THE SIZE IS PART OF THE RESULT. Restore time and sweep time both grow with the
# log, so a number here is a claim about a size and nothing else. The size is
# stamped into the JSON beside the timings for exactly that reason.
set -euo pipefail

BIN="${BIN:-bin}"
# EVENTS is small by default so this can run beside the other gates. A real
# measurement wants orders more; the JSON records what was actually used.
EVENTS="${EVENTS:-20000}"
OUT="${OUT:-docs/bench/phase6-restore.json}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# PROJECTION_DSN is opt-in and deliberately not the Makefile's PG_DSN, which has
# a default: a drill that silently found a database and emptied it would be the
# accident this variable exists to make impossible.
PROJECTION_DSN="${PROJECTION_DSN:-}"

NEED=(janus-tier janus-keys janus-bench janus-verify)
if [[ -n "$PROJECTION_DSN" ]]; then
  NEED+=(janus-projection)
  # `rebuild` TRUNCATEs whatever the DSN resolves to and rebinds it to the log it
  # was pointed at. Pointed at a shared `public` schema it would destroy the
  # projection `make latency` or `make sagachaos-projection` built, and the
  # operator would find out from the next gate decision. So the schema is
  # required to be named, and required to exist: creating it here would mean
  # this script can create schemas, which is the other half of the same
  # accident.
  # A substring check on its own would pass `search_path=public`, which is the
  # schema every other target's projection lives in — the exact accident this
  # refusal exists to stop.
  SCHEMA="${PROJECTION_DSN##*search_path}"
  SCHEMA="${SCHEMA#%3D}"
  SCHEMA="${SCHEMA#%3d}"
  SCHEMA="${SCHEMA#=}"
  SCHEMA="${SCHEMA%%[,&]*}"
  if [[ "$PROJECTION_DSN" != *search_path* || "$SCHEMA" == "public" || -z "$SCHEMA" ]]; then
    echo "PROJECTION_DSN must name a schema of its own, not public:" >&2
    echo "  rebuild empties whatever it resolves to." >&2
    echo "  create one first:  psql \"\$PG_DSN\" -c 'CREATE SCHEMA restore_drill'" >&2
    echo "  then:  PROJECTION_DSN='...?options=-c%20search_path%3Drestore_drill' make restore-drill" >&2
    exit 1
  fi
fi

for b in "${NEED[@]}"; do
  if [[ ! -x "$BIN/$b" ]]; then
    echo "missing $BIN/$b — run 'make build' first" >&2
    exit 1
  fi
done

EVIDENCE="$WORK/evidence"
BACKUP="$WORK/backup"
RESTORED="$WORK/restored"
mkdir -p "$WORK/keys"

# janus-bench writes a real log through the real append path, which is what makes
# this a measurement of restoring evidence rather than of copying files.
echo "--- writing $EVENTS events"
# -key so the log is signed with a key that still exists afterwards. Without it
# janus-bench signs with a fresh in-memory key and throws away the private half,
# which is fine for a throughput number and useless for a log anybody wants to
# back up.
KEY="$WORK/keys/writer.key"
#
# -shape sagas, not the benchmark's default. The default writes one STEP_RESULT
# per producer over and over, which measures the append path and produces a log
# no projector can fold: `janus-projection rebuild` on it fails outright, because
# a STEP_RESULT whose SAGA_BEGIN is nowhere in the log is not a saga. A restore
# drill whose log nothing downstream can read is measuring the restore of
# something no deployment has.
"$BIN/janus-bench" -dir "$EVIDENCE" -events "$EVENTS" -shape sagas \
  -producers 8 -sync none -skip-verify -key "$KEY" >"$WORK/bench.log" 2>&1

# janus-bench writes into a run-<name>-<producers> subdirectory, so the segment
# directory is one level down from what -dir names. Resolved rather than assumed:
# an evidence directory is the one holding the segments.
EVIDENCE="$(dirname "$(find "$EVIDENCE" -name '*.jseg' | head -1)")"
if [[ ! -d "$EVIDENCE" ]]; then
  echo "no segments were written; janus-bench produced nothing to back up" >&2
  exit 1
fi
"$BIN/janus-keys" pub "$KEY" >"$WORK/keys/public.json"

LOGBYTES=$(( $(cat "$EVIDENCE"/*.jseg | wc -c) ))
SEGMENTS=$(find "$EVIDENCE" -maxdepth 1 -name '*.jseg' | wc -l | tr -d ' ')
echo "    $LOGBYTES bytes across $SEGMENTS segments in $EVIDENCE"

echo "--- backup"
BACKUP_START=$(date +%s%N)
"$BIN/janus-tier" backup -evidence "$EVIDENCE" -out "$BACKUP" \
  -key "$KEY" -keys "$WORK/keys/public.json"
BACKUP_NS=$(( $(date +%s%N) - BACKUP_START ))

echo "--- restore"
"$BIN/janus-tier" restore -backup "$BACKUP" -evidence "$RESTORED" \
  -keys "$WORK/keys/public.json" -json "$WORK/restore.json"

# The headline number: the window a restore opens. Until this completes, the
# restored bytes are trusted on the signed manifest and their digests alone.
echo "--- the window: one full sweep of the restored log"
"$BIN/janus-tier" sweep -evidence "$RESTORED" -keys "$WORK/keys/public.json" \
  -json "$WORK/sweep.json"

# The second half of the RTO, and the one nobody had timed. A restored evidence
# directory is the source of truth; the projection is derived, so it
# comes back empty and a rebuild is a separate operator step. Until this ran, an
# operator's RTO was the numbers above plus an unknown.
#
# Opt-in, because `make restore-drill` needing nothing is a property worth
# keeping: the rest of this script has no dependency on a database and a drill
# an operator cannot run is not a drill.
REBUILD_JSON=""
if [[ -n "$PROJECTION_DSN" ]]; then
  echo "--- the rest of the RTO: folding the restored log into a projection"
  REBUILD_JSON="$WORK/rebuild.json"
  "$BIN/janus-projection" rebuild -evidence "$RESTORED" \
    -projection "$PROJECTION_DSN" -json "$REBUILD_JSON"
fi

echo "--- merging the timings"
python3 - "$WORK/restore.json" "$WORK/sweep.json" "$OUT" \
  "$EVENTS" "$LOGBYTES" "$SEGMENTS" "$BACKUP_NS" "$REBUILD_JSON" <<'PY'
import json, sys, datetime
restore, sweep, out, events, logbytes, segments, backup_ns, rebuild = sys.argv[1:9]
r = json.load(open(restore))
s = json.load(open(sweep))
doc = {
    "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    # The size is part of the result, not context: restore and sweep both grow
    # with the log, so every number below is a claim about this size.
    "size": {
        "events": int(events),
        "log_bytes": int(logbytes),
        "segments": int(segments),
    },
    "backup_ns": int(backup_ns),
    "restore": {"phases": r["phases"], "total_ns": r["total_ns"]},
    # The window: how long the restored log is trusted on its manifest and
    # digests alone.
    "window_ns": s["took_ns"],
    "window_events_verified": s["events_verified"],
}
# Absent rather than zero when no database was given: a rebuild time of 0 in a
# file somebody reads later is a claim, and the claim would be false.
if rebuild:
    doc["rebuild"] = json.load(open(rebuild))
json.dump(doc, open(out, "w"), indent=2)
open(out, "a").write("\n")
keys = ["size", "backup_ns", "window_ns"] + (["rebuild"] if rebuild else [])
print(json.dumps({k: doc[k] for k in keys}, indent=2))
PY

# The drill has to reach what it exists to measure. A sweep that verified fewer
# events than the backup carried would mean it stopped early and the window
# number would be a measurement of stopping early.
VERIFIED=$(python3 -c "import json,sys; print(json.load(open('$WORK/sweep.json'))['events_verified'])")
if [[ "$VERIFIED" -lt "$EVENTS" ]]; then
  echo "FAIL: the sweep verified $VERIFIED events and the log holds $EVENTS;" >&2
  echo "      the window number would be a measurement of a sweep that stopped early" >&2
  exit 1
fi

# The same check for the rebuild, and it needs both halves. A projection that
# reached the log's head having kept nothing is the hollow pass here: it would
# finish fast, report the right sequence, and have measured a scan. `kept` is
# what separates a fold from a skim.
if [[ -n "$REBUILD_JSON" ]]; then
  read -r HEAD KEPT < <(python3 -c "
import json
d = json.load(open('$REBUILD_JSON'))
print(d['head'], d['kept'])")
  if [[ "$HEAD" -lt "$EVENTS" || "$KEPT" -lt "$EVENTS" ]]; then
    echo "FAIL: the rebuild folded to $HEAD keeping $KEPT of $EVENTS events;" >&2
    echo "      a rebuild that kept nothing is a scan, and its time is a scan's time" >&2
    exit 1
  fi
fi

echo
echo "janus-tier restore-drill: PASS"
echo "  written to $OUT"
echo
if [[ -n "$PROJECTION_DSN" ]]; then
  echo "  The sweep and the rebuild are timed one after the other here so that each"
  echo "  has a number. Both only READ the restored directory, so a real recovery"
  echo "  can run them together and pay the larger rather than the sum."
  echo
fi
echo "  This is a measurement at ONE size. Restore and sweep both grow with the"
echo "  log, so nothing here says the five-minute RTO is met at a deployment's"
echo "  size — only that it was met at this one, and by how much."
if [[ -z "$PROJECTION_DSN" ]]; then
  echo
  echo "  The projection rebuild was NOT measured: set PROJECTION_DSN to include it."
  echo "  Without it the numbers above are the time to have the log back, not the"
  echo "  time to be serving at the latency the log alone cannot reach -- and the"
  echo "  JSON just written has no 'rebuild' key, where the committed one does."
fi
