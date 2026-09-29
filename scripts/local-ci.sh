#!/usr/bin/env bash
# The CI signal, run locally.
#
# `.github/workflows/ci.yml` is still the definition of green and is kept
# correct, but the account has no Actions credits and every job is refused
# before it starts. This script is how the same checks get run instead: the same
# commands, in the same order, on Linux, in a container — against the working
# tree, including the uncommitted part, which is the half a pushed workflow
# never sees.
#
# Where a step here differs from the workflow, the difference is commented. That
# matters more than it looks: a local check that quietly tests something weaker
# than CI reports a pass and buys nothing.
#
#   scripts/local-ci.sh              # build, lint, proto, repro, gate — the pull-request set
#   scripts/local-ci.sh quick        # host-only: gofmt, vet, build, tests. No container.
#   scripts/local-ci.sh all          # the above plus the object-storage job
#   scripts/local-ci.sh gate storage # named jobs, run in the order given
#
# What this does not give you: the architecture. GitHub's runners are amd64 and
# this machine may not be. Linux is the part that carries the weight — fsync
# semantics, scheduling, the race detector under real parallelism — and that is
# what the container provides. A word-size or unaligned-atomic bug is still
# something only a real amd64 run would find.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# Pinned to the toolchain in go.mod. A container whose Go is older would make
# the module download a toolchain on every run; one that is newer would be
# testing something the workflow does not.
# Pinned by digest, and to the SAME image scripts/reproducible-build.sh uses.
# A tag was wrong twice over: this container runs with GOTOOLCHAIN=local, so
# `golang:1.26-bookworm` meant "whatever was last pulled onto this machine" --
# which was 1.26.5 for three patch releases after 1.26.8 shipped. scripts/
# check-toolchain-pins.sh enforces the agreement.
GO_IMAGE="${JANUS_GO_IMAGE:-golang@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81}"

# The Python SDK's toolchain, pinned by digest rather than by tag for the same
# reason the reproducible build pins the verifier's: a tag resolves to a
# different image over time, so a checked answer silently becomes a different
# answer on a commit that changed nothing. python:3.12-slim as of 2026-08-28.
PY_IMAGE="${JANUS_PY_IMAGE:-python@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217}"
# The version ci.yml pins for golangci-lint-action. Kept identical on purpose: a
# lint release must not be able to fail a commit that CI would pass.
LINT_IMAGE="${JANUS_LINT_IMAGE:-golangci/golangci-lint:v2.12.2}"

# Linux binaries go somewhere the host's bin/ is not, so a container run cannot
# leave the host holding an ELF binary it will refuse to execute. Both are under
# the gitignored /bin/.
LINUX_BIN="bin/linux"

# Build and module caches live on the host so the second run is not as slow as
# the first. Outside the repository: they are machine state, not project state.
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/janus-local-ci"

bold=$'\033[1m'; red=$'\033[31m'; green=$'\033[32m'; dim=$'\033[2m'; off=$'\033[0m'
if [[ ! -t 1 ]]; then bold=; red=; green=; dim=; off=; fi

FAILED=()
START_ALL=$SECONDS

# Extra `docker run` arguments for the job in hand. It carries a harmless
# element at all times because the bash on macOS is 3.2, where expanding an
# empty array under `set -u` is an error rather than an empty list.
EXTRA_DOCKER_ARGS=(-e JANUS_LOCAL_CI=1)

say()  { printf '%s\n' "${bold}==> $*${off}"; }
note() { printf '%s\n' "${dim}    $*${off}"; }
step() { printf '%s\n' "${dim}--- $*${off}"; }
die()  { printf '%s\n' "${red}$*${off}" >&2; exit 1; }
# Inside a job. `fail` reports and hands a non-zero status back to the runner,
# which records the job and carries on to the next one; `die` aborts everything
# and is only for the setup checks before any job starts.
fail() { printf '%s\n' "${red}$*${off}" >&2; return 1; }

# Every job below states the failure of every step explicitly, with `|| return`.
# This looks redundant next to `set -e` and is not: a function called from an
# `if` condition — which is how the runner calls each job — runs with `-e`
# suppressed, for itself and for every subshell beneath it. Neither re-asserting
# `set -e` nor an ERR trap restores it. A job written in the ordinary style
# would therefore run on past a failing check and report a pass, which is the
# one outcome this script exists to prevent.

# ---------------------------------------------------------------------------
# container plumbing
# ---------------------------------------------------------------------------

have_docker() { command -v docker >/dev/null && docker version >/dev/null 2>&1; }

# Run a script inside the Go image with the repository mounted.
#
# --user is the host's uid so nothing written through the bind mount — bin/linux,
# regenerated fixtures — comes back owned by root. That in turn means HOME and
# both Go caches have to be pointed at paths the host user can write.
#
# safe.directory is passed through the environment rather than written into a
# config file, because git inside the container sees an ownership it did not
# create and otherwise refuses to answer `git describe` for the version stamp.
in_go_container() {
  mkdir -p "$CACHE_ROOT/go-build" "$CACHE_ROOT/go-mod"
  docker run --rm \
    -v "$REPO:/src" -w /src \
    -v "$CACHE_ROOT/go-build:/gocache" \
    -v "$CACHE_ROOT/go-mod:/gomodcache" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e GOCACHE=/gocache -e GOMODCACHE=/gomodcache \
    -e GOFLAGS=-buildvcs=false \
    -e GIT_CONFIG_COUNT=1 \
    -e GIT_CONFIG_KEY_0=safe.directory \
    -e GIT_CONFIG_VALUE_0=/src \
    "${EXTRA_DOCKER_ARGS[@]}" \
    "$GO_IMAGE" bash -euo pipefail -c "$1"
}

# Refuse to run a "regenerate and compare" check over paths that were already
# dirty. The check is only evidence when the diff it produces can have come from
# nothing but the regeneration; over a modified tree it is noise, and worse, the
# restore afterwards would throw away real work.
require_clean_paths() {
  local dirty
  dirty="$(git status --porcelain -- "$@")"
  if [[ -n "$dirty" ]]; then
    printf '%s\n' "${red}cannot check that these are current — they have uncommitted changes:${off}" >&2
    printf '%s\n' "$dirty" >&2
    fail "commit or stash them, then re-run; a regenerate-and-diff over a dirty tree proves nothing"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# jobs — one per job in ci.yml, same name
# ---------------------------------------------------------------------------

## job_build mirrors ci.yml's "build, vet, test".
job_build() {
  in_go_container "
    echo '--- gofmt'
    out=\$(gofmt -l cmd pkg)
    if [ -n \"\$out\" ]; then echo 'these files need gofmt:'; echo \"\$out\"; exit 1; fi

    echo '--- go vet'
    go vet ./...

    echo '--- build'
    make build BIN=$LINUX_BIN

    echo '--- go test -race'
    go test -race ./...
  "
}

## job_lint mirrors ci.yml's "lint".
#
# In the container rather than against the golangci-lint on this machine, even
# when the versions match: the linters type-check per GOOS, so a bug in a file
# behind a linux build tag is invisible to a run on a Mac — and the fsync paths
# are exactly where those files are.
job_lint() {
  mkdir -p "$CACHE_ROOT/go-build" "$CACHE_ROOT/go-mod" "$CACHE_ROOT/golangci"
  docker run --rm \
    -v "$REPO:/src" -w /src \
    -v "$CACHE_ROOT/go-build:/gocache" \
    -v "$CACHE_ROOT/go-mod:/gomodcache" \
    -v "$CACHE_ROOT/golangci:/lintcache" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e GOCACHE=/gocache -e GOMODCACHE=/gomodcache \
    -e GOLANGCI_LINT_CACHE=/lintcache \
    -e GOFLAGS=-buildvcs=false \
    "$LINT_IMAGE" golangci-lint run ./...
}

## job_proto mirrors ci.yml's "protobuf codegen is current".
#
# On the host, not in a container: buf resolves its plugins remotely and the
# output of protoc-gen-go does not depend on the operating system. What is being
# checked is that committed generated code still matches its source, and that
# answer is the same everywhere.
job_proto() {
  command -v buf >/dev/null || fail "buf is not installed — 'brew install bufbuild/buf/buf', or skip this job" || return 1
  # Both generated trees. The Python SDK's wire types are generated from the
  # same protos into sdk/python/janus/v1/, and generated code that is not
  # diffed is generated code that drifts.
  require_clean_paths gen/ sdk/python/janus/v1/ || return 1

  step 'buf lint'
  buf lint || return 1

  # The wire format is the other half of "old sagas replay forever".
  # A semantics version pins which *rules* a saga was admitted under; it can do
  # nothing about a field that was renumbered or retyped underneath it, which
  # makes every log ever written decode into different values with no error
  # anywhere. buf.yaml has declared `breaking: FILE` since the vocabulary was
  # first written and nothing ran it.
  #
  # Comparing against master means this is vacuous *on* master and meaningful on
  # every branch that reaches it, which is where proto changes actually arrive.
  # It needs the master ref present, so a shallow clone must fetch it.
  step 'buf breaking (against master)'
  if git rev-parse --verify --quiet refs/heads/master >/dev/null ||
     git rev-parse --verify --quiet refs/remotes/origin/master >/dev/null; then
    buf breaking --against '.git#branch=master' || return 1
  else
    fail "no master ref to compare the protobuf vocabulary against; a shallow clone needs 'git fetch origin master'"
    return 1
  fi

  step 'regenerate and diff'
  buf generate || return 1
  if ! git diff --exit-code -- gen/ sdk/python/janus/v1/; then
    git checkout -- gen/ sdk/python/janus/v1/
    fail "generated code is out of date — run 'make gen' and commit the result"
    return 1
  fi
}

## job_repro mirrors ci.yml's "janus-verify is reproducible".
#
# It runs on every commit rather than at release time because the failure it
# catches is silent: a dependency or a flag change makes the build
# path-dependent, nothing breaks, and the discovery is an auditor who rebuilt
# the verifier and got a different digest — at which point the honest answer is
# that we do not know which of the two binaries is the real one.
#
# It also proves the SBOM, which is the same claim one level up: the
# bill of materials is generated from the built binary, twice, and required to
# be identical — a dependency list that cannot be regenerated cannot be
# published beside a checksum.
job_repro() {
  ./scripts/reproducible-build.sh check || return 1
}

## job_vuln mirrors ci.yml's "no known vulnerability is reachable".
#
# Two modes, because they answer different questions. Source mode is
# reachability-filtered over the whole tree: what this code can actually call.
# Binary mode reads the linked symbol table of the one artifact handed to
# somebody outside this project, which is what an auditor holding only that
# binary can run -- and running it here is how we find out before they do.
#
# The scanner is pinned. An unpinned one is a moving definition of green.
#
# When this goes red on a Go patch release, the fix is `go.mod` and
# scripts/reproducible-build.sh's GO_IMAGE digest moving TOGETHER; only
# job_repro notices if they drift apart.
job_vuln() {
  ./scripts/check-toolchain-pins.sh || return 1

  local bin
  bin="$(go env GOPATH)/bin/govulncheck"
  if [[ ! -x "$bin" ]]; then
    go install golang.org/x/vuln/cmd/govulncheck@v1.1.4 || return 1
  fi
  "$bin" ./... || return 1
  make build >/dev/null || return 1
  "$bin" -mode=binary bin/janus-verify || return 1
}

## job_gate mirrors ci.yml's "phase 0 exit gate", which by now carries the exit
## criteria of phases 0, 2 and 3 as well.
job_gate() {
  require_clean_paths pkg/saga/testdata/ || return 1

  local rc=0
  in_go_container "
    export BIN=$LINUX_BIN

    echo '--- build'
    make build BIN=$LINUX_BIN

    echo '--- walking skeleton (phase 0 exit gate)'
    ./$LINUX_BIN/janus-skeleton

    echo '--- replay corpus (replay determinism)'
    make corpus

    echo '--- corpus is current'
    make corpus-update >/dev/null

    echo '--- gate policy compiles'
    make policy BIN=$LINUX_BIN

    echo '--- MCP interception spike'
    ./scripts/spike-mcp.sh

    echo '--- registry round-trip (phase 3 exit gate)'
    ./scripts/registry-roundtrip.sh

    echo '--- chaos soak (short)'
    ./$LINUX_BIN/janus-soak -duration 25s -sync data -segment-bytes 32768 -min-life 200ms -max-life 1500ms

    echo '--- saga chaos suite (phase 2 exit gate)'
    ./$LINUX_BIN/janus-sagachaos

    echo '--- evidence append benchmark (informational)'
    ./$LINUX_BIN/janus-bench -events 50000 -payload 256 -sweep 64,256 -sync full
  " || rc=$?

  # The fixture check runs out here rather than in the container, because on a
  # failure it has to say which fixture moved before putting the tree back.
  if ! git diff --exit-code -- pkg/saga/testdata/; then
    git checkout -- pkg/saga/testdata/
    fail "the corpus on disk does not match what the builders produce; run 'make corpus-update' and commit the result"
    return 1
  fi
  return $rc
}

## job_storage mirrors ci.yml's "object storage and WORM tier".
#
# The tests run inside a container attached to the compose network, so the
# endpoint is the service name and no port publishing or host-gateway trick is
# involved. JANUS_S3_REQUIRED turns "cannot reach object storage" from a skip
# into a failure — without it a broken container looks like a clean run while
# the WORM tier goes entirely untested.
job_storage() {
  local started_here=0
  if [[ -z "$(docker compose ps -q minio 2>/dev/null)" ]]; then
    started_here=1
    step 'starting object storage'
    docker compose up -d minio minio-init || return 1
  else
    note "minio was already running; leaving it up afterwards"
  fi

  step 'waiting for object storage'
  local i
  for i in $(seq 1 60); do
    if curl -sf http://127.0.0.1:9000/minio/health/live >/dev/null 2>&1; then break; fi
    if [[ $i -eq 60 ]]; then
      docker compose logs minio
      [[ $started_here -eq 1 ]] && docker compose down -v
      fail "minio did not become healthy"
      return 1
    fi
    sleep 1
  done

  local net
  net="$(docker inspect janus-minio -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null || true)"
  if [[ -z "$net" ]]; then
    [[ $started_here -eq 1 ]] && docker compose down -v
    fail "could not determine the compose network for janus-minio"
    return 1
  fi

  local rc=0
  EXTRA_DOCKER_ARGS=(
    -e JANUS_LOCAL_CI=1
    --network "$net"
    -e JANUS_S3_ENDPOINT=http://minio:9000
    -e JANUS_S3_ACCESS_KEY=janus
    -e JANUS_S3_SECRET_KEY=januspassword
    -e JANUS_S3_REQUIRED=1
  )
  in_go_container "
    go test ./pkg/evidence/cas/... ./pkg/evidence/worm/... ./pkg/evidence/objstore/... ./pkg/evidence/fence/... -count=1 -v
  " || rc=$?
  EXTRA_DOCKER_ARGS=(-e JANUS_LOCAL_CI=1)

  if [[ $rc -ne 0 ]]; then docker compose logs minio minio-init; fi
  if [[ $started_here -eq 1 ]]; then docker compose down -v; fi
  return $rc
}

## job_python mirrors ci.yml's "python sdk".
#
# In the pinned image rather than against whatever Python this machine has, for
# the same reason every other job runs in a container: the answer has to be the
# same on a laptop and on a runner. The dev dependencies are pinned exactly in
# requirements-dev.txt — a check whose linter moves underneath it reports a
# different answer on a commit that changed nothing.
#
# The generated wire types are excluded from ruff and mypy in pyproject.toml.
# That is not weakening the tools: it is pointing them at the code somebody
# wrote. The SDK's own modules are checked under mypy --strict.
job_python() {
  docker run --rm \
    -v "$REPO/sdk/python:/sdk" \
    -w /sdk \
    "$PY_IMAGE" bash -euo pipefail -c "
      pip install --quiet --disable-pip-version-check --root-user-action=ignore -r requirements-dev.txt

      echo '--- ruff'
      ruff check .

      echo '--- mypy'
      mypy janus

      echo '--- pytest'
      # -ra names the skips: the end-to-end tests skip without a running
      # daemon, and a reader of this output should see why rather than a bare 's'.
      python -m pytest -q -ra
    "
}

## job_projection mirrors ci.yml's "relational projections".
##
## This is the job that made `make ci` need a database. It is in the default set
## rather than beside it in `all`, which is a deliberate difference from the
## object-storage job: the projections back a *frontier gate*, and a check that
## only runs when somebody remembers to ask for it is not defending a safety
## property. Standing up postgres:16-alpine costs a couple of seconds.
##
## JANUS_PG_REQUIRED turns "no database" from a skip into a failure, for the same
## reason JANUS_S3_REQUIRED exists: without it a job whose database never came up
## reports a clean run while the projection goes entirely untested.
job_projection() {
  local started_here=0
  if [[ -z "$(docker compose ps -q postgres 2>/dev/null)" ]]; then
    started_here=1
    step 'starting postgres'
    docker compose up -d postgres || return 1
  else
    note "postgres was already running; leaving it up afterwards"
  fi

  step 'waiting for postgres'
  local i
  for i in $(seq 1 60); do
    if docker compose exec -T postgres pg_isready -U janus -d janus >/dev/null 2>&1; then break; fi
    if [[ $i -eq 60 ]]; then
      docker compose logs postgres
      [[ $started_here -eq 1 ]] && docker compose down -v
      fail "postgres did not become healthy"
      return 1
    fi
    sleep 1
  done

  local net
  net="$(docker inspect janus-postgres -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null || true)"
  if [[ -z "$net" ]]; then
    [[ $started_here -eq 1 ]] && docker compose down -v
    fail "could not determine the compose network for janus-postgres"
    return 1
  fi

  local rc=0
  EXTRA_DOCKER_ARGS=(
    -e JANUS_LOCAL_CI=1
    --network "$net"
    # The service name, not localhost: the tests run in a container on the
    # compose network, so no port publishing is involved.
    -e JANUS_PG_DSN=postgres://janus:janus@postgres:5432/janus
    -e JANUS_PG_REQUIRED=1
  )
  # pkg/orchd is here as well as in the build job because the tests that
  # exercise the daemon's projection wiring skip without a database, and the
  # build job has none. Without this line the only checks on `-projection`
  # actually being read would never run anywhere.
  in_go_container "
    go test ./pkg/projection/... ./pkg/orchd/... ./pkg/console/... ./cmd/janus-projection/... -race -count=1 -v
  " || rc=$?
  EXTRA_DOCKER_ARGS=(-e JANUS_LOCAL_CI=1)

  if [[ $rc -ne 0 ]]; then docker compose logs postgres; fi
  if [[ $started_here -eq 1 ]]; then docker compose down -v; fi
  return $rc
}

## job_quick is not a CI job. It is the fastest thing that can still be wrong on
## the host, for running between edits — and it is explicitly not the signal.
## Nothing gets committed on the strength of a quick pass alone.
job_quick() {
  local out
  step 'gofmt'
  out=$(gofmt -l cmd pkg)
  if [[ -n "$out" ]]; then echo "these files need gofmt:"; echo "$out"; return 1; fi

  step 'go vet'
  go vet ./... || return 1

  step 'build'
  make build || return 1

  step 'go test'
  go test ./... || return 1

  note "this was $(go env GOOS) without the race detector — run 'make ci' before committing"
}

# ---------------------------------------------------------------------------

JOBS=("$@")
if [[ ${#JOBS[@]} -eq 0 ]]; then
  JOBS=(build lint proto vuln repro gate python projection)
elif [[ ${#JOBS[@]} -eq 1 && ${JOBS[0]} == all ]]; then
  JOBS=(build lint proto vuln repro gate python projection storage)
fi

for j in "${JOBS[@]}"; do
  case "$j" in
    build|lint|proto|vuln|repro|gate|python|projection|storage|quick) ;;
    *) die "unknown job: $j (build, lint, proto, vuln, repro, gate, python, projection, storage, quick, all)" ;;
  esac
done

# One check up front rather than a container failure three jobs in.
needs_docker=0
for j in "${JOBS[@]}"; do
  [[ "$j" != quick && "$j" != proto ]] && needs_docker=1
done
if [[ $needs_docker -eq 1 ]] && ! have_docker; then
  die "docker is not running, and every job but 'quick' and 'proto' needs it"
fi

for j in "${JOBS[@]}"; do
  say "$j"
  t0=$SECONDS
  if "job_$j"; then
    printf '%s\n' "${green}    $j passed in $((SECONDS - t0))s${off}"
  else
    printf '%s\n' "${red}    $j FAILED after $((SECONDS - t0))s${off}"
    FAILED+=("$j")
  fi
done

echo
if [[ ${#FAILED[@]} -eq 0 ]]; then
  printf '%s\n' "${green}${bold}all jobs passed in $((SECONDS - START_ALL))s: ${JOBS[*]}${off}"
  exit 0
fi
printf '%s\n' "${red}${bold}failed: ${FAILED[*]}${off}"
exit 1
