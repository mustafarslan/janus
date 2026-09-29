#!/usr/bin/env bash
# The Go toolchain is pinned in three places and they must agree -- and so must
# the two pins of golangci-lint, which carries a security gate (gosec).
#
# The vulnerability scanner is blocking, which makes a Go patch release a CI event:
# when an advisory lands, the toolchain moves. It moves in three files, and
# nothing in the language or the build system checks that they moved together:
#
#   go.mod                        what GitHub CI compiles with (go-version-file)
#   scripts/reproducible-build.sh what the PUBLISHED verifier is compiled with
#   scripts/local-ci.sh           what `make ci` compiles with, GOTOOLCHAIN=local
#
# A drift is silent in the direction that matters. Bump go.mod alone and
# govulncheck goes green while the published verifier still carries the
# vulnerable standard library — the scanner reports on a toolchain nobody ships.
# This is the check that would have caught it, and it is cheap enough to run
# everywhere rather than to remember.
#
# golangci-lint is the same shape one tool over. It is pinned in ci.yml and in
# scripts/local-ci.sh, was kept identical by a comment asking politely, and now
# runs gosec -- so a drift means `make ci` and GitHub CI enforce
# different versions of a SECURITY check, and the one that is behind is the one
# that goes green.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
note() { printf '  %s\n' "$*" >&2; }

mod="$(awk '/^go [0-9]/ {print $2; exit}' go.mod)"
repro="$(awk -F'"' '/^GO_VERSION=/ {print $2; exit}' scripts/reproducible-build.sh)"
repro_digest="$(sed -n 's/.*golang@\(sha256:[0-9a-f]*\).*/\1/p' scripts/reproducible-build.sh | head -1)"
local_img="$(sed -n 's/^GO_IMAGE="\${JANUS_GO_IMAGE:-\(.*\)}"/\1/p' scripts/local-ci.sh | head -1)"
local_digest="${local_img#golang@}"

echo "go.mod                     go $mod"
echo "reproducible-build.sh      GO_VERSION $repro, image $repro_digest"
echo "local-ci.sh                image $local_digest"

if [[ "$mod" != "$repro" ]]; then
  note "DRIFT: go.mod says $mod and reproducible-build.sh's GO_VERSION says $repro."
  note "       CI would scan one toolchain and publish a verifier built with another."
  fail=1
fi

# local-ci runs with GOTOOLCHAIN=local, so a tag rather than a digest means the
# job compiles with whatever that tag resolved to the last time somebody pulled
# — which is how this check came to exist.
if [[ "$local_digest" != sha256:* ]]; then
  note "DRIFT: local-ci.sh pins the tag '$local_img' rather than a digest."
  note "       With GOTOOLCHAIN=local that is whatever was last pulled, not a pin."
  fail=1
elif [[ "$local_digest" != "$repro_digest" ]]; then
  note "DRIFT: local-ci.sh and reproducible-build.sh pin different images."
  note "       $local_digest != $repro_digest"
  fail=1
fi

lint_local="$(sed -n 's|^LINT_IMAGE="\${JANUS_LINT_IMAGE:-golangci/golangci-lint:\(v[0-9.]*\)}"|\1|p' scripts/local-ci.sh | head -1)"
lint_ci="$(sed -n 's/^ *version: *\(v[0-9][0-9.]*\) *$/\1/p' .github/workflows/ci.yml | head -1)"
echo "golangci-lint              local-ci $lint_local, ci.yml $lint_ci"

if [[ -z "$lint_local" || -z "$lint_ci" ]]; then
  note "DRIFT: could not read a golangci-lint version from both files."
  note "       local-ci.sh='$lint_local' ci.yml='$lint_ci' -- one of the two patterns moved."
  fail=1
elif [[ "$lint_local" != "$lint_ci" ]]; then
  note "DRIFT: local-ci.sh runs golangci-lint $lint_local and ci.yml runs $lint_ci."
  note "       gosec ships inside it, so the two would enforce different security rules"
  note "       and the older one is the one that passes."
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  note ""
  note "They move together or not at all."
  exit 1
fi
echo "toolchain pins agree"
