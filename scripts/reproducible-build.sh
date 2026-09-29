#!/usr/bin/env bash
# Build janus-verify so that somebody else can build it again and get the same
# bytes.
#
# The verifier is the one artefact whose whole value is that it is not trusted.
# An auditor runs it to check evidence Janus produced; if the only reason to
# believe the binary is that we compiled it, the check has just moved the trust
# rather than removed it. "Compile it yourself and compare the digest" is a
# different and much stronger claim, and it is only true if the build is
# actually deterministic — which is a property that has to be tested, not
# asserted.
#
#   scripts/reproducible-build.sh check      # build twice, differently, require identical bytes
#   scripts/reproducible-build.sh release    # build the published matrix, write SHA256SUMS
#
# Phase 1 exit criterion: "janus-verify v1 (static binary,
# reproducible build)".
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# The toolchain is pinned by digest, not by tag.
#
# `golang:1.26-bookworm` is a moving target: the same tag in six months is a
# different patch release producing different bytes, which would make every
# checksum ever published wrong and the reproducibility claim worthless. A tag
# is not a pin. A digest is.
GO_IMAGE="${JANUS_GO_IMAGE_DIGEST:-golang@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81}"
# What that digest contains, recorded so the build can be reproduced by somebody
# who has the toolchain but not the container — an air-gapped auditor, or anyone
# reading this after the image has been garbage-collected from the registry.
GO_VERSION="1.26.8"

# The SBOM generator, pinned the same way and for the same reason.
#
# It runs INSIDE the pinned image rather than on the host, which is not
# fastidiousness. The CI job that runs this script has no setup-go step on
# purpose -- a runner's Go anywhere near a reproducibility claim defeats the pin
# -- and a tool needing one would drag it back in.
#
# What the tool does is narrow, and that is the argument for using one at all.
# Go embeds the module table in every binary and `go version -m` prints it; this
# repository already reads that table, because govulncheck's binary mode
# reads the same one. The tool is a formatter over a fact the binary
# already carries, which is what makes the SBOM a description of what SHIPPED
# rather than of what `go.mod` declared.
CDX_VERSION="v1.9.0"

# Where an auditor is plausibly sitting. Windows is on the list because a bank's
# compliance function is on Windows, and a verifier they cannot run is a
# verifier they will not use.
TARGETS=(
  linux/amd64
  linux/arm64
  darwin/amd64
  darwin/arm64
  windows/amd64
)

# The build, in one place. Every flag here is load-bearing:
#
#   CGO_ENABLED=0   no host C toolchain in the output, and a genuinely static
#                   binary — the verifier must run on a machine that has nothing
#                   installed on it.
#   -trimpath       strips the absolute path of the source tree and of the
#                   module cache. Without it the binary differs depending on
#                   which directory it was built in, which is the single most
#                   common reason a "reproducible" build is not.
#   -buildvcs=false the VCS stamp embeds the commit and whether the tree was
#                   dirty. That cannot be reproduced from a source tarball, and
#                   an auditor who was sent a tarball is exactly the case this
#                   exists for. The version is stamped explicitly instead.
#
# Deliberately absent: -s -w. Stripping the symbol table would shave a few
# megabytes off an artefact whose size nobody is paying for, and would turn a
# crash on an auditor's own bundle — the moment where a usable stack trace is
# worth most — into an address with no name attached.
BUILD_FLAGS=(-trimpath -buildvcs=false)

bold=$'\033[1m'; red=$'\033[31m'; green=$'\033[32m'; dim=$'\033[2m'; off=$'\033[0m'
if [[ ! -t 1 ]]; then bold=; red=; green=; dim=; off=; fi

say() { printf '%s\n' "${bold}==> $*${off}"; }
die() { printf '%s\n' "${red}$*${off}" >&2; exit 1; }

command -v docker >/dev/null && docker version >/dev/null 2>&1 ||
  die "docker is required: the toolchain is pinned by image digest, which is the pin"

# build_into <output-dir> <source-dir> <source-mount-path> <cache-dir> <version> <home> [targets...]
#
# The source is mounted read-only at a caller-chosen path, from a caller-chosen
# directory. Both are inputs to the check below rather than decoration: building
# at two different paths is what proves -trimpath is doing its job, and building
# from a tree with no .git in it is what proves the result does not quietly
# depend on the repository.
build_into() {
  local out="$1" srcdir="$2" srcpath="$3" cache="$4" version="$5" home="$6"; shift 6
  local targets=("$@")

  mkdir -p "$out" "$cache/go-build" "$cache/go-mod"

  # `if` rather than `[ ... ] && ...` for the extension: the second form returns
  # non-zero on every non-Windows target, and under `set -e` that ends the build
  # after the first one.
  local script='set -euo pipefail
mkdir -p "$HOME" /out
for t in '"${targets[*]}"'; do
  os=${t%/*}; arch=${t#*/}
  ext=""
  if [ "$os" = windows ]; then ext=".exe"; fi
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build '"${BUILD_FLAGS[*]}"' \
      -ldflags "-X main.version='"$version"'" \
      -o "/out/janus-verify-$os-$arch$ext" ./cmd/janus-verify
done
cd /out && sha256sum janus-verify-* | sort -k2 > SHA256SUMS
'

  docker run --rm \
    -v "$srcdir:$srcpath:ro" -w "$srcpath" \
    -v "$out:/out" \
    -v "$cache/go-build:/gocache" \
    -v "$cache/go-mod:/gomodcache" \
    --user "$(id -u):$(id -g)" \
    -e HOME="$home" \
    -e GOCACHE=/gocache -e GOMODCACHE=/gomodcache \
    "$GO_IMAGE" bash -c "$script"
}

# sbom_into <out-dir> <dir holding the built binaries> <binary name> <version> <cache-dir>
#
# Writes two files, and the second is the point:
#
#   sbom.cdx.json  the CycloneDX document
#   modules.txt    `go version -m` on the same binary, raw
#
# Both, because one of them is checkable with no tool at all. An SBOM only its
# own generator can confirm is a claim about a program nobody else ran.
sbom_into() {
  local out="$1" bindir="$2" name="$3" version="$4" cache="$5"

  mkdir -p "$out" "$cache/go-build" "$cache/go-mod"

  # -noserial because CycloneDX stamps a random UUID into every document by
  # default, and a serial number is exactly the kind of field that makes two
  # identical bills of materials differ. The timestamp has no flag; it is
  # stripped below.
  # GOBIN explicitly: the golang image sets GOPATH=/go, which this container
  # runs as a non-root user and cannot write to. Without it `go install`
  # succeeds at downloading and fails at the last step, which reads as the tool
  # not existing.
  local script='set -euo pipefail
mkdir -p "$HOME" /out "$HOME/gobin"
export GOBIN="$HOME/gobin"
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@'"$CDX_VERSION"'
"$GOBIN/cyclonedx-gomod" bin -json -noserial -version "'"$version"'" \
  -output /out/sbom.cdx.json "/bin-in/'"$name"'"
go version -m "/bin-in/'"$name"'" > /out/modules.txt
# And the module table of every binary in the directory, so the claim that one
# document describes all five can be checked without a Go toolchain on the host
# -- which this script does not have and deliberately does not want.
for f in /bin-in/janus-verify-*; do
  case "$f" in *SHA256SUMS*|*.json|*.md) continue ;; esac
  go version -m "$f" | awk "\$1==\"dep\"{print \$2\" \"\$3}" | sort > "/out/mods-$(basename "$f").txt"
done
'

  docker run --rm \
    -v "$bindir:/bin-in:ro" \
    -v "$out:/out" \
    -v "$cache/go-build:/gocache" \
    -v "$cache/go-mod:/gomodcache" \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -e GOCACHE=/gocache -e GOMODCACHE=/gomodcache \
    "$GO_IMAGE" bash -c "$script"
}

# normalise <sbom.cdx.json> -- remove the one field that has no flag.
#
# CycloneDX writes metadata.timestamp as "when this document was generated",
# which is true and makes every document differ from every other one. A bill of
# materials that cannot be regenerated to the same bytes cannot be published
# beside a checksum, so the published document does not carry it. The cost: the
# SBOM says what is in the binary, not when somebody asked.
normalise_sbom() {
  python3 -c 'import json,sys
p=sys.argv[1]
d=json.load(open(p))
d.get("metadata",{}).pop("timestamp",None)
with open(p,"w") as f:
    json.dump(d,f,indent=2,sort_keys=True); f.write("\n")' "$1"
}

# agrees_with_the_binary <sbom.cdx.json> <modules.txt>
#
# The SBOM's component list must be exactly the module table Go embedded in the
# binary. This is the check that makes the document evidence rather than
# decoration: the generator could have read `go.mod` instead, and `go.mod` says
# what was declared rather than what was linked. The two differ -- the scanner
# found the same distinction from the other side, when govulncheck's binary mode
# reported zero on modules the source mode also had to consider.
agrees_with_the_binary() {
  python3 -c 'import json,sys
sbom,mods=sys.argv[1],sys.argv[2]
d=json.load(open(sbom))
listed={c["name"] for c in d.get("components",[])}
linked={l.split()[1] for l in open(mods) if l.split() and l.split()[0]=="dep"}
if listed!=linked:
    print("the SBOM does not describe the binary it was generated from.")
    print("  in the SBOM and not linked:", sorted(listed-linked) or "none")
    print("  linked and not in the SBOM:", sorted(linked-listed) or "none")
    print("  A bill of materials generated from go.mod rather than from the")
    print("  binary looks exactly like this, and is a list of what was")
    print("  declared rather than what shipped.")
    sys.exit(1)
print("    %d components, and every one of them is a module the binary links" % len(listed))' "$1" "$2"
}

# same_modules_across_targets <dist dir>
#
# One SBOM is published for five binaries, which is only honest if the five have
# the same dependencies. They do -- 23 modules, identical across linux/amd64,
# linux/arm64, darwin/amd64, darwin/arm64 and windows/amd64 -- and this is what
# keeps it true rather than remembered. A GOOS-conditional dependency would make
# the published document wrong for four of the five artifacts beside it.
same_modules_across_targets() {
  local sbomdir="$1" first="" n=0
  local f
  for f in "$sbomdir"/mods-janus-verify-*.txt; do
    [[ -e "$f" ]] || die "no per-target module tables were written"
    local d; d="$(shasum < "$f" | cut -d' ' -f1)"
    n=$((n + 1))
    if [[ -z "$first" ]]; then first="$d"; continue; fi
    if [[ "$d" != "$first" ]]; then
      die "$(basename "$f" .txt | sed 's/^mods-//') links a different module set from the other targets, so one document cannot describe all five. Publish per target, or find the GOOS-conditional dependency that appeared."
    fi
  done
  printf '%s\n' "    the same module set across all $n published targets"
}

# ---------------------------------------------------------------------------

cmd_check() {
  local work
  work="$(mktemp -d)"
  # Go marks everything it writes into the module cache read-only, and rm(1)
  # cannot unlink a file from a directory that has no write bit on it. Without
  # the chmod the cleanup fails, and under `set -e` it fails the job — after the
  # comparison has already passed, which is what makes it confusing to read.
  trap 'chmod -R u+w "$work" 2>/dev/null || true; rm -rf "$work"' RETURN

  # One target is enough to catch a non-deterministic build and five times
  # faster; the release path builds them all.
  local targets=(linux/amd64)
  local version="repro-check"

  local deep="/a/much/deeper/path/for/the/second/build"

  # What somebody who was sent a tarball actually has: the source, and no
  # repository around it. This is the case the claim is really about — an
  # auditor is not going to be handed a git remote — and it is the only one that
  # can catch a build reading from .git.
  mkdir -p "$work/tarball"
  tar -cf - --exclude='./.git' --exclude='./bin' --exclude='./dist' -C "$REPO" . |
    tar -xf - -C "$work/tarball"
  [[ ! -e "$work/tarball/.git" ]] || die "the tarball copy still contains .git; the check would prove nothing"

  say "building three times, under conditions chosen to disagree"
  printf '%s\n' "${dim}    A: /src  · cold cache · HOME=/tmp          · from the git working tree${off}"
  printf '%s\n' "${dim}    B: $deep · warm cache · HOME=/tmp/other    · from the git working tree${off}"
  printf '%s\n' "${dim}    C: /src  · cold cache · HOME=/tmp          · from a tarball, no .git${off}"

  # A: a short source path, an empty build cache, one HOME.
  build_into "$work/a" "$REPO" "/src" "$work/cache-a" "$version" "/tmp" "${targets[@]}"

  # B: a longer source path, a different HOME, and a cache that has already been
  # used — the first of these two runs exists only to warm it, because a build
  # that reads from cache and one that compiles from scratch are exactly the
  # pair most likely to disagree. If any absolute path, or anything derived from
  # one, reaches the output, A and B differ.
  build_into "$work/warm" "$REPO" "$deep" "$work/cache-b" "$version" "/tmp/other" "${targets[@]}"
  build_into "$work/b" "$REPO" "$deep" "$work/cache-b" "$version" "/tmp/other" "${targets[@]}"

  # C: the auditor's copy.
  build_into "$work/c" "$work/tarball" "/src" "$work/cache-c" "$version" "/tmp" "${targets[@]}"

  say "comparing"
  local failed=0
  if ! diff -u "$work/a/SHA256SUMS" "$work/b/SHA256SUMS"; then
    printf '%s\n' "${red}A and B differ: the build depends on where it was run.${off}" >&2
    printf '%s\n' "  -trimpath is the usual cause — without it the source path is in the binary." >&2
    failed=1
  fi
  if ! diff -u "$work/a/SHA256SUMS" "$work/c/SHA256SUMS"; then
    printf '%s\n' "${red}A and C differ: the build depends on the git repository.${off}" >&2
    printf '%s\n' "  -buildvcs=false is the usual cause. An auditor building from a tarball" >&2
    printf '%s\n' "  cannot reproduce this, which is the only case the claim is about." >&2
    failed=1
  fi
  if [[ $failed -ne 0 ]]; then
    printf '%s\n' "" >&2
    printf '%s\n' "the verifier's reproducibility claim is false as of this commit;" >&2
    printf '%s\n' "somebody who rebuilt the verifier would get a digest that does not match the" >&2
    printf '%s\n' "one we published, and would be right not to trust either." >&2
    return 1
  fi

  printf '%s\n' "${green}identical across all three: $(cut -d' ' -f1 "$work/a/SHA256SUMS" | head -1)${off}"
  cat "$work/a/SHA256SUMS"

  # The bill of materials, and the same question asked of it.
  #
  # A reproducible binary published beside an SBOM that is not reproducible is
  # half a claim: an auditor can confirm the bytes and not the list of what is
  # in them. So the SBOM is generated from two of the three builds and required
  # to be identical, exactly like the binaries.
  #
  # Generated from the BINARY, never from go.mod. That is the whole design
  # decision and the check below is what enforces it: a document
  # listing what was declared rather than what was linked fails
  # agrees_with_the_binary, because the two are not the same set.
  local bin_name="janus-verify-linux-amd64"
  say "generating the bill of materials from the binary, twice"
  sbom_into "$work/sbom-a" "$work/a" "$bin_name" "$version" "$work/cache-b"
  sbom_into "$work/sbom-b" "$work/b" "$bin_name" "$version" "$work/cache-b"
  normalise_sbom "$work/sbom-a/sbom.cdx.json"
  normalise_sbom "$work/sbom-b/sbom.cdx.json"

  if ! diff -u "$work/sbom-a/sbom.cdx.json" "$work/sbom-b/sbom.cdx.json"; then
    printf '%s\n' "${red}the two bills of materials differ.${off}" >&2
    printf '%s\n' "  The binaries are identical, so this is the generator: something in the" >&2
    printf '%s\n' "  document is about when it ran rather than about what it describes." >&2
    printf '%s\n' "  -noserial covers the UUID; metadata.timestamp is stripped; a third such" >&2
    printf '%s\n' "  field means the published SBOM cannot sit beside a checksum." >&2
    return 1
  fi

  agrees_with_the_binary "$work/sbom-a/sbom.cdx.json" "$work/sbom-a/modules.txt" || {
    printf '%s\n' "${red}the SBOM does not describe the binary.${off}" >&2
    return 1
  }
  printf '%s\n' "${green}the bill of materials is reproducible too${off}"
}

cmd_release() {
  local version="${1:-}"
  if [[ -z "$version" ]]; then
    version="$(git rev-parse --short=12 HEAD 2>/dev/null || true)"
    [[ -n "$version" ]] || die "pass a version, or run inside a git repository"
  fi

  # A published artefact has to name a commit somebody else can check out. A
  # dirty tree names nothing: the digest would be reproducible only by whoever
  # happens to hold those uncommitted edits, which is the opposite of the point.
  if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
    die "the working tree has uncommitted changes; a published digest must name a commit that exists"
  fi

  local out="$REPO/dist"
  rm -rf "$out"
  say "building janus-verify $version for ${#TARGETS[@]} targets"
  build_into "$out" "$REPO" "/src" "$(mktemp -d)" "$version" "/tmp" "${TARGETS[@]}"

  # The bill of materials, beside the binaries rather than in the tree.
  #
  # Never committed. An SBOM in version control is a description of what was
  # declared on the day somebody generated it, and it ages silently while the
  # thing it describes changes -- which is the hollow-control shape this
  # repository keeps finding. Generated from a published binary on every
  # release, it cannot say anything the binary does not.
  #
  # One document, not five. The module table is identical across all five
  # published targets -- measured, not assumed -- so a per-target
  # SBOM would be the same list five times with a different filename. The check
  # below is what keeps that true: if a GOOS-conditional dependency ever
  # appears, the release stops.
  say "the bill of materials"
  sbom_into "$out/sbom" "$out" "janus-verify-linux-amd64" "$version" "$(mktemp -d)"
  normalise_sbom "$out/sbom/sbom.cdx.json"
  agrees_with_the_binary "$out/sbom/sbom.cdx.json" "$out/sbom/modules.txt" || die "the SBOM does not describe the binary"
  same_modules_across_targets "$out/sbom"
  mv "$out/sbom/sbom.cdx.json" "$out/janus-verify.sbom.cdx.json"
  rm -rf "$out/sbom"
  ( cd "$out" && sha256sum janus-verify.sbom.cdx.json >> SHA256SUMS && sort -k2 -o SHA256SUMS SHA256SUMS )

  local commit
  commit="$(git rev-parse HEAD)"
  cat > "$out/REPRODUCE.md" <<EOF
# Reproducing janus-verify $version

These binaries are meant to be checked, not trusted. Rebuild them and compare.

    git clone <this repository> janus && cd janus
    git checkout $commit
    scripts/reproducible-build.sh release $version
    diff dist/SHA256SUMS SHA256SUMS   # this file, as published

## What the build is pinned to

| | |
|---|---|
| Commit | \`$commit\` |
| Go toolchain | $GO_VERSION |
| Container | \`$GO_IMAGE\` |
| Flags | \`${BUILD_FLAGS[*]}\`, \`CGO_ENABLED=0\`, \`-ldflags "-X main.version=$version"\` |

The container is pinned by digest rather than by tag on purpose: \`golang:1.26-bookworm\`
resolves to a different patch release over time, and a tag would silently
invalidate every checksum below.

## The bill of materials

`janus-verify.sbom.cdx.json` is CycloneDX, and it was generated **from the
binary** rather than from `go.mod`. That distinction is the whole of its value:
`go.mod` lists what this repository declares, and the repository also contains a
daemon, a Postgres projection and a gRPC surface that the verifier does not
link. A bill of materials taken from it would tell you the verifier contains a
database driver. It does not.

Check it without trusting the generator, or this file:

    go version -m janus-verify-linux-amd64 | awk '$1=="dep"{print $2, $3}' | sort

That is the table Go embeds in every binary, and it is where the document's
contents came from. The same table is what `govulncheck -mode=binary` reads.

One document covers all five binaries: their module sets are identical, which
the release checks rather than assumes.

Regenerating it byte-for-byte needs the serial number and the timestamp
suppressed — CycloneDX writes both by default and both describe the act of
generating rather than the thing described. `scripts/reproducible-build.sh` does
that.

## Without Docker

The container is a convenience for pinning the toolchain, not a dependency of
the result. Go $GO_VERSION with the same flags produces the same bytes:

    CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> \\
      go build ${BUILD_FLAGS[*]} -ldflags "-X main.version=$version" \\
      -o janus-verify-<os>-<arch> ./cmd/janus-verify

If your digest differs, check your Go version first — it is the input that
changes the output most often, and \`go version\` is the fastest thing to rule
out.

## Checksums

\`\`\`
$(cat "$out/SHA256SUMS")
\`\`\`
EOF

  say "dist/"
  ls -la "$out" | tail -n +2
  printf '\n%s\n' "${green}$(wc -l < "$out/SHA256SUMS") artefacts, checksums in dist/SHA256SUMS, instructions in dist/REPRODUCE.md${off}"
}

case "${1:-check}" in
  check)   cmd_check ;;
  release) shift || true; cmd_release "${1:-}" ;;
  *)       die "usage: $0 [check|release [version]]" ;;
esac
