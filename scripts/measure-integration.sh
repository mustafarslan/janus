#!/usr/bin/env bash
# How much code does Janus cost an application?
#
# Phase 4's exit gate is a number — under fifty lines of integration code — and
# a number like that is trivially fudged. So it is measured rather than claimed,
# by the only definition that cannot be argued with: write the same application
# twice, once plain and once governed, and count what had to be added.
#
# Four rules make the count honest, and each exists because leaving it out would
# flatter the result:
#
#   * A changed line counts as added. A line Janus made you touch is a line
#     Janus cost you, and excluding them would let a rewrite hide behind an edit.
#   * Removed lines do not offset. Integration cost is not netted against
#     whatever the governed version happened to drop.
#   * Comments, docstrings and blank lines are stripped from both files first.
#     Integration cost is code you have to write, not prose you chose to write
#     about it — and counting prose would mean a well-documented example scored
#     worse than a terse one. Stripping blank lines stops the plain version
#     being padded.
#   * The diff itself is printed, not just the total. A reader who does not
#     trust the arithmetic can read the lines.
#
# What it cannot check is that the two files implement the same application.
# That is by inspection, and both files are short and shown in full in the PR
# for exactly that reason.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -lt 2 ]]; then
  echo "usage: measure-integration.sh <plain> <governed> [label]" >&2
  exit 2
fi

plain="$1"
governed="$2"
label="${3:-$(basename "$(dirname "$governed")")}"

plain_code="$(mktemp)"
governed_code="$(mktemp)"
trap 'rm -f "$plain_code" "$governed_code"' EXIT

# Python gets the tokenizer, so a "#" inside a string is not mistaken for a
# comment. Everything else gets the shell/JSON reading of a comment, which is
# the same rule applied with a blunter tool.
strip() {
  case "$1" in
    *.py) python3 "$REPO/scripts/strip-comments.py" "$1" ;;
    *)    sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' "$1" ;;
  esac
}

strip "$plain" > "$plain_code"
strip "$governed" > "$governed_code"

# -U0: no context lines, so only real changes are counted.
# '^+[^+]': added lines, excluding the +++ file header.
added="$(diff -U0 "$plain_code" "$governed_code" | grep -c '^+[^+]' || true)"

echo "── $label: what Janus cost this application"
echo
diff -U0 "$plain_code" "$governed_code" | grep '^+[^+]' | sed 's/^+/   /' || true
echo
echo "   $added lines of integration code"
