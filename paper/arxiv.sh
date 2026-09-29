#!/usr/bin/env bash
# Build the paper and the source tarball arXiv takes.
#
# arXiv does not run BibTeX, so the generated main.bbl goes in the tarball; the
# section files are kept as \input{sections/...}, which arXiv resolves from the
# archive. Nothing here needs shell-escape.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex >/dev/null
out="arxiv-janus.tar.gz"
tar -czf "$out" main.tex main.bbl sections/*.tex
echo "built main.pdf ($(pdfinfo main.pdf | awk '/Pages/{print $2}') pages) and $out"
