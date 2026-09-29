# The Janus paper

`./arxiv.sh` builds `main.pdf` and `arxiv-janus.tar.gz` (the source arXiv takes,
with the generated `main.bbl`, because arXiv does not run BibTeX). Needs a TeX
distribution with IEEEtran; the paper uses no shell-escape.

Every number in `sections/` carries a `% source:` comment naming the file, test,
command or committed run directory under `docs/bench/agentic/` it comes from, and
the appendix names the command that reproduces each result.
