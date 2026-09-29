# loan-desk with a real model — run 2026-09-29T055923Z

- injected notice failures: none; applications: all
- condition: A (A: the mandate is in the underwriter's prompt and in the policy; B: in the policy only; Bprime: policy only, unit stated)
- oracle: always-approve; intake replayed from: docs/bench/agentic/2026-09-27T140840Z/results.json
- model: `gemma4:31b-cloud` via ollama, temperature 0.7, seed per saga (recorded in each DPR)
- janus-orchd: `-sync full`, one saga at a time, on Darwin/arm64
- corpus: examples/loan-desk/agentic/applications.json (author-written, synthetic)
- commit: 0264b28

`results.json` holds the summary and every row. The evidence log is in `evidence/`
and the writer's public key in `pub.json` (committed 2026-09-29), so
`janus-verify -keys pub.json evidence` and `janus-gate audit evidence` re-run
the auditor's checks from this directory alone.
