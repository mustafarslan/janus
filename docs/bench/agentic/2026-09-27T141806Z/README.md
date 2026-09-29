# loan-desk with a real model — run 2026-09-27T141806Z

- injected notice failures: app_06,app_07,app_08,app_09,app_10; applications: app_06,app_07,app_08,app_09,app_10
- condition: A (A: the mandate is in the underwriter's prompt and in the policy; B: in the policy only)
- model: `gemma4:31b-cloud` via ollama, temperature ${JANUS_TEMPERATURE:-0.7}, seed per saga (recorded in each DPR)
- janus-orchd: `-sync full`, one saga at a time, on Darwin/arm64
- corpus: examples/loan-desk/agentic/applications.json (author-written, synthetic)
- commit: 1bd72f3

`results.json` holds the summary and every row. The evidence log is in `evidence/`
and the writer's public key in `pub.json` (committed 2026-09-29), so
`janus-verify -keys pub.json evidence` and `janus-gate audit evidence` re-run
the auditor's checks from this directory alone.
