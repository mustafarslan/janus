# Janus SDKs

- `python/` — **the Python SDK, built in Phase 4c.** `@saga`, `@step` and
  `@compensation` over the `janus-orchd` API. See `python/README.md`.
- `ts/` — still a stub. TypeScript is enterprise glue and the console's
  language; it was not required by any Phase 4 exit gate and is not published.

Neither package is published to a registry yet. The Python one works and is
tested on every commit (`make ci`, job `python`); the TypeScript one raises on
import rather than returning a client that silently records nothing, because an
SDK that appears to work while recording nothing is worse than one that is
absent — it lets an agent act unevidenced while looking compliant.
