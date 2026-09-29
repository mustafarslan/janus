# Security

**There is no security team.** This repository is a research prototype with one
maintainer and no production deployment. Everything below says what that does and does not get you, because a
`SECURITY.md` that reads like a programme and is one person is the failure this
project exists to prevent.

## Reporting

Report a vulnerability privately, through GitHub's private vulnerability
reporting on this repository (**Security → Report a vulnerability**). A report
there is visible only to the maintainer until an advisory is published, so a
flaw is not disclosed by the act of reporting it.

If you are reading this in a fork or a mirror where that button does not exist,
open an issue titled "security contact requested", with no details, and a
private channel will be given to you there. Please do not describe the flaw in
a public issue, a pull request or a discussion.

What you are **not** getting: no response-time commitment, no coordinated
disclosure process, no embargo handling, no security advisory feed, no CVE
assignment, no backported fix (see [SUPPORT.md](docs/SUPPORT.md) — there is one
branch).

**Supported versions.** Only `master`. A fix lands there and nowhere else.

**What is not a vulnerability here.** The limits listed at the end of this file
are the system's documented behaviour, not flaws in it: a report that one of them
holds is not a report of a vulnerability. A report that the system is weaker than
this file or the paper says, or that a claim under "What you can check
yourself" is false, is exactly what the reporting channel is for.

## What you can check yourself

This is the substantive half, and it is deliberately larger than the half above.
A reader who cannot be given a process can still be given evidence they verify
without trusting anybody here.

**The verifier is reproducible.** `make repro` builds `janus-verify` three ways
and requires identical bytes; CI runs it as the `repro` job, and
`make release-verifier` ships the checksums and the instructions to reproduce
them. So the binary handed to an auditor can be rebuilt from source and diffed
rather than trusted. It is a job in `make ci`, which runs the workflow's jobs in
a Linux container and is what every change here is merged on; the GitHub
workflow itself runs on demand, not on every push.

**You can see what is in it, from the binary rather than from our manifest.**
`make release-verifier` ships `janus-verify.sbom.cdx.json` — CycloneDX, generated
from the built binary by reading the module table Go embeds in it, not
from `go.mod`. That distinction is not pedantry: `go.mod` lists 43 modules and
the binary contains 5, because this repository also holds a
daemon, a Postgres projection and a gRPC surface that the verifier does not link.
You do not need the document or our word for it — `go version -m janus-verify`
prints the same table, and `make repro` regenerates the document from two
separate builds and requires identical bytes.

**Count them: there are five.** `cbor`, `uuid`, `blake3`, `float16`, `cpuid` —
what it takes to parse a segment, check a BLAKE3 chain and verify an Ed25519
signature, and nothing else.

**That paragraph used to say eighteen of twenty-three, and what it said is worth
keeping.** Until recently the verifier linked an S3 client it never called,
because the package holding content-addressed storage also held an S3 backend,
and 78% of the dependency list handed to an auditor was code that existed to be
linked and not run. It went from 23 modules to 5 and from 6.98 MB to 4.88 MB.
What made it happen was publishing the list: the claim below had been in this
file, unchecked, for as long as it had been false.

**The verifier is offline, and this is now checked rather than asserted.** It
reads a directory of segments and a public key set, and needs neither this
project nor a live writer. `TestTheVerifierLinksOnlyWhatItReads` runs
`go list -deps ./cmd/janus-verify` in CI and fails on `net/http`, `crypto/tls`,
an S3 SDK, a Postgres driver, gRPC, protobuf or OpenTelemetry — each with the
reason it does not belong.

This sentence said "checked rather than asserted" for months while **nothing
checked it**, which is how the S3 client got in and stayed. It is a dependency
check and not a syscall one: it proves the verifier does not *link* the usual
ways of not being offline, which is weaker than proving it makes no network call
and is what can actually be enforced on every commit.

**And it is scanned, which is new.** `govulncheck` runs in `make ci` in both
source and binary mode and blocks. Binary mode reads the linked symbol table of
the verifier as built, which is the same check an auditor holding only a
released binary can run on it.
**It reports zero.**

**This paragraph used to carry a caveat and no longer does, which is worth
recording rather than deleting.** Until recently the verifier stamped **23
modules, 18 of them `aws-sdk-go-v2`** — `service/s3`, `credentials`, `sts`,
`sso`, `feature/ec2/imds` — reached through `cas` → `objstore`, for an S3 offload
the verifier never performs.
`govulncheck` saw through it, because it filters by reachability and the linker
had dropped most of the bodies. **A module-list scanner — Trivy, Grype,
Dependabot — would not**, because it matches a module and a version and cannot
see what was dropped. That gap between the two kinds of scanner is the reason the
dependency was worth removing while nothing was going wrong: it is **5 modules
now, none of them AWS**, and the two kinds of scanner agree. Today the point is
moot: **no advisory names any dependency this repository requires** — every
finding in the first scan was the Go standard library, and the toolchain is now
kept current in its minor line so those get fixed rather than accumulated.

**The adversarial suite is runnable, and fails unless it names every attack.**
It is not part of `make ci`; run it. `make evil-auditor`
performs the adversarial attacks for real — back-dating, forged writer
signatures, replayed segments, shredding then claiming integrity, double-released
effects — and asks whether the system *names* each one from the log alone. Two of
the attacks are gated elsewhere and the suite says so on its way past, rather
than counting them.

**A version this build does not have is refused, not read past.** There are four
version gates: segment format, event envelope, saga semantics and protobuf. A newer
record is a hard stop naming both versions, because CBOR drops keys it does not
know and a half-read record looks entirely ordinary. This was found by
measurement, not argument — a v1 build read a real v2 log silently and
`janus-verify` printed `result: PASS`.

**The auditor's second tool authenticates before it re-derives.** `janus-gate
audit -keys pub.json <log or bundle>` verifies the log against the writer's key
first, as `janus-verify` does, and refuses to re-derive anything from a log that
does not verify; without `-keys` it says, on its first line, that the log was not
authenticated. It also reports how many recorded answers and results carry no
signature, so a log where nobody signed cannot read like one where every
signature held. For a bundle, `janus-verify` checks that each event the manifest
lists is the record its inclusion proof covers, and that a saga's bundle lists
each of that saga's records once and nothing else. The seven model runs under
`docs/bench/agentic/` pass both tools from their own directories.
`TestTheAuditAuthenticatesTheLogBeforeReDerivingIt`,
`TestTheAuditCountsWhatNobodySigned`,
`TestASelectionNamesTheEventItsProofCovers` and
`TestASagaBundleSelectsTheWholeSagaAndNothingElse` are what hold these.

**The threat model is written down.** The paper's Section III
([`paper/sections/model.tex`](paper/sections/model.tex)) states the threats in
scope, the ones out of scope, and the invariants each defence rests on.

## What was planned and does not exist

The project's plan at the outset described a security engineering program in the
present tense — SAST/DAST and dependency scanning "from Phase 0", fuzzing on the codecs
and the verifier, an external pentest, a SOC 2 Type II track, a FIPS-mode build,
and an SBOM with every release.

**Four of the eight now exist: dependency scanning, fuzzing at
the decode boundary, an SBOM with every release and SAST.** Fuzzing has a
remainder — nothing searches continuously; CI replays the corpus. SAST is
`gosec`, as an include list of rules that find nothing rather than the
default set with eight exclusions, and `docs/security/gosec-2026-09-12.md`
records the run that decided that. **Still absent: DAST, external pentest,
SOC 2, FIPS build.**

**What the first scan found is the honest measure of what was missing:** seven
reachable vulnerabilities, all of them the Go standard library, on a toolchain
three patch releases behind. All seven were fixed by moving it. Nobody here would
have been told — which is what "no scanner" meant in practice.

**The first SAST run says something different and worth being plain about.** 120
findings, of which **one** was genuinely wrong — a bound the evidence log
enforced when reading and not when writing, so a 64 MiB record could be written
and then read back as corruption. It is fixed. The other 119 were intended or
were the tool guessing wrong, and the triage of every one is in
`docs/security/gosec-2026-09-12.md` rather than summarised here. A scanner's
value on a codebase like this one is not the rule firing correctly; it is the
rule pointing somewhere worth reading.

## Security-relevant limits that are known and documented

These are not vulnerabilities. They are places where the system's answer is
"names it afterwards" rather than "prevents it", and an operator should know
which is which before relying on one.

- Without `-fence-bucket`, the default, nothing prevents two writers; with it,
  a lease fences a superseded writer. Either way a fork is detected and
  attributed.
- The daemon's channel is not encrypted, and the replication, operator,
  effect-delivery and read-only calls are not authenticated.
- A participant whose manifest declares no key is taken at its word unless the
  daemon runs with `-require-caller-signatures`.
- What a signature covers is narrower than it may look: an answer's signature
  covers its verdict, not the facts its answerer was shown, so an answerer
  deceived about the facts approves the real proposal; a declaration's does not
  cover its attempt, so a captured declaration can be replayed into a later
  attempt of the same step; and a key withdrawn from a manifest still signs for
  sagas that pinned the version declaring it.
- A gate decides on the facts a step *declares*, not on whether they are true: a
  model that declares 4,000 for a request of 40,000 is judged on 4,000. The log
  records the declaration faithfully; it does not check it.
- A holder of the writer's key can write a consistent alternative history.
  Anchoring log heads outside Janus is not built; an auditor can pin a head
  obtained by another route (`janus-verify -expect-head`).
- With the fence on, a writer cut off from the lease store goes on sealing
  until its lease expires (`-fence-ttl`, 30 seconds by default).
- Through the Python SDK, a client that ignores a refusal is not stopped: the
  log shows the refusal, and only the payment's own record would show that the
  payment was made anyway. Only the MCP edge holds an effect on the wire.

The paper's Section III
([`paper/sections/model.tex`](paper/sections/model.tex)) and Section VII
([`paper/sections/limitations.tex`](paper/sections/limitations.tex)) state these
with the rest of what is out of scope.
- Evidence bundles are not anchored, so a truncated *unsigned* bundle is
  invisible from inside it — `janus-verify -expect-head` catches it only if a
  head reached the reader by another route.
- Nothing disposes of anything: the retention engine has no caller, so
  maximum-retention obligations are enforced by nobody.
- The clock is attested but not disciplined — a breach is recorded, and no
  deployment fails closed on one.
- A downgrade after writing under a newer envelope is a hard stop, by design.
