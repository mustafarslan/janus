# Security

**There is no security team.** This repository is pre-GA, private, and has one
maintainer. Everything below says what that does and does not get you, because a
`SECURITY.md` that reads like a programme and is one person is the failure this
project exists to prevent.

## Reporting

Open an issue in this repository.

That is the whole channel, and it is adequate for exactly one reason: **the
repository is private, so everyone who can read a report is already trusted with
the source it describes.** There is no gap to protect between disclosure and fix,
because there is no third party running this in production.

**The day the repository goes public, this stops being true and this section is
wrong.** A public repo needs a private channel — GitHub's private vulnerability
reporting, which is not available on private repositories — and going public
without changing this page publishes a "report it in the open" instruction.

What you are **not** getting: no response-time commitment, no coordinated
disclosure process, no embargo handling, no security advisory feed, no CVE
assignment, no backported fix (see [SUPPORT.md](docs/SUPPORT.md) — there is one
branch).

## What you can check yourself

This is the substantive half, and it is deliberately larger than the half above.
A reader who cannot be given a process can still be given evidence they verify
without trusting anybody here.

**The verifier is reproducible.** `make repro` builds `janus-verify` three ways
and requires identical bytes; CI runs it as the `repro` job, and
`make release-verifier` ships the checksums and the instructions to reproduce
them. So the binary handed to an auditor can be rebuilt from source and diffed
rather than trusted — and because it is a CI job rather than a release ritual, a
change that breaks reproducibility fails on the commit that makes it.

**You can see what is in it, from the binary rather than from our manifest.**
`make release-verifier` ships `janus-verify.sbom.cdx.json` — CycloneDX, generated
from the built binary by reading the module table Go embeds in it, not
from `go.mod`. That distinction is not pedantry: `go.mod` would list 41
components and the binary contains 23, because this repository also holds a
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

**And it is scanned, which is new.** `govulncheck` runs in CI in both source and
binary mode and blocks. Binary mode reads the linked symbol table of the
published verifier — the same check an auditor holding only that binary can run.
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

**The adversarial suite is runnable, and it blocks on 100%.** `make evil-auditor`
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

**The threat model is written down.** The paper's Section III
([`paper/sections/model.tex`](paper/sections/model.tex)) states the threats in
scope, the ones out of scope, and the invariants each defence rests on.

## What was planned and does not exist

The project's design describes a security engineering program in the present
tense — SAST/DAST and dependency scanning "from Phase 0", fuzzing on the codecs
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

- Nothing prevents two writers; a fork is detected and attributed, not fenced.
- Evidence bundles are not anchored, so a truncated *unsigned* bundle is
  invisible from inside it — `janus-verify -expect-head` catches it only if a
  head reached the reader by another route.
- Nothing disposes of anything: the retention engine has no caller, so
  maximum-retention obligations are enforced by nobody.
- The clock is attested but not disciplined — a breach is recorded, and no
  deployment fails closed on one.
- A downgrade after writing under a newer envelope is a hard stop, by design.
