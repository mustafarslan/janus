# Compliance packs

A pack maps a framework's articles onto checks Janus can evaluate. Packs are
**data**: a legal review that changes a mapping produces a new pack version, not
a new build.

```bash
janus-compliance packs                          # what is mapped
janus-compliance checks                         # the vocabulary a pack may use
janus-compliance lint -evidence ./janus-evidence -policy docs/policy/reference.json
```

## What the linter reads, and what it does not

It reads **declarations and rules** — the registry and the gate policy. It does
not read a log.

That is the distinction the whole subsystem turns on. An article about controls
asks what is *allowed* to happen; a log answers what *did*. A quiet month is not
a control, and a tool that conflated the two would let one read as the other.
What happened is `janus-verify`'s question over a log and `janus-conformance`'s
over a run.

It runs **before** an audit. "Three actions declare no way to be undone and no
gate stands in for one" is a finding somebody can act on in a sprint; the same
finding from an inspector is a finding in a report.

## The honest limit

A pack chooses from a fixed vocabulary and **cannot invent a new kind of check
without code**. Mapping "Article 22 requires X", where X is a property nothing
here can evaluate, needs a new checker and therefore a build.

That limit is stated rather than worked around. The alternative — an expression
language inside the pack — would make packs into code with none of the review a
build gets, and the failure mode would be a pack that quietly evaluates to true.

Two consequences follow, and both are enforced at load time:

- a pack naming a check this build does not know is **refused**, with the list
  of checks it could have meant. An article mapped to a check that does not
  exist would evaluate to nothing and report as satisfied.
- an article requiring **no** checks is refused, for the same reason.

And `unknown` is a status of its own. A check that could not run — no policy was
supplied, or there was nothing of that kind to look at — is not a mild pass.

## What it found in this repository

Run against `docs/policy/reference.json`, the linter reports EU AI Act Art. 14
and SS1/23 P4.3 as **exposed**:

```
irreversible_effects_require_a_human: 2 rule(s) cover an irreversible effect
without requiring a person: outbound-messages, wires
```

That is correct and it has been left alone rather than quietly fixed. The
reference policy gates those two rules on `approved == true` — a fact the step
itself declares. Under a strict reading of Art. 14 a flag the agent sets is not
human oversight, and only the `large-wires` rule requires an actual person.

Whether that is the right policy is a judgement for whoever deploys it. What the
tool is for is making the judgement visible before somebody else makes it for
you.

## Packs that exist

| Pack | Framework | Articles mapped |
|---|---|---|
| `eu-ai-act` | Regulation (EU) 2024/1689 | Art. 12, 14, 14(4)(d), 49 |
| `ss1-23` | PRA SS1/23 model risk management | P1.2, P2.1, P4.3 |

The design lists nine frameworks. Two are written, and a handful of
articles in each. The rest are unwritten rather than partially written, because
a pack that maps an article to nothing reports it as satisfied — which is why
that is refused at load time and why the missing ones are absent rather than
stubbed.
