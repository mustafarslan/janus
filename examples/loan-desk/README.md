# loan-desk

The Phase 4 exit gate: one application — intake agent → credit-policy validator
→ payments tool → notification — running on **LangGraph** and on **raw MCP**,
with the conformance suite passing for both.

```bash
make loan-desk
```

## What the gate asks, and how it is measured

> under 50 lines of integration code each; the conformance suite passes for both
> adapters

A line count is trivially fudged, so it is measured rather than claimed. Each
adapter has the same application written twice — `plain.*` with no Janus at all,
`governed.*` with it — and `scripts/measure-integration.sh` diffs them. Four
rules keep the number honest:

- **A changed line counts as added.** A line Janus made you touch is a line Janus
  cost you; excluding them would let a rewrite hide behind an edit.
- **Removed lines do not offset.** The cost is not netted against whatever the
  governed version happened to drop.
- **Comments, docstrings and blank lines are stripped from both files.**
  Integration cost is code you have to write, not prose you chose to write about
  it — counting prose would mean a well-documented example scored worse than a
  terse one.
- **The diff is printed, not just the total.** A reader who does not trust the
  arithmetic can read the lines.

What the script cannot check is that the two files implement the same
application. That is by inspection, which is why both are short.

| Adapter | Integration code | Conformance |
|---|---|---|
| LangGraph, via the Python SDK | **45 lines** | PASS |
| raw MCP, via `janus-mcpd` | **34 lines** | PASS |

## What each adapter actually costs

**LangGraph** pays for a declaration and a wrapper. The application says what
each step does to the world — the effect class is what every gate matches on, so
nothing can infer it — and wraps the graph so its nodes are steps. LangGraph
keeps the control flow: `janus.langgraph.govern` intercepts `add_node`, which is
where the adapter sits, and a Janus adapter with an opinion
about *which node runs when* would be a second scheduler disagreeing with the
first.

**Raw MCP** pays for configuration and nothing else. `agent.py` and
`toolserver.py` are identical between the two runs and neither knows Janus
exists. What is added is the manifest declaring what the tool really does,
registering it, standing up the daemon, and putting `janus-mcpd` in front of the
server. Those daemon lines are counted, which is the conservative reading: they
are what a deployment does, not what this application had to be rewritten to do.

## The validator is a participant, not integration

The credit-policy validator is its own process (`validator.py`). In the
LangGraph run the application answers as it, because it is the process that
happens to be there — one line. In the raw-MCP run there is no application in
the loop at all, so the validator is what it would be in a deployment: something
separate that watches for questions addressed to it.

It is not counted as integration code for either application, and nothing in
either application changes to accommodate it.

Both validators judge the amount against the mandate, from the facts the
question carries. Until those were carried they approved everything
unseen — `lambda *_: (True, ...)` — because there was nothing to read; the
standalone one now refuses a question that does not say how much.

## What the run demonstrates beyond the numbers

The interesting moment is the disbursement. It is `COMPENSABLE`, so the policy
requires a second opinion before release. In the raw-MCP run the agent is simply
told:

```
  payments.disburse: refused
    janus is holding this call for a decision (saga sg_loan_desk_3);
    it will be sent if it is approved
```

The agent is not blocked, the tool server is never called, and the payment goes
out when the validator answers — from a process the agent knows nothing about,
on evidence the agent cannot write.
