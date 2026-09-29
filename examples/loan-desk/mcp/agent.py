"""loan-desk as a raw MCP agent.

Four tool calls: read the application, assess it, disburse the loan, notify the
applicant. It speaks ordinary MCP over stdio to whatever command it is given and
knows nothing about Janus — which is the claim janus-mcpd makes, and the reason
this same file is used by both the plain and the governed runs.
"""

from __future__ import annotations

import json
import subprocess
import sys


def call(proc: subprocess.Popen[bytes], request_id: int, tool: str, args: dict) -> dict:
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }
    proc.stdin.write((json.dumps(request) + "\n").encode())
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def main() -> None:
    command = sys.argv[1:]
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    steps = [
        (1, "intake.read", {"applicant": "acct_1701"}),
        (2, "credit.assess", {"amount_minor": 250000}),
        (3, "payments.disburse", {"amount_minor": 250000, "currency": "EUR"}),
        (4, "notify.email", {"recipient": "acct_1701", "approved": True}),
    ]
    for request_id, tool, args in steps:
        answer = call(proc, request_id, tool, args)
        state = "refused" if "error" in answer else "ok"
        print(f"  {tool}: {state}")
        if "error" in answer:
            print(f"    {answer['error']['message']}")

    proc.stdin.close()
    proc.wait()


if __name__ == "__main__":
    main()
