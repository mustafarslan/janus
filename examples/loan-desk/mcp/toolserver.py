#!/usr/bin/env python3
"""The loan-desk tool server: ordinary MCP, no idea Janus exists.

It is the thing janus-mcpd fronts. Nothing in it changes between the plain and
the governed run, which is the claim being demonstrated.
"""

from __future__ import annotations

import json
import sys

RESULTS = {
    "intake.read": "application read",
    "credit.assess": "within the mandate",
    "payments.disburse": "disbursed",
    "notify.email": "notified",
}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        request = json.loads(line)
        name = request.get("params", {}).get("name", "")
        if request.get("method") != "tools/call" or name not in RESULTS:
            answer = {
                "jsonrpc": "2.0", "id": request.get("id"),
                "error": {"code": -32602, "message": f"unknown tool: {name}"},
            }
        else:
            answer = {
                "jsonrpc": "2.0", "id": request.get("id"),
                "result": {"content": [{"type": "text", "text": RESULTS[name]}],
                           "isError": False},
            }
        sys.stdout.write(json.dumps(answer) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
