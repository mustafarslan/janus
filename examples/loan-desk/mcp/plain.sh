#!/usr/bin/env bash
# loan-desk on raw MCP, with no Janus.
#
# The agent talks to the tool server. That is the whole of it.
set -euo pipefail
python3 "$(dirname "$0")/agent.py" "$JANUS_TOOL_SERVER"
