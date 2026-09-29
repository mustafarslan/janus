#!/usr/bin/env bash
# Wait for the compose postgres to accept connections.
#
# Split out of the Makefile because two targets need it and a retry loop written
# twice drifts: the copy that is not being looked at is the one that starts
# passing a container that is up but not yet accepting connections.
set -euo pipefail

for _ in $(seq 1 60); do
  if docker compose exec -T postgres pg_isready -U janus -d janus >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

docker compose logs postgres
echo "postgres did not become ready within 60s" >&2
exit 1
