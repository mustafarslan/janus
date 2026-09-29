SHELL := /bin/bash
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# Soak defaults. The Phase 1 exit gate is DURATION=72h; the default is short
# enough to run on a laptop between changes.
DURATION ?= 2m
JANUS_S3_ENDPOINT ?= http://127.0.0.1:9000
SOAK_SYNC ?= data
SOAK_SEGMENT_BYTES ?= 65536
# How stale the re-reading of old segments may be, and how large an evidence
# directory grows before it is verified whole and retired. The defaults are the
# ones the 72-hour gate wants; lower SOAK_EPOCH_BYTES if a run's round cost
# starts climbing.
SOAK_SWEEP_PERIOD ?= 15m
SOAK_EPOCH_BYTES ?= 5368709120
# Where the projection lives when a target wants one. Empty is allowed and
# means "measure only what needs no database".
PG_DSN ?= postgres://janus:janus@localhost:5432/janus
EVIDENCE ?= ./janus-evidence
POLICY ?= docs/policy/reference.json
CADENCE ?= docs/compliance/revalidation.json
CONSOLE_ADDR ?= 127.0.0.1:8088
# Empty by default, which makes the reproducible build stamp the commit. Set it
# for a real release: VERIFIER_VERSION=v1.2.3 make release-verifier
VERIFIER_VERSION ?=
LDFLAGS := -X main.version=$(VERSION)
BIN := bin
CMDS := janus-bench janus-latency janus-verify janus-identity janus-replicad janus-evilauditor janus-skeleton janus-mcpd janus-toytool janus-keys janus-soak janus-tier janus-sagachaos janus-gate janus-registry janus-console janus-orchd janus-a2ad janus-conformance janus-compliance janus-signer janus-spotreplay janus-projection

.DEFAULT_GOAL := help

## help: list targets
help:
	@echo "Janus"
	@echo
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /' | column -t -s ':'

## build: compile every command into bin/
build:
	@mkdir -p $(BIN)
	@for c in $(CMDS); do \
		echo "  building $$c"; \
		go build -ldflags "$(LDFLAGS)" -o $(BIN)/$$c ./cmd/$$c || exit 1; \
	done

## test: run the full test suite with the race detector
test:
	go test -race ./...

## test-short: run tests without the race detector
test-short:
	go test ./...

## lint: vet, gofmt check, and golangci-lint
lint:
	go vet ./...
	@out=$$(gofmt -l cmd pkg); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	@command -v golangci-lint >/dev/null && golangci-lint run ./... || echo "  golangci-lint not installed, skipped"

## ci: run the CI jobs locally, on linux, in a container
## (build lint proto repro gate python)
ci:
	@./scripts/local-ci.sh

## ci-all: the above plus the object-storage and WORM job
ci-all:
	@./scripts/local-ci.sh all

## ci-quick: host-only gofmt, vet, build and tests. Fast, and not the signal.
ci-quick:
	@./scripts/local-ci.sh quick

## repro: prove janus-verify builds to the same bytes from a different path,
## a different cache, and a tarball with no .git (Phase 1 exit criterion) -- and
## that its bill of materials, generated from the binary, regenerates to the
## same bytes too
repro:
	@./scripts/reproducible-build.sh check

## release-verifier: build the published janus-verify matrix with checksums, a
## CycloneDX bill of materials generated from the binary, and reproduction
## instructions into dist/ (VERSION=v1.2.3, defaults to the commit)
release-verifier:
	@./scripts/reproducible-build.sh release $(VERIFIER_VERSION)

## gen: regenerate protobuf code (requires buf)
gen:
	buf lint
	buf generate

## bench: the Phase 0 go/no-go gate — evidence append path, swept over concurrency
bench: build
	$(BIN)/janus-bench -events 150000 -payload 256 -sweep 16,64,256,1024

## bench-linux: run the gate on linux in a container, which is the number that counts
bench-linux:
	@mkdir -p $(BIN)
	GOOS=linux GOARCH=$$(go env GOARCH) CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN)/janus-bench.linux ./cmd/janus-bench
	docker run --rm -v "$(PWD)/$(BIN)/janus-bench.linux:/janus-bench:ro" debian:bookworm-slim \
		/janus-bench -events 150000 -payload 256 -sweep 16,64,256,1024

## latency: the decision-path budgets -- gated-effect p50 (25 ms) and gate
## decision p99 (50 ms). Needs postgres for the projection arm: docker compose up -d postgres
latency: build
	$(BIN)/janus-latency -policy $(POLICY) -dsn "$(PG_DSN)" \
		-samples 300 -background 0,2000 -concurrency 1,8 -sync full

# LATENCY_ARGS is what latency-linux measures. Overridable so that the Phase 6
# local gate can state its reference scale rather than inherit one, and because a
# sweep and a single point are different questions.
LATENCY_ARGS ?= -samples 300 -background 0,2000 -concurrency 1,8 -sync full

## latency-linux: the same measurement on linux against the compose postgres,
## which is the number that counts -- a darwin run measures F_FULLFSYNC, which is
## a device-wide barrier and not what a deployment pays (docs/bench/README.md)
latency-linux:
	@mkdir -p $(BIN)
	GOOS=linux GOARCH=$$(go env GOARCH) CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN)/janus-latency.linux ./cmd/janus-latency
	@docker compose up -d postgres
	@scripts/wait-for-postgres.sh
	docker run --rm \
		--network "$$(docker inspect janus-postgres -f '{{range $$k, $$v := .NetworkSettings.Networks}}{{$$k}}{{end}}')" \
		-v "$(PWD)/$(BIN)/janus-latency.linux:/janus-latency:ro" \
		-v "$(PWD)/docs/policy:/policy:ro" \
		debian:bookworm-slim \
		/janus-latency -policy /policy/reference.json \
			-dsn postgres://janus:janus@postgres:5432/janus \
			$(LATENCY_ARGS)

## replica: follow a live janus-orchd into a second directory and check the copy
## converges byte for byte. The local equivalent of a second region, and it says
## so: two processes on one host is not a region failure.
replica: build
	@./scripts/replica-drill.sh

## restore-drill: time a backup and restore, and measure the window a restore opens
## (EVENTS=... for a bigger log; the size is stamped into the JSON, because a
## restore-time number is a claim about a size and nothing else). Add the
## projection rebuild -- the rest of the RTO -- with a DSN naming its own schema:
##   psql "$(PG_DSN)" -c 'CREATE SCHEMA restore_drill'
##   PROJECTION_DSN='$(PG_DSN)?options=-c%20search_path%3Drestore_drill' make restore-drill
restore-drill: build
	@./scripts/restore-drill.sh

## failover: kill a primary, promote its replica, and measure what that cost --
## RTO, the RPO violations, and whether the promoted log still verifies from the
## original writer's key alone. The local equivalent of a region failover, and it
## says so.
failover: build
	@./scripts/failover-drill.sh

## failover-fenced: the same drill with the writer lease armed.
## Three refusals, and they are not the same refusal: a second operator promoting
## a second replica is refused while the first writer holds the lease and writes
## nothing; the old primary comes back while the promoted writer is serving and
## must REFUSE TO START, because the log has moved past its epoch; and the two
## directories must not diverge. Needs an object store:
## JANUS_S3_ENDPOINT=http://127.0.0.1:9000 after `make dev`.
failover-fenced: build
	@FENCE=1 FORK=1 ./scripts/failover-drill.sh

## failover-twice: fail the log over, then fail the promoted log over again.
## Until a writer marker told a writer's directory from a replica of
## one, this could not run at all: a promotion's tenure is replicated, so every
## replica of a failed-over log read as already promoted -- the follower could
## not restart and no replica could be promoted. The headline is that the
## twice-promoted log still verifies from the ORIGINAL writer's key alone.
failover-twice: build
	@ROUNDS=2 OUT=docs/bench/phase6-failover-twice.json ./scripts/failover-drill.sh

## evil-auditor: the standing adversarial suite, and Phase 5's
## internal gate. Each attack is performed for real; the question is
## whether the system NAMES it, from the log alone. Blocks on 100%.
evil-auditor: build
	$(BIN)/janus-evilauditor

## phase6-local: the three legs of Phase 6's exit gate, in the only form this
## repository can produce them -- and each says which of the two it is. Not the
## gate: there is no design partner and no second region.
phase6-local: build
	@./scripts/phase6-local.sh

## skeleton: run the Phase 0 walking skeleton end to end (the exit gate)
skeleton: build
	$(BIN)/janus-skeleton

## spike-mcp: prove MCP interception with real subprocesses, then verify the log
spike-mcp: build
	@./scripts/spike-mcp.sh

## soak: kill the writer repeatedly and require the chain to survive (DURATION=72h for the real gate)
## Read the history lines in the summary, not just the exit status: a run where no
## sweep completed and nothing rotated never re-read an old segment.
soak: build
	$(BIN)/janus-soak -duration $(DURATION) -sync $(SOAK_SYNC) -segment-bytes $(SOAK_SEGMENT_BYTES) \
		-sweep-period $(SOAK_SWEEP_PERIOD) -epoch-bytes $(SOAK_EPOCH_BYTES)

## spotreplay: the other half of the replay-determinism criterion — re-derive the sagas a real run
## produced and check they still come out the way the log says they did. Runs
## both chaos suites and checks every directory they leave behind.
spotreplay: build
	@./scripts/spotreplay-corpus.sh

## fuzz: the decode boundary, where untrusted bytes become structs. FUZZTIME=5m
## per target by default. A crash is written to pkg/evidence/testdata/fuzz/ and
## COMMITTING IT is the point -- from then on plain `go test` replays it forever,
## so the finding becomes a regression test rather than a memory.
FUZZTIME ?= 5m
FUZZ_TARGETS := FuzzDecodeHeaderSurvivesAnything FuzzASegmentReaderSurvivesAnything
fuzz:
	@for t in $(FUZZ_TARGETS); do \
		echo "==> $$t ($(FUZZTIME))"; \
		go test ./pkg/evidence/ -run "^$$t$$" -fuzz "^$$t$$" -fuzztime=$(FUZZTIME) -count=1 || exit 1; \
	done
	@echo "fuzz: no input found that panics or hangs a decoder"

## corpus: replay every recorded saga fixture (replay determinism)
corpus:
	go test ./pkg/saga/ -run 'TestReplayCorpus|TestCorpus|TestPrefixes' -count=1 -v

## corpus-update: regenerate the fixtures after a deliberate semantic change
corpus-update:
	JANUS_UPDATE_FIXTURES=1 go test ./pkg/saga/ -run TestGenerateFixtures -count=1 -v
	@echo
	@echo "Review the diff: it shows exactly what the change did to recorded history."

## sagachaos: kill a coordinator at every saga state and require recovery to reach
## the same outcome (Phase 2 exit gate)
sagachaos: build
	$(BIN)/janus-sagachaos

## sagachaos-hosted: the same suite driven through janus-orchd over gRPC, with
## the daemon killed along with its client. Covers the scenarios whose only
## outside party is a participant; it prints which ones it skipped and why.
## An addition to `sagachaos`, not a replacement.
sagachaos-hosted: build
	$(BIN)/janus-sagachaos -hosted

## sagachaos-projection: the hosted suite with every frontier gate answered from
## the projection instead of by replaying the log.
## Needs the dev postgres: `make dev` first.
sagachaos-projection: build
	$(BIN)/janus-sagachaos -hosted \
		-projection "postgres://janus:janus@127.0.0.1:5432/janus"

## mcpd: front a tool server, routing effectful calls through janus-orchd
## (ORCHD=addr, TOOL=participant id, then the server command after --)
## Without ORCHD it records and classifies but forwards everything.
mcpd: build
	$(BIN)/janus-mcpd -evidence $(EVIDENCE)-mcp -orchd $(ORCHD) -participant $(TOOL) $(ARGS)

## revalidation: check the periodic-review cadence a deployment would run under
revalidation: build
	$(BIN)/janus-orchd -h 2>&1 | grep -A1 revalidation || true
	@python3 -c "import json,sys; d=json.load(open('$(CADENCE)')); print('cadence from $(CADENCE):'); [print('  tier %s: %s days' % (k,v)) for k,v in sorted(d['by_tier'].items())]"

## compliance: which regulatory articles this deployment can satisfy
## (EVIDENCE=dir, POLICY=file)
compliance: build
	$(BIN)/janus-compliance lint -evidence $(EVIDENCE) -policy $(POLICY)

## loan-desk-agentic: loan-desk with a real model (ollama), governed and plain on
## the same model outputs, then verify, gate audit and spot-replay. The paper's
## one real-model measurement. JANUS_AGENTIC_LIMIT=N runs the first N only.
loan-desk-agentic:
	./scripts/loan-desk-agentic.sh

## loan-desk: the Phase 4 exit gate — the reference app on LangGraph and on raw
## MCP, with the integration cost measured and conformance run for each
loan-desk:
	@./scripts/loan-desk.sh

## sdk-e2e: run the Python SDK against a real janus-orchd, end to end
## Needs docker and the Go toolchain, which is why it is not a `make ci` job.
sdk-e2e:
	@./scripts/sdk-e2e.sh

## a2ad: serve the A2A discovery surface for a participant, and optionally
## forward messages to a counterpart
## (PARTICIPANT=id, REGISTRY=evidence dir, and UPSTREAM/COUNTERPART to forward)
a2ad: build
	$(BIN)/janus-a2ad -registry $(EVIDENCE) -participant $(PARTICIPANT) $(ARGS)

## orchd: run the orchestrator daemon over an evidence directory (EVIDENCE=path)
## One per directory: the second one to start is refused by name.
orchd: build
	$(BIN)/janus-orchd -dir $(EVIDENCE)

## policy: validate the reference gate policy and print its content address
policy: build
	$(BIN)/janus-gate check docs/policy/reference.json

## registry: the registry round-trip (Phase 3 exit gate) — register, evaluate,
## activate, pin by a real tool call, change, revalidate, audit
registry: build
	@./scripts/registry-roundtrip.sh

## console: serve the operator view over an evidence directory (EVIDENCE=path)
## Read-only by default: it will not record an approval it cannot attribute.
## Beside a running daemon, add -orchd <addr> so approvals go through it rather
## than failing on the writer lock.
console: build
	$(BIN)/janus-console -evidence $(EVIDENCE) -addr $(CONSOLE_ADDR)

## property: run the seeded crash-recovery property tests (JANUS_SEED=... to reproduce)
property:
	go test ./pkg/evidence/ -run TestProperty -count=1 -v

## dev: start the local stack (postgres, minio with an object-lock bucket)
dev:
	docker compose up -d
	@echo "postgres  localhost:5432  (janus/janus/janus)"
	@echo "minio     localhost:9000  console localhost:9001  (janus/januspassword)"
	@echo
	@echo "to exercise the object-storage and WORM tests:"
	@echo "  export JANUS_S3_ENDPOINT=http://127.0.0.1:9000"
	@echo "  go test ./pkg/evidence/..."

## test-storage: run the object-storage and WORM tests against the local stack
test-storage:
	JANUS_S3_ENDPOINT=$(JANUS_S3_ENDPOINT) JANUS_S3_REQUIRED=1 \
		go test ./pkg/evidence/worm/ ./pkg/evidence/cas/ ./pkg/evidence/objstore/... -count=1 -v

## dev-down: stop the local stack and remove its volumes
dev-down:
	docker compose down -v

## clean: remove build output
clean:
	rm -rf $(BIN)

.PHONY: fuzz help build evil-auditor replica failover failover-fenced failover-twice phase6-local restore-drill revalidation latency latency-linux spotreplay test test-short test-storage lint gen bench bench-linux skeleton spike-mcp soak sagachaos sagachaos-hosted sagachaos-projection orchd mcpd a2ad compliance loan-desk loan-desk-agentic sdk-e2e registry console property corpus corpus-update ci ci-all ci-quick repro release-verifier dev dev-down clean
