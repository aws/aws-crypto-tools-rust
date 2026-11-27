SHELL := bash

PORT ?= 8093

BIN      := target/release/mpl-test-server
PID_FILE := .server.pid
LOG_FILE := .server.log

# `make test-server-duvet` clones commons from server-config.json; COMMONS_BRANCH=<b> picks another branch.
MAKEFILE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPO_ROOT    := $(abspath $(MAKEFILE_DIR)/../..)
COMMONS_CONFIGURATION := $(MAKEFILE_DIR)/server-config.json
COMMONS_BRANCH ?=
CLONE_DIR      ?= $(MAKEFILE_DIR)/.commons-clone

.PHONY: help build-server run-server start-server wait-for-server stop-server \
        test test-server-duvet fmt clippy check clean

help: ## Show this help
	@echo "MPL TestServer (Rust) — make targets"
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' "$(lastword $(MAKEFILE_LIST))" \
		| sort | awk 'BEGIN{FS=":.*## "}{printf "  %-18s %s\n", $$1, $$2}'
	@echo ""
	@echo "  PORT=$(PORT)"

build-server: ## Build the server (release)
	cargo build --release

run-server: build-server ## Run the server in the FOREGROUND on PORT (Ctrl-C to stop)
	$(BIN) $(PORT)

start-server: build-server ## Start the server in the BACKGROUND on PORT (writes .server.pid)
	@$(BIN) $(PORT) >"$(LOG_FILE)" 2>&1 & echo $$! >"$(PID_FILE)"; \
		echo "started mpl-test-server (pid $$(cat $(PID_FILE))) on port $(PORT)"

wait-for-server: ## Block until the server accepts connections on PORT (120s timeout)
	@for i in $$(seq 1 120); do \
		if nc -z 127.0.0.1 "$(PORT)" 2>/dev/null; then echo "server ready on $(PORT)"; exit 0; fi; \
		sleep 1; \
	done; \
	echo "timed out waiting for port $(PORT)"; [ -f "$(LOG_FILE)" ] && tail -n 40 "$(LOG_FILE)"; exit 1

stop-server: ## Stop the background server and free PORT
	@if [ -f "$(PID_FILE)" ]; then kill "$$(cat $(PID_FILE))" 2>/dev/null || true; rm -f "$(PID_FILE)"; fi; \
		pids=$$(lsof -ti tcp:$(PORT) 2>/dev/null || true); \
		if [ -n "$$pids" ]; then kill $$pids 2>/dev/null || true; fi; \
		echo "stopped server on port $(PORT)"

test: ## Run the server's tests
	cargo test

# The local version of CI's mpl-test-server-duvet job.
# It dry-runs the commons Tests for Rust, which starts no servers.
# Then it writes the duvet test annotations of the Tests that ran into ../build/test-server-duvet/,
# where ../.duvet/config.toml reads them.
# Needs a JDK 21+ and network access to clone commons, but no AWS credentials.
DUVET_OUT := $(abspath $(MAKEFILE_DIR)/../build/test-server-duvet)
test-server-duvet: ## Write the shared Tests' duvet annotations that run for Rust; COMMONS_BRANCH=<b> overrides
	@set -eo pipefail; \
	{ read -r url; read -r branch; } <<< "$$(python3 -c 'import json,sys; c=json.load(open(sys.argv[1]))["commonsRepository"]; print(c["url"]); print(c["branch"])' "$(COMMONS_CONFIGURATION)")"; \
	if [ -n "$(strip $(COMMONS_BRANCH))" ]; then branch="$(strip $(COMMONS_BRANCH))"; fi; \
	echo "==> Cloning commons at '$$branch' into $(CLONE_DIR)"; \
	rm -rf "$(CLONE_DIR)"; \
	git clone --quiet --depth 1 --single-branch --branch "$$branch" "$$url" "$(CLONE_DIR)"; \
	"$(REPO_ROOT)/scripts/resolve-spec.sh"; \
	$(MAKE) -C "$(CLONE_DIR)/mpl/test-server" orchestrate \
		ORCHESTRATE_ARGS="workingTreeOverlay.aws-crypto-tools-rust=$(REPO_ROOT) workingTreeLanguages=rust languages=rust dryRun=true"; \
	python3 "$(CLONE_DIR)/test-server-common/tools/duvet_test_annotations.py" \
		--gate-log "$(CLONE_DIR)/mpl/test-server/tests/build/test-results/feature-gate-log.jsonl" \
		--tests-dir "$(CLONE_DIR)/mpl/test-server/tests/src/test/java" \
		--bug-config "$(MAKEFILE_DIR)/bug-config.json" \
		--spec-root "$(REPO_ROOT)" \
		--out "$(DUVET_OUT)/mpl.java"

fmt: ## Check formatting
	cargo fmt --all -- --check

clippy: ## Lint with warnings denied
	cargo clippy --all-targets -- -D warnings

check: fmt clippy build-server test ## fmt + clippy + build + test (the CI gate)

clean: ## Remove build output and server scratch files
	cargo clean; rm -f "$(PID_FILE)" "$(LOG_FILE)"
