# Target vocabulary (build-server / start-server / wait-for-server / stop-server)
# matches the commons TestServer orchestration.

SHELL := bash

# Port for the server (override: make run-server PORT=9090).
PORT ?= 8094

BIN      := target/release/primitives-test-server
PID_FILE := .server.pid
LOG_FILE := .server.log

.PHONY: help build-server run-server start-server wait-for-server stop-server \
        test fmt clippy check clean

help: ## Show this help
	@echo "Primitives TestServer (Rust) — make targets"
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
		echo "started primitives-test-server (pid $$(cat $(PID_FILE))) on port $(PORT)"

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

fmt: ## Check formatting
	cargo fmt --all -- --check

clippy: ## Lint with warnings denied
	cargo clippy --all-targets -- -D warnings

check: fmt clippy build-server test ## fmt + clippy + build + test (the CI gate)

clean: ## Remove build output and server scratch files
	cargo clean; rm -f "$(PID_FILE)" "$(LOG_FILE)"
