.PHONY: build test clippy fmt fmt-check clean run help

build:
	cargo build

test:
	cargo test

clippy:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clean:
	cargo clean

# Convenience targets to exercise the CLI. Requires MANIFEST_DIR / OUTPUT_DIR.
# Example:
#   make generate PROJECT=mpl OUTPUT_DIR=./out
generate:
	cargo run --bin test-vectors -- encrypt-manifest --project $(PROJECT) --output $(OUTPUT_DIR)

encrypt:
	cargo run --bin test-vectors -- encrypt --project $(PROJECT) --manifest-path $(MANIFEST_DIR) --decrypt-manifest-output $(OUTPUT_DIR)

decrypt:
	cargo run --bin test-vectors -- decrypt --project $(PROJECT) --manifest-path $(MANIFEST_DIR)

list:
	cargo run --bin test-vectors -- list

help:
	cargo run --bin test-vectors -- --help
