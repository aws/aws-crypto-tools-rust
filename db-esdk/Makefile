.PHONY: clippy test examples duvet

# Fetches the spec pinned in scripts/spec-source.json, then rebuilds the requirements and report from scratch.
duvet:
	scripts/resolve-spec.sh
	rm -rf .duvet/reports .duvet/requirements
	duvet report

# The tests use the tokio-based caches, so every test run has `rt-tokio`.

clippy:
	cargo clippy --tests --examples
	cargo clippy --no-default-features --features aws-lc-sys
	cargo clippy --tests --no-default-features --features aws-lc-sys,rt-tokio

test:
	cargo test
	cargo test --no-default-features --features aws-lc-sys,rt-tokio
	cargo test --no-default-features --features aws-lc-sys,kms,rt-tokio

# `make examples LOCAL_ONLY=--local-only` skips the examples that need AWS credentials.
LOCAL_ONLY ?=
# Cargo discovers examples at examples/NAME.rs and examples/NAME/main.rs; match both.
EXAMPLES := $(basename $(notdir $(wildcard examples/*.rs))) \
            $(notdir $(patsubst %/main.rs,%,$(wildcard examples/*/main.rs)))
LOCAL_EXAMPLES := custom_keyring item_encryptor set_algorithm_suite
ifeq ($(LOCAL_ONLY),)
# get_encrypted_data_key_description reads the item that hierarchical_keyring writes, so hierarchical_keyring runs first.
RUN_EXAMPLES := hierarchical_keyring $(filter-out hierarchical_keyring,$(EXAMPLES))
else
RUN_EXAMPLES := $(LOCAL_EXAMPLES)
endif

examples:
	@for ex in $(RUN_EXAMPLES); do \
		echo "=== cargo run --example $$ex ==="; \
		cargo run --example $$ex || exit 1; \
	done
