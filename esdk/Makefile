.PHONY: clippy test examples duvet

clippy:
	cargo clippy --tests
	cargo clippy --tests --no-default-features
	cargo clippy --tests --no-default-features --features kms
	cargo clippy --tests --no-default-features --features ddb

test:
	cargo test
	cargo test --no-default-features
	cargo test --no-default-features --features kms
	cargo test --no-default-features --features ddb

# `make examples LOCAL_ONLY=--local-only` skips the examples that need AWS credentials.
LOCAL_ONLY ?=
# Cargo discovers examples at examples/NAME.rs and examples/NAME/main.rs; match both.
EXAMPLES := $(basename $(notdir $(wildcard examples/*.rs))) \
            $(notdir $(patsubst %/main.rs,%,$(wildcard examples/*/main.rs)))
CREDS_EXAMPLES := branch_key_supplier handling_errors hierarchical_keyring per_request_credentials rotate_branch_key shared_storm_tracking_cache
ifeq ($(LOCAL_ONLY),)
RUN_EXAMPLES := $(EXAMPLES)
else
RUN_EXAMPLES := $(filter-out $(CREDS_EXAMPLES),$(EXAMPLES))
endif

examples:
	@for ex in $(RUN_EXAMPLES); do \
		echo "=== cargo run --example $$ex ==="; \
		cargo run --example $$ex || exit 1; \
	done

duvet:
	../scripts/resolve-spec.sh
	@test -e spec || ln -s ../spec spec
	rm -rf .duvet/reports .duvet/requirements
	duvet report
