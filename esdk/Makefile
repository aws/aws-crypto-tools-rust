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

# Run `make examples LOCAL_ONLY=--local-only` to skip examples that need AWS credentials.
# Otherwise `make examples` runs all examples by default.
LOCAL_ONLY ?=
# Cargo will only register examples in 2 cases:
# - examples/*.rs
# - examples/NAME/main.rs
# Examples cannot be declared elsewhere.
EXAMPLES := $(basename $(notdir $(wildcard examples/*.rs))) \
            $(notdir $(patsubst %/main.rs,%,$(wildcard examples/*/main.rs)))
CREDS_EXAMPLES := handling_errors hierarchical_keyring shared_storm_tracking_cache
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
	@test -e spec || ln -s ../spec spec
	rm -rf .duvet/reports .duvet/requirements
	duvet report
