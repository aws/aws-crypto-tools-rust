.PHONY: clippy test examples duvet

clippy:
	cargo clippy --tests
	cargo clippy --tests --no-default-features
	cargo clippy --tests --no-default-features --features kms
	cargo clippy --tests --no-default-features --features ddb
	cargo clippy --tests --no-default-features --features legacy

test:
	cargo test
	cargo test --no-default-features
	cargo test --no-default-features --features kms
	cargo test --no-default-features --features ddb
	cargo test --no-default-features --features legacy

# Set LOCAL_ONLY=--local-only to skip the examples that need AWS credentials.
# Empty by default, so `make examples` runs the full example suite, including
# the hierarchical_keyring example (needs KMS and DynamoDB).
LOCAL_ONLY ?=

examples:
	cargo run --example raw_aes_keyring
	cargo run --example streaming
	cargo run --example custom_keyring
	cargo run --example required_encryption_context
ifeq ($(LOCAL_ONLY),)
	cargo run --example hierarchical_keyring
endif

duvet:
	@test -e spec || ln -s ../spec spec
	rm -rf .duvet/reports .duvet/requirements
	duvet report
