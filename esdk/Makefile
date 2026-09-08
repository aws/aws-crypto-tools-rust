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

# Build and run the offline examples (no AWS credentials required).
# The hierarchical_keyring example needs KMS and DynamoDB and is excluded here.
examples:
	cargo run --example raw_aes_keyring
	cargo run --example streaming
	cargo run --example custom_keyring
	cargo run --example required_encryption_context

duvet:
	@test -e spec || ln -s ../spec spec
	rm -rf .duvet/reports .duvet/requirements
	duvet report
