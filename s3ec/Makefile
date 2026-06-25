# Duvet + test harness for the s3ec Rust implementation.
# Run from the s3ec/ directory. The duvet config lives in s3ec/.duvet/config.toml
# and the s3-encryption spec lives at ../spec/s3-encryption/.

SPEC := ../spec/s3-encryption

SPEC_FILES := \
	$(SPEC)/client.md \
	$(SPEC)/encryption.md \
	$(SPEC)/decryption.md \
	$(SPEC)/key-commitment.md \
	$(SPEC)/key-derivation.md \
	$(SPEC)/data-format/content-metadata.md \
	$(SPEC)/data-format/metadata-strategy.md \
	$(SPEC)/materials/keyrings.md \
	$(SPEC)/materials/s3-keyring.md \
	$(SPEC)/materials/s3-kms-keyring.md

.PHONY: duvet duvet_extract duvet_report validate-all-tests agent-validate

# Extract requirements from the markdown specs into compliance/ TOMLs.
duvet_extract:
	rm -rf compliance
	@for f in $(SPEC_FILES); do \
		duvet extract -f markdown -o compliance "$$f"; \
	done

# Generate the duvet coverage report + snapshot.
duvet_report:
	duvet report

# Default duvet target: regenerate the report/snapshot from current annotations.
duvet: duvet_report

# Run the s3ec test suite.
validate-all-tests:
	cargo test

# Lightweight validation used by agents: compile + duvet report.
agent-validate:
	cargo check
	duvet report
