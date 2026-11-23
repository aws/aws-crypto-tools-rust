# Verus verification targets for the AWS ESDK Rust proofs.
# Requires Verus installed at ~/verus/verus (see the `verus` skill / README).

VERUS ?= $(HOME)/verus/verus

# All standalone proof files in this directory.
PROOFS := body_aad_proofs.rs edk_count_proofs.rs zeroize_proofs.rs frame_layout_proofs.rs header_parse_proofs.rs frame_sequence_proofs.rs io_stream_model.rs io_stream_aligned.rs header_auth_ordering_proofs.rs commitment_ordering_proofs.rs aes_gcm_bounds_proofs.rs

.PHONY: verify
verify: $(PROOFS)
	@for f in $(PROOFS); do \
		echo "== Verifying $$f =="; \
		$(VERUS) $$f || exit 1; \
	done

.PHONY: version
version:
	@$(VERUS) --version
