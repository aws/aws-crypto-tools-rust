clean:
	rm -f *.o

clippy:
	cargo clippy --tests --examples

test:
	cargo build
	cargo build --release

.PHONY: clean test clippy
