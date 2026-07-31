# Simple Makefile - all C++ bridge code is compiled into the Rust static library.

clean:
	rm -f *.o

clippy:
	cargo clippy --tests --examples

test:
	cargo build
	cargo build --release

.PHONY: clean test clippy
