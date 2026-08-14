# Every C++ binary links the Rust STATIC library by path. Linking with
# -laws_esdk_cpp would pick the cdylib (also built), whose Rust export list
# hides the compiled facade's Aws::Esdk symbols, failing the link. The
# generated bridge C++ (lib.rs.cc) and the facade (EncryptionSDK.cpp) are
# already compiled into the staticlib by build.rs, so binaries need only their
# own source plus the archives.

# The debug build dir. Overridable so the coverage build can point the C++
# binaries at whatever dir cargo-llvm-cov's show-env put the instrumented
# staticlib in (CARGO_TARGET_DIR/debug; the coverage instrumentation rides in
# via RUSTFLAGS, so the archive at that path is the instrumented one).
PROFILE_DIR ?= target/debug

STATICLIB   := $(PROFILE_DIR)/libaws_esdk_cpp.a
CXXBRIDGE_RT = $$(find $(PROFILE_DIR)/build -path "*/cxx-*/out/libcxxbridge1.a" | head -n1)
UNAME_S     := $(shell uname -s)

PLATFORM_LIBS =
ifeq ($(UNAME_S),Darwin)
PLATFORM_LIBS += -framework Security -framework CoreFoundation -framework SystemConfiguration
endif

LINK_LIBS = $(STATICLIB) $(CXXBRIDGE_RT) -lpthread -ldl $(PLATFORM_LIBS)

CXXFLAGS_COMMON = -Iinclude -std=c++17

example: examples/basic_hierarchical_keyring_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ examples/basic_hierarchical_keyring_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o basic_hierarchical_keyring_example

raw_aes_example: examples/raw_aes_keyring_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ examples/raw_aes_keyring_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o raw_aes_keyring_example

zero_copy_example: examples/zero_copy_comparison.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ examples/zero_copy_comparison.cpp \
		$(CXXFLAGS_COMMON) -O2 $(LINK_LIBS) \
		-o zero_copy_comparison

shared_cache_example: examples/shared_cache_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ examples/shared_cache_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o shared_cache_example

# COV_CXXFLAGS is empty for normal builds. The coverage-cpp target sets it to
# the clang coverage flags so the C++ link pulls in the LLVM profile runtime
# that the instrumented Rust staticlib references (cargo adds this runtime for
# its own binaries; a standalone g++ link does not).
COV_CXXFLAGS ?=

test_esdk: tests/test_esdk.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ tests/test_esdk.cpp \
		$(CXXFLAGS_COMMON) $(COV_CXXFLAGS) $(LINK_LIBS) \
		-o test_esdk

# The consumer's Rust crate builds a self-contained staticlib (its keyring plus
# this crate as an rlib); the C++ example links that single archive.
custom_keyring_example: examples/custom-keyring/src/lib.rs examples/custom-keyring/example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs
	cd examples/custom-keyring && cargo build
	g++ examples/custom-keyring/example.cpp \
		-Iinclude \
		examples/custom-keyring/target/debug/libcustom_keyring_example.a \
		-lpthread -ldl $(PLATFORM_LIBS) \
		-std=c++17 \
		-o custom_keyring_example

streaming_example: examples/streaming_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ examples/streaming_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o streaming_example

# White-box like enum_parity: includes the bridge header to play the
# consumer's Rust side, which manufactures the keyring handle C++ adopts.
adopt_keyring_test: tests/adopt_keyring_test.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ tests/adopt_keyring_test.cpp \
		-Itarget/cxxbridge $(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o adopt_keyring_test

test_concurrency: tests/test_concurrency.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ tests/test_concurrency.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o test_concurrency

test_resource_leaks: tests/test_resource_leaks.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ tests/test_resource_leaks.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o test_resource_leaks

# Compile-only: the static_asserts fire during compilation, so no link step.
enum_parity: enum_parity_test.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ -c enum_parity_test.cpp \
		-Itarget/cxxbridge -Iinclude \
		-std=c++17 \
		-o enum_parity_test.o

clean:
	rm -f basic_hierarchical_keyring_example raw_aes_keyring_example zero_copy_comparison shared_cache_example custom_keyring_example streaming_example test_esdk adopt_keyring_test test_concurrency test_resource_leaks enum_parity_test.o

clippy:
	cargo clippy --tests --examples

# Build the Rust static library, the C++ examples, the compile-time parity check,
# and the test binaries.
build-tests:
	cargo build
	$(MAKE) example raw_aes_example zero_copy_example shared_cache_example custom_keyring_example streaming_example enum_parity test_esdk adopt_keyring_test test_concurrency test_resource_leaks

# Run the C++ integration + local-correctness binaries.
# LOCAL_ONLY=--local-only skips the credentialed integration tests; when it is
# empty (the default), a missing ESDK_TEST_* credential is a hard failure
# (see integration_config_or_gate in tests/esdk_test_support.h).
LOCAL_ONLY ?=

run-cpp:
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./raw_aes_keyring_example
	./custom_keyring_example
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./streaming_example
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./test_esdk $(LOCAL_ONLY)
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./adopt_keyring_test
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./test_concurrency $(LOCAL_ONLY)
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./test_resource_leaks $(LOCAL_ONLY)

# Full local suite without credentials (all Rust tests are offline).
test: build-tests
	cargo test
	$(MAKE) run-cpp LOCAL_ONLY=--local-only

# CI runs the full suite. Split Rust/C++ because the workflow runs the C++
# half on Linux only.
test-ci-rust:
	cargo test

test-ci-cpp: build-tests
	$(MAKE) run-cpp

duvet:
	rm -rf .duvet/reports .duvet/requirements
	duvet report

# Line coverage for the Rust bridge from the offline unit tests.
# Prereqs: cargo install cargo-llvm-cov && rustup component add llvm-tools-preview
# This covers the translation/logic surface (conversions, raw-AES keyring,
# streaming, null-handle checks, error encoding, client construction). The
# KMS/DynamoDB network paths and resource-creation success paths are NOT
# exercised here; they are covered by the C++ integration suite (test-ci-cpp
# with ESDK_TEST_* set). So <100% from this target is expected, not a gap.
coverage:
	cargo llvm-cov --lib

# Same, emitting a browsable HTML report under target/llvm-cov/html.
coverage-html:
	cargo llvm-cov --lib --html

# Union coverage of lib.rs from BOTH the Rust unit tests and the C++ test_esdk
# binary. This is the only way the credentialed KMS/DynamoDB and
# resource-creation lines show up in a coverage number: the instrumentation is
# baked into the Rust staticlib, and running the C++ binary that links it emits
# the same .profraw the Rust tests do, so `report` unions them.
#
# Requires ESDK_TEST_* credentials (test_esdk runs its integration section with
# no --local-only, so a missing credential is a hard failure by design).
# Prereqs: cargo install cargo-llvm-cov && rustup component add llvm-tools-preview
#
# Sequencing notes:
#  - clean runs BEFORE show-env: once show-env sets RUSTC_WRAPPER=cargo-llvm-cov,
#    any further `cargo llvm-cov ...` subcommand nests the wrapper and fork-bombs.
#    So after show-env only plain `cargo build`/`cargo test` are used; the whole
#    chain (build, test, C++ run, report) shares one shell so it inherits the
#    show-env RUSTFLAGS, LLVM_PROFILE_FILE, and profraw dir.
#  - The C++ test_esdk is force-relinked (rm -f) with -fprofile-instr-generate
#    -fcoverage-mapping so the link pulls in the LLVM profile runtime the
#    instrumented staticlib references (cargo adds it for its own binaries; a
#    standalone g++ link does not). Running it emits profraw into the same dir,
#    so `report` unions the Rust-unit and C++-integration coverage.
coverage-cpp:
	cargo llvm-cov clean --workspace
	eval "$$(cargo llvm-cov show-env --export-prefix)" && \
	cargo build && \
	cargo test --lib && \
	PROFILE_DIR="$${CARGO_TARGET_DIR:-target}/debug" && \
	rm -f test_esdk && \
	$(MAKE) test_esdk PROFILE_DIR="$$PROFILE_DIR" COV_CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping" && \
	LD_LIBRARY_PATH="$(CURDIR)/$$PROFILE_DIR" ./test_esdk $(LOCAL_ONLY) && \
	cargo llvm-cov report

.PHONY: all clean clippy duvet build-tests run-cpp test test-ci-rust test-ci-cpp coverage coverage-html coverage-cpp
