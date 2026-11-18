# debug build dir, overridable if needed
PROFILE_DIR ?= target/debug

STATICLIB   := $(PROFILE_DIR)/libaws_esdk_cpp.a
UNAME_S     := $(shell uname -s)

PLATFORM_LIBS =
ifeq ($(UNAME_S),Darwin)
PLATFORM_LIBS += -framework Security -framework CoreFoundation -framework SystemConfiguration
endif

LINK_LIBS = $(STATICLIB) -lpthread -ldl $(PLATFORM_LIBS)

CXXFLAGS_COMMON = -Iinclude -std=c++17
COV_CXXFLAGS ?=

example: examples/basic_hierarchical_keyring_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) examples/basic_hierarchical_keyring_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o basic_hierarchical_keyring_example

raw_aes_example: examples/raw_aes_keyring_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) examples/raw_aes_keyring_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o raw_aes_keyring_example

handling_errors_example: examples/handling_errors_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ examples/handling_errors_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o handling_errors_example

per_request_credentials_example: examples/per_request_credentials_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ examples/per_request_credentials_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o per_request_credentials_example

zero_copy_example: examples/zero_copy_comparison.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) examples/zero_copy_comparison.cpp \
		$(CXXFLAGS_COMMON) -O2 $(LINK_LIBS) \
		-o zero_copy_comparison

shared_cache_example: examples/shared_cache_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) examples/shared_cache_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o shared_cache_example

set_algorithm_suite_example: examples/set_algorithm_suite_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ examples/set_algorithm_suite_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o set_algorithm_suite_example

set_commitment_policy_example: examples/set_commitment_policy_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ examples/set_commitment_policy_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o set_commitment_policy_example

test_esdk: tests/test_esdk.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) tests/test_esdk.cpp \
		$(CXXFLAGS_COMMON) $(COV_CXXFLAGS) $(LINK_LIBS) \
		-o test_esdk

adopt_keyring_test: tests/adopt_keyring_test.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) tests/adopt_keyring_test.cpp \
		-Itarget/cxxbridge $(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o adopt_keyring_test

custom_keyring_example: examples/custom-keyring/src/lib.rs examples/custom-keyring/example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs
	cd examples/custom-keyring && cargo build
	$(CXX) examples/custom-keyring/example.cpp \
		-Iinclude \
		examples/custom-keyring/target/debug/libcustom_keyring_example.a \
		-lpthread -ldl $(PLATFORM_LIBS) \
		-std=c++17 \
		-o custom_keyring_example

streaming_example: examples/streaming_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) examples/streaming_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o streaming_example

streaming_chunks_example: examples/streaming_chunks_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) examples/streaming_chunks_example.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o streaming_chunks_example

adopt_keyring_test: tests/adopt_keyring_test.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) tests/adopt_keyring_test.cpp \
		-Itarget/cxxbridge $(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o adopt_keyring_test

test_concurrency: tests/test_concurrency.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) tests/test_concurrency.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o test_concurrency

test_fork: tests/test_fork.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) tests/test_fork.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o test_fork

test_resource_leaks: tests/test_resource_leaks.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) tests/test_resource_leaks.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o test_resource_leaks

# This test runs during compilation (static asserts)
enum_parity: enum_parity_test.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	$(CXX) -c enum_parity_test.cpp \
		-Itarget/cxxbridge -Iinclude \
		-std=c++17 \
		-o enum_parity_test.o

clean:
	rm -f test_esdk adopt_keyring_test custom_keyring_example set_algorithm_suite_example set_commitment_policy_example enum_parity_test.o

clippy:
	cargo clippy --tests

# Build the Rust static library, examples, the compile-time enum_parity check,
# and the test binaries.
build-tests:
	cargo build
	$(MAKE) example raw_aes_example handling_errors_example per_request_credentials_example zero_copy_example shared_cache_example set_algorithm_suite_example set_commitment_policy_example custom_keyring_example streaming_example streaming_chunks_example enum_parity test_esdk adopt_keyring_test test_concurrency test_fork test_resource_leaks

# Set LOCAL_ONLY=--local-only to skip integration tests that needs creds.
# When it is empty, a missing ESDK_TEST_* credential is a hard failure.
# (Empty by default, so default to requiring creds.)
LOCAL_ONLY ?=
# Set NON_LINUX=--non-linux if on a non-linux machine.
# When it is empty, this runs a memory leak test that is only on Linux right now.
# (Empty by default, so default to running this test.)
NON_LINUX ?=

# Run the C++ integ tests and examples
run-cpp:
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./raw_aes_keyring_example
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./set_algorithm_suite_example
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./set_commitment_policy_example
	./custom_keyring_example
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./streaming_example
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./streaming_chunks_example
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./test_esdk $(LOCAL_ONLY)
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./adopt_keyring_test
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./test_concurrency $(LOCAL_ONLY)
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./test_fork
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./test_resource_leaks $(LOCAL_ONLY) $(NON_LINUX)

# Full local suite without credentials
test: build-tests
	cargo test
	$(MAKE) run-cpp LOCAL_ONLY=--local-only

# Run all Rust tests
test-ci-rust:
	cargo test

# Run all C++ tests
test-ci-cpp: build-tests
	$(MAKE) run-cpp

duvet:
	../../../scripts/resolve-spec.sh
	rm -rf .duvet/reports .duvet/requirements
	duvet report

# Line coverage targets.
# Prereqs: cargo install cargo-llvm-cov && rustup component add llvm-tools-preview

# Rust coverage.
# (All Rust tests are offline unit tests, so this doesn't need creds.)
coverage:
	cargo llvm-cov --lib

# Union of coverage from Rust tests and C++ unit/integ tests.
# Requires creds. COV_CPP_REPORT picks the report format (see coverage-cpp-html).
COV_CPP_REPORT ?= report
coverage-cpp:
	cargo llvm-cov clean --workspace
	eval "$$(cargo llvm-cov show-env --export-prefix)" && \
	cargo build && \
	cargo test --lib && \
	PROFILE_DIR="$${CARGO_TARGET_DIR:-target}/debug" && \
	rm -f test_esdk && \
	$(MAKE) test_esdk PROFILE_DIR="$$PROFILE_DIR" COV_CXXFLAGS="-fprofile-instr-generate -fcoverage-mapping" && \
	LD_LIBRARY_PATH="$(CURDIR)/$$PROFILE_DIR" ./test_esdk $(LOCAL_ONLY) && \
	cargo llvm-cov $(COV_CPP_REPORT)

# Same as coverage-cpp, emitting a browsable HTML report under target/llvm-cov/html.
coverage-cpp-html:
	$(MAKE) coverage-cpp COV_CPP_REPORT="report --html"

.PHONY: all clean clippy duvet build-tests run-cpp test test-ci-rust test-ci-cpp coverage coverage-html coverage-cpp coverage-cpp-html
