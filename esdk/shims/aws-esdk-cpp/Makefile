# debug build dir, overridable if needed
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
COV_CXXFLAGS ?=

test_esdk: tests/test_esdk.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ tests/test_esdk.cpp \
		$(CXXFLAGS_COMMON) $(COV_CXXFLAGS) $(LINK_LIBS) \
		-o test_esdk

adopt_keyring_test: tests/adopt_keyring_test.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ tests/adopt_keyring_test.cpp \
		-Itarget/cxxbridge $(CXXFLAGS_COMMON) $(LINK_LIBS) \
		-o adopt_keyring_test

custom_keyring_example: examples/custom-keyring/src/lib.rs examples/custom-keyring/example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs
	cd examples/custom-keyring && cargo build
	g++ examples/custom-keyring/example.cpp \
		-Iinclude \
		examples/custom-keyring/target/debug/libcustom_keyring_example.a \
		-lpthread -ldl $(PLATFORM_LIBS) \
		-std=c++17 \
		-o custom_keyring_example

# This test runs during compilation (static asserts)
enum_parity: enum_parity_test.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ -c enum_parity_test.cpp \
		-Itarget/cxxbridge -Iinclude \
		-std=c++17 \
		-o enum_parity_test.o

clean:
	rm -f test_esdk adopt_keyring_test custom_keyring_example enum_parity_test.o

clippy:
	cargo clippy --tests

# Build the Rust static library, the compile-time parity check, the test binary,
# the custom-keyring adoption test, and the custom-keyring example.
build-tests:
	cargo build
	$(MAKE) enum_parity test_esdk custom_keyring_example adopt_keyring_test

# Run C++ tests. LOCAL_ONLY=--local-only skips the credentialed integration
# tests; empty (the default) makes a missing ESDK_TEST_* credential a hard
# failure (see integration_config_or_gate in tests/esdk_test_support.h).
LOCAL_ONLY ?=
run-cpp:
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./test_esdk $(LOCAL_ONLY)
	./custom_keyring_example
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./adopt_keyring_test

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
	rm -rf .duvet/reports .duvet/requirements
	duvet report

# Line coverage for Rust from the offline unit tests.
# Prereqs: cargo install cargo-llvm-cov && rustup component add llvm-tools-preview
coverage:
	cargo llvm-cov --lib

# Same as above, emitting a browsable HTML report under target/llvm-cov/html.
coverage-html:
	cargo llvm-cov --lib --html

.PHONY: all clean clippy duvet build-tests run-cpp test test-ci-rust test-ci-cpp coverage coverage-html
