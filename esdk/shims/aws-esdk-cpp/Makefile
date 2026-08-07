# Every C++ binary links the Rust STATIC library by path. Linking with
# -laws_esdk_cpp would pick the cdylib (also built), whose Rust export list
# hides the compiled facade's Aws::Esdk symbols, failing the link. The
# generated bridge C++ (lib.rs.cc) and the facade (EncryptionSDK.cpp) are
# already compiled into the staticlib by build.rs, so binaries need only their
# own source plus the archives.

STATICLIB   := target/debug/libaws_esdk_cpp.a
CXXBRIDGE_RT = $$(find target/debug/build -path "*/cxx-*/out/libcxxbridge1.a" | head -n1)
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

test_esdk: tests/test_esdk.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ tests/test_esdk.cpp \
		$(CXXFLAGS_COMMON) $(LINK_LIBS) \
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
	rm -f basic_hierarchical_keyring_example raw_aes_keyring_example zero_copy_comparison test_esdk test_concurrency test_resource_leaks enum_parity_test.o

clippy:
	cargo clippy --tests --examples

# Build the Rust static library, the C++ examples, the compile-time parity check,
# and the test binaries.
build-tests:
	cargo build
	$(MAKE) example raw_aes_example zero_copy_example custom_keyring_example streaming_example enum_parity test_esdk adopt_keyring_test test_concurrency test_resource_leaks

# Run the C++ integration + local-correctness binaries.
run-cpp:
	LD_LIBRARY_PATH="$(CURDIR)/target/debug" ./raw_aes_keyring_example
	./custom_keyring_example
	LD_LIBRARY_PATH="$(CURDIR)/target/debug" ./streaming_example
	LD_LIBRARY_PATH="$(CURDIR)/target/debug" ./test_esdk
	LD_LIBRARY_PATH="$(CURDIR)/target/debug" ./adopt_keyring_test
	LD_LIBRARY_PATH="$(CURDIR)/target/debug" ./test_concurrency
	LD_LIBRARY_PATH="$(CURDIR)/target/debug" ./test_resource_leaks

# Full local test suite (Rust + C++). Credential-gated tests skip when the
# ESDK_TEST_* variables are unset.
test: build-tests
	cargo test
	$(MAKE) run-cpp

# CI test targets refuse to run when the ESDK_TEST_* credentials are unset, so
# unsetting them cannot turn the integration tests into silent skips. Split
# Rust/C++ because the workflow runs the C++ half on Linux only.
require-creds:
	@test -n "$$ESDK_TEST_KMS_KEY_ARN" && test -n "$$ESDK_TEST_DDB_TABLE" \
	&& test -n "$$ESDK_TEST_LOGICAL_KEYSTORE" && test -n "$$ESDK_TEST_BRANCH_KEY_ID" \
	|| { echo "FAIL: ESDK_TEST_* credentials are unset; CI requires them."; exit 1; }

test-ci-rust: require-creds
	cargo test

test-ci-cpp: require-creds build-tests
	$(MAKE) run-cpp

duvet:
	rm -rf .duvet/reports .duvet/requirements
	duvet report

.PHONY: all clean clippy duvet build-tests run-cpp require-creds test test-ci-rust test-ci-cpp
