# The cxx bridge's C++ side is compiled into the Rust static library, so every
# binary links lib.rs.cc + libcxxbridge1.a + libaws_esdk_cpp.a.

example: examples/basic_hierarchical_keyring_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs target/debug/libaws_esdk_cpp.a
	g++ examples/basic_hierarchical_keyring_example.cpp target/cxxbridge/aws-esdk-cpp/src/lib.rs.cc \
		$$(find target/debug/build -path "*/cxx-*/out/libcxxbridge1.a" | head -n1) \
		-Ltarget/debug -laws_esdk_cpp \
		-Itarget/cxxbridge -Iinclude \
		-lpthread -ldl \
		-std=c++17 \
		-o basic_hierarchical_keyring_example

raw_aes_example: examples/raw_aes_keyring_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs target/debug/libaws_esdk_cpp.a
	g++ examples/raw_aes_keyring_example.cpp target/cxxbridge/aws-esdk-cpp/src/lib.rs.cc \
		$$(find target/debug/build -path "*/cxx-*/out/libcxxbridge1.a" | head -n1) \
		-Ltarget/debug -laws_esdk_cpp \
		-Itarget/cxxbridge -Iinclude \
		-lpthread -ldl \
		-std=c++17 \
		-o raw_aes_keyring_example

test_esdk: tests/test_esdk.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs target/debug/libaws_esdk_cpp.a
	g++ tests/test_esdk.cpp target/cxxbridge/aws-esdk-cpp/src/lib.rs.cc \
		$$(find target/debug/build -path "*/cxx-*/out/libcxxbridge1.a" | head -n1) \
		-Ltarget/debug -laws_esdk_cpp \
		-Itarget/cxxbridge -Iinclude \
		-lpthread -ldl \
		-std=c++17 \
		-o test_esdk

test_concurrency: tests/test_concurrency.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs target/debug/libaws_esdk_cpp.a
	g++ tests/test_concurrency.cpp target/cxxbridge/aws-esdk-cpp/src/lib.rs.cc \
		$$(find target/debug/build -path "*/cxx-*/out/libcxxbridge1.a" | head -n1) \
		-Ltarget/debug -laws_esdk_cpp \
		-Itarget/cxxbridge -Iinclude \
		-lpthread -ldl \
		-std=c++17 \
		-o test_concurrency

test_resource_leaks: tests/test_resource_leaks.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs target/debug/libaws_esdk_cpp.a
	g++ tests/test_resource_leaks.cpp target/cxxbridge/aws-esdk-cpp/src/lib.rs.cc \
		$$(find target/debug/build -path "*/cxx-*/out/libcxxbridge1.a" | head -n1) \
		-Ltarget/debug -laws_esdk_cpp \
		-Itarget/cxxbridge -Iinclude \
		-lpthread -ldl \
		-std=c++17 \
		-o test_resource_leaks

# Compile-only: the static_asserts fire during compilation, so no link step.
enum_parity: enum_parity_test.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs target/debug/libaws_esdk_cpp.a
	g++ -c enum_parity_test.cpp \
		-Itarget/cxxbridge -Iinclude \
		-std=c++17 \
		-o enum_parity_test.o

clean:
	rm -f basic_hierarchical_keyring_example raw_aes_keyring_example test_esdk test_concurrency test_resource_leaks enum_parity_test.o

clippy:
	cargo clippy --tests --examples

# Build the Rust static library, the C++ example, the compile-time parity check,
# and the test binaries.
build-tests:
	cargo build
	$(MAKE) example raw_aes_example enum_parity test_esdk test_concurrency test_resource_leaks

# Run the C++ integration + local-correctness binaries.
run-cpp:
	LD_LIBRARY_PATH="$(CURDIR)/target/debug" ./raw_aes_keyring_example
	LD_LIBRARY_PATH="$(CURDIR)/target/debug" ./test_esdk
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
