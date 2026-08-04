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
	rm -f basic_hierarchical_keyring_example test_esdk test_concurrency test_resource_leaks enum_parity_test.o

clippy:
	cargo clippy --tests --examples

# Build the Rust static library, the C++ example, the compile-time parity check,
# and the test binaries.
build-tests:
	cargo build
	$(MAKE) example enum_parity test_esdk test_concurrency test_resource_leaks

# Run the C++ integration + local-correctness binaries.
run-cpp:
	LD_LIBRARY_PATH="$(CURDIR)/target/debug" ./test_esdk
	LD_LIBRARY_PATH="$(CURDIR)/target/debug" ./test_concurrency
	LD_LIBRARY_PATH="$(CURDIR)/target/debug" ./test_resource_leaks

# Full local test suite (Rust + C++). Credential-gated tests skip when the
# ESDK_TEST_* variables are unset.
test: build-tests
	cargo test
	$(MAKE) run-cpp

# CI test targets: ESDK_TEST_REQUIRE_CREDS turns absent ESDK_TEST_* credentials
# into a failure instead of a skip, so unsetting them cannot pass silently. Split
# Rust/C++ because the workflow runs the C++ half on Linux only.
test-ci-rust:
	ESDK_TEST_REQUIRE_CREDS=1 cargo test

test-ci-cpp: build-tests
	ESDK_TEST_REQUIRE_CREDS=1 $(MAKE) run-cpp

.PHONY: all clean clippy build-tests run-cpp test test-ci-rust test-ci-cpp
