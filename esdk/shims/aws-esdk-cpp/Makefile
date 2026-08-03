# Simple Makefile - all C++ bridge code is compiled into the Rust static library.

# Example, compiled as C++17.
# Needs live AWS resources / ESDK_TEST_* env vars to run; builds without them.
example: examples/basic_hierarchical_keyring_example.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs target/debug/libaws_esdk_cpp.a
	g++ examples/basic_hierarchical_keyring_example.cpp target/cxxbridge/aws-esdk-cpp/src/lib.rs.cc \
		$$(find target/debug/build -path "*/cxx-*/out/libcxxbridge1.a" | head -n1) \
		-Ltarget/debug -laws_esdk_cpp \
		-Itarget/cxxbridge -Iinclude \
		-lpthread -ldl \
		-std=c++17 \
		-o basic_hierarchical_keyring_example

# Integration tests, compiled as C++17. Run ./test_esdk with
# ESDK_TEST_* env vars set (it skips cleanly if they are unset).
test_esdk: test_esdk.cpp esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs target/debug/libaws_esdk_cpp.a
	g++ test_esdk.cpp target/cxxbridge/aws-esdk-cpp/src/lib.rs.cc \
		$$(find target/debug/build -path "*/cxx-*/out/libcxxbridge1.a" | head -n1) \
		-Ltarget/debug -laws_esdk_cpp \
		-Itarget/cxxbridge -Iinclude \
		-lpthread -ldl \
		-std=c++17 \
		-o test_esdk

# Concurrency local-correctness test, compiled as C++17. Run ./test_concurrency
# with ESDK_TEST_* env vars set (it skips cleanly if they are unset).
test_concurrency: test_concurrency.cpp esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs target/debug/libaws_esdk_cpp.a
	g++ test_concurrency.cpp target/cxxbridge/aws-esdk-cpp/src/lib.rs.cc \
		$$(find target/debug/build -path "*/cxx-*/out/libcxxbridge1.a" | head -n1) \
		-Ltarget/debug -laws_esdk_cpp \
		-Itarget/cxxbridge -Iinclude \
		-lpthread -ldl \
		-std=c++17 \
		-o test_concurrency

# Resource-leak local-correctness test, compiled as C++17. Linux only (reads
# /proc/self/statm). Run ./test_resource_leaks with ESDK_TEST_* env vars set
# (it skips cleanly if they are unset).
test_resource_leaks: test_resource_leaks.cpp esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs target/debug/libaws_esdk_cpp.a
	g++ test_resource_leaks.cpp target/cxxbridge/aws-esdk-cpp/src/lib.rs.cc \
		$$(find target/debug/build -path "*/cxx-*/out/libcxxbridge1.a" | head -n1) \
		-Ltarget/debug -laws_esdk_cpp \
		-Itarget/cxxbridge -Iinclude \
		-lpthread -ldl \
		-std=c++17 \
		-o test_resource_leaks

# Compile-time enum parity check. No link: the static_asserts fire during
# compilation, so a value mismatch fails the build.
enum_parity: enum_parity_test.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs target/debug/libaws_esdk_cpp.a
	g++ -c enum_parity_test.cpp \
		-Itarget/cxxbridge -Iinclude \
		-std=c++17 \
		-o enum_parity_test.o

clean:
	rm -f basic_hierarchical_keyring_example test_esdk test_concurrency test_resource_leaks enum_parity_test.o

clippy:
	cargo clippy --tests --examples

test:
	cargo build
	cargo build --release
	make example
	make enum_parity
	make test_esdk
	make test_concurrency
	make test_resource_leaks

.PHONY: all clean test clippy
