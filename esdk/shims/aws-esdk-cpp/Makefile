# Every C++ binary links the Rust STATIC library by path. Linking with
# -laws_esdk_cpp would pick the cdylib (also built), whose Rust export list
# hides the compiled facade's Aws::Esdk symbols, failing the link. The
# generated bridge C++ (lib.rs.cc) and the facade (EncryptionSDK.cpp) are
# already compiled into the staticlib by build.rs, so binaries need only their
# own source plus the archives.

# The debug build dir. Overridable so a different build can point the C++
# binaries at whatever dir holds the staticlib.
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

# COV_CXXFLAGS is empty for normal builds.
COV_CXXFLAGS ?=

test_esdk: tests/test_esdk.cpp tests/esdk_test_support.h include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ tests/test_esdk.cpp \
		$(CXXFLAGS_COMMON) $(COV_CXXFLAGS) $(LINK_LIBS) \
		-o test_esdk

# Compile-only: the static_asserts fire during compilation, so no link step.
enum_parity: enum_parity_test.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ -c enum_parity_test.cpp \
		-Itarget/cxxbridge -Iinclude \
		-std=c++17 \
		-o enum_parity_test.o

clean:
	rm -f test_esdk enum_parity_test.o

clippy:
	cargo clippy --tests

# Build the Rust static library, the compile-time parity check, and the test binary.
build-tests:
	cargo build
	$(MAKE) enum_parity test_esdk

# Run the offline C++ test binary. Fully offline: no creds, no flags.
run-cpp:
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./test_esdk

# Full local suite (all tests are offline).
test: build-tests
	cargo test
	$(MAKE) run-cpp

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
coverage:
	cargo llvm-cov --lib

# Same, emitting a browsable HTML report under target/llvm-cov/html.
coverage-html:
	cargo llvm-cov --lib --html

.PHONY: all clean clippy duvet build-tests run-cpp test test-ci-rust test-ci-cpp coverage coverage-html
