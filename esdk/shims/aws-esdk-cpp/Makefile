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

# enum_parity tests run during compile step
enum_parity: enum_parity_test.cpp include/aws/esdk/EncryptionSDK.h src/lib.rs $(STATICLIB)
	g++ -c enum_parity_test.cpp \
		-Itarget/cxxbridge -Iinclude \
		-std=c++17 \
		-o enum_parity_test.o

clean:
	rm -f test_esdk enum_parity_test.o

clippy:
	cargo clippy --tests

# Build the library and the tests
build-tests:
	cargo build
	$(MAKE) enum_parity test_esdk

# Run offline C++ tests
run-cpp:
	LD_LIBRARY_PATH="$(CURDIR)/$(PROFILE_DIR)" ./test_esdk

# Full local offline suite
test: build-tests
	cargo test
	$(MAKE) run-cpp

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
