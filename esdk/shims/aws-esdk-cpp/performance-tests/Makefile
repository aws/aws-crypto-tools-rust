# Builds the C++ hierarchical-keyring performance benchmark against the
# aws-esdk-cpp static library from the parent directory. Compiled as C++17.

SHIM_DIR := ..
TARGET_DIR := $(SHIM_DIR)/target
PROFILE := release
CARGO_FLAGS := $(if $(filter release,$(PROFILE)),--release,)

CXXBRIDGE_CC := $(TARGET_DIR)/cxxbridge/aws-esdk-cpp/src/lib.rs.cc
STATICLIB := $(TARGET_DIR)/$(PROFILE)/libaws_esdk_cpp.a
CXXBRIDGE_RT = $(shell find $(TARGET_DIR)/$(PROFILE)/build -path "*/cxx-*/out/libcxxbridge1.a" | head -n1)

benchmark: benchmark.cpp benchmark_support.h $(STATICLIB)
	g++ benchmark.cpp $(CXXBRIDGE_CC) \
		$(CXXBRIDGE_RT) \
		-L$(TARGET_DIR)/$(PROFILE) -laws_esdk_cpp \
		-I$(TARGET_DIR)/cxxbridge -I$(SHIM_DIR)/include \
		-lpthread -ldl \
		-std=c++17 -O2 \
		-o benchmark

$(STATICLIB):
	cd $(SHIM_DIR) && cargo build $(CARGO_FLAGS)

# Run needs live AWS resources / ESDK_TEST_* env vars; it skips cleanly without
# them. Pass flags through ARGS, e.g. `make run ARGS="--quick"`.
run: benchmark
	LD_LIBRARY_PATH="$(TARGET_DIR)/$(PROFILE)" ./benchmark $(ARGS)

clean:
	rm -f benchmark

.PHONY: run clean
