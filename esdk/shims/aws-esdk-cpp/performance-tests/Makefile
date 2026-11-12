# Builds the C++ performance benchmark against the aws-esdk-cpp static
# library from the parent directory. Compiled as C++17.

SHIM_DIR := ..
TARGET_DIR := $(SHIM_DIR)/target
PROFILE := release
CARGO_FLAGS := $(if $(filter release,$(PROFILE)),--release,)

CXXBRIDGE_CC := $(TARGET_DIR)/cxxbridge/aws-esdk-cpp/src/lib.rs.cc
STATICLIB := $(TARGET_DIR)/$(PROFILE)/libaws_esdk_cpp.a
CXXBRIDGE_RT = $(shell find $(TARGET_DIR)/$(PROFILE)/build -path "*/cxx[-/]*/out/libcxxbridge1.a" | head -n1)

# Link the static archive BY PATH: -laws_esdk_cpp would pick the cdylib, whose
# Rust export list hides the compiled facade's Aws::Esdk symbols. The generated
# bridge C++ and the facade are already inside the archive (built by build.rs).
UNAME_S := $(shell uname -s)
PLATFORM_LIBS :=
ifeq ($(UNAME_S),Darwin)
PLATFORM_LIBS += -framework Security -framework CoreFoundation -framework SystemConfiguration
endif

benchmark: benchmark.cpp benchmark_support.h $(STATICLIB)
	g++ benchmark.cpp \
		$(STATICLIB) \
		$(CXXBRIDGE_RT) \
		-I$(SHIM_DIR)/include \
		-lpthread -ldl $(PLATFORM_LIBS) \
		-std=c++17 -O2 \
		-o benchmark

$(STATICLIB):
	cd $(SHIM_DIR) && cargo build $(CARGO_FLAGS)

# The hierarchical keyring needs live AWS resources / ESDK_TEST_* env vars and
# skips cleanly without them; the raw AES keyring needs neither. Pass flags
# through ARGS, e.g. `make run ARGS="--quick --keyring raw-aes"`.
run: benchmark
	LD_LIBRARY_PATH="$(TARGET_DIR)/$(PROFILE)" ./benchmark $(ARGS)

clean:
	rm -f benchmark

.PHONY: run clean
