# CMake integration for the AWS Encryption SDK C++ bindings (aws-esdk-cpp)
#
# Consumers do:
#     add_subdirectory(aws-esdk-cpp)
#     target_link_libraries(my_app PRIVATE AWS::esdk)
#     #include <aws/esdk/EncryptionSDK.h>
#
# `cargo build` produces the Rust staticlib and the cxx-generated
# C++ sources, then exposes them behind the AWS::esdk target.
cmake_minimum_required(VERSION 3.20)
project(aws_esdk_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(ESDK_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(ESDK_TARGET_DIR ${ESDK_ROOT}/target)

# Pick the Cargo profile from CMAKE_BUILD_TYPE
# Default to the optimized core if none provided
set(ESDK_CARGO_ARGS build)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(ESDK_PROFILE debug)
else()
    set(ESDK_PROFILE release)
    list(APPEND ESDK_CARGO_ARGS --release)
endif()

# Build the Rust staticlib/cxx-generated source
execute_process(
    COMMAND cargo ${ESDK_CARGO_ARGS}
    WORKING_DIRECTORY ${ESDK_ROOT}
    RESULT_VARIABLE _esdk_cargo_result
)
if(NOT _esdk_cargo_result EQUAL 0)
    message(FATAL_ERROR "cargo build failed (exit ${_esdk_cargo_result})")
endif()

set(ESDK_STATICLIB ${ESDK_TARGET_DIR}/${ESDK_PROFILE}/libaws_esdk_cpp.a)
set(ESDK_BRIDGE_CC ${ESDK_TARGET_DIR}/cxxbridge/aws-esdk-cpp/src/lib.rs.cc)

# Find cxx runtime archive used to compile
file(GLOB_RECURSE _esdk_cxxbridge_rt
     ${ESDK_TARGET_DIR}/${ESDK_PROFILE}/build/cxx-*/out/libcxxbridge1.a)
if(NOT _esdk_cxxbridge_rt)
    message(FATAL_ERROR
        "cxx runtime archive libcxxbridge1.a not found under "
        "${ESDK_TARGET_DIR}/${ESDK_PROFILE}/build/cxx-*/out/. "
        "Run `cargo build` in ${ESDK_ROOT} first.")
endif()
list(GET _esdk_cxxbridge_rt 0 ESDK_CXXBRIDGE_RT)

# Compile and link C++ bridge
add_library(aws_esdk_cpp STATIC ${ESDK_BRIDGE_CC})
target_include_directories(aws_esdk_cpp PUBLIC
    ${ESDK_ROOT}/include
    ${ESDK_TARGET_DIR}/cxxbridge
)
target_link_libraries(aws_esdk_cpp PUBLIC
    ${ESDK_STATICLIB}
    ${ESDK_CXXBRIDGE_RT}
    pthread
    ${CMAKE_DL_LIBS}
)
if(APPLE)
    target_link_libraries(aws_esdk_cpp PUBLIC
        "-framework Security"
        "-framework CoreFoundation"
        "-framework SystemConfiguration"
    )
endif()
add_library(AWS::esdk ALIAS aws_esdk_cpp)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    add_executable(esdk_integration_test tests/test_esdk.cpp)
    target_link_libraries(esdk_integration_test PRIVATE AWS::esdk)

    add_executable(esdk_concurrency_test tests/test_concurrency.cpp)
    target_link_libraries(esdk_concurrency_test PRIVATE AWS::esdk)

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_executable(esdk_resource_leaks_test tests/test_resource_leaks.cpp)
        target_link_libraries(esdk_resource_leaks_test PRIVATE AWS::esdk)
    endif()
endif()
