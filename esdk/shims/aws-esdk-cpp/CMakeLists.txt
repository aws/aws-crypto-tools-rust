# CMake integration for the AWS Encryption SDK C++ bindings (aws-esdk-cpp)
#
# Consumers do:
#     add_subdirectory(aws-esdk-cpp)  # pull this folder into your build
#     target_link_libraries(my_app PRIVATE AWS::esdk)  # link against the AWS::esdk target
#     #include <aws/esdk/EncryptionSDK.h>  # in your code
#
# `cargo build` produces the Rust staticlib and the cxx-generated C++ sources,
# then exposes them behind the AWS::esdk target.
cmake_minimum_required(VERSION 3.20)
project(aws_esdk_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(ESDK_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(ESDK_TARGET_DIR ${ESDK_ROOT}/target)

# Pick the Cargo profile from CMAKE_BUILD_TYPE.
# Default to the optimized profile (release) if none provided
set(ESDK_CARGO_ARGS build)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(ESDK_PROFILE debug)
else()
    set(ESDK_PROFILE release)
    list(APPEND ESDK_CARGO_ARGS --release)
endif()

# One option per Cargo feature: ESDK_FEATURE_KMS turns on `kms`, and so on.
option(ESDK_FEATURE_FIPS "Use AWS-LC's FIPS module instead of AWS-LC" OFF)
option(ESDK_FEATURE_KMS "Cargo feature kms" ON)
option(ESDK_FEATURE_DDB "Cargo feature ddb" ON)
option(ESDK_FEATURE_DEFAULT_AWS_SDK_CLIENTS "Cargo feature default-aws-sdk-clients" ON)
option(ESDK_FEATURE_RT_TOKIO "Cargo feature rt-tokio" ON)
if(ESDK_FEATURE_FIPS)
    set(ESDK_FEATURES fips)
else()
    set(ESDK_FEATURES aws-lc-sys)
endif()
foreach(_esdk_feature kms ddb default-aws-sdk-clients rt-tokio)
    string(TOUPPER "${_esdk_feature}" _esdk_option)
    string(REPLACE "-" "_" _esdk_option "${_esdk_option}")
    if(ESDK_FEATURE_${_esdk_option})
        list(APPEND ESDK_FEATURES ${_esdk_feature})
    endif()
endforeach()
list(JOIN ESDK_FEATURES "," _esdk_feature_list)
list(APPEND ESDK_CARGO_ARGS --no-default-features --features ${_esdk_feature_list})

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

# Compile and link C++ bridge
add_library(aws_esdk_cpp STATIC ${ESDK_BRIDGE_CC})
target_include_directories(aws_esdk_cpp PUBLIC
    ${ESDK_ROOT}/include
    ${ESDK_TARGET_DIR}/${ESDK_PROFILE}/include
    ${ESDK_TARGET_DIR}/cxxbridge
)
target_link_libraries(aws_esdk_cpp PUBLIC
    ${ESDK_STATICLIB}
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
