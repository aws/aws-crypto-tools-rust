// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// White-box test: like enum_parity_test.cpp, this TU includes the bridge header.
// It plays the consumer's Rust crate, which produces the keyring handle C++ adopts.
// Everything after the handle exists goes through the public facade only.

#include <cstdint>
#include <iostream>
#include <vector>

#include "aws-esdk-cpp/src/lib.rs.h"
#include "rust/cxx.h"

#include "esdk_test_support.h"

int main() {
    try {
        // Consumer's Rust side: any keyring the core accepts, as a raw handle.
        ::aws_esdk_ffi::RawAesKeyringInput in{};
        std::vector<std::uint8_t> key(32, 0x2A);
        in.key_namespace = ::rust::String("test-ns");
        in.key_name = ::rust::String("test-key");
        in.wrapping_key = ::rust::Slice<const std::uint8_t>(key.data(), key.size());
        in.wrapping_alg = ::aws_esdk_ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16;
        void* raw_handle = ::aws_esdk_ffi::create_raw_aes_keyring(in).into_raw();

        // Consumer's C++ side: adopt and use through the public facade.
        //= spec/shim/shim.md#custom-implementations-of-core-library-interfaces
        //= type=test
        //= reason=A handle produced by the shim's conversion is adopted and the result encrypts and decrypts through the facade.
        //# - The shim MAY let the target adopt a consumer-written implementation of a
        //# core-library interface.
        auto keyring = Aws::Esdk::Keyring::adopt(raw_handle);
        Aws::Esdk::EncryptionSDK sdk;
        auto plaintext = esdk_test::to_bytes("adopted keyring through the facade");
        auto ciphertext = sdk.encrypt(plaintext, keyring).ciphertext;
        ESDK_CHECK(ciphertext != plaintext);
        auto decrypted = sdk.decrypt(ciphertext, keyring);
        ESDK_CHECK(decrypted.plaintext == plaintext);

        // The adopted keyring is a first-class keyring: a different keyring
        // cannot decrypt its output.
        std::vector<std::uint8_t> other_key(32, 0x07);
        Aws::Esdk::RawAesKeyring other("test-ns", "test-key", other_key,
                                       Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
        ++::esdk_test::g_checks;
        try {
            sdk.decrypt(ciphertext, other);
            ++::esdk_test::g_failures;
            std::cerr << "FAIL: wrong keyring decrypted adopted keyring's message\n";
        } catch (const Aws::Esdk::AwsEncryptionSdkException&) {
            // expected
        }
    } catch (const std::exception& e) {
        std::cerr << "FATAL: unexpected exception aborted the suite: " << e.what() << "\n";
        return 2;
    }

    return esdk_test::report("adopt_keyring_test");
}
