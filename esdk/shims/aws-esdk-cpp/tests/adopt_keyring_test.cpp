// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Adopting a custom keyring.
// A consumer writes a keyring implementation in Rust,
// turns it into a raw handle (void*),
// and hands that handle to Aws::Esdk::Keyring::adopt on the C++ side.
// The custom-keyring example shows the real consumer flow end to end; this is an internal test.

#include <cstdint>
#include <iostream>
#include <vector>

#include "aws-esdk-cpp/src/lib.rs.h"
#include "rust/cxx.h"

#include "esdk_test_support.h"

int main() {
    try {
        // Make a "custom" keyring, which is just the Dafny Rust Raw AES keyring.
        // This is sufficent to test adoption.
        // TODO: Once native MPL support exists, copy-paste the native Raw AES keyring implementation
        // into a test file, then use that implementation.
        // That pins the raw AES keyring interface/behavior, acting as an additional assertion
        // that future changes to the keyring interface/behaviorial contract are non-breaking.
        ::aws_esdk_ffi::RawAesKeyringInput in{};
        std::vector<std::uint8_t> key(32, 0x2A);
        in.key_namespace = ::rust::String("test-ns");
        in.key_name = ::rust::String("test-key");
        in.wrapping_key = ::rust::Slice<const std::uint8_t>(key.data(), key.size());
        in.wrapping_alg = ::aws_esdk_ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16;
        void* raw_handle = ::aws_esdk_ffi::create_raw_aes_keyring(in).into_raw();

        // Adopt the handle for use by C++
        //= spec/shim/shim.md#custom-implementations-of-core-library-interfaces
        //= type=test
        //# - The shim MAY let the target adopt a consumer-written implementation of a
        //# core-library interface.
        auto keyring = Aws::Esdk::Keyring::adopt(raw_handle);
        Aws::Esdk::Client sdk;
        auto plaintext = esdk_test::to_bytes("adopted keyring through the facade");
        auto ciphertext = sdk.encrypt(plaintext, keyring).ciphertext;
        ESDK_CHECK(ciphertext != plaintext);
        auto decrypted = sdk.decrypt(ciphertext, keyring);
        ESDK_CHECK(decrypted.plaintext == plaintext);

        // A different keyring can't decrypt the custom keyring's messages
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
