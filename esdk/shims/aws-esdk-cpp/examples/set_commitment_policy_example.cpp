// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Encrypts and decrypts under a non-default commitment policy.
//
// The default policy, RequireEncryptRequireDecrypt, encrypts and decrypts only with key-committing suites.
// Use ForbidEncryptAllowDecrypt only while migrating from an ESDK version 1.x that cannot read committing messages,
// and move to the default once every reader is upgraded.
//
// An Client applies its policy to every operation it runs.

#include <iostream>
#include <string>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

int main() {
    try {
        Aws::Esdk::Client esdk(Aws::Esdk::Config().with_commitment_policy(
            Aws::Esdk::CommitmentPolicy::ForbidEncryptAllowDecrypt));

        // For demonstration only: a real application must source its wrapping
        // key from a secure store and never hardcode it.
        auto keyring = Aws::Esdk::RawAesKeyring(
            "my-key-namespace",
            "my-key-name",
            std::vector<std::uint8_t>(32, 0x01),
            Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16
        );

        const std::string plaintext = "Hello World";
        auto encrypted = esdk.encrypt(plaintext, keyring);
        auto decrypted = esdk.decrypt(encrypted.ciphertext, keyring);
        if (decrypted.plaintext.as_string_view() != plaintext) {
            std::cerr << "Decryption failed: plaintext mismatch\n";
            return 1;
        }

        std::cout << "Success! Encrypted and decrypted under ForbidEncryptAllowDecrypt.\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
