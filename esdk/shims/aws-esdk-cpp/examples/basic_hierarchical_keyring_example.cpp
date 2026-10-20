// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Encrypts and decrypts a message with a hierarchical keyring.
//
// Requires an existing key store with a provisioned branch key.

#include <chrono>
#include <iostream>
#include <string>
#include <aws/esdk/EncryptionSDK.h>

using namespace std::chrono_literals;

int main() {
    try {
        // The AWS Crypto Tools CI test key store.
        // Replace these with your own key store's table, name, and KMS key ARN. 
        auto keystore = Aws::Esdk::KeyStore(
            "KeyStoreDdbTable",  // table_name
            "KeyStoreDdbTable",  // logical_key_store_name
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126" // kms_arn
            // KMS and DynamoDB clients are optional and omitted here.
            // The ESDK will build defaults from the standard AWS config chain (region and credentials).
        );

        auto keyring = Aws::Esdk::HierarchicalKeyring(
            keystore,
            "3ce7656b-e166-40f3-8c9b-a920ce6596cd",  // branch_key_id
            4242s,  // ttl: how long cached branch key material may be reused
            // Unset options keep the library defaults.
            Aws::Esdk::HierarchicalKeyringOptions()
                .with_cache(Aws::Esdk::DefaultCmc(42))
        );

        Aws::Esdk::Client esdk;

        const std::string plaintext = "Hello World";
        try {
            // This uses the string API; the bytes APIs take a std::vector, a pointer and length, or a std::span (C++20).
            auto encrypted = esdk.encrypt(plaintext, keyring);

            auto decrypted = esdk.decrypt(encrypted.ciphertext, keyring);

            if (decrypted.plaintext.as_string_view() != plaintext) {
                std::cerr << "Decryption failed: plaintext mismatch\n";
                return 1;
            }
        } catch (const Aws::Esdk::ResourceNotFoundException& e) {
            const auto resource = e.resource();
            if (resource && resource->type() == Aws::Esdk::ResourceType::BranchKey) {
                std::cerr << "branch key " << resource->name() << " is not in the key store\n";
            } else {
                std::cerr << "an AWS resource does not exist: " << e.what() << "\n";
            }
            return 1;
        } catch (const Aws::Esdk::AccessDeniedException& e) {
            if (e.service() == Aws::Esdk::Service::Kms) {
                std::cerr << "AWS KMS denied access: " << e.what() << "\n";
            } else if (e.service() == Aws::Esdk::Service::DynamoDb) {
                std::cerr << "DynamoDB denied access: " << e.what() << "\n";
            } else {
                std::cerr << "access denied: " << e.what() << "\n";
            }
            return 1;
        }

        std::cout << "Success! Encryption and decryption completed successfully.\n";

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
