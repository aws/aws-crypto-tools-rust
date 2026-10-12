// Shares one cache across two hierarchical keyrings.
//
// A hierarchical keyring caches branch key material so it does not call KMS on every message.
// By default, each keyring gets its own cache.
// However, you can configure multiple keyrings to share a single cache.
// Constructing one CryptographicMaterialsCache and passing it to several keyrings
// makes them reference the same cache so they can reuse each other's entries.
// Keyrings that share one cache reuse each other's entries
// when they also have the same partition ID, logical key store name, and branch key ID.
// Here the two keyrings use separate key store instances with the same logical name,
// as two services reading one key store table would.
// Never give two different key store tables the same logical name.
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
        auto make_keystore = [] {
            return Aws::Esdk::KeyStore(
                "KeyStoreDdbTable",
                "KeyStoreDdbTable",
                "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"
                // KMS and DynamoDB clients are optional and omitted here.
                // The ESDK builds defaults from the standard AWS config chain (region and credentials).
            );
        };
        auto keystore_a = make_keystore();
        auto keystore_b = make_keystore();

        // Construct one cache. entry_capacity is required.
        Aws::Esdk::DefaultCmc cache(1000);

        // Same cache, partition ID, logical key store name, and branch key ID,
        // so the keyrings reuse each other's cached branch key material.
        const std::string branch_key_id = "3ce7656b-e166-40f3-8c9b-a920ce6596cd";
        auto make_keyring = [&](const Aws::Esdk::KeyStore& keystore) {
            return Aws::Esdk::HierarchicalKeyring(
                keystore, branch_key_id, 4242s,
                Aws::Esdk::HierarchicalKeyringOptions()
                    .with_cache(cache)
                    .with_partition_id("shared-partition"));
        };
        auto keyring_a = make_keyring(keystore_a);
        auto keyring_b = make_keyring(keystore_b);

        Aws::Esdk::EncryptionSDK esdk;
        const std::string plaintext = "Hello";

        // Encrypt with A, decrypt with B: both go through the same cache.
        // This uses the string API; the bytes APIs take a std::vector, a pointer and length, or a std::span (C++20).
        auto encrypted = esdk.encrypt(plaintext, keyring_a);
        auto decrypted = esdk.decrypt(encrypted.ciphertext, keyring_b);

        if (decrypted.plaintext.as_string_view() != plaintext) {
            std::cerr << "Decryption failed: plaintext mismatch\n";
            return 1;
        }

        std::cout << "Success! Two keyrings shared one cache.\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
