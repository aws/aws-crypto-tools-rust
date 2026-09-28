// Shares one cache across two hierarchical keyrings.
//
// A hierarchical keyring caches branch key material so it does not call KMS on every message.
// By default, each keyring gets its own cache.
// However, you can configure multiple keyrings to share a single cache.
// Constructing one CryptographicMaterialsCache and passing it to several keyrings
// makes them reference the same cache so they can reuse each other's entries.
// Partition IDs control which keyrings see each other's entries within the same cache.
//
// Requires an existing key store with a provisioned branch key.

#include <chrono>
#include <iostream>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

using namespace std::chrono_literals;

int main() {
    try {
        // The AWS Crypto Tools CI test key store.
        // Replace these with your own key store's table, name, and KMS key ARN. 
        auto keystore = Aws::Esdk::KeyStore(
            "KeyStoreDdbTable",
            "KeyStoreDdbTable",
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126"
            // KMS and DynamoDB clients are optional and omitted here.
            // The ESDK will build defaults from the standard AWS config chain (region and credentials).
        );

        // Construct one cache. entry_capacity is required.
        Aws::Esdk::CryptographicMaterialsCache cache(
            Aws::Esdk::CacheType::Default(1000));

        // Pass the same cache to both keyrings, with the same partition id, so
        // they reuse each other's cached branch key material.
        const std::string branch_key_id = "3ce7656b-e166-40f3-8c9b-a920ce6596cd";
        auto make_keyring = [&] {
            return Aws::Esdk::HierarchicalKeyring(
                keystore, branch_key_id, 4242s,
                Aws::Esdk::HierarchicalKeyringOptions()
                    .with_cache(Aws::Esdk::CacheType::Shared(cache))
                    .with_partition_id("shared-partition"));
        };
        auto keyring_a = make_keyring();
        auto keyring_b = make_keyring();

        Aws::Esdk::EncryptionSDK esdk;
        std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};

        // Encrypt with A, decrypt with B: both go through the same cache.
        auto encrypted = esdk.encrypt(plaintext, keyring_a);
        auto decrypted = esdk.decrypt(encrypted.ciphertext, keyring_b);

        if (plaintext != decrypted.plaintext) {
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
