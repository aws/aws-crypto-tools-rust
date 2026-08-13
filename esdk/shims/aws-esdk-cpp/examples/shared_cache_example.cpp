// Shares one cache across two hierarchical keyrings.
//
// A hierarchical keyring caches branch key material so it does not call KMS on
// every message. By default each keyring gets its own cache. Constructing one
// CryptographicMaterialsCache and passing it to several keyrings makes them
// reference the same cache, so they reuse each other's entries. Partition ids
// control which keyrings see each other's entries.
//
// Requires an existing key store with a provisioned branch key.

#include <iostream>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

int main() {
    try {
        auto client_config = Aws::Esdk::ClientConfig();
        auto kms = Aws::Esdk::KmsClient(client_config);
        auto ddb = Aws::Esdk::DdbClient(client_config);

        // Replace these with your own key store's table, name, and KMS key ARN.
        auto keystore = Aws::Esdk::KeyStore(
            "KeyStoreDdbTable",
            "KeyStoreDdbTable",
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126",
            kms,
            ddb);

        // Construct one cache. entry_capacity is required.
        auto cache = Aws::Esdk::CryptographicMaterialsCache::Create(
            Aws::Esdk::CacheType::MultiThreaded(1000));

        // Pass the same cache to both keyrings, with the same partition id, so
        // they reuse each other's cached branch key material.
        const std::string branch_key_id = "3ce7656b-e166-40f3-8c9b-a920ce6596cd";
        auto make_keyring = [&] {
            return Aws::Esdk::HierarchicalKeyring(
                keystore, branch_key_id, 4242,
                Aws::Esdk::HierarchicalKeyringOptions()
                    .with_cache(Aws::Esdk::CacheType::Shared(cache))
                    .with_partition_id("shared-partition"));
        };
        auto keyring_a = make_keyring();
        auto keyring_b = make_keyring();

        Aws::Esdk::EncryptionSDK sdk;
        std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};

        // Encrypt with A, decrypt with B: both go through the same cache.
        auto encrypted = sdk.encrypt(plaintext, keyring_a);
        auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring_b);

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
