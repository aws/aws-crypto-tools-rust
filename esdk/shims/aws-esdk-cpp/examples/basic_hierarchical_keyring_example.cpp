// Encrypts and decrypts a message with a hierarchical keyring backed by a
// DynamoDB key store and a KMS key. Requires an existing key store with a
// provisioned branch key.

#include <iostream>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

int main() {
    try {
        // Region and credentials come from the default AWS config chain.
        auto client_config = Aws::Esdk::ClientConfig()
            .with_max_retry_attempts(5);

        auto kms = Aws::Esdk::KmsClient(client_config);
        auto ddb = Aws::Esdk::DdbClient(client_config);

        // The AWS Crypto Tools CI test key store; replace these with your own
        // key store's table, name, and KMS key ARN.
        auto keystore = Aws::Esdk::KeyStore(
            "KeyStoreDdbTable",                                                    // table_name
            "KeyStoreDdbTable",                                                    // logical_key_store_name
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126",  // kms_arn
            kms,
            ddb
        );

        auto keyring = Aws::Esdk::HierarchicalKeyring(
            keystore,
            "3ce7656b-e166-40f3-8c9b-a920ce6596cd",  // branch_key_id
            4242,  // ttl_seconds: how long cached branch key material may be reused
            // Unset options keep the library defaults.
            Aws::Esdk::HierarchicalKeyringOptions()
                .with_cache(Aws::Esdk::Cache::MultiThreaded(42))
        );

        Aws::Esdk::EncryptionSDK sdk;

        std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
        auto encrypted = sdk.encrypt(plaintext, keyring);

        auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring);

        if (plaintext != decrypted.plaintext) {
            std::cerr << "Decryption failed: plaintext mismatch\n";
            return 1;
        }

        std::cout << "Success! Encryption and decryption completed successfully.\n";

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
