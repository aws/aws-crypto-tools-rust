#include <iostream>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

// Uses a CustomKeyring, whose creation entry point lives in the core library's
// language (Rust) and delegates to the hierarchical keyring. It is a Keyring, so
// encrypt and decrypt accept it like any other keyring.
int main() {
    try {
        auto client_config = Aws::Esdk::ClientConfig()
            .with_max_retry_attempts(5);

        auto kms = Aws::Esdk::KmsClient(client_config);
        auto ddb = Aws::Esdk::DdbClient(client_config);

        auto keystore = Aws::Esdk::KeyStore(
            "KeyStoreDdbTable",                                                    // table_name
            "KeyStoreDdbTable",                                                    // logical_key_store_name
            "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126",  // kms_arn
            kms,
            ddb
        );

        auto keyring = Aws::Esdk::CustomKeyring(
            keystore,
            "3ce7656b-e166-40f3-8c9b-a920ce6596cd",  // branch_key_id
            4242                                      // ttl_seconds
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
