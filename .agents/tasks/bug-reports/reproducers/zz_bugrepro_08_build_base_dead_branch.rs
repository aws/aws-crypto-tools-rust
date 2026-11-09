// TEMPORARY reproducer for BUG-08 (C01(c)). Delete after running.
use aws_crypto_mpl::keystore::encryption_context::{
    EncryptionContextInput, active_encryption_context, decrypt_only_encryption_context,
};
use aws_crypto_mpl::structures::EncryptionContext;

#[test]
fn inputs_named_by_the_comment_do_not_reach_the_collision_branch() {
    let mut custom = EncryptionContext::new();
    // "A custom key that already carries the prefix":
    custom.insert(b"aws-crypto-ec:a".to_vec(), b"1".to_vec());
    custom.insert(b"a".to_vec(), b"2".to_vec());
    // Custom keys equal to every base key name:
    for k in ["branch-key-id", "type", "create-time", "tablename", "kms-arn", "hierarchy-version", "version", "enc"] {
        custom.insert(k.as_bytes().to_vec(), b"x".to_vec());
    }
    let input = EncryptionContextInput {
        branch_key_id: "bk",
        create_time: "2024-01-01T00:00:00Z",
        logical_keystore_name: "L",
        kms_arn: "arn:aws:kms:us-west-2:111122223333:key/k",
        hierarchy_version: 1,
        custom_ec: Some(&custom),
    };
    let act = active_encryption_context(&input, "11111111-2222-4333-8444-555555555555");
    let dec = decrypt_only_encryption_context(&input, "11111111-2222-4333-8444-555555555555");
    println!("REPRO BUG-08 active is_ok = {}, decrypt_only is_ok = {}", act.is_ok(), dec.is_ok());
    let act = act.unwrap();
    let custom_keys: Vec<&String> = act.keys().filter(|k| k.starts_with("aws-crypto-ec:")).collect();
    println!("REPRO BUG-08 {} custom entries in, {} prefixed entries out: {custom_keys:?}", custom.len(), custom_keys.len());
}
