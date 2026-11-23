// TEMPORARY reproducer for BUG-08 (C01(c)). Delete after running.
// Re-check adaptation for main 620771c: same custom keys, same inputs, same
// observation. API changes only: the module moved to
// key_store::__test_internals::encryption_context (test-utils), and
// EncryptionContext::insert now takes strings instead of byte vectors.
use aws_crypto_mpl::key_store::__test_internals::encryption_context::{
    EncryptionContextInput, active_encryption_context, decrypt_only_encryption_context,
};
use aws_crypto_mpl::types::EncryptionContext;

#[test]
fn inputs_named_by_the_comment_do_not_reach_the_collision_branch() {
    let mut custom = EncryptionContext::new();
    // "A custom key that already carries the prefix":
    custom.insert("aws-crypto-ec:a", "1");
    custom.insert("a", "2");
    // Custom keys equal to every base key name:
    for k in ["branch-key-id", "type", "create-time", "tablename", "kms-arn", "hierarchy-version", "version", "enc"] {
        custom.insert(k, "x");
    }
    let input = EncryptionContextInput {
        branch_key_id: "bk",
        create_time: "2024-01-01T00:00:00Z",
        logical_key_store_name: "L",
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
