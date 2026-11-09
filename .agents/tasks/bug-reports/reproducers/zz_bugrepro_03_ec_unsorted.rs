// TEMPORARY reproducer for BUG-03 (T15). Delete after running.
use aws_crypto_mpl::structures::EncryptionContext;

#[test]
fn deserialize_accepts_unsorted_entries() {
    // count = 2, then ("b" -> "1"), ("a" -> "2"): keys in DESCENDING order.
    let unsorted: Vec<u8> = vec![0x00, 0x02, 0x00, 0x01, b'b', 0x00, 0x01, b'1', 0x00, 0x01, b'a', 0x00, 0x01, b'2'];
    // Same pairs, ascending order (the only spec-conformant encoding).
    let sorted: Vec<u8> = vec![0x00, 0x02, 0x00, 0x01, b'a', 0x00, 0x01, b'2', 0x00, 0x01, b'b', 0x00, 0x01, b'1'];

    let ec_u = EncryptionContext::deserialize(&unsorted);
    println!("REPRO BUG-03 deserialize(unsorted) is_ok = {}", ec_u.is_ok());
    let ec_u = ec_u.unwrap();
    let ec_s = EncryptionContext::deserialize(&sorted).unwrap();
    println!("REPRO BUG-03 deserialize(unsorted) == deserialize(sorted): {}", ec_u == ec_s);
    let re = ec_u.serialize().unwrap();
    println!("REPRO BUG-03 input     = {unsorted:02x?}");
    println!("REPRO BUG-03 serialize = {re:02x?}");
    println!("REPRO BUG-03 serialize(deserialize(b)) == b: {}", re == unsorted);
}

#[test]
fn related_deserialize_accepts_non_utf8() {
    // count = 1, key = [0xFF] (not UTF-8), value = "v".
    let b: Vec<u8> = vec![0x00, 0x01, 0x00, 0x01, 0xFF, 0x00, 0x01, b'v'];
    println!("REPRO BUG-03 (related) deserialize(non-UTF-8 key) is_ok = {}", EncryptionContext::deserialize(&b).is_ok());
}
