#!/usr/bin/env python3
"""Manual citation expectations for lines the heuristic citation scripts cannot resolve.
Each row: (code file, line or a-b, regex that must match somewhere in that range, doc location).
Prints OK / FAIL per row and a summary. Rows were written by reading the doc sentence next to
each citation; they are an independent second check, not generated from the scripts."""
import os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
HK = "mpl/src/aws_kms/hierarchical_keyring.rs"
ST = "mpl/src/cmc/storm_tracking.rs"
BKS = "mpl/src/key_store/branch_key_store.rs"
KEC = "mpl/src/key_store/encryption_context.rs"
RAW = "mpl/src/keyring/raw_aes_keyring.rs"
SHIM = "esdk/shims/aws-esdk-cpp/src/lib.rs"
ERR = "mpl/src/error/generated.rs"
DCMM = "mpl/src/cmm/default_cmm.rs"
ROWS = [
    # hierarchical keyring on_decrypt chain (merged T-block, 01 T27)
    (HK, "734", r"async fn on_decrypt", "merged:362 01:610"),
    (HK, "751", r"for edk in &encrypted_data_keys", "merged:362"),
    (HK, "764", r"try_decrypt_edk", "merged:362"),
    (HK, "867", r"async fn try_decrypt_edk", "merged:362"),
    (HK, "879", r"ciphertext\.len\(\) <", "merged:362 length guard"),
    (HK, "889-894", r"version_bytes", "merged:362"),
    (HK, "901", r"async fn decrypt_edk_at_version", "merged:363"),
    (HK, "908", r"build_cache_identifier", "merged:363"),
    (HK, "916-924", r"get_cache_entry|into_entry", "merged:363"),
    (HK, "934-938", r"get_branch_key_version", "merged:363"),
    (HK, "947-953", r"put_cache_entry|self\s*$|\.inner", "merged:363 put"),
    (HK, "746-748", r"resolve_branch_key_id", "01:1225"),
    (HK, "760", r"edk_branch_key_id != branch_key_id", "01:1225"),
    (HK, "831", r"async fn resolve_branch_key_id", "01:1225"),
    (HK, "692", r"get_active_branch_key", "01:292"),
    (HK, "722", r"key_provider_info", "01:1208"),
    (HK, "767", r"add_data_key", "01:719"),
    (HK, "943", r"CachedMaterials::BranchKey", "01:556"),
    (HK, "535", r"", "01:458 exists"),
    (BKS, "711", r"", "01:245 exists"),
    (BKS, "792", r"fn get_active_branch_key|get_active", "01:292"),
    (BKS, "801", r"", "01:292 exists"),
    (BKS, "1098", r"ATTR_HIERARCHY_VERSION", "01:245"),
    (KEC, "67", r"", "01:245 02:475 exists"),
    (KEC, "77", r"", "01:245 02:475 exists"),
    # storm tracking
    (ST, "199", r"expect", "01:965 test-utils expects"),
    (ST, "213", r"expect", "01:965"),
    (ST, "227", r"expect", "01:965"),
    (ST, "239", r"fn state_locked", "01:988"),
    (ST, "248", r"cache lock poisoned", "01:1021"),
    (ST, "250-255", r"retain|prune|skip|filter|!=", "01:989"),
    (ST, "264", r"fn classify_and_mark", "01:989"),
    (ST, "313", r"deadline: None", "01:989 01:1015"),
    (ST, "322-323", r"in_flight_ttl_exceeded|elapsed > ", "01:990 01:1029"),
    (ST, "333", r"now \+ self\.inner\.in_flight_ttl", "01:990"),
    (ST, "360", r"fn wait_for_leader", "01:990"),
    (ST, "378-382", r"deadline", "01:990"),
    (ST, "388", r"lock|state_locked", "01:990"),
    (ST, "390-394", r"", "01:990 exists"),
    (ST, "606", r"pub fn build", "01:988"),
    (ST, "613", r"fan_out == 0", "02:23 02:464"),
    (ST, "616", r"in_flight_ttl\.is_zero", "02:23 02:464"),
    (ST, "619", r"sleep\.is_zero", "02:23 02:464"),
    (ST, "622", r"grace_interval > ", "02:23 02:464"),
    (ST, "661", r"fn within_grace_period", "01:992"),
    (ST, "675", r"fn within_grace_interval", "01:992"),
    (ST, "680", r"grace_interval", "01:1019"),
    (ST, "710", r"fn put_cache_entry", "01:991"),
    (ST, "721", r"", "01:991 exists"),
    (ST, "724-725", r"remove|clear|inflight", "01:991"),
    (ST, "729", r"fn get_cache_entry", "01:991"),
    (ST, "739-740", r"classify_and_mark|state_locked|lock", "01:991"),
    # raw AES / shim / misc
    (RAW, "471", r"vec!\[0u8;", "01:691 merged:389"),
    (RAW, "489", r"plaintext_dk\.len\(\) != expected_dk_len", "01:691"),
    (RAW, "129", r"", "merged:93 exists"),
    (RAW, "191", r"", "merged:93 exists"),
    (RAW, "350", r"pub fn build", "merged:97"),
    (RAW, "360", r"", "merged:97 exists"),
    (SHIM, "715", r"fn require_handle", "02:473"),
    (SHIM, "720", r"is_null", "01:1331"),
    (SHIM, "728", r"unsafe \{ &\*ptr \}", "01:1331"),
    (SHIM, "1570-1571", r"set_kms_client|set_ddb_client", "merged:15 02:473"),
    (SHIM, "1661", r"input\.cache\.as_ref", "merged:15 02:473"),
    (SHIM, "2059", r"fn into_keyring_handle", "merged:15"),
    (SHIM, "1287", r"require_handle", "01:1331"),
    (SHIM, "1331", r"require_handle", "01:1331"),
    (SHIM, "1652", r"require_handle", "01:1331"),
    (SHIM, "1942", r"require_handle", "01:1331"),
    (SHIM, "1985", r"require_handle", "01:1331"),
    # error type
    (ERR, "271", r"encrypted_data_keys", "01:1289"),
    (ERR, "1064", r"fn with_encrypted_data_keys", "01:1289"),
    (ERR, "1591", r"fn encrypted_data_keys", "01:1289"),
    (ERR, "1596", r"impl fmt::Debug for NoMatchingDataKeyError", "01:1289"),
    (DCMM, "198", r"merge_reproduced_encryption_context", "01:1225"),
    ("prim/src/ecdsa.rs", "387", r"to_vec", "merged:16 02:15"),
    ("prim/src/ecdsa.rs", "391-392", r"field_size|Err", "merged:16"),
    ("mpl/src/cmc/local.rs", "131", r"fn get_fresh", "merged:527"),
    ("mpl/src/cmc/local.rs", "166", r"fn prune_tail", "merged:527"),
    ("mpl/tests/test_encryption_materials.rs", "248", r"fn test_plaintext_data_key_zeroize", "01:731"),
    ("mpl/tests/test_decryption_materials.rs", "228", r"fn test_plaintext_data_key_zeroize_decryption", "01:731"),
    ("mpl/tests/test_local_cmc.rs", "465", r"fn test_pruning_does_not_evict_outside_tail", "01:731"),
    ("mpl/tests/test_keyring_memory.rs", "100", r"fn raw_aes_keyring", "merged:374"),
    ("mpl/tests/test_keyring_memory.rs", "113", r"fn hierarchical_keyring", "merged:374"),
    ("mpl/tests/test_storm_tracking_cmc.rs", "388", r"fn test_durations_are_stored_exactly", "merged:456"),
    ("mpl/src/cmm/fluent_builders.rs", "168-171", r"", "01:912 exists"),
    ("esdk/src/materials.rs", "130", r"allows_for_decrypt", "01:915"),
    ("esdk/src/materials.rs", "202", r"allows_for_encrypt", "01:915"),
    ("mpl/src/structures/materials_checks.rs", "97", r"", "01:882 exists"),
    ("mpl/src/key_store/kms_ops.rs", "172", r"ATTR_KMS_ARN", "01:219"),
    ("mpl/src/key_store/kms_ops.rs", "179", r"resolve_key_store_arn", "merged:240"),
    ("mpl/src/aws_kms/branch_key_wrap.rs", "230", r"pub fn unwrap", "merged:389 01:694"),
    ("mpl/src/aws_kms/branch_key_wrap.rs", "236", r"FIXED_OVERHEAD_LEN", "01:1520"),
    ("mpl/src/structures/branch_key_materials.rs", "205", r"impl Drop for BranchKeyMaterials", "01:1521"),
    ("prim/src/lib.rs", "215", r"plain_text\.len\(\) < cipher_text\.len\(\)", "02:502"),
    ("esdk/shims/aws-esdk-cpp/include/aws/esdk/EncryptionSDK.h", "656-663", r"Adopts a custom keyring", "merged:511"),
    ("esdk/shims/aws-esdk-cpp/include/aws/esdk/EncryptionSDK.h", "664", r"static Keyring adopt", "01:1337"),
    ("mpl/test-server/src/handlers.rs", "137-147", r"Client::new|sdk_config", "01:1491"),
]
cache = {}
bad = 0
for f, rng, rx, where in ROWS:
    if f not in cache:
        p = os.path.join(ROOT, f)
        cache[f] = open(p, errors="replace").read().split("\n") if os.path.exists(p) else None
    L = cache[f]
    a, _, b = rng.partition("-")
    a = int(a); b = int(b or a)
    if L is None:
        print("FAIL nofile", f, rng, where); bad += 1; continue
    if b > len(L):
        print("FAIL range", f, rng, "len", len(L), where); bad += 1; continue
    window = "\n".join(L[a - 1:b])
    if re.search(rx, window, re.M):
        print("OK  ", f, rng, where)
    else:
        print("FAIL", f, rng, "expected /%s/ got: %s" % (rx, L[a - 1].strip()[:90]), where); bad += 1
print("SUMMARY rows=%d fail=%d" % (len(ROWS), bad))
sys.exit(1 if bad else 0)
