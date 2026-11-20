// TEMPORARY reproducer for BUG-04 (T17). In-crate test: `resolve_key_store_arn`
// is pub(crate), so this file is compiled as a child module of
// `mpl/src/key_store/kms_ops.rs` in a throwaway copy of the crate (/tmp), by appending
//     #[cfg(test)] #[path = "zz_bugrepro_04.rs"] mod zz_bugrepro_04;
// to that copy's kms_ops.rs. The repository source is not modified.
//
// Re-check adaptation for main 620771c: same ARNs, same region, same
// observations. API changes only: module keystore -> key_store,
// resolve_keystore_arn(cfg, arn) -> resolve_key_store_arn(cfg, arn, branch_key_id),
// KmsConfiguration::MrDiscovery { region } -> MrDiscovery(MrDiscovery::builder().region(..).build()),
// KmsConfiguration::Discovery -> Discovery(Discovery::builder().build()).
use super::resolve_key_store_arn;
use crate::key_store::config::{Discovery, KmsConfiguration, MrDiscovery};

const SRK_EAST: &str = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
const MRK_EAST: &str = "arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab";
const BKID: &str = "bk";

fn mr_discovery(region: &str) -> KmsConfiguration {
    KmsConfiguration::MrDiscovery(MrDiscovery::builder().region(region).build().unwrap())
}

#[test]
fn mrdiscovery_rewrites_region_of_single_region_key() {
    let out = resolve_key_store_arn(&mr_discovery("us-west-2"), SRK_EAST, BKID);
    println!("REPRO BUG-04 MRDiscovery(us-west-2), record SRK  {SRK_EAST} -> {:?}", out.as_ref().map_err(|e| e.to_string()));
    // Control: an MRK record is expected to be rewritten.
    let out_mrk = resolve_key_store_arn(&mr_discovery("us-west-2"), MRK_EAST, BKID);
    println!("REPRO BUG-04 MRDiscovery(us-west-2), record MRK  {MRK_EAST} -> {:?}", out_mrk.as_ref().map_err(|e| e.to_string()));
    // Control: Discovery leaves the record ARN unchanged.
    let disc = KmsConfiguration::Discovery(Discovery::builder().build().unwrap());
    let out_disc = resolve_key_store_arn(&disc, SRK_EAST, BKID);
    println!("REPRO BUG-04 Discovery,              record SRK  {SRK_EAST} -> {:?}", out_disc.as_ref().map_err(|e| e.to_string()));
    println!(
        "REPRO BUG-04 SRK ARN changed by MRDiscovery: {}",
        out.as_deref().ok() != Some(SRK_EAST)
    );
}
