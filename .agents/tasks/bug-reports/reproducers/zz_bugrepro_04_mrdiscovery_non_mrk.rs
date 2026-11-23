// TEMPORARY reproducer for BUG-04 (T17). In-crate test: `resolve_keystore_arn`
// is pub(crate), so this file is compiled as a child module of
// `mpl/src/keystore/kms_ops.rs` in a throwaway copy of the crate, by appending
//     #[cfg(test)] #[path = "zz_bugrepro_04.rs"] mod zz_bugrepro_04;
// to that copy's kms_ops.rs. The repository source is not modified.
use super::resolve_keystore_arn;
use crate::keystore::KmsConfiguration;

const SRK_EAST: &str = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
const MRK_EAST: &str = "arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd-12ab-34cd-56ef-1234567890ab";

fn mr_discovery(region: &str) -> KmsConfiguration {
    KmsConfiguration::MrDiscovery { region: region.to_string() }
}

#[test]
fn mrdiscovery_rewrites_region_of_single_region_key() {
    let out = resolve_keystore_arn(&mr_discovery("us-west-2"), SRK_EAST);
    println!("REPRO BUG-04 MRDiscovery(us-west-2), record SRK  {SRK_EAST} -> {out:?}");
    // Control: an MRK record is expected to be rewritten.
    let out_mrk = resolve_keystore_arn(&mr_discovery("us-west-2"), MRK_EAST);
    println!("REPRO BUG-04 MRDiscovery(us-west-2), record MRK  {MRK_EAST} -> {out_mrk:?}");
    // Control: Discovery leaves the record ARN unchanged.
    let out_disc = resolve_keystore_arn(&KmsConfiguration::Discovery, SRK_EAST);
    println!("REPRO BUG-04 Discovery,              record SRK  {SRK_EAST} -> {out_disc:?}");
    println!(
        "REPRO BUG-04 SRK ARN changed by MRDiscovery: {}",
        out.as_deref().ok() != Some(SRK_EAST)
    );
}
