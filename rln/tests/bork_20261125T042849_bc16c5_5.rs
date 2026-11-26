#![cfg(not(target_arch = "wasm32"))]
// Proof for finding 20261125T042849-bc16c5/5.
//
// Spec: get_empty_leaves_indices(): "Returns the indices of the leaves set to the default value,
// up to the last set leaf."
//
// The backends answer from a "was written" bitmap, not from the leaf values: a leaf whose value
// IS the default value but that was written through set_leaf / set_leaves_from is not reported.
// PmTree rebuilds the bitmap from values on reopen, so the same tree gives two different answers
// before and after a restart.

use rln::prelude::*;
use tempfile::TempDir;
use zerokit_utils::merkle_tree::{FullMerkleTree, OptimalMerkleTree, ZerokitMerkleTree};

const DEPTH: usize = 4;

fn empty_indices<T>(tree: T) -> Vec<usize>
where
    T: ZerokitMerkleTree<Hasher = PoseidonHash>,
    T::Error: std::fmt::Debug,
{
    let mut rln = RLNBuilder::stateful().tree(tree).build();
    // Leaves 0 and 2 hold members, leaf 1 holds the default value.
    rln.set_leaves_from(0, vec![Fr::from(11u64), Fr::default(), Fr::from(33u64)])
        .unwrap();
    assert_eq!(rln.get_leaf(1).unwrap(), Fr::default());
    rln.get_empty_leaves_indices()
}

#[test]
fn leaf_holding_default_value_is_reported_empty_full() {
    let got = empty_indices(FullMerkleTree::<PoseidonHash>::default(DEPTH).unwrap());
    assert_eq!(got, vec![1], "FullMerkleTree: leaf 1 is set to the default value");
}

#[test]
fn leaf_holding_default_value_is_reported_empty_optimal() {
    let got = empty_indices(OptimalMerkleTree::<PoseidonHash>::default(DEPTH).unwrap());
    assert_eq!(got, vec![1], "OptimalMerkleTree: leaf 1 is set to the default value");
}

#[test]
fn pmtree_empty_indices_are_stable_across_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("db");
    let open = || {
        let config = PmTreeSledConfig::new()
            .path(path.clone())
            .temporary(false)
            .build()
            .unwrap();
        PmTree::<SledDB, PoseidonHash>::new(DEPTH, Fr::default(), config).unwrap()
    };

    let mut rln = RLNBuilder::stateful().tree(open()).build();
    rln.set_leaves_from(0, vec![Fr::from(11u64), Fr::default(), Fr::from(33u64)])
        .unwrap();
    let before = rln.get_empty_leaves_indices();
    rln.close().unwrap();
    drop(rln);

    let after = open().get_empty_leaves_indices();
    println!("PmTree empty indices before reopen: {before:?}, after reopen: {after:?}");
    assert_eq!(
        before, after,
        "PmTree reports different empty-leaf indices for the same persisted tree before and \
         after a restart"
    );
}
