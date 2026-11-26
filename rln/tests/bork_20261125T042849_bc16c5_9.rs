#![cfg(not(target_arch = "wasm32"))]
// Proof for finding 20261125T042849-bc16c5/9.
//
// Spec: "All backends ... implement the common `ZerokitMerkleTree` trait; applications pick one
// by constructing it and passing it to the builder", with the constructor shown as
// `PmTree::<SledDB, PoseidonHash>::new(DEFAULT_TREE_DEPTH, Fr::default(), config)`.
//
// The second argument is the tree's default leaf. FullMerkleTree and OptimalMerkleTree honour
// it; PmTree silently ignores it (`_default_leaf`) and always builds over the zero leaf.

use rln::prelude::*;
use zerokit_utils::merkle_tree::{
    FullMerkleConfig, FullMerkleTree, OptimalMerkleConfig, OptimalMerkleTree, ZerokitMerkleTree,
};

const DEPTH: usize = 4;

#[test]
fn pmtree_new_honours_the_default_leaf_argument() {
    let default_leaf = Fr::from(5u64);

    let full =
        FullMerkleTree::<PoseidonHash>::new(DEPTH, default_leaf, FullMerkleConfig::default())
            .unwrap();
    let optimal = OptimalMerkleTree::<PoseidonHash>::new(
        DEPTH,
        default_leaf,
        OptimalMerkleConfig::default(),
    )
    .unwrap();
    let pm = PmTree::<SledDB, PoseidonHash>::new(
        DEPTH,
        default_leaf,
        PmTreeSledConfig::new().temporary(true).build().unwrap(),
    )
    .unwrap();

    assert_eq!(full.root(), optimal.root(), "control: in-memory backends agree");
    assert_eq!(full.get(0).unwrap(), default_leaf);

    assert_eq!(
        pm.get(0).unwrap(),
        default_leaf,
        "PmTree::new(depth, default_leaf, config) ignored default_leaf"
    );
    assert_eq!(pm.root(), full.root());
}
