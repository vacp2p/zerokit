#![cfg(not(target_arch = "wasm32"))]
// Proof for finding 20261125T042849-bc16c5/8.
//
// Spec: init_tree_with_leaves(leaves): "Resets the tree state to default (keeping the current
// depth) and initializes it with the provided leaves starting from index 0."
// Spec: set_metadata / get_metadata: "Stores and retrieves arbitrary application metadata in the
// RLN object."
//
// The method is implemented as `self.state.tree = T::default(depth)?` followed by
// `set_leaves_from(0, leaves)`. The spec does not say what happens to anything but the leaves;
// the code (a) discards the application metadata, (b) leaves an EMPTY tree behind when the
// leaves are rejected, and (c) swaps a caller-chosen default leaf for the type default.

use rln::prelude::*;
use zerokit_utils::merkle_tree::{FullMerkleConfig, FullMerkleTree, ZerokitMerkleTree};

const DEPTH: usize = 2;

#[test]
fn init_tree_with_leaves_keeps_application_metadata() {
    let tree = FullMerkleTree::<PoseidonHash>::default(DEPTH).unwrap();
    let mut rln = RLNBuilder::stateful().tree(tree).build();
    rln.set_metadata(b"chain-id=1;block=42").unwrap();

    rln.init_tree_with_leaves(vec![Fr::from(1u64)]).unwrap();

    assert_eq!(
        rln.get_metadata().unwrap(),
        b"chain-id=1;block=42".to_vec(),
        "metadata stored in the RLN object is gone after init_tree_with_leaves"
    );
}

#[test]
fn failed_init_tree_with_leaves_leaves_the_tree_untouched() {
    let tree = FullMerkleTree::<PoseidonHash>::default(DEPTH).unwrap();
    let mut rln = RLNBuilder::stateful().tree(tree).build();
    rln.set_leaves_from(0, vec![Fr::from(1u64), Fr::from(2u64)])
        .unwrap();
    let root_before = rln.get_root();

    // Five leaves do not fit in a depth-2 tree: the call is rejected ...
    let too_many: Vec<Fr> = (1..=5u64).map(Fr::from).collect();
    assert!(rln.init_tree_with_leaves(too_many).is_err());

    // ... and a rejected call should not have destroyed the membership set.
    assert_eq!(
        rln.get_root(),
        root_before,
        "init_tree_with_leaves returned Err but the tree was wiped (leaves_set = {})",
        rln.leaves_set()
    );
}

#[test]
fn init_tree_with_leaves_keeps_the_tree_default_leaf() {
    let default_leaf = Fr::from(5u64);
    let tree =
        FullMerkleTree::<PoseidonHash>::new(DEPTH, default_leaf, FullMerkleConfig::default())
            .unwrap();
    let mut rln = RLNBuilder::stateful().tree(tree).build();
    assert_eq!(rln.get_leaf(3).unwrap(), default_leaf);

    rln.init_tree_with_leaves(vec![Fr::from(1u64)]).unwrap();

    assert_eq!(
        rln.get_leaf(3).unwrap(),
        default_leaf,
        "the tree's default leaf changed across init_tree_with_leaves"
    );
}
