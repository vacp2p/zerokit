#![cfg(not(target_arch = "wasm32"))]
// Proof for finding 20261125T042849-bc16c5/2.
//
// Spec:
//   "`PmTree<D, H>` persists the tree to disk and enables state durability across process
//    restarts."
//   init_tree_with_leaves(leaves): "Resets the tree state to default (keeping the current depth)
//    and initializes it with the provided leaves starting from index 0."
//   close(): "Closes the tree, flushing pending writes for persistent backends ... users MUST
//    call close() before exit to guarantee durability."
//
// `RLN::init_tree_with_leaves` replaces the tree with `T::default(depth)`. For `PmTree` that is a
// brand new *temporary* sled database, so the configured on-disk tree is neither reset nor
// written to again.

use std::path::PathBuf;

use rln::prelude::*;
use tempfile::TempDir;
use zerokit_utils::merkle_tree::ZerokitMerkleTree;

const DEPTH: usize = 4;

fn open(path: PathBuf) -> PmTree<SledDB, PoseidonHash> {
    let config = PmTreeSledConfig::new()
        .path(path)
        .temporary(false)
        .build()
        .unwrap();
    PmTree::<SledDB, PoseidonHash>::new(DEPTH, Fr::default(), config).unwrap()
}

#[test]
fn control_set_leaves_from_survives_close_and_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("db");

    let mut rln = RLNBuilder::stateful().tree(open(path.clone())).build();
    rln.set_leaves_from(0, vec![Fr::from(1u64), Fr::from(2u64)])
        .unwrap();
    let root = rln.get_root();
    rln.close().unwrap();
    drop(rln);

    let reopened = open(path);
    assert_eq!(reopened.root(), root);
    assert_eq!(reopened.leaves_set(), 2);
}

#[test]
fn init_tree_with_leaves_is_durable_on_persistent_pmtree() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("db");

    let old_leaves = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
    let new_leaves = vec![Fr::from(100u64), Fr::from(200u64)];

    let mut rln = RLNBuilder::stateful().tree(open(path.clone())).build();
    rln.set_leaves_from(0, old_leaves).unwrap();
    let old_root = rln.get_root();

    // Reset the membership set and initialise it with the new leaves.
    rln.init_tree_with_leaves(new_leaves.clone()).unwrap();
    let new_root = rln.get_root();
    assert_ne!(new_root, old_root);
    assert_eq!(rln.leaves_set(), 2);

    // Later writes must also be durable.
    rln.set_next_leaf(Fr::from(300u64)).unwrap();
    let final_root = rln.get_root();

    // Flush and "restart the process".
    rln.close().unwrap();
    drop(rln);

    let reopened = open(path);
    assert_ne!(
        reopened.root(),
        old_root,
        "after init_tree_with_leaves + close + reopen the persisted tree is still the OLD tree"
    );
    assert_eq!(
        reopened.root(),
        final_root,
        "state written after init_tree_with_leaves was not persisted to the configured database"
    );
    assert_eq!(reopened.leaves_set(), 3);
}
