#![cfg(not(target_arch = "wasm32"))]
// Proof for finding 20261125T042849-bc16c5/6.
//
// Spec: leaves_set(): "Returns the number of leaves that have been set in the tree."
//
// Every backend returns `next_index` (highest written index + 1) instead: gaps are counted,
// and deleted leaves keep being counted.

use rln::prelude::*;
use zerokit_utils::merkle_tree::{FullMerkleTree, OptimalMerkleTree, ZerokitMerkleTree};

const DEPTH: usize = 4;

fn leaves_set_after_one_leaf<T>(tree: T) -> usize
where
    T: ZerokitMerkleTree<Hasher = PoseidonHash>,
    T::Error: std::fmt::Debug,
{
    let mut rln = RLNBuilder::stateful().tree(tree).build();
    // Exactly one leaf is set in the whole tree.
    rln.set_leaf(5, Fr::from(42u64)).unwrap();
    rln.leaves_set()
}

#[test]
fn leaves_set_counts_the_leaves_that_have_been_set() {
    let full = leaves_set_after_one_leaf(FullMerkleTree::<PoseidonHash>::default(DEPTH).unwrap());
    let optimal =
        leaves_set_after_one_leaf(OptimalMerkleTree::<PoseidonHash>::default(DEPTH).unwrap());
    let pm = leaves_set_after_one_leaf(PmTree::<SledDB, PoseidonHash>::default(DEPTH).unwrap());

    assert_eq!(
        (full, optimal, pm),
        (1, 1, 1),
        "one leaf was set (at index 5); leaves_set() on (Full, Optimal, PmTree) must be 1"
    );
}
