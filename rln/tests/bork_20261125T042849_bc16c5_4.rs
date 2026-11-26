#![cfg(not(target_arch = "wasm32"))]
// Proof for finding 20261125T042849-bc16c5/4.
//
// Spec: "All backends ... implement the common `ZerokitMerkleTree` trait" and
//   set_leaves_from(index, leaves): "Updates `next_index` to `max(next_index, index + n)`."
//
// For n = 0 the three shipped backends disagree: OptimalMerkleTree moves `next_index` to
// `index`, FullMerkleTree and PmTree leave it untouched.

use rln::prelude::*;
use zerokit_utils::merkle_tree::{FullMerkleTree, OptimalMerkleTree, ZerokitMerkleTree};

const DEPTH: usize = 4;

fn leaves_set_after_empty_batch<T>(tree: T) -> (usize, Vec<usize>, usize)
where
    T: ZerokitMerkleTree<Hasher = PoseidonHash>,
    T::Error: std::fmt::Debug,
{
    let mut rln = RLNBuilder::stateful().tree(tree).build();
    rln.set_leaves_from(5, vec![]).unwrap();
    let leaves_set = rln.leaves_set();
    let empty = rln.get_empty_leaves_indices();
    // Where does the next member land?
    rln.set_next_leaf(Fr::from(7u64)).unwrap();
    let landed = (0..1 << DEPTH)
        .find(|&i| rln.get_leaf(i).unwrap() == Fr::from(7u64))
        .unwrap();
    (leaves_set, empty, landed)
}

#[test]
fn empty_set_leaves_from_is_the_same_on_every_backend() {
    let full = leaves_set_after_empty_batch(FullMerkleTree::<PoseidonHash>::default(DEPTH).unwrap());
    let optimal =
        leaves_set_after_empty_batch(OptimalMerkleTree::<PoseidonHash>::default(DEPTH).unwrap());
    let pm = leaves_set_after_empty_batch(PmTree::<SledDB, PoseidonHash>::default(DEPTH).unwrap());

    println!("full    (leaves_set, empty_indices, next leaf lands at) = {full:?}");
    println!("optimal (leaves_set, empty_indices, next leaf lands at) = {optimal:?}");
    println!("pmtree  (leaves_set, empty_indices, next leaf lands at) = {pm:?}");

    assert_eq!(full, pm, "FullMerkleTree and PmTree disagree");
    assert_eq!(
        optimal, full,
        "set_leaves_from(5, []) leaves a different next_index on OptimalMerkleTree than on \
         FullMerkleTree / PmTree"
    );
}
