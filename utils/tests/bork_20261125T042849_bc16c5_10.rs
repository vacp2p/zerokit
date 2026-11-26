// Proof for finding 20261125T042849-bc16c5/10.
//
// Spec: get_merkle_proof(index): "Returns the Merkle proof for the leaf at the specified index."
// Spec: "All backends ... implement the common `ZerokitMerkleTree` trait".
//
// A depth-0 tree (one leaf, which is the root) is accepted by every backend's constructor.
// FullMerkleTree returns the empty proof for it; OptimalMerkleTree::proof underflows its level
// counter and panics (index out of bounds in release, subtraction overflow in debug).

use std::panic::{catch_unwind, AssertUnwindSafe};

use zerokit_utils::merkle_tree::{
    FullMerkleTree, OptimalMerkleTree, ZerokitHasher, ZerokitMerkleProof, ZerokitMerkleTree,
};

#[derive(Clone, Copy, PartialEq)]
struct XorHash;

impl ZerokitHasher for XorHash {
    type Scalar = u64;

    fn hash(input: &[Self::Scalar]) -> Self::Scalar {
        input.iter().fold(0x9e3779b97f4a7c15, |acc, v| {
            (acc ^ v).wrapping_mul(0x100000001b3)
        })
    }
}

#[test]
fn optimal_depth_zero_proof_does_not_panic() {
    // Control: FullMerkleTree handles the degenerate tree.
    let mut full = FullMerkleTree::<XorHash>::default(0).unwrap();
    full.set(0, 7).unwrap();
    let proof = full.proof(0).unwrap();
    assert_eq!(proof.length(), 0);
    assert!(full.verify(&7, &proof).unwrap());

    // OptimalMerkleTree accepts the same depth and the same write ...
    let mut optimal = OptimalMerkleTree::<XorHash>::default(0).unwrap();
    optimal.set(0, 7).unwrap();
    assert_eq!(optimal.root(), 7);

    // ... but asking for the proof must return Ok (or Err), never panic.
    let outcome = catch_unwind(AssertUnwindSafe(|| optimal.proof(0).map(|p| p.length())));
    assert!(
        outcome.is_ok(),
        "OptimalMerkleTree::proof(0) panicked on a depth-0 tree"
    );
    assert_eq!(outcome.unwrap().unwrap(), 0);
}
