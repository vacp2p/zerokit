// Proof for finding 20261125T042849-bc16c5/1.
//
// Spec (Merkle Tree Management):
//   set_leaves_from(index, leaves): "If n leaves are passed, they will be set at positions index,
//   index + 1, ..., index + n - 1."
//   get_root(): "Returns the current Merkle tree root."
//   get_merkle_proof(index): "Returns the Merkle proof for the leaf at the specified index."
//
// `OptimalMerkleTree::set_range` does not re-hash every touched ancestor, so after a batch write
// the root (and the proofs) do not commit to all the leaves that were written.

use tiny_keccak::{Hasher as _, Keccak};
use zerokit_utils::merkle_tree::{
    FullMerkleTree, OptimalMerkleTree, ZerokitHasher, ZerokitMerkleTree,
};

#[derive(Clone, Copy, PartialEq)]
struct Keccak256;

#[derive(Debug, Clone, Copy, PartialEq, Default)]
struct TestFr([u8; 32]);

impl ZerokitHasher for Keccak256 {
    type Scalar = TestFr;

    fn hash(input: &[Self::Scalar]) -> Self::Scalar {
        let mut output = [0; 32];
        let mut hasher = Keccak::v256();
        for fr in input {
            hasher.update(fr.0.as_slice());
        }
        hasher.finalize(&mut output);
        TestFr(output)
    }
}

fn leaf(value: u8) -> TestFr {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    TestFr(bytes)
}

const DEPTH: usize = 4;

/// Reference root: the same leaves written one by one with `set` on the same backend.
fn root_one_by_one(start: usize, leaves: &[TestFr]) -> TestFr {
    let mut tree = OptimalMerkleTree::<Keccak256>::default(DEPTH).unwrap();
    for (offset, leaf) in leaves.iter().enumerate() {
        tree.set(start + offset, *leaf).unwrap();
    }
    tree.root()
}

#[test]
fn optimal_set_range_root_commits_to_every_written_leaf() {
    // Two leaves written at positions 3 and 4 of an empty depth-4 tree.
    let leaves = [leaf(1), leaf(2)];

    let mut optimal = OptimalMerkleTree::<Keccak256>::default(DEPTH).unwrap();
    optimal.set_range(3, leaves.into_iter()).unwrap();

    // The leaves are stored ...
    assert_eq!(optimal.get(3).unwrap(), leaves[0]);
    assert_eq!(optimal.get(4).unwrap(), leaves[1]);

    // ... so the "current Merkle tree root" must be the root of a tree holding them.
    let mut full = FullMerkleTree::<Keccak256>::default(DEPTH).unwrap();
    full.set_range(3, leaves.into_iter()).unwrap();
    assert_eq!(
        root_one_by_one(3, &leaves),
        full.root(),
        "control: set() one by one on OptimalMerkleTree agrees with FullMerkleTree"
    );

    assert_eq!(
        optimal.root(),
        root_one_by_one(3, &leaves),
        "OptimalMerkleTree::set_range(3, [a, b]) root differs from the root of the same leaves \
         written with set(): the batch write left a stale ancestor"
    );
}

#[test]
fn optimal_set_range_proof_verifies_for_written_leaf() {
    let leaves = [leaf(1), leaf(2)];
    let mut optimal = OptimalMerkleTree::<Keccak256>::default(DEPTH).unwrap();
    optimal.set_range(3, leaves.into_iter()).unwrap();

    // The Merkle proof of a leaf that was just written must open to the tree root.
    let proof = optimal.proof(4).unwrap();
    assert!(
        optimal.verify(&leaves[1], &proof).unwrap(),
        "proof for leaf 4 (written by set_range) does not verify against the tree's own root"
    );
}

#[test]
fn optimal_set_range_sweep_matches_one_by_one() {
    // Every (start, len) on a depth-4 tree: batch write must equal one-by-one writes.
    let capacity = 1usize << DEPTH;
    let mut mismatches = Vec::new();
    let mut total = 0usize;
    for start in 0..capacity {
        for len in 1..=(capacity - start) {
            total += 1;
            let leaves: Vec<TestFr> = (0..len).map(|i| leaf(i as u8 + 1)).collect();
            let mut optimal = OptimalMerkleTree::<Keccak256>::default(DEPTH).unwrap();
            optimal.set_range(start, leaves.clone().into_iter()).unwrap();
            if optimal.root() != root_one_by_one(start, &leaves) {
                mismatches.push((start, len));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} (start, len) batch writes produce a wrong root: {:?}",
        mismatches.len(),
        total,
        mismatches
    );
}
