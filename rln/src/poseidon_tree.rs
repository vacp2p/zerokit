// This crate defines the RLN module default Merkle tree implementation and its Hasher

// Implementation inspired by https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/poseidon_tree.rs (no differences)

use cfg_if::cfg_if;

// The zerokit RLN default Merkle tree implementation is the OptimalMerkleTree.
// To switch to FullMerkleTree implementation, it is enough to enable the fullmerkletree feature

cfg_if! {
    if #[cfg(feature = "fullmerkletree")] {

        use utils::{
            FullMerkleTree,
            FullMerkleProof,
        };
        use crate::hashers::PoseidonHash;

        pub type PoseidonTree = FullMerkleTree<PoseidonHash>;
        pub type MerkleProof = FullMerkleProof<PoseidonHash>;
    } else if #[cfg(feature = "pmtree-ft")] {
        use crate::pm_tree_adapter::{PmTree, PmTreeProof};

        pub type PoseidonTree =  PmTree;
        pub type MerkleProof = PmTreeProof;
    } else {

        use crate::hashers::{PoseidonHash};
        use utils::{
            OptimalMerkleTree,
            OptimalMerkleProof,
        };

        pub type PoseidonTree = OptimalMerkleTree<PoseidonHash>;
        pub type MerkleProof = OptimalMerkleProof<PoseidonHash>;
    }
}
