// This crate defines the RLN module default Merkle tree implementation and its Hasher
// Implementation inspired by https://github.com/worldcoin/semaphore-rs/blob/d462a4372f1fd9c27610f2acfe4841fab1d396aa/src/poseidon_tree.rs

#![cfg(not(feature = "stateless"))]

use cfg_if::cfg_if;

// The zerokit RLN default Merkle tree implementation is the PMTree from the vacp2p_pmtree crate
// To switch to FullMerkleTree or OptimalMerkleTree, enable the corresponding feature in the Cargo.toml file

cfg_if! {
    if #[cfg(feature = "fullmerkletree")] {
        use utils::{FullMerkleTree, FullMerkleProof};
        use crate::hashers::PoseidonHash;

        pub type PoseidonTree = FullMerkleTree<PoseidonHash>;
        pub type MerkleProof = FullMerkleProof<PoseidonHash>;
    } else if #[cfg(feature = "optimalmerkletree")] {
        use utils::{OptimalMerkleTree, OptimalMerkleProof};
        use crate::hashers::PoseidonHash;

        pub type PoseidonTree = OptimalMerkleTree<PoseidonHash>;
        pub type MerkleProof = OptimalMerkleProof<PoseidonHash>;
    } else if #[cfg(feature = "pmtree-ft")] {
        use crate::pm_tree_adapter::{PmTree, PmTreeProof};

        pub type PoseidonTree = PmTree;
        pub type MerkleProof = PmTreeProof;
    } else {
        compile_error!("One of the features `fullmerkletree`, `optimalmerkletree`, or `pmtree-ft` must be enabled.");
    }
}
