#![allow(clippy::multiple_crate_versions)]

pub mod circuit;
pub mod protocol;

#[cfg(feature = "dylib")]
pub use circuit::initialize;

#[cfg(test)]
mod tests {
    use crate::protocol::*;
    use semaphore::{hash_to_field, identity::Identity, poseidon_tree::PoseidonTree, Field};

    #[test]
    fn test_semaphore() {
        // generate identity
        let id = Identity::from_seed(b"secret");

        // generate merkle tree
        let leaf = Field::from(0);
        let mut tree = PoseidonTree::new(21, leaf);
        tree.set(0, id.commitment());

        let merkle_proof = tree.proof(0).expect("proof should exist");
        let root = tree.root().into();

        // change signal and external_nullifier here
        let signal_hash = hash_to_field(b"xxx");
        let external_nullifier_hash = hash_to_field(b"appId");

        let nullifier_hash = generate_nullifier_hash(&id, external_nullifier_hash);

        let proof =
            generate_proof(&id, &merkle_proof, external_nullifier_hash, signal_hash).unwrap();

        let success = verify_proof(
            root,
            nullifier_hash,
            signal_hash,
            external_nullifier_hash,
            &proof,
        )
        .unwrap();

        assert!(success);
    }
}
