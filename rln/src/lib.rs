#![allow(dead_code)]
#![allow(unused_imports)]

pub mod ffi;
pub mod public;

use ark_bn254::{Fr, Parameters};
use ark_ec::bn::Bn;

pub mod circuit;
pub mod protocol;

pub type Field = Fr;
pub type Groth16Proof = ark_groth16::Proof<Bn<Parameters>>;
pub type EthereumGroth16Proof = ark_circom::ethereum::Proof;

// RLN lib
pub mod merkle;
pub mod poseidon;

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol::*;
    use hex_literal::hex;
    use num_bigint::BigInt;
    use semaphore::{
        hash::Hash, hash_to_field, identity::Identity, poseidon_tree::PoseidonTree, Field,
    };

    #[test]
    fn test_merkle_proof() {
        let leaf = Field::from(0);

        // generate identity
        let id = Identity::from_seed(b"hello");

        // generate merkle tree
        let mut tree = PoseidonTree::new(21, leaf);
        tree.set(0, id.commitment());

        let merkle_proof = tree.proof(0).expect("proof should exist");
        let root: Field = tree.root().into();

        println!("Root: {:#}", root);
        println!("Merkle proof: {:#?}", merkle_proof);
    }

    #[test]
    fn test_semaphore() {
        let leaf = Field::from(0);

        // generate identity
        let id = Identity::from_seed(b"hello");

        // generate merkle tree
        let mut tree = PoseidonTree::new(21, leaf);
        tree.set(0, id.commitment());

        let merkle_proof = tree.proof(0).expect("proof should exist");
        let root = tree.root().into();

        // change signal_hash and external_nullifier here
        let signal_hash = hash_to_field(b"xxx");
        let external_nullifier_hash = hash_to_field(b"appId");

        let nullifier_hash =
            semaphore::protocol::generate_nullifier_hash(&id, external_nullifier_hash);

        let proof = semaphore::protocol::generate_proof(
            &id,
            &merkle_proof,
            external_nullifier_hash,
            signal_hash,
        )
        .unwrap();

        let success = semaphore::protocol::verify_proof(
            root,
            nullifier_hash,
            signal_hash,
            external_nullifier_hash,
            &proof,
        )
        .unwrap();

        assert!(success);
    }

    #[ignore]
    #[test]
    fn test_end_to_end() {
        let leaf = Field::from(0);

        // generate identity
        let id = Identity::from_seed(b"hello");

        // generate merkle tree
        let mut tree = PoseidonTree::new(21, leaf);
        tree.set(0, id.commitment().into());

        let merkle_proof = tree.proof(0).expect("proof should exist");
        let root = tree.root().into();

        println!("Root: {:#}", root);
        println!("Merkle proof: {:#?}", merkle_proof);

        // change signal_hash and external_nullifier_hash here
        let signal_hash = hash_to_field(b"xxx");
        let external_nullifier_hash = hash_to_field(b"appId");

        let nullifier_hash = generate_nullifier_hash(&id, external_nullifier_hash);

        let proof =
            generate_proof(&id, &merkle_proof, external_nullifier_hash, signal_hash).unwrap();

        println!("Proof: {:#?}", proof);

        // TODO Make this test pass
        //
        // Currently fails at:
        // thread 'test::test_end_to_end' panicked at 'called `Result::unwrap()`
        // on an `Err` value: SynthesisError(MalformedVerifyingKey)',
        // rln/src/lib.rs:62:84
        //
        // Not sure why this is MalformedVerifyingKey, though the proof is
        // likely incorrect with wrong fields in protocol.rs
        //
        // Indeed:
        // if (public_inputs.len() + 1) != pvk.vk.gamma_abc_g1.len() {
        let success = verify_proof(
            root,
            nullifier_hash,
            signal_hash,
            external_nullifier_hash,
            &proof,
        )
        .unwrap();
    }
}
