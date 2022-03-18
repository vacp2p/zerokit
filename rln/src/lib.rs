#![allow(dead_code)]
#![allow(unused_imports)]

pub mod ffi;
pub mod public;

use ark_bn254::{Fr, Parameters};
use ark_ec::bn::Bn;

pub type Field = Fr;
pub type Groth16Proof = ark_groth16::Proof<Bn<Parameters>>;
pub type EthereumGroth16Proof = ark_circom::ethereum::Proof;

// RLN lib
pub mod merkle;
pub mod poseidon;

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use num_bigint::BigInt;
    use semaphore::{hash::Hash, identity::Identity, poseidon_tree::PoseidonTree, protocol::*};

    #[test]
    fn test_merkle_proof() {
        const LEAF: Hash = Hash::from_bytes_be(hex!(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));

        // generate identity
        let id = Identity::new(b"hello");

        // generate merkle tree
        let mut tree = PoseidonTree::new(21, LEAF);
        tree.set(0, id.commitment().into());

        let merkle_proof = tree.proof(0).expect("proof should exist");
        let root: Hash = tree.root().into();

        println!("Root: {:#}", root);
        println!("Merkle proof: {:#?}", merkle_proof);

        // TODO Expand this test to cover RLN end to end

        // // change signal and external_nullifier here
        // let signal = b"xxx";
        // let external_nullifier = b"appId";

        // let external_nullifier_hash = hash_external_nullifier(external_nullifier);
        // let nullifier_hash = generate_nullifier_hash(&id, external_nullifier_hash);

        // let proof = generate_proof(&id, &merkle_proof, external_nullifier, signal).unwrap();

        // let success =
        //     verify_proof(root, nullifier_hash, signal, external_nullifier, &proof).unwrap();
    }
}
