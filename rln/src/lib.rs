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

use crate::circuit::{ZKEY,VK,CIRCOM};


#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol::*;
    use hex_literal::hex;
    use num_bigint::BigInt;
    use semaphore::{
        hash::Hash, hash_to_field, identity::Identity, poseidon_tree::PoseidonTree, Field, poseidon_hash
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

    #[test]
    fn test_end_to_end() {

        let TREE_HEIGHT = 16;
        let leafIndex = 3;

        // Generate identity
        // We follow zk-kit approach for identity generation
        let id = Identity::from_seed(b"hello");
        let identity_secret = poseidon_hash(&vec![id.trapdoor, id.nullifier]);
        let id_commitment = poseidon_hash(&vec![identity_secret]);

        //// generate merkle tree
        let leaf = Field::from(0);
        let mut tree = PoseidonTree::new(TREE_HEIGHT, leaf);
        tree.set(leafIndex, id_commitment.into());

        let merkle_proof = tree.proof(leafIndex).expect("proof should exist");

        let signal = b"hey hey";
        let x = hash_to_field(signal);

        // We set the remaining values to random ones
        let epoch = hash_to_field(b"test-epoch");
        let rln_identifier =hash_to_field(b"test-rln-identifier");

        let rlnWitness: RLNWitnessInput = initRLNWitnessFromValues(identity_secret, &merkle_proof, x, epoch, rln_identifier);

        println!("rlnWitness: {:#?}", rlnWitness);

        // We generate all relevant keys
        let provingKey = &ZKEY();
        let verificationKey = &VK(); 
        let mut builder = CIRCOM();
        
        // Let's generate a zkSNARK proof
        let (proof, inputs) = generate_proof(builder, provingKey, rlnWitness).unwrap();

        // Let's verify the proof
        let success = verify_proof(verificationKey, proof, inputs).unwrap();

        assert!(success);

}


        //to_str_radix(10);

//
        //// change signal_hash and external_nullifier_hash here
        //let signal_hash = hash_to_field(b"xxx");
        //let external_nullifier_hash = hash_to_field(b"appId");
//
        //let nullifier_hash = generate_nullifier_hash(&id, external_nullifier_hash);
//
        //
        //// We generate all relevant keys
        //let provingKey = &ZKEY();
        //let verificationKey = &VK(); 
        //let mut builder = CIRCOM();

        //println!("Proof: {:#?}", proof);
    }

