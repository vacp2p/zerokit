#![allow(dead_code)]
#![allow(unused_imports)]

pub mod ffi;
pub mod hash;
pub mod identity;
pub mod merkle_tree;
pub mod poseidon_tree;
pub mod public;
pub mod util;

pub mod poseidon;

#[cfg(test)]
mod test {
    use super::*;
    use hash::*;
    use identity::*;
    use poseidon_tree::*;
    // use protocol::*;

    // Adapted from https://github.com/worldcoin/semaphore-rs/blob/main/src/lib.rs
    #[test]
    fn test_merkle_proof() {
        //fn test_end_to_end() {
        // generate identity
        let id = Identity::new(b"secret");

        // generate merkle tree
        const LEAF: Hash = Hash::from_bytes_be([0u8; 32]);

        let mut tree = PoseidonTree::new(21, LEAF);
        let (_, leaf) = id.commitment().to_bytes_be();
        tree.set(0, leaf.into());

        let merkle_proof = tree.proof(0).expect("proof should exist");
        let root = tree.root();

        println!("Root: {:#}", root);
        println!("Merkle proof: {:#?}", merkle_proof);

        // change signal and external_nullifier here
        // let signal = "xxx".as_bytes();
        // let external_nullifier = "appId".as_bytes();

        // let external_nullifier_hash = hash_external_nullifier(external_nullifier);
        // let nullifier_hash = generate_nullifier_hash(&id, &external_nullifier_hash);

        // let config = SnarkFileConfig {
        //     zkey: "./semaphore/build/snark/semaphore_final.zkey".to_string(),
        //     wasm: "./semaphore/build/snark/semaphore.wasm".to_string(),
        // };

        // let proof =
        //     generate_proof(&config, &id, &merkle_proof, &external_nullifier_hash, signal).unwrap();

        // let success = verify_proof(
        //     &config,
        //     &root.into(),
        //     &nullifier_hash,
        //     signal,
        //     &external_nullifier_hash,
        //     &proof,
        // )
        // .unwrap();

        // assert!(success);
    }
}
