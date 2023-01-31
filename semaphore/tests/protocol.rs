#[cfg(test)]
mod tests {
    use ark_bn254::Parameters;
    use ark_ec::bn::Bn;
    use ark_groth16::Proof as ArkProof;
    use rand::{Rng, SeedableRng as _};
    use rand_chacha::ChaChaRng;
    use semaphore::{hash_to_field, identity::Identity, poseidon_tree::PoseidonTree, Field};
    use semaphore_wrapper::protocol::{
        generate_nullifier_hash, generate_proof, generate_proof_rng, verify_proof, Proof,
    };
    use serde_json::json;

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

    fn arb_proof(seed: u64) -> Proof {
        // Deterministic randomness for testing
        let mut rng = ChaChaRng::seed_from_u64(seed);

        // generate identity
        let seed: [u8; 16] = rng.gen();
        let id = Identity::from_seed(&seed);

        // generate merkle tree
        let leaf = Field::from(0);
        let mut tree = PoseidonTree::new(21, leaf);
        tree.set(0, id.commitment());

        let merkle_proof = tree.proof(0).expect("proof should exist");

        let external_nullifier: [u8; 16] = rng.gen();
        let external_nullifier_hash = hash_to_field(&external_nullifier);

        let signal: [u8; 16] = rng.gen();
        let signal_hash = hash_to_field(&signal);

        generate_proof_rng(
            &id,
            &merkle_proof,
            external_nullifier_hash,
            signal_hash,
            &mut rng,
        )
        .unwrap()
    }

    #[test]
    fn test_proof_cast_roundtrip() {
        let proof = arb_proof(123);
        let ark_proof: ArkProof<Bn<Parameters>> = proof.into();
        let result: Proof = ark_proof.into();
        assert_eq!(proof, result);
    }

    #[test]
    fn test_proof_serialize() {
        let proof = arb_proof(456);
        let json = serde_json::to_value(&proof).unwrap();
        assert_eq!(
            json,
            json!([
                [
                    "0x249ae469686987ee9368da60dd177a8c42891c02f5760e955e590c79d55cfab2",
                    "0xf22e25870f49388459d388afb24dcf6ec11bb2d4def1e2ec26d6e42f373aad8"
                ],
                [
                    [
                        "0x17bd25dbd7436c30ea5b8a3a47aadf11ed646c4b25cc14a84ff8cbe0252ff1f8",
                        "0x1c140668c56688367416534d57b4a14e5a825efdd5e121a6a2099f6dc4cd277b"
                    ],
                    [
                        "0x26a8524759d969ea0682a092cf7a551697d81962d6c998f543f81e52d83e05e1",
                        "0x273eb3f796fd1807b9df9c6d769d983e3dabdc61677b75d48bb7691303b2c8dd"
                    ]
                ],
                [
                    "0x62715c53a0eb4c46dbb5f73f1fd7449b9c63d37c1ece65debc39b472065a90f",
                    "0x114f7becc66f1cd7a8b01c89db8233622372fc0b6fc037c4313bca41e2377fd9"
                ]
            ])
        );
    }
}
