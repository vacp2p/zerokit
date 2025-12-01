#![cfg(not(feature = "stateless"))]

#[cfg(test)]
mod test {
    use ark_ff::BigInt;
    use rln::circuit::{graph_from_folder, zkey_from_folder};
    use rln::circuit::{Fr, DEFAULT_TREE_DEPTH};
    use rln::hashers::{hash_to_field_le, poseidon_hash};
    use rln::poseidon_tree::PoseidonTree;
    use rln::protocol::{
        bytes_le_to_rln_proof_values, bytes_le_to_rln_witness, generate_proof, keygen,
        proof_values_from_witness, rln_proof_values_to_bytes_le, rln_witness_to_bytes_le,
        seeded_keygen, verify_proof, RLNWitnessInput,
    };
    use rln::utils::str_to_fr;
    use utils::{ZerokitMerkleProof, ZerokitMerkleTree};

    type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

    #[test]
    // We test Merkle tree generation, proofs and verification
    fn test_merkle_proof() {
        let leaf_index = 3;

        // generate identity
        let identity_secret_hash = hash_to_field_le(b"test-merkle-proof");
        let id_commitment = poseidon_hash(&[identity_secret_hash]);
        let rate_commitment = poseidon_hash(&[id_commitment, 100.into()]);

        // generate merkle tree
        let default_leaf = Fr::from(0);
        let mut tree = PoseidonTree::new(
            DEFAULT_TREE_DEPTH,
            default_leaf,
            ConfigOf::<PoseidonTree>::default(),
        )
        .unwrap();
        tree.set(leaf_index, rate_commitment).unwrap();

        // We check correct computation of the root
        let root = tree.root();

        assert_eq!(
            root,
            BigInt([
                4939322235247991215,
                5110804094006647505,
                4427606543677101242,
                910933464535675827
            ])
            .into()
        );

        let merkle_proof = tree.proof(leaf_index).expect("proof should exist");
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        // We check correct computation of the path and indexes
        let expected_path_elements: Vec<Fr> = [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
            "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1",
            "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238",
            "0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a",
            "0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55",
            "0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78",
            "0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d",
            "0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61",
            "0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747",
            "0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2",
            "0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636",
            "0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a",
            "0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0",
            "0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c",
            "0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92",
            "0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323",
            "0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992",
            "0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f",
            "0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca",
        ]
        .map(|e| str_to_fr(e, 16).unwrap())
        .to_vec();

        let expected_identity_path_index: Vec<u8> =
            vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(path_elements, expected_path_elements);
        assert_eq!(identity_path_index, expected_identity_path_index);

        // We check correct verification of the proof
        assert!(tree.verify(&rate_commitment, &merkle_proof).unwrap());
    }

    fn get_test_witness() -> RLNWitnessInput {
        let leaf_index = 3;
        // Generate identity pair
        let (identity_secret_hash, id_commitment) = keygen();
        let user_message_limit = Fr::from(100);
        let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]);

        //// generate merkle tree
        let default_leaf = Fr::from(0);
        let mut tree = PoseidonTree::new(
            DEFAULT_TREE_DEPTH,
            default_leaf,
            ConfigOf::<PoseidonTree>::default(),
        )
        .unwrap();
        tree.set(leaf_index, rate_commitment).unwrap();

        let merkle_proof = tree.proof(leaf_index).expect("proof should exist");

        let signal = b"hey hey";
        let x = hash_to_field_le(signal);

        // We set the remaining values to random ones
        let epoch = hash_to_field_le(b"test-epoch");
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        let external_nullifier = poseidon_hash(&[epoch, rln_identifier]);

        let message_id = Fr::from(1);

        RLNWitnessInput::new(
            identity_secret_hash,
            user_message_limit,
            message_id,
            merkle_proof.get_path_elements(),
            merkle_proof.get_path_index(),
            x,
            external_nullifier,
        )
        .unwrap()
    }

    #[test]
    // We test a RLN proof generation and verification
    fn test_end_to_end() {
        let witness = get_test_witness();

        // We generate all relevant keys
        let proving_key = zkey_from_folder();
        let verification_key = &proving_key.0.vk;
        let graph_data = graph_from_folder();

        // Let's generate a zkSNARK proof
        let proof = generate_proof(proving_key, &witness, graph_data).unwrap();

        let proof_values = proof_values_from_witness(&witness).unwrap();

        // Let's verify the proof
        let success = verify_proof(verification_key, &proof, &proof_values).unwrap();

        assert!(success);
    }

    #[test]
    fn test_witness_serialization() {
        let witness = get_test_witness();

        // We test witness serialization
        let ser = rln_witness_to_bytes_le(&witness).unwrap();
        let (deser, _) = bytes_le_to_rln_witness(&ser).unwrap();
        assert_eq!(witness, deser);

        // We test Proof values serialization
        let proof_values = proof_values_from_witness(&witness).unwrap();
        let ser = rln_proof_values_to_bytes_le(&proof_values);
        let (deser, _) = bytes_le_to_rln_proof_values(&ser);
        assert_eq!(proof_values, deser);
    }

    #[test]
    // Tests seeded keygen
    // Note that hardcoded values are only valid for Bn254
    fn test_seeded_keygen() {
        // Generate identity pair using a seed phrase
        let seed_phrase: &str = "A seed phrase example";
        let (identity_secret_hash, id_commitment) = seeded_keygen(seed_phrase.as_bytes());

        // We check against expected values
        let expected_identity_secret_hash_seed_phrase = str_to_fr(
            "0x20df38f3f00496f19fe7c6535492543b21798ed7cb91aebe4af8012db884eda3",
            16,
        )
        .unwrap();
        let expected_id_commitment_seed_phrase = str_to_fr(
            "0x1223a78a5d66043a7f9863e14507dc80720a5602b2a894923e5b5147d5a9c325",
            16,
        )
        .unwrap();

        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_phrase
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_phrase);

        // Generate identity pair using an byte array
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let (identity_secret_hash, id_commitment) = seeded_keygen(seed_bytes);

        // We check against expected values
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        )
        .unwrap();
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0xbf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f",
            16,
        )
        .unwrap();

        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_bytes
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes);

        // We check again if the identity pair generated with the same seed phrase corresponds to the previously generated one
        let (identity_secret_hash, id_commitment) = seeded_keygen(seed_phrase.as_bytes());

        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_phrase
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_phrase);
    }
}
