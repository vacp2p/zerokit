#![cfg(not(feature = "stateless"))]

#[cfg(test)]
mod test {
    use ark_ff::BigInt;
    use rln::prelude::*;
    use zerokit_utils::merkle_tree::{ZerokitMerkleProof, ZerokitMerkleTree};

    type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

    #[test]
    // We test Merkle tree generation, proofs and verification
    fn test_merkle_proof() {
        let leaf_index = 3;

        // generate identity
        let identity_secret = hash_to_field_le(b"test-merkle-proof").unwrap();
        let id_commitment = poseidon_hash(&[identity_secret]).unwrap();
        let rate_commitment = poseidon_hash(&[id_commitment, 100.into()]).unwrap();

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

        let merkle_proof = tree.proof(leaf_index).unwrap();
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
        .map(|str| str_to_fr(str, 16).unwrap())
        .to_vec();

        let expected_identity_path_index: Vec<u8> =
            vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(path_elements, expected_path_elements);
        assert_eq!(identity_path_index, expected_identity_path_index);

        // We check correct verification of the proof
        assert!(tree.verify(&rate_commitment, &merkle_proof).unwrap());
    }

    fn get_test_witness_and_root() -> (RLNWitnessInput, Fr) {
        let leaf_index = 3;
        // Generate identity pair
        let (identity_secret, id_commitment) = keygen().unwrap();
        let user_message_limit = Fr::from(100);
        let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();

        //// generate merkle tree
        let default_leaf = Fr::from(0);
        let mut tree = PoseidonTree::new(
            DEFAULT_TREE_DEPTH,
            default_leaf,
            ConfigOf::<PoseidonTree>::default(),
        )
        .unwrap();
        tree.set(leaf_index, rate_commitment).unwrap();
        let root = tree.root();

        let merkle_proof = tree.proof(leaf_index).unwrap();

        let signal = b"hey hey";
        let x = hash_to_field_le(signal).unwrap();

        // We set the remaining values to random ones
        let epoch = hash_to_field_le(b"test-epoch").unwrap();
        let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
        let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();

        let message_id = Fr::from(1);

        RLNWitnessInput::new(
            identity_secret,
            user_message_limit,
            message_id,
            merkle_proof.get_path_elements(),
            merkle_proof.get_path_index(),
            x,
            external_nullifier,
        )
        .map(|witness| (witness, root))
        .unwrap()
    }

    fn get_test_witness() -> RLNWitnessInput {
        get_test_witness_and_root().0
    }

    fn get_test_witness_with_params(
        signal: &[u8],
        epoch: &[u8],
        rln_identifier: &[u8],
        message_id: u64,
        user_message_limit: u64,
    ) -> RLNWitnessInput {
        let leaf_index = 3;
        // Generate identity pair
        let (identity_secret, id_commitment) = keygen().unwrap();
        let user_message_limit = Fr::from(user_message_limit);
        let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();

        //// generate merkle tree
        let default_leaf = Fr::from(0);
        let mut tree = PoseidonTree::new(
            DEFAULT_TREE_DEPTH,
            default_leaf,
            ConfigOf::<PoseidonTree>::default(),
        )
        .unwrap();
        tree.set(leaf_index, rate_commitment).unwrap();

        let merkle_proof = tree.proof(leaf_index).unwrap();

        let x = hash_to_field_le(signal).unwrap();

        // We set the remaining values to random ones
        let epoch = hash_to_field_le(epoch).unwrap();
        let rln_identifier = hash_to_field_le(rln_identifier).unwrap();
        let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();

        let message_id = Fr::from(message_id);

        RLNWitnessInput::new(
            identity_secret,
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
        let graph_data = graph_from_folder();

        // Let's generate a zkSNARK proof
        let proof = generate_zk_proof(proving_key, &witness, graph_data).unwrap();

        let proof_values = proof_values_from_witness(&witness).unwrap();

        // Let's verify the proof
        let success = verify_zk_proof(&proving_key.0.vk, &proof, &proof_values).unwrap();

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
        let (deser, _) = bytes_le_to_rln_proof_values(&ser).unwrap();
        assert_eq!(proof_values, deser);
    }

    #[test]
    fn test_rln_witness_input_validation() {
        let leaf_index = 3;

        // generate identity
        let identity_secret_fr = hash_to_field_le(b"test-witness-validation").unwrap();
        let identity_secret = IdSecret::from(&mut identity_secret_fr.clone());
        let id_commitment = poseidon_hash(&[identity_secret_fr]).unwrap();
        let user_message_limit = Fr::from(100);
        let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();

        // generate merkle tree
        let default_leaf = Fr::from(0);
        let mut tree = PoseidonTree::new(
            DEFAULT_TREE_DEPTH,
            default_leaf,
            ConfigOf::<PoseidonTree>::default(),
        )
        .unwrap();
        tree.set(leaf_index, rate_commitment).unwrap();

        let merkle_proof = tree.proof(leaf_index).unwrap();
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        let signal = b"hey hey";
        let x = hash_to_field_le(signal).unwrap();
        let epoch = hash_to_field_le(b"test-epoch").unwrap();
        let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
        let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();

        // Test valid witness input
        let valid_message_id = Fr::from(50);
        let result = RLNWitnessInput::new(
            identity_secret.clone(),
            user_message_limit,
            valid_message_id,
            path_elements.clone(),
            identity_path_index.clone(),
            x,
            external_nullifier,
        );
        assert!(result.is_ok());

        // Test message_id >= user_message_limit (should fail)
        let invalid_message_id = Fr::from(100); // equal to limit
        let result = RLNWitnessInput::new(
            identity_secret.clone(),
            user_message_limit,
            invalid_message_id,
            path_elements.clone(),
            identity_path_index.clone(),
            x,
            external_nullifier,
        );
        assert!(matches!(result, Err(ProtocolError::InvalidMessageId(_, _))));

        let invalid_message_id = Fr::from(150); // greater than limit
        let result = RLNWitnessInput::new(
            identity_secret.clone(),
            user_message_limit,
            invalid_message_id,
            path_elements.clone(),
            identity_path_index.clone(),
            x,
            external_nullifier,
        );
        assert!(matches!(result, Err(ProtocolError::InvalidMessageId(_, _))));

        // Test user_message_limit = 0 (should fail)
        let zero_limit = Fr::from(0);
        let result = RLNWitnessInput::new(
            identity_secret,
            zero_limit,
            Fr::from(0),
            path_elements.clone(),
            identity_path_index.clone(),
            x,
            external_nullifier,
        );
        assert!(matches!(result, Err(ProtocolError::ZeroUserMessageLimit)));
    }

    #[test]
    // Tests seeded keygen
    // Note that hardcoded values are only valid for Bn254
    fn test_seeded_keygen() {
        // Generate identity pair using a seed phrase
        let seed_phrase: &str = "A seed phrase example";
        let (identity_secret, id_commitment) = seeded_keygen(seed_phrase.as_bytes()).unwrap();

        // We check against expected values
        let expected_identity_secret_seed_phrase = str_to_fr(
            "0x20df38f3f00496f19fe7c6535492543b21798ed7cb91aebe4af8012db884eda3",
            16,
        )
        .unwrap();
        let expected_id_commitment_seed_phrase = str_to_fr(
            "0x1223a78a5d66043a7f9863e14507dc80720a5602b2a894923e5b5147d5a9c325",
            16,
        )
        .unwrap();

        assert_eq!(identity_secret, expected_identity_secret_seed_phrase);
        assert_eq!(id_commitment, expected_id_commitment_seed_phrase);

        // Generate identity pair using an byte array
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let (identity_secret, id_commitment) = seeded_keygen(seed_bytes).unwrap();

        // We check against expected values
        let expected_identity_secret_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        )
        .unwrap();
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0xbf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f",
            16,
        )
        .unwrap();

        assert_eq!(identity_secret, expected_identity_secret_seed_bytes);
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes);

        // We check again if the identity pair generated with the same seed phrase corresponds to the previously generated one
        let (identity_secret, id_commitment) = seeded_keygen(seed_phrase.as_bytes()).unwrap();

        assert_eq!(identity_secret, expected_identity_secret_seed_phrase);
        assert_eq!(id_commitment, expected_id_commitment_seed_phrase);
    }

    #[test]
    fn test_extended_keygen_relations() {
        let (trapdoor, nullifier, identity_secret, id_commitment) = extended_keygen().unwrap();

        let expected_identity_secret = poseidon_hash(&[trapdoor, nullifier]).unwrap();
        let expected_id_commitment = poseidon_hash(&[identity_secret]).unwrap();

        assert_eq!(identity_secret, expected_identity_secret);
        assert_eq!(id_commitment, expected_id_commitment);
    }

    #[test]
    fn test_extended_seeded_keygen_determinism() {
        let seed = b"test-seed-extended";
        let first = extended_seeded_keygen(seed).unwrap();
        let second = extended_seeded_keygen(seed).unwrap();

        assert_eq!(first, second);

        let (trapdoor, nullifier, identity_secret, id_commitment) = first;
        let expected_identity_secret = poseidon_hash(&[trapdoor, nullifier]).unwrap();
        let expected_id_commitment = poseidon_hash(&[identity_secret]).unwrap();

        assert_eq!(identity_secret, expected_identity_secret);
        assert_eq!(id_commitment, expected_id_commitment);
    }

    #[test]
    fn test_witness_serialization_be_roundtrip_and_length_check() {
        // Test with default witness
        let witness = get_test_witness();
        let ser = rln_witness_to_bytes_be(&witness).unwrap();
        let (deser, _) = bytes_be_to_rln_witness(&ser).unwrap();
        assert_eq!(witness, deser);

        // Test with varied witness
        let witness2 = get_test_witness_with_params(
            b"different signal",
            b"another epoch",
            b"alt rln id",
            42,
            200,
        );
        let ser2 = rln_witness_to_bytes_be(&witness2).unwrap();
        let (deser2, _) = bytes_be_to_rln_witness(&ser2).unwrap();
        assert_eq!(witness2, deser2);

        // Test with extreme values (large message_id and limit)
        let witness3 = get_test_witness_with_params(
            b"extreme signal",
            b"extreme epoch",
            b"extreme id",
            1000000,
            2000000,
        );
        let ser3 = rln_witness_to_bytes_be(&witness3).unwrap();
        let (deser3, _) = bytes_be_to_rln_witness(&ser3).unwrap();
        assert_eq!(witness3, deser3);

        let mut bad = ser.clone();
        bad.push(0);
        assert!(matches!(
            bytes_be_to_rln_witness(&bad),
            Err(ProtocolError::InvalidReadLen(_, _))
        ));
    }

    #[test]
    fn test_proof_values_serialization_be_roundtrip() {
        // Test with default witness
        let witness = get_test_witness();
        let proof_values = proof_values_from_witness(&witness).unwrap();

        let ser = rln_proof_values_to_bytes_be(&proof_values);
        let (deser, _) = bytes_be_to_rln_proof_values(&ser).unwrap();

        assert_eq!(proof_values, deser);

        // Test with varied witness
        let witness2 = get_test_witness_with_params(b"another signal", b"epoch2", b"id2", 10, 150);
        let proof_values2 = proof_values_from_witness(&witness2).unwrap();

        let ser2 = rln_proof_values_to_bytes_be(&proof_values2);
        let (deser2, _) = bytes_be_to_rln_proof_values(&ser2).unwrap();

        assert_eq!(proof_values2, deser2);
    }

    #[test]
    fn test_rln_proof_serialization_be_roundtrip() {
        let witness = get_test_witness();
        let proving_key = zkey_from_folder();
        let graph_data = graph_from_folder();
        let proof = generate_zk_proof(proving_key, &witness, graph_data).unwrap();
        let proof_values = proof_values_from_witness(&witness).unwrap();

        let rln_proof = RLNProof {
            proof: proof.clone(),
            proof_values,
        };

        let ser = rln_proof_to_bytes_be(&rln_proof).unwrap();
        let (deser, _) = bytes_be_to_rln_proof(&ser).unwrap();

        assert_eq!(rln_proof.proof, deser.proof);
        assert_eq!(rln_proof.proof_values, deser.proof_values);
    }

    #[test]
    fn test_verify_zk_proof_with_modified_public_value_fails() {
        let witness = get_test_witness();
        let proving_key = zkey_from_folder();
        let graph_data = graph_from_folder();
        let proof = generate_zk_proof(proving_key, &witness, graph_data).unwrap();
        let mut proof_values = proof_values_from_witness(&witness).unwrap();

        proof_values.root += Fr::from(1u64);

        let verified = verify_zk_proof(&proving_key.0.vk, &proof, &proof_values).unwrap();
        assert!(!verified);
    }

    #[test]
    fn test_compute_tree_root_matches_merkle_tree_root() {
        // Test with default witness
        let (witness, root) = get_test_witness_and_root();

        let computed_root = compute_tree_root(
            witness.identity_secret(),
            witness.user_message_limit(),
            witness.path_elements(),
            witness.identity_path_index(),
        )
        .unwrap();

        assert_eq!(computed_root, root);

        // Test with varied witness
        let witness2 =
            get_test_witness_with_params(b"root test signal", b"root epoch", b"root id", 25, 300);
        let leaf_index = 3;
        let id_commitment = poseidon_hash(&[**witness2.identity_secret()]).unwrap();
        let rate_commitment =
            poseidon_hash(&[id_commitment, *witness2.user_message_limit()]).unwrap();
        let default_leaf = Fr::from(0);
        let mut tree = PoseidonTree::new(
            DEFAULT_TREE_DEPTH,
            default_leaf,
            ConfigOf::<PoseidonTree>::default(),
        )
        .unwrap();
        tree.set(leaf_index, rate_commitment).unwrap();
        let root2 = tree.root();

        let computed_root2 = compute_tree_root(
            witness2.identity_secret(),
            witness2.user_message_limit(),
            witness2.path_elements(),
            witness2.identity_path_index(),
        )
        .unwrap();

        assert_eq!(computed_root2, root2);
    }

    #[test]
    fn test_rln_witness_to_bigint_json_fields() {
        // Test with default witness
        let witness = get_test_witness();
        let json = rln_witness_to_bigint_json(&witness).unwrap();

        assert_eq!(
            json["identitySecret"].as_str().unwrap(),
            to_bigint(witness.identity_secret()).to_str_radix(10)
        );
        assert_eq!(
            json["userMessageLimit"].as_str().unwrap(),
            to_bigint(witness.user_message_limit()).to_str_radix(10)
        );
        assert_eq!(
            json["messageId"].as_str().unwrap(),
            to_bigint(witness.message_id()).to_str_radix(10)
        );
        assert_eq!(
            json["x"].as_str().unwrap(),
            to_bigint(witness.x()).to_str_radix(10)
        );
        assert_eq!(
            json["externalNullifier"].as_str().unwrap(),
            to_bigint(witness.external_nullifier()).to_str_radix(10)
        );

        assert_eq!(
            json["pathElements"].as_array().unwrap().len(),
            witness.path_elements().len()
        );
        assert_eq!(
            json["identityPathIndex"].as_array().unwrap().len(),
            witness.identity_path_index().len()
        );

        // Test with varied witness
        let witness2 =
            get_test_witness_with_params(b"json test signal", b"json epoch", b"json id", 99, 500);
        let json2 = rln_witness_to_bigint_json(&witness2).unwrap();

        assert_eq!(
            json2["identitySecret"].as_str().unwrap(),
            to_bigint(witness2.identity_secret()).to_str_radix(10)
        );
        assert_eq!(
            json2["userMessageLimit"].as_str().unwrap(),
            to_bigint(witness2.user_message_limit()).to_str_radix(10)
        );
        assert_eq!(
            json2["messageId"].as_str().unwrap(),
            to_bigint(witness2.message_id()).to_str_radix(10)
        );
        assert_eq!(
            json2["x"].as_str().unwrap(),
            to_bigint(witness2.x()).to_str_radix(10)
        );
        assert_eq!(
            json2["externalNullifier"].as_str().unwrap(),
            to_bigint(witness2.external_nullifier()).to_str_radix(10)
        );

        assert_eq!(
            json2["pathElements"].as_array().unwrap().len(),
            witness2.path_elements().len()
        );
        assert_eq!(
            json2["identityPathIndex"].as_array().unwrap().len(),
            witness2.identity_path_index().len()
        );
    }
}
