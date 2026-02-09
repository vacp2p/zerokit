#![cfg(not(feature = "stateless"))]

#[cfg(test)]
mod test {
    use ark_ff::BigInt;
    use rln::prelude::*;
    use zerokit_utils::merkle_tree::{ZerokitMerkleProof, ZerokitMerkleTree};

    type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

    fn new_single_message_witness(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        message_id: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: Fr,
        external_nullifier: Fr,
    ) -> Result<RLNWitnessInput, ProtocolError> {
        #[cfg(not(feature = "multi-message-id"))]
        {
            RLNWitnessInput::new(
                identity_secret,
                user_message_limit,
                message_id,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
            )
        }
        #[cfg(feature = "multi-message-id")]
        {
            RLNWitnessInput::new(
                identity_secret,
                user_message_limit,
                Some(message_id),
                None,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
                None,
            )
        }
    }

    #[test]
    // We test Merkle tree generation, proofs and verification
    fn test_merkle_proof() {
        let leaf_index = 3;

        // Generate identity
        let identity_secret = hash_to_field_le(b"test-merkle-proof").unwrap();
        let id_commitment = poseidon_hash(&[identity_secret]).unwrap();
        let rate_commitment = poseidon_hash(&[id_commitment, 100.into()]).unwrap();

        // Generate merkle tree
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

        // Generate merkle tree
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

        new_single_message_witness(
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

        // Generate merkle tree
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

        new_single_message_witness(
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

        // Generate a zkSNARK proof
        let proof = generate_zk_proof(proving_key, &witness, graph_data).unwrap();

        let proof_values = proof_values_from_witness(&witness).unwrap();

        // Verify the proof
        let success = verify_zk_proof(&proving_key.0.vk, &proof, &proof_values).unwrap();

        assert!(success);
    }

    #[test]
    fn test_witness_and_proof_values_serialization() {
        let witness = get_test_witness();

        // We test witness serialization
        let ser_le = rln_witness_to_bytes_le(&witness).unwrap();
        let (deser_le, _) = bytes_le_to_rln_witness(&ser_le).unwrap();
        assert_eq!(witness, deser_le);

        let ser_be = rln_witness_to_bytes_be(&witness).unwrap();
        let (deser_be, _) = bytes_be_to_rln_witness(&ser_be).unwrap();
        assert_eq!(witness, deser_be);

        // We test proof values serialization
        let proof_values = proof_values_from_witness(&witness).unwrap();

        let ser_le = rln_proof_values_to_bytes_le(&proof_values);
        let (deser_le, _) = bytes_le_to_rln_proof_values(&ser_le).unwrap();
        assert_eq!(proof_values, deser_le);

        let ser_be = rln_proof_values_to_bytes_be(&proof_values);
        let (deser_be, _) = bytes_be_to_rln_proof_values(&ser_be).unwrap();
        assert_eq!(proof_values, deser_be);
    }

    #[test]
    fn test_rln_witness_input_validation() {
        let leaf_index = 3;

        // Generate identity
        let identity_secret_fr = hash_to_field_le(b"test-witness-validation").unwrap();
        let identity_secret = IdSecret::from(&mut identity_secret_fr.clone());
        let id_commitment = poseidon_hash(&[identity_secret_fr]).unwrap();
        let user_message_limit = Fr::from(100);
        let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();

        // Generate merkle tree
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
        let result = new_single_message_witness(
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
        let result = new_single_message_witness(
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
        let result = new_single_message_witness(
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
        let result = new_single_message_witness(
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
        #[cfg(not(feature = "multi-message-id"))]
        assert_eq!(
            json["messageId"].as_str().unwrap(),
            to_bigint(witness.message_id()).to_str_radix(10)
        );
        #[cfg(feature = "multi-message-id")]
        assert_eq!(
            json["messageId"].as_str().unwrap(),
            to_bigint(witness.message_id().unwrap()).to_str_radix(10)
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
        #[cfg(not(feature = "multi-message-id"))]
        assert_eq!(
            json2["messageId"].as_str().unwrap(),
            to_bigint(witness2.message_id()).to_str_radix(10)
        );
        #[cfg(feature = "multi-message-id")]
        assert_eq!(
            json2["messageId"].as_str().unwrap(),
            to_bigint(witness2.message_id().unwrap()).to_str_radix(10)
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

    #[cfg(feature = "multi-message-id")]
    mod multi_message_id_test {
        use rln::prelude::*;
        use zerokit_utils::merkle_tree::{ZerokitMerkleProof, ZerokitMerkleTree};

        type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

        fn get_test_witness_multi_message_id() -> RLNWitnessInput {
            let leaf_index = 3;
            // Generate identity pair
            let (identity_secret, id_commitment) = keygen().unwrap();
            let user_message_limit = Fr::from(100);
            let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();

            // Generate merkle tree
            let default_leaf = Fr::from(0);
            let mut tree = PoseidonTree::new(
                DEFAULT_TREE_DEPTH,
                default_leaf,
                ConfigOf::<PoseidonTree>::default(),
            )
            .unwrap();
            tree.set(leaf_index, rate_commitment).unwrap();

            let merkle_proof = tree.proof(leaf_index).unwrap();

            let signal = b"hey hey";
            let x = hash_to_field_le(signal).unwrap();

            // We set the remaining values to random ones
            let epoch = hash_to_field_le(b"test-epoch").unwrap();
            let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
            let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();

            let message_ids = vec![Fr::from(0), Fr::from(1), Fr::from(2), Fr::from(3)];
            let selector_used = vec![false, true, true, false];

            RLNWitnessInput::new(
                identity_secret,
                user_message_limit,
                None,
                Some(message_ids),
                merkle_proof.get_path_elements(),
                merkle_proof.get_path_index(),
                x,
                external_nullifier,
                Some(selector_used),
            )
            .unwrap()
        }

        #[test]
        fn test_cross_mode_witness_and_proof_values_compatibility_hardcoded() {
            let witness_bytes_le: Vec<u8> = vec![
                0, 250, 172, 130, 183, 65, 46, 58, 75, 209, 157, 122, 161, 220, 32, 215, 212, 36,
                74, 147, 200, 229, 106, 193, 160, 5, 72, 28, 50, 2, 76, 0, 10, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 72, 182, 70, 132, 238, 57, 168, 35,
                213, 254, 95, 213, 36, 49, 220, 129, 228, 129, 123, 242, 195, 234, 60, 171, 158,
                35, 158, 251, 245, 152, 32, 225, 241, 177, 96, 68, 119, 164, 103, 240, 141, 198,
                157, 203, 68, 26, 38, 236, 167, 132, 245, 111, 26, 48, 223, 99, 34, 177, 205, 61,
                103, 105, 16, 56, 210, 86, 184, 178, 126, 213, 40, 213, 29, 55, 80, 234, 110, 124,
                70, 6, 33, 247, 80, 141, 117, 61, 46, 175, 226, 126, 83, 49, 51, 244, 24, 42, 149,
                188, 157, 85, 151, 172, 202, 101, 130, 86, 26, 87, 40, 183, 241, 69, 35, 165, 59,
                233, 255, 32, 99, 211, 176, 23, 203, 55, 216, 249, 7, 85, 63, 24, 57, 22, 236, 92,
                123, 77, 173, 178, 148, 140, 197, 153, 166, 7, 41, 243, 93, 76, 31, 99, 201, 245,
                179, 70, 135, 94, 207, 148, 43, 120, 157, 160, 46, 163, 221, 17, 29, 97, 83, 185,
                81, 105, 30, 215, 254, 188, 225, 169, 204, 34, 125, 234, 70, 150, 69, 102, 166,
                197, 147, 238, 45, 157, 52, 135, 60, 190, 170, 164, 168, 127, 172, 181, 140, 168,
                21, 5, 139, 123, 89, 57, 182, 30, 96, 207, 130, 233, 132, 43, 162, 229, 149, 130,
                7, 97, 204, 243, 153, 58, 190, 76, 68, 26, 33, 65, 74, 39, 46, 107, 97, 42, 71,
                100, 69, 134, 236, 27, 80, 166, 39, 96, 143, 241, 229, 165, 47, 71, 215, 252, 20,
                166, 86, 33, 62, 171, 40, 226, 227, 204, 122, 94, 228, 102, 31, 148, 158, 56, 128,
                183, 236, 33, 253, 216, 208, 118, 67, 136, 14, 242, 10, 25, 218, 229, 117, 97, 222,
                51, 53, 113, 87, 249, 146, 88, 249, 105, 180, 46, 165, 209, 122, 113, 40, 30, 79,
                73, 114, 218, 1, 114, 27, 54, 118, 125, 206, 250, 107, 188, 190, 181, 8, 8, 101,
                228, 225, 230, 166, 25, 152, 36, 1, 178, 192, 0, 82, 56, 54, 94, 114, 34, 136, 141,
                31, 90, 248, 181, 113, 4, 154, 135, 208, 168, 136, 207, 42, 161, 176, 98, 97, 251,
                252, 140, 186, 137, 21, 112, 185, 175, 75, 145, 108, 246, 130, 93, 44, 208, 191,
                191, 224, 112, 242, 88, 100, 100, 244, 19, 161, 170, 196, 245, 78, 19, 161, 63,
                223, 90, 127, 149, 32, 184, 11, 148, 160, 72, 65, 197, 20, 12, 232, 235, 244, 75,
                142, 17, 22, 212, 137, 173, 140, 88, 37, 190, 17, 175, 185, 216, 68, 238, 192, 16,
                30, 150, 111, 152, 47, 177, 51, 13, 25, 146, 108, 224, 37, 147, 100, 179, 165, 10,
                81, 175, 150, 101, 174, 103, 17, 237, 115, 173, 20, 73, 53, 23, 172, 82, 65, 112,
                206, 169, 138, 249, 34, 35, 115, 186, 139, 211, 83, 183, 248, 238, 204, 110, 198,
                41, 111, 82, 90, 87, 106, 191, 114, 141, 34, 111, 159, 11, 136, 229, 108, 155, 124,
                124, 42, 146, 185, 54, 63, 100, 221, 117, 77, 149, 139, 152, 194, 201, 67, 0, 71,
                252, 63, 70, 77, 193, 249, 122, 198, 193, 142, 105, 88, 229, 134, 129, 46, 15, 241,
                31, 28, 157, 36, 70, 53, 39, 146, 115, 100, 173, 110, 239, 138, 148, 174, 13, 5,
                207, 200, 226, 73, 171, 78, 154, 30, 87, 197, 87, 15, 202, 44, 247, 52, 97, 227,
                156, 60, 228, 70, 125, 105, 16, 227, 120, 254, 28, 14, 128, 136, 67, 61, 246, 213,
                74, 85, 251, 181, 103, 238, 48, 24, 20, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 157, 156, 85, 219, 237, 97, 120, 61, 199,
                114, 159, 166, 165, 175, 5, 38, 142, 119, 160, 164, 25, 143, 32, 26, 84, 136, 102,
                244, 226, 8, 90, 13, 207, 65, 218, 218, 160, 65, 118, 101, 213, 191, 148, 0, 185,
                201, 217, 241, 102, 5, 89, 211, 56, 216, 190, 237, 232, 127, 77, 192, 21, 114, 97,
                42,
            ];

            let proof_values_bytes_le: Vec<u8> = vec![
                93, 28, 108, 135, 66, 194, 206, 252, 96, 180, 193, 189, 24, 73, 112, 147, 144, 134,
                216, 47, 60, 15, 120, 218, 72, 214, 231, 210, 16, 144, 200, 15, 207, 65, 218, 218,
                160, 65, 118, 101, 213, 191, 148, 0, 185, 201, 217, 241, 102, 5, 89, 211, 56, 216,
                190, 237, 232, 127, 77, 192, 21, 114, 97, 42, 157, 156, 85, 219, 237, 97, 120, 61,
                199, 114, 159, 166, 165, 175, 5, 38, 142, 119, 160, 164, 25, 143, 32, 26, 84, 136,
                102, 244, 226, 8, 90, 13, 234, 125, 87, 38, 58, 105, 116, 245, 81, 147, 184, 57,
                54, 56, 38, 234, 228, 38, 23, 125, 133, 184, 254, 201, 242, 203, 227, 223, 8, 122,
                215, 33, 118, 44, 23, 40, 218, 209, 165, 117, 235, 20, 25, 138, 210, 30, 164, 71,
                207, 131, 181, 220, 165, 118, 2, 24, 121, 23, 74, 207, 133, 89, 66, 43,
            ];

            let witness_bytes_be: Vec<u8> = vec![
                46, 120, 78, 70, 77, 15, 99, 99, 96, 246, 156, 201, 223, 76, 5, 77, 119, 74, 251,
                203, 132, 202, 78, 205, 214, 47, 68, 187, 31, 232, 189, 77, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 152, 245, 251, 158, 35, 158, 171, 60,
                234, 195, 242, 123, 129, 228, 129, 220, 49, 36, 213, 95, 254, 213, 35, 168, 57,
                238, 132, 70, 182, 72, 100, 16, 105, 103, 61, 205, 177, 34, 99, 223, 48, 26, 111,
                245, 132, 167, 236, 38, 26, 68, 203, 157, 198, 141, 240, 103, 164, 119, 68, 96,
                177, 241, 225, 24, 244, 51, 49, 83, 126, 226, 175, 46, 61, 117, 141, 80, 247, 33,
                6, 70, 124, 110, 234, 80, 55, 29, 213, 40, 213, 126, 178, 184, 86, 210, 56, 7, 249,
                216, 55, 203, 23, 176, 211, 99, 32, 255, 233, 59, 165, 35, 69, 241, 183, 40, 87,
                26, 86, 130, 101, 202, 172, 151, 85, 157, 188, 149, 42, 43, 148, 207, 94, 135, 70,
                179, 245, 201, 99, 31, 76, 93, 243, 41, 7, 166, 153, 197, 140, 148, 178, 173, 77,
                123, 92, 236, 22, 57, 24, 63, 85, 45, 238, 147, 197, 166, 102, 69, 150, 70, 234,
                125, 34, 204, 169, 225, 188, 254, 215, 30, 105, 81, 185, 83, 97, 29, 17, 221, 163,
                46, 160, 157, 120, 7, 130, 149, 229, 162, 43, 132, 233, 130, 207, 96, 30, 182, 57,
                89, 123, 139, 5, 21, 168, 140, 181, 172, 127, 168, 164, 170, 190, 60, 135, 52, 157,
                47, 165, 229, 241, 143, 96, 39, 166, 80, 27, 236, 134, 69, 100, 71, 42, 97, 107,
                46, 39, 74, 65, 33, 26, 68, 76, 190, 58, 153, 243, 204, 97, 14, 136, 67, 118, 208,
                216, 253, 33, 236, 183, 128, 56, 158, 148, 31, 102, 228, 94, 122, 204, 227, 226,
                40, 171, 62, 33, 86, 166, 20, 252, 215, 71, 27, 114, 1, 218, 114, 73, 79, 30, 40,
                113, 122, 209, 165, 46, 180, 105, 249, 88, 146, 249, 87, 113, 53, 51, 222, 97, 117,
                229, 218, 25, 10, 242, 31, 141, 136, 34, 114, 94, 54, 56, 82, 0, 192, 178, 1, 36,
                152, 25, 166, 230, 225, 228, 101, 8, 8, 181, 190, 188, 107, 250, 206, 125, 118, 54,
                44, 93, 130, 246, 108, 145, 75, 175, 185, 112, 21, 137, 186, 140, 252, 251, 97, 98,
                176, 161, 42, 207, 136, 168, 208, 135, 154, 4, 113, 181, 248, 90, 20, 197, 65, 72,
                160, 148, 11, 184, 32, 149, 127, 90, 223, 63, 161, 19, 78, 245, 196, 170, 161, 19,
                244, 100, 100, 88, 242, 112, 224, 191, 191, 208, 25, 13, 51, 177, 47, 152, 111,
                150, 30, 16, 192, 238, 68, 216, 185, 175, 17, 190, 37, 88, 140, 173, 137, 212, 22,
                17, 142, 75, 244, 235, 232, 12, 34, 249, 138, 169, 206, 112, 65, 82, 172, 23, 53,
                73, 20, 173, 115, 237, 17, 103, 174, 101, 150, 175, 81, 10, 165, 179, 100, 147, 37,
                224, 108, 146, 42, 124, 124, 155, 108, 229, 136, 11, 159, 111, 34, 141, 114, 191,
                106, 87, 90, 82, 111, 41, 198, 110, 204, 238, 248, 183, 83, 211, 139, 186, 115, 35,
                46, 129, 134, 229, 88, 105, 142, 193, 198, 122, 249, 193, 77, 70, 63, 252, 71, 0,
                67, 201, 194, 152, 139, 149, 77, 117, 221, 100, 63, 54, 185, 146, 15, 87, 197, 87,
                30, 154, 78, 171, 73, 226, 200, 207, 5, 13, 174, 148, 138, 239, 110, 173, 100, 115,
                146, 39, 53, 70, 36, 157, 28, 31, 241, 15, 24, 48, 238, 103, 181, 251, 85, 74, 213,
                246, 61, 67, 136, 128, 14, 28, 254, 120, 227, 16, 105, 125, 70, 228, 60, 156, 227,
                97, 52, 247, 44, 202, 0, 0, 0, 0, 0, 0, 0, 20, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 13, 90, 8, 226, 244, 102, 136, 84, 26, 32, 143, 25, 164,
                160, 119, 142, 38, 5, 175, 165, 166, 159, 114, 199, 61, 120, 97, 237, 219, 85, 156,
                157, 42, 97, 114, 21, 192, 77, 127, 232, 237, 190, 216, 56, 211, 89, 5, 102, 241,
                217, 201, 185, 0, 148, 191, 213, 101, 118, 65, 160, 218, 218, 65, 207,
            ];

            let proof_values_bytes_be = vec![
                3, 248, 197, 50, 41, 130, 22, 102, 234, 24, 230, 111, 33, 207, 115, 85, 48, 133,
                189, 0, 139, 242, 140, 228, 56, 101, 12, 35, 250, 108, 108, 195, 42, 97, 114, 21,
                192, 77, 127, 232, 237, 190, 216, 56, 211, 89, 5, 102, 241, 217, 201, 185, 0, 148,
                191, 213, 101, 118, 65, 160, 218, 218, 65, 207, 13, 90, 8, 226, 244, 102, 136, 84,
                26, 32, 143, 25, 164, 160, 119, 142, 38, 5, 175, 165, 166, 159, 114, 199, 61, 120,
                97, 237, 219, 85, 156, 157, 27, 106, 229, 188, 94, 214, 48, 237, 15, 55, 242, 182,
                144, 115, 197, 70, 53, 147, 40, 96, 88, 28, 89, 98, 79, 174, 91, 156, 181, 221,
                160, 197, 28, 21, 75, 140, 250, 64, 135, 13, 250, 209, 11, 115, 95, 222, 156, 221,
                241, 19, 60, 86, 220, 115, 211, 245, 44, 125, 57, 82, 184, 53, 238, 67,
            ];

            assert!(bytes_le_to_rln_witness(&witness_bytes_le).is_ok());
            assert!(bytes_le_to_rln_proof_values(&proof_values_bytes_le).is_ok());

            assert!(bytes_be_to_rln_witness(&witness_bytes_be).is_ok());
            assert!(bytes_be_to_rln_proof_values(&proof_values_bytes_be).is_ok());
        }

        #[test]
        fn test_witness_and_proof_values_serialization() {
            let witness = get_test_witness_multi_message_id();

            // We test witness serialization
            let ser_le = rln_witness_to_bytes_le(&witness).unwrap();
            let (deser_le, _) = bytes_le_to_rln_witness(&ser_le).unwrap();
            assert_eq!(witness, deser_le);

            let ser_be = rln_witness_to_bytes_be(&witness).unwrap();
            let (deser_be, _) = bytes_be_to_rln_witness(&ser_be).unwrap();
            assert_eq!(witness, deser_be);

            // We test proof values serialization
            let proof_values = proof_values_from_witness(&witness).unwrap();

            let ser_le = rln_proof_values_to_bytes_le(&proof_values);
            let (deser_le, _) = bytes_le_to_rln_proof_values(&ser_le).unwrap();
            assert_eq!(proof_values, deser_le);

            let ser_be = rln_proof_values_to_bytes_be(&proof_values);
            let (deser_be, _) = bytes_be_to_rln_proof_values(&ser_be).unwrap();
            assert_eq!(proof_values, deser_be);
        }

        #[test]
        fn test_end_to_end() {
            let witness = get_test_witness_multi_message_id();

            // Load multi-message-id circuit resources
            let arkzkey_bytes =
                include_bytes!("../resources/tree_depth_20/multi_message_id/rln_final.arkzkey");
            let graph_bytes =
                include_bytes!("../resources/tree_depth_20/multi_message_id/graph.bin");

            let proving_key = zkey_from_raw(arkzkey_bytes).unwrap();
            let graph_data = graph_from_raw(graph_bytes, Some(DEFAULT_TREE_DEPTH)).unwrap();

            // Generate a zkSNARK proof
            let proof = generate_zk_proof(&proving_key, &witness, &graph_data).unwrap();

            let proof_values = proof_values_from_witness(&witness).unwrap();

            // Verify the proof
            let success = verify_zk_proof(&proving_key.0.vk, &proof, &proof_values).unwrap();

            assert!(success);
        }
    }
}
