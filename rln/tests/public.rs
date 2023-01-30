#[cfg(test)]
mod test {
    use crate::poseidon_hash::poseidon_hash;
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;

    #[test]
    // We test merkle batch Merkle tree additions
    fn test_merkle_operations() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // We create a new tree
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // We first add leaves one by one specifying the index
        for (i, leaf) in leaves.iter().enumerate() {
            // We check if the number of leaves set is consistent
            assert_eq!(rln.tree.leaves_set(), i);

            let mut buffer = Cursor::new(fr_to_bytes_le(&leaf));
            rln.set_leaf(i, &mut buffer).unwrap();
        }

        // We get the root of the tree obtained adding one leaf per time
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_single, _) = bytes_le_to_fr(&buffer.into_inner());

        // We reset the tree to default
        rln.set_tree(tree_height).unwrap();

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let mut buffer = Cursor::new(fr_to_bytes_le(&leaf));
            rln.set_next_leaf(&mut buffer).unwrap();
        }

        // We check if numbers of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        // We get the root of the tree obtained adding leaves using the internal index
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_next, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(root_single, root_next);

        // We reset the tree to default
        rln.set_tree(tree_height).unwrap();

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // We check if number of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        // We get the root of the tree obtained adding leaves in batch
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_batch, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(root_single, root_batch);

        // We now delete all leaves set and check if the root corresponds to the empty tree root
        // delete calls over indexes higher than no_of_leaves are ignored and will not increase self.tree.next_index
        for i in 0..2 * no_of_leaves {
            rln.delete_leaf(i).unwrap();
        }

        // We check if number of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_delete, _) = bytes_le_to_fr(&buffer.into_inner());

        // We reset the tree to default
        rln.set_tree(tree_height).unwrap();

        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_empty, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(root_delete, root_empty);
    }

    #[test]
    // We test leaf setting with a custom index, to enable batch updates to the root
    // Uses `set_leaves_from` to set leaves in a batch, from index `start_index`
    fn test_leaf_setting_with_index() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // set_index is the index from which we start setting leaves
        // random number between 0..no_of_leaves
        let set_index = rng.gen_range(0..no_of_leaves) as usize;

        // We create a new tree
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // We check if number of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        // We get the root of the tree obtained adding leaves in batch
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_batch_with_init, _) = bytes_le_to_fr(&buffer.into_inner());

        // `init_tree_with_leaves` resets the tree to the height it was initialized with, using `set_tree`

        // We add leaves in a batch starting from index 0..set_index
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves[0..set_index]));
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // We add the remaining n leaves in a batch starting from index m
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves[set_index..]));
        rln.set_leaves_from(set_index, &mut buffer).unwrap();

        // We check if number of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        // We get the root of the tree obtained adding leaves in batch
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_batch_with_custom_index, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(root_batch_with_init, root_batch_with_custom_index);

        // We reset the tree to default
        rln.set_tree(tree_height).unwrap();

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let mut buffer = Cursor::new(fr_to_bytes_le(&leaf));
            rln.set_next_leaf(&mut buffer).unwrap();
        }

        // We check if numbers of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), no_of_leaves);

        // We get the root of the tree obtained adding leaves using the internal index
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_single_additions, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(root_batch_with_init, root_single_additions);
    }

    #[test]
    // This test checks if `set_leaves_from` throws an error when the index is out of bounds
    fn test_set_leaves_bad_index() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }
        let bad_index = (1 << tree_height) - rng.gen_range(0..no_of_leaves) as usize;

        // We create a new tree
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // Get root of empty tree
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_empty, _) = bytes_le_to_fr(&buffer.into_inner());

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
        rln.set_leaves_from(bad_index, &mut buffer)
            .expect_err("Should throw an error");

        // We check if number of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), 0);

        // Get the root of the tree
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root_after_bad_set, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(root_empty, root_after_bad_set);
    }

    #[test]
    // This test is similar to the one in lib, but uses only public API
    fn test_merkle_proof() {
        let tree_height = TEST_TREE_HEIGHT;
        let leaf_index = 3;

        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // generate identity
        let identity_secret_hash = hash_to_field(b"test-merkle-proof");
        let id_commitment = poseidon_hash(&vec![identity_secret_hash]);

        // We pass id_commitment as Read buffer to RLN's set_leaf
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
        rln.set_leaf(leaf_index, &mut buffer).unwrap();

        // We check correct computation of the root
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root, _) = bytes_le_to_fr(&buffer.into_inner());

        if TEST_TREE_HEIGHT == 15 {
            assert_eq!(
                root,
                str_to_fr(
                    "0x1984f2e01184aef5cb974640898a5f5c25556554e2b06d99d4841badb8b198cd",
                    16
                )
            );
        } else if TEST_TREE_HEIGHT == 19 {
            assert_eq!(
                root,
                str_to_fr(
                    "0x219ceb53f2b1b7a6cf74e80d50d44d68ecb4a53c6cc65b25593c8d56343fb1fe",
                    16
                )
            );
        } else if TEST_TREE_HEIGHT == 20 {
            assert_eq!(
                root,
                str_to_fr(
                    "0x21947ffd0bce0c385f876e7c97d6a42eec5b1fe935aab2f01c1f8a8cbcc356d2",
                    16
                )
            );
        }

        // We check correct computation of merkle proof
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_proof(leaf_index, &mut buffer).unwrap();

        let buffer_inner = buffer.into_inner();
        let (path_elements, read) = bytes_le_to_vec_fr(&buffer_inner);
        let (identity_path_index, _) = bytes_le_to_vec_u8(&buffer_inner[read..].to_vec());

        // We check correct computation of the path and indexes
        let mut expected_path_elements = vec![
            str_to_fr(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                16,
            ),
            str_to_fr(
                "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
                16,
            ),
            str_to_fr(
                "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1",
                16,
            ),
            str_to_fr(
                "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238",
                16,
            ),
            str_to_fr(
                "0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a",
                16,
            ),
            str_to_fr(
                "0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55",
                16,
            ),
            str_to_fr(
                "0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78",
                16,
            ),
            str_to_fr(
                "0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d",
                16,
            ),
            str_to_fr(
                "0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61",
                16,
            ),
            str_to_fr(
                "0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747",
                16,
            ),
            str_to_fr(
                "0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2",
                16,
            ),
            str_to_fr(
                "0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636",
                16,
            ),
            str_to_fr(
                "0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a",
                16,
            ),
            str_to_fr(
                "0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0",
                16,
            ),
            str_to_fr(
                "0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c",
                16,
            ),
        ];

        let mut expected_identity_path_index: Vec<u8> =
            vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        // We add the remaining elements for the case TEST_TREE_HEIGHT = 20
        if TEST_TREE_HEIGHT == 19 || TEST_TREE_HEIGHT == 20 {
            expected_path_elements.append(&mut vec![
                str_to_fr(
                    "0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92",
                    16,
                ),
                str_to_fr(
                    "0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323",
                    16,
                ),
                str_to_fr(
                    "0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992",
                    16,
                ),
                str_to_fr(
                    "0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f",
                    16,
                ),
            ]);
            expected_identity_path_index.append(&mut vec![0, 0, 0, 0]);
        }

        if TEST_TREE_HEIGHT == 20 {
            expected_path_elements.append(&mut vec![str_to_fr(
                "0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca",
                16,
            )]);
            expected_identity_path_index.append(&mut vec![0]);
        }

        assert_eq!(path_elements, expected_path_elements);
        assert_eq!(identity_path_index, expected_identity_path_index);

        // We double check that the proof computed from public API is correct
        let root_from_proof =
            compute_tree_root(&id_commitment, &path_elements, &identity_path_index, false);

        assert_eq!(root, root_from_proof);
    }

    #[test]
    // This test is similar to the one in lib, but uses only public API
    fn test_groth16_proof() {
        let tree_height = TEST_TREE_HEIGHT;

        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // Note: we only test Groth16 proof generation, so we ignore setting the tree in the RLN object
        let rln_witness = random_rln_witness(tree_height);
        let proof_values = proof_values_from_witness(&rln_witness);

        // We compute a Groth16 proof
        let mut input_buffer = Cursor::new(serialize_witness(&rln_witness));
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.prove(&mut input_buffer, &mut output_buffer).unwrap();
        let serialized_proof = output_buffer.into_inner();

        // Before checking public verify API, we check that the (deserialized) proof generated by prove is actually valid
        let proof = ArkProof::deserialize(&mut Cursor::new(&serialized_proof)).unwrap();
        let verified = verify_proof(
            &rln.verification_key.as_ref().unwrap(),
            &proof,
            &proof_values,
        );
        assert!(verified.unwrap());

        // We prepare the input to prove API, consisting of serialized_proof (compressed, 4*32 bytes) || serialized_proof_values (6*32 bytes)
        let serialized_proof_values = serialize_proof_values(&proof_values);
        let mut verify_data = Vec::<u8>::new();
        verify_data.extend(&serialized_proof);
        verify_data.extend(&serialized_proof_values);
        let mut input_buffer = Cursor::new(verify_data);

        // We verify the Groth16 proof against the provided proof values
        let verified = rln.verify(&mut input_buffer).unwrap();

        assert!(verified);
    }

    #[test]
    fn test_rln_proof() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // We create a new RLN instance
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // Generate identity pair
        let (identity_secret_hash, id_commitment) = keygen();

        // We set as leaf id_commitment after storing its index
        let identity_index = u64::try_from(rln.tree.leaves_set()).unwrap();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
        rln.set_next_leaf(&mut buffer).unwrap();

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();
        let signal_len = u64::try_from(signal.len()).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut fr_to_bytes_le(&identity_secret_hash));
        serialized.append(&mut identity_index.to_le_bytes().to_vec());
        serialized.append(&mut fr_to_bytes_le(&epoch));
        serialized.append(&mut signal_len.to_le_bytes().to_vec());
        serialized.append(&mut signal.to_vec());

        let mut input_buffer = Cursor::new(serialized);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
            .unwrap();

        // output_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> ]
        let mut proof_data = output_buffer.into_inner();

        // We prepare input for verify_rln_proof API
        // input_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> | signal_len<8> | signal<var> ]
        // that is [ proof_data || signal_len<8> | signal<var> ]
        proof_data.append(&mut signal_len.to_le_bytes().to_vec());
        proof_data.append(&mut signal.to_vec());

        let mut input_buffer = Cursor::new(proof_data);
        let verified = rln.verify_rln_proof(&mut input_buffer).unwrap();

        assert!(verified);
    }

    #[test]
    fn test_rln_with_witness() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // We create a new RLN instance
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // Generate identity pair
        let (identity_secret_hash, id_commitment) = keygen();

        // We set as leaf id_commitment after storing its index
        let identity_index = u64::try_from(rln.tree.leaves_set()).unwrap();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
        rln.set_next_leaf(&mut buffer).unwrap();

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();
        let signal_len = u64::try_from(signal.len()).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut fr_to_bytes_le(&identity_secret_hash));
        serialized.append(&mut identity_index.to_le_bytes().to_vec());
        serialized.append(&mut fr_to_bytes_le(&epoch));
        serialized.append(&mut signal_len.to_le_bytes().to_vec());
        serialized.append(&mut signal.to_vec());

        let mut input_buffer = Cursor::new(serialized);

        // We read input RLN witness and we deserialize it
        let mut witness_byte: Vec<u8> = Vec::new();
        input_buffer.read_to_end(&mut witness_byte).unwrap();
        let (rln_witness, _) = proof_inputs_to_rln_witness(&mut rln.tree, &witness_byte);

        let serialized_witness = serialize_witness(&rln_witness);

        // Calculate witness outside zerokit (simulating what JS is doing)
        let inputs = inputs_for_witness_calculation(&rln_witness)
            .into_iter()
            .map(|(name, values)| (name.to_string(), values));
        let calculated_witness = rln
            .witness_calculator
            .lock()
            .expect("witness_calculator mutex should not get poisoned")
            .calculate_witness_element::<Curve, _>(inputs, false)
            .map_err(ProofError::WitnessError)
            .unwrap();

        let calculated_witness_vec: Vec<BigInt> = calculated_witness
            .into_iter()
            .map(|v| to_bigint(&v))
            .collect();

        // Generating the proof
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.generate_rln_proof_with_witness(
            calculated_witness_vec,
            serialized_witness,
            &mut output_buffer,
        )
            .unwrap();

        // output_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> ]
        let mut proof_data = output_buffer.into_inner();

        // We prepare input for verify_rln_proof API
        // input_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> | signal_len<8> | signal<var> ]
        // that is [ proof_data || signal_len<8> | signal<var> ]
        proof_data.append(&mut signal_len.to_le_bytes().to_vec());
        proof_data.append(&mut signal.to_vec());

        let mut input_buffer = Cursor::new(proof_data);
        let verified = rln.verify_rln_proof(&mut input_buffer).unwrap();

        assert!(verified);
    }

    #[test]
    fn test_seeded_keygen() {
        let rln = RLN::default();

        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let mut input_buffer = Cursor::new(&seed_bytes);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        rln.seeded_key_gen(&mut input_buffer, &mut output_buffer)
            .unwrap();
        let serialized_output = output_buffer.into_inner();

        let (identity_secret_hash, read) = bytes_le_to_fr(&serialized_output);
        let (id_commitment, _) = bytes_le_to_fr(&serialized_output[read..].to_vec());

        // We check against expected values
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        );
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0xbf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f",
            16,
        );

        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_bytes
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes);
    }

    #[test]
    fn test_seeded_extended_keygen() {
        let rln = RLN::default();

        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let mut input_buffer = Cursor::new(&seed_bytes);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        rln.seeded_extended_key_gen(&mut input_buffer, &mut output_buffer)
            .unwrap();
        let serialized_output = output_buffer.into_inner();

        let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
            deserialize_identity_tuple(serialized_output);

        // We check against expected values
        let expected_identity_trapdoor_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        );
        let expected_identity_nullifier_seed_bytes = str_to_fr(
            "0x1f18714c7bc83b5bca9e89d404cf6f2f585bc4c0f7ed8b53742b7e2b298f50b4",
            16,
        );
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x2aca62aaa7abaf3686fff2caf00f55ab9462dc12db5b5d4bcf3994e671f8e521",
            16,
        );
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0x68b66aa0a8320d2e56842581553285393188714c48f9b17acd198b4f1734c5c",
            16,
        );

        assert_eq!(identity_trapdoor, expected_identity_trapdoor_seed_bytes);
        assert_eq!(identity_nullifier, expected_identity_nullifier_seed_bytes);
        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_bytes
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes);
    }

    #[test]
    fn test_hash_to_field() {
        let rln = RLN::default();

        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        let mut input_buffer = Cursor::new(&signal);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        rln.hash(&mut input_buffer, &mut output_buffer).unwrap();
        let serialized_hash = output_buffer.into_inner();
        let (hash1, _) = bytes_le_to_fr(&serialized_hash);

        let hash2 = hash_to_field(&signal);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn proof_verification_with_roots() {
        // The first part is similar to test_rln_with_witness
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // We create a new RLN instance
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // We add leaves in a batch into the tree
        let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves));
        rln.init_tree_with_leaves(&mut buffer).unwrap();

        // Generate identity pair
        let (identity_secret_hash, id_commitment) = keygen();

        // We set as leaf id_commitment after storing its index
        let identity_index = u64::try_from(rln.tree.leaves_set()).unwrap();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
        rln.set_next_leaf(&mut buffer).unwrap();

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();
        let signal_len = u64::try_from(signal.len()).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut fr_to_bytes_le(&identity_secret_hash));
        serialized.append(&mut identity_index.to_le_bytes().to_vec());
        serialized.append(&mut fr_to_bytes_le(&epoch));
        serialized.append(&mut signal_len.to_le_bytes().to_vec());
        serialized.append(&mut signal.to_vec());

        let mut input_buffer = Cursor::new(serialized);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
            .unwrap();

        // output_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> ]
        let mut proof_data = output_buffer.into_inner();

        // We prepare input for verify_rln_proof API
        // input_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> | signal_len<8> | signal<var> ]
        // that is [ proof_data || signal_len<8> | signal<var> ]
        proof_data.append(&mut signal_len.to_le_bytes().to_vec());
        proof_data.append(&mut signal.to_vec());
        let input_buffer = Cursor::new(proof_data);

        // If no roots is provided, proof validation is skipped and if the remaining proof values are valid, the proof will be correctly verified
        let mut roots_serialized: Vec<u8> = Vec::new();
        let mut roots_buffer = Cursor::new(roots_serialized.clone());
        let verified = rln
            .verify_with_roots(&mut input_buffer.clone(), &mut roots_buffer)
            .unwrap();

        assert!(verified);

        // We serialize in the roots buffer some random values and we check that the proof is not verified since doesn't contain the correct root the proof refers to
        for _ in 0..5 {
            roots_serialized.append(&mut fr_to_bytes_le(&Fr::rand(&mut rng)));
        }
        roots_buffer = Cursor::new(roots_serialized.clone());
        let verified = rln
            .verify_with_roots(&mut input_buffer.clone(), &mut roots_buffer)
            .unwrap();

        assert!(verified == false);

        // We get the root of the tree obtained adding one leaf per time
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root, _) = bytes_le_to_fr(&buffer.into_inner());

        // We add the real root and we check if now the proof is verified
        roots_serialized.append(&mut fr_to_bytes_le(&root));
        roots_buffer = Cursor::new(roots_serialized.clone());
        let verified = rln
            .verify_with_roots(&mut input_buffer.clone(), &mut roots_buffer)
            .unwrap();

        assert!(verified);
    }

    #[test]
    fn test_recover_id_secret() {
        let tree_height = TEST_TREE_HEIGHT;

        // We create a new RLN instance
        let input_buffer = Cursor::new(TEST_RESOURCES_FOLDER);
        let mut rln = RLN::new(tree_height, input_buffer);

        // Generate identity pair
        let (identity_secret_hash, id_commitment) = keygen();

        // We set as leaf id_commitment after storing its index
        let identity_index = u64::try_from(rln.tree.leaves_set()).unwrap();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment));
        rln.set_next_leaf(&mut buffer).unwrap();

        // We generate two random signals
        let mut rng = rand::thread_rng();
        let signal1: [u8; 32] = rng.gen();
        let signal1_len = u64::try_from(signal1.len()).unwrap();

        let signal2: [u8; 32] = rng.gen();
        let signal2_len = u64::try_from(signal2.len()).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");

        // We generate two proofs using same epoch but different signals.

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized1: Vec<u8> = Vec::new();
        serialized1.append(&mut fr_to_bytes_le(&identity_secret_hash));
        serialized1.append(&mut identity_index.to_le_bytes().to_vec());
        serialized1.append(&mut fr_to_bytes_le(&epoch));

        // The first part is the same for both proof input, so we clone
        let mut serialized2 = serialized1.clone();

        // We attach the first signal to the first proof input
        serialized1.append(&mut signal1_len.to_le_bytes().to_vec());
        serialized1.append(&mut signal1.to_vec());

        // We attach the second signal to the first proof input
        serialized2.append(&mut signal2_len.to_le_bytes().to_vec());
        serialized2.append(&mut signal2.to_vec());

        // We generate the first proof
        let mut input_buffer = Cursor::new(serialized1);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
            .unwrap();
        let proof_data_1 = output_buffer.into_inner();

        // We generate the second proof
        let mut input_buffer = Cursor::new(serialized2);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
            .unwrap();
        let proof_data_2 = output_buffer.into_inner();

        let mut input_proof_data_1 = Cursor::new(proof_data_1.clone());
        let mut input_proof_data_2 = Cursor::new(proof_data_2);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.recover_id_secret(
            &mut input_proof_data_1,
            &mut input_proof_data_2,
            &mut output_buffer,
        )
            .unwrap();

        let serialized_identity_secret_hash = output_buffer.into_inner();

        // We ensure that a non-empty value is written to output_buffer
        assert!(!serialized_identity_secret_hash.is_empty());

        // We check if the recovered identity secret hash corresponds to the original one
        let (recovered_identity_secret_hash, _) = bytes_le_to_fr(&serialized_identity_secret_hash);
        assert_eq!(recovered_identity_secret_hash, identity_secret_hash);

        // We now test that computing identity_secret_hash is unsuccessful if shares computed from two different identity secret hashes but within same epoch are passed

        // We generate a new identity pair
        let (identity_secret_hash_new, id_commitment_new) = keygen();

        // We add it to the tree
        let identity_index_new = u64::try_from(rln.tree.leaves_set()).unwrap();
        let mut buffer = Cursor::new(fr_to_bytes_le(&id_commitment_new));
        rln.set_next_leaf(&mut buffer).unwrap();

        // We generate a random signals
        let signal3: [u8; 32] = rng.gen();
        let signal3_len = u64::try_from(signal3.len()).unwrap();

        // We prepare proof input. Note that epoch is the same as before
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized3: Vec<u8> = Vec::new();
        serialized3.append(&mut fr_to_bytes_le(&identity_secret_hash_new));
        serialized3.append(&mut identity_index_new.to_le_bytes().to_vec());
        serialized3.append(&mut fr_to_bytes_le(&epoch));
        serialized3.append(&mut signal3_len.to_le_bytes().to_vec());
        serialized3.append(&mut signal3.to_vec());

        // We generate the proof
        let mut input_buffer = Cursor::new(serialized3);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
            .unwrap();
        let proof_data_3 = output_buffer.into_inner();

        // We attempt to recover the secret using share1 (coming from identity_secret_hash) and share3 (coming from identity_secret_hash_new)

        let mut input_proof_data_1 = Cursor::new(proof_data_1.clone());
        let mut input_proof_data_3 = Cursor::new(proof_data_3);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());
        rln.recover_id_secret(
            &mut input_proof_data_1,
            &mut input_proof_data_3,
            &mut output_buffer,
        )
            .unwrap();

        let serialized_identity_secret_hash = output_buffer.into_inner();

        // We ensure that an empty value was written to output_buffer, i.e. no secret is recovered
        assert!(serialized_identity_secret_hash.is_empty());
    }
}