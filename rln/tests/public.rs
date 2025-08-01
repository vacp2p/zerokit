#[cfg(test)]
mod test {
    #[cfg(not(feature = "stateless"))]
    use {
        ark_ff::BigInt,
        rln::{
            circuit::TEST_TREE_HEIGHT,
            protocol::compute_tree_root,
            public::RLN,
            utils::{
                bytes_le_to_vec_fr, bytes_le_to_vec_u8, bytes_le_to_vec_usize, fr_to_bytes_le,
                generate_input_buffer, IdSecret,
            },
        },
        zeroize::Zeroize,
    };

    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;
    use rln::circuit::Fr;
    use rln::hashers::{
        hash_to_field_be, hash_to_field_le, poseidon_hash as utils_poseidon_hash, ROUND_PARAMS,
    };
    use rln::protocol::{
        deserialize_identity_pair_be, deserialize_identity_pair_le, deserialize_identity_tuple_be,
        deserialize_identity_tuple_le,
    };
    use rln::public::{
        hash as public_hash, poseidon_hash as public_poseidon_hash, seeded_extended_key_gen,
        seeded_key_gen,
    };
    use rln::utils::{
        bytes_be_to_fr, bytes_le_to_fr, str_to_fr, vec_fr_to_bytes_be, vec_fr_to_bytes_le,
    };
    use std::io::Cursor;

    #[test]
    // This test is similar to the one in lib, but uses only public API
    #[cfg(not(feature = "stateless"))]
    fn test_merkle_proof() {
        let leaf_index = 3;
        let user_message_limit = 1;

        let mut rln = RLN::new(TEST_TREE_HEIGHT, generate_input_buffer()).unwrap();

        // generate identity
        let mut identity_secret_hash_ = hash_to_field_le(b"test-merkle-proof");
        let identity_secret_hash = IdSecret::from(&mut identity_secret_hash_);

        let mut to_hash = [*identity_secret_hash.clone()];
        let id_commitment = utils_poseidon_hash(&to_hash);
        to_hash[0].zeroize();

        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit.into()]);

        // check that leaves indices is empty
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_empty_leaves_indices(&mut buffer).unwrap();
        let idxs = bytes_le_to_vec_usize(&buffer.into_inner()).unwrap();
        assert!(idxs.is_empty());

        // We pass rate_commitment as Read buffer to RLN's set_leaf
        let mut buffer = Cursor::new(fr_to_bytes_le(&rate_commitment));
        rln.set_leaf(leaf_index, &mut buffer).unwrap();

        // check that leaves before leaf_index is set to zero
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_empty_leaves_indices(&mut buffer).unwrap();
        let idxs = bytes_le_to_vec_usize(&buffer.into_inner()).unwrap();
        assert_eq!(idxs, [0, 1, 2]);

        // We check correct computation of the root
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_root(&mut buffer).unwrap();
        let (root, _) = bytes_le_to_fr(&buffer.into_inner());

        assert_eq!(
            root,
            Fr::from(BigInt([
                17110646155607829651,
                5040045984242729823,
                6965416728592533086,
                2328960363755461975
            ]))
        );

        // We check correct computation of merkle proof
        let mut buffer = Cursor::new(Vec::<u8>::new());
        rln.get_proof(leaf_index, &mut buffer).unwrap();

        let buffer_inner = buffer.into_inner();
        let (path_elements, read) = bytes_le_to_vec_fr(&buffer_inner).unwrap();
        let (identity_path_index, _) = bytes_le_to_vec_u8(&buffer_inner[read..]).unwrap();

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

        // check subtree root computation for leaf 0 for all corresponding node until the root
        let l_idx = 0;
        for n in (1..=TEST_TREE_HEIGHT).rev() {
            let idx_l = l_idx * (1 << (TEST_TREE_HEIGHT - n));
            let idx_r = (l_idx + 1) * (1 << (TEST_TREE_HEIGHT - n));
            let idx_sr = idx_l;

            let mut buffer = Cursor::new(Vec::<u8>::new());
            rln.get_subtree_root(n, idx_l, &mut buffer).unwrap();
            let (prev_l, _) = bytes_le_to_fr(&buffer.into_inner());

            let mut buffer = Cursor::new(Vec::<u8>::new());
            rln.get_subtree_root(n, idx_r, &mut buffer).unwrap();
            let (prev_r, _) = bytes_le_to_fr(&buffer.into_inner());

            let mut buffer = Cursor::new(Vec::<u8>::new());
            rln.get_subtree_root(n - 1, idx_sr, &mut buffer).unwrap();
            let (subroot, _) = bytes_le_to_fr(&buffer.into_inner());

            let res = utils_poseidon_hash(&[prev_l, prev_r]);
            assert_eq!(res, subroot);
        }

        // We double check that the proof computed from public API is correct
        let root_from_proof = compute_tree_root(
            &identity_secret_hash,
            &user_message_limit.into(),
            &path_elements,
            &identity_path_index,
        );

        assert_eq!(root, root_from_proof);
    }

    #[test]
    fn test_seeded_keygen() {
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let mut input_buffer = Cursor::new(&seed_bytes);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        seeded_key_gen(&mut input_buffer, &mut output_buffer, true).unwrap();
        let serialized_output = output_buffer.into_inner();

        let (identity_secret_hash, id_commitment) = deserialize_identity_pair_le(serialized_output);

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
    }

    #[test]
    fn test_seeded_keygen_big_endian() {
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let mut input_buffer = Cursor::new(&seed_bytes);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        seeded_key_gen(&mut input_buffer, &mut output_buffer, false).unwrap();
        let serialized_output = output_buffer.into_inner();

        let (identity_secret_hash, id_commitment) = deserialize_identity_pair_be(serialized_output);

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
    }

    #[test]
    fn test_seeded_extended_keygen() {
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let mut input_buffer = Cursor::new(&seed_bytes);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        seeded_extended_key_gen(&mut input_buffer, &mut output_buffer, true).unwrap();
        let serialized_output = output_buffer.into_inner();

        let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
            deserialize_identity_tuple_le(serialized_output);

        // We check against expected values
        let expected_identity_trapdoor_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        )
        .unwrap();
        let expected_identity_nullifier_seed_bytes = str_to_fr(
            "0x1f18714c7bc83b5bca9e89d404cf6f2f585bc4c0f7ed8b53742b7e2b298f50b4",
            16,
        )
        .unwrap();
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x2aca62aaa7abaf3686fff2caf00f55ab9462dc12db5b5d4bcf3994e671f8e521",
            16,
        )
        .unwrap();
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0x68b66aa0a8320d2e56842581553285393188714c48f9b17acd198b4f1734c5c",
            16,
        )
        .unwrap();

        assert_eq!(identity_trapdoor, expected_identity_trapdoor_seed_bytes);
        assert_eq!(identity_nullifier, expected_identity_nullifier_seed_bytes);
        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_bytes
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes);
    }

    #[test]
    fn test_seeded_extended_keygen_big_endian() {
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let mut input_buffer = Cursor::new(&seed_bytes);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        seeded_extended_key_gen(&mut input_buffer, &mut output_buffer, false).unwrap();
        let serialized_output = output_buffer.into_inner();

        let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
            deserialize_identity_tuple_be(serialized_output);

        // We check against expected values
        let expected_identity_trapdoor_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        )
        .unwrap();
        let expected_identity_nullifier_seed_bytes = str_to_fr(
            "0x1f18714c7bc83b5bca9e89d404cf6f2f585bc4c0f7ed8b53742b7e2b298f50b4",
            16,
        )
        .unwrap();
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x2aca62aaa7abaf3686fff2caf00f55ab9462dc12db5b5d4bcf3994e671f8e521",
            16,
        )
        .unwrap();
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0x68b66aa0a8320d2e56842581553285393188714c48f9b17acd198b4f1734c5c",
            16,
        )
        .unwrap();

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
        let mut rng = thread_rng();
        let signal: [u8; 32] = rng.gen();

        let mut input_buffer = Cursor::new(&signal);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        public_hash(&mut input_buffer, &mut output_buffer, true).unwrap();
        let serialized_hash = output_buffer.into_inner();
        let (hash1, _) = bytes_le_to_fr(&serialized_hash);

        let hash2 = hash_to_field_le(&signal);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_to_field_big_endian() {
        let mut rng = thread_rng();
        let signal: [u8; 32] = rng.gen();

        let mut input_buffer = Cursor::new(&signal);
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        public_hash(&mut input_buffer, &mut output_buffer, false).unwrap();
        let serialized_hash = output_buffer.into_inner();
        let (hash1, _) = bytes_be_to_fr(&serialized_hash);

        let hash2 = hash_to_field_be(&signal);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_hash() {
        let mut rng = thread_rng();
        let number_of_inputs = rng.gen_range(1..ROUND_PARAMS.len());
        let mut inputs = Vec::with_capacity(number_of_inputs);
        for _ in 0..number_of_inputs {
            inputs.push(Fr::rand(&mut rng));
        }
        let expected_hash = utils_poseidon_hash(&inputs);

        let mut input_buffer = Cursor::new(vec_fr_to_bytes_le(&inputs));
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        public_poseidon_hash(&mut input_buffer, &mut output_buffer, true).unwrap();
        let serialized_hash = output_buffer.into_inner();
        let (hash, _) = bytes_le_to_fr(&serialized_hash);

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_poseidon_hash_big_endian() {
        let mut rng = thread_rng();
        let number_of_inputs = rng.gen_range(1..ROUND_PARAMS.len());
        let mut inputs = Vec::with_capacity(number_of_inputs);
        for _ in 0..number_of_inputs {
            inputs.push(Fr::rand(&mut rng));
        }
        let expected_hash = utils_poseidon_hash(&inputs);

        let mut input_buffer = Cursor::new(vec_fr_to_bytes_be(&inputs));
        let mut output_buffer = Cursor::new(Vec::<u8>::new());

        public_poseidon_hash(&mut input_buffer, &mut output_buffer, false).unwrap();
        let serialized_hash = output_buffer.into_inner();
        let (hash, _) = bytes_be_to_fr(&serialized_hash);

        assert_eq!(hash, expected_hash);
    }
}
