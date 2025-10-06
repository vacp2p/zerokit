#[cfg(test)]
#[cfg(not(feature = "stateless"))]
mod test {
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;
    use rln::circuit::{Fr, TEST_TREE_DEPTH};
    use rln::ffi2::{
        ffi2_delete_leaf, ffi2_generate_rln_proof, ffi2_get_leaf, ffi2_get_root,
        ffi2_init_tree_with_leaves, ffi2_key_gen, ffi2_leaves_set, ffi2_new, ffi2_new_with_params,
        ffi2_set_leaf, ffi2_set_leaves_from, ffi2_set_next_leaf, ffi2_set_tree,
        ffi2_verify_rln_proof, ffi2_verify_with_roots, CFr, CResult, FFI2_RLNWitnessInput,
        FFI2_RLN,
    };
    use rln::hashers::{hash_to_field_le, poseidon_hash as utils_poseidon_hash};
    use safer_ffi::boxed::Box_;
    use safer_ffi::prelude::repr_c;
    use serde_json::json;
    use std::ops::Deref;

    const NO_OF_LEAVES: usize = 256;

    fn create_rln_instance() -> repr_c::Box<FFI2_RLN> {
        let input_config = json!({}).to_string();
        let c_str = std::ffi::CString::new(input_config).unwrap();
        let result = ffi2_new(TEST_TREE_DEPTH, c_str.as_c_str().into());
        match result {
            CResult {
                ok: Some(rln),
                err: None,
            } => rln,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("RLN object creation failed: {}", err),
            _ => unreachable!(),
        }
    }

    #[test]
    // Computes and verifies an RLN ZK proof using FFI APIs
    fn test_rln_proof_ffi() {
        let user_message_limit = Fr::from(100);

        // We generate a new identity pair
        let key_gen = ffi2_key_gen();
        let id_secret_hash = &key_gen[0];
        let id_commitment = &key_gen[1];

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field_le(b"test-epoch");
        // We generate a random rln_identifier
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        // We generate a external nullifier
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);
        // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
        let message_id = Fr::from(1);

        let rate_commitment = utils_poseidon_hash(&[*id_commitment.deref(), user_message_limit]);

        // Create RLN & update its tree
        let mut rln = create_rln_instance();
        ffi2_set_next_leaf(&mut rln, CFr::from(rate_commitment).into());
        // set_next_leaf has just updated the tree index 0
        let identity_index: usize = 0;
        //

        let mut witness_input = Box_::new(FFI2_RLNWitnessInput {
            identity_secret: id_secret_hash.into(),
            user_message_limit: CFr::from(user_message_limit).into(),
            message_id: CFr::from(message_id).into(),
            external_nullifier: CFr::from(external_nullifier).into(),
            tree_index: identity_index as u64,
            signal: signal.to_vec().into_boxed_slice().into(),
        });

        let rln_proof = match ffi2_generate_rln_proof(&rln, &mut witness_input) {
            CResult {
                ok: Some(rln_proof),
                err: None,
            } => rln_proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("Error: {err}"),
            _ => unreachable!(),
        };

        let success = ffi2_verify_rln_proof(&rln, rln_proof, signal.as_slice().into());
        assert!(success);
    }

    fn set_leaves_init(rln: &mut repr_c::Box<FFI2_RLN>, leaves: &[Fr]) {
        let leaves_cfr: repr_c::Vec<CFr> = leaves
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let success = ffi2_init_tree_with_leaves(rln, leaves_cfr);
        assert!(success, "init tree with leaves call failed");
        assert_eq!(ffi2_leaves_set(rln), leaves.len());
    }

    fn get_random_leaves() -> Vec<Fr> {
        let mut rng = thread_rng();
        (0..NO_OF_LEAVES).map(|_| Fr::rand(&mut rng)).collect()
    }

    fn get_tree_root(rln_pointer: &repr_c::Box<FFI2_RLN>) -> Fr {
        let root_cfr = ffi2_get_root(rln_pointer);
        **root_cfr.deref()
    }

    #[test]
    // We test merkle batch Merkle tree additions
    fn test_merkle_operations_ffi() {
        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let mut rln = create_rln_instance();

        // We first add leaves one by one specifying the index
        for (i, leaf) in leaves.iter().enumerate() {
            // We prepare the rate_commitment and we set the leaf at provided index
            let success = ffi2_set_leaf(&mut rln, i, CFr::from(*leaf).into());
            assert!(success, "set leaf call failed");
        }

        // We get the root of the tree obtained adding one leaf per time
        let root_single = get_tree_root(&rln);

        // We reset the tree to default
        let success = ffi2_set_tree(&mut rln, TEST_TREE_DEPTH);
        assert!(success, "set tree call failed");

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let success = ffi2_set_next_leaf(&mut rln, CFr::from(*leaf).into());
            assert!(success, "set next leaf call failed");
        }

        // We get the root of the tree obtained adding leaves using the internal index
        let root_next = get_tree_root(&rln);

        // We check if roots are the same
        assert_eq!(root_single, root_next);

        // We reset the tree to default
        let success = ffi2_set_tree(&mut rln, TEST_TREE_DEPTH);
        assert!(success, "set tree call failed");

        // We add leaves in a batch into the tree
        set_leaves_init(&mut rln, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_batch = get_tree_root(&rln);

        // We check if roots are the same
        assert_eq!(root_single, root_batch);

        // We now delete all leaves set and check if the root corresponds to the empty tree root
        // delete calls over indexes higher than no_of_leaves are ignored and will not increase self.tree.next_index
        for i in 0..NO_OF_LEAVES {
            let success = ffi2_delete_leaf(&mut rln, i);
            assert!(success, "delete leaf call failed");
        }

        // We get the root of the tree obtained deleting all leaves
        let root_delete = get_tree_root(&rln);

        // We reset the tree to default
        let success = ffi2_set_tree(&mut rln, TEST_TREE_DEPTH);
        assert!(success, "set tree call failed");

        // We get the root of the empty tree
        let root_empty = get_tree_root(&rln);

        // We check if roots are the same
        assert_eq!(root_delete, root_empty);
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    // Uses `set_leaves_from` to set leaves in a batch
    fn test_leaf_setting_with_index_ffi() {
        // We create a RLN instance
        let mut rln = create_rln_instance();
        assert_eq!(ffi2_leaves_set(&rln), 0);

        // We generate a vector of random leaves
        let leaves = get_random_leaves();

        // set_index is the index from which we start setting leaves
        // random number between 0..no_of_leaves
        let mut rng = thread_rng();
        let set_index = rng.gen_range(0..NO_OF_LEAVES) as usize;
        println!("set_index: {set_index}");

        // We add leaves in a batch into the tree
        set_leaves_init(&mut rln, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_batch_with_init = get_tree_root(&rln);

        // `init_tree_with_leaves` resets the tree to the depth it was initialized with, using `set_tree`

        // We add leaves in a batch starting from index 0..set_index
        set_leaves_init(&mut rln, &leaves[0..set_index]);

        // We add the remaining n leaves in a batch starting from index set_index
        let leaves_n: repr_c::Vec<CFr> = leaves[set_index..]
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let success = ffi2_set_leaves_from(&mut rln, set_index, leaves_n);
        assert!(success, "set leaves from call failed");

        // We get the root of the tree obtained adding leaves in batch
        let root_batch_with_custom_index = get_tree_root(&rln);
        assert_eq!(
            root_batch_with_init, root_batch_with_custom_index,
            "root batch !="
        );

        // We reset the tree to default
        let success = ffi2_set_tree(&mut rln, TEST_TREE_DEPTH);
        assert!(success, "set tree call failed");

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let success = ffi2_set_next_leaf(&mut rln, CFr::from(*leaf).into());
            assert!(success, "set next leaf call failed");
        }

        // We get the root of the tree obtained adding leaves using the internal index
        let root_single_additions = get_tree_root(&rln);
        assert_eq!(
            root_batch_with_init, root_single_additions,
            "root single additions !="
        );
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    fn test_set_leaves_bad_index_ffi() {
        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let mut rln = create_rln_instance();

        let mut rng = thread_rng();
        let bad_index = (1 << TEST_TREE_DEPTH) - rng.gen_range(0..NO_OF_LEAVES) as usize;

        // Get root of empty tree
        let root_empty = get_tree_root(&rln);

        // We add leaves in a batch into the tree
        let leaves_cfr: repr_c::Vec<CFr> = leaves
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let success = ffi2_set_leaves_from(&mut rln, bad_index, leaves_cfr);
        assert!(!success, "set leaves from call succeeded");

        // Get root of tree after attempted set
        let root_after_bad_set = get_tree_root(&rln);
        assert_eq!(root_empty, root_after_bad_set);
    }

    #[test]
    fn test_get_leaf_ffi() {
        let leaf_index = 3;
        // We create a RLN instance
        let mut rln = create_rln_instance();

        // generate identity
        let user_message_limit = Fr::from(100);
        let key_gen = ffi2_key_gen();
        let id_commitment = &key_gen[1];
        let rate_commitment = utils_poseidon_hash(&[*id_commitment.deref(), user_message_limit]);

        // We set the leaf at provided index
        let success = ffi2_set_leaf(&mut rln, leaf_index, CFr::from(rate_commitment).into());
        assert!(success, "set leaf call failed");

        // We get the leaf at provided index
        let result = ffi2_get_leaf(&rln, leaf_index);
        let leaf = match result {
            CResult {
                ok: Some(leaf),
                err: None,
            } => **leaf.deref(),
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get leaf call failed: {}", err),
            _ => unreachable!(),
        };

        assert_eq!(leaf, rate_commitment);
    }

    #[test]
    // Computes and verifies an RLN ZK proof by checking proof's root against an input roots buffer
    fn test_verify_with_roots_ffi() {
        // First part similar to test_rln_proof_ffi
        let user_message_limit = Fr::from(100);

        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let mut rln = create_rln_instance();

        // We add leaves in a batch into the tree
        set_leaves_init(&mut rln, &leaves);

        // We generate a new identity pair
        let key_gen = ffi2_key_gen();
        let id_secret_hash = &key_gen[0];
        let id_commitment = &key_gen[1];
        let rate_commitment = utils_poseidon_hash(&[*id_commitment.deref(), user_message_limit]);
        let identity_index: usize = NO_OF_LEAVES;

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field_le(b"test-epoch");
        // We generate a random rln_identifier
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        // We generate a external nullifier
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);
        // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
        let message_id = Fr::from(1);

        // We set as leaf rate_commitment, its index would be equal to no_of_leaves
        let success = ffi2_set_next_leaf(&mut rln, CFr::from(rate_commitment).into());
        assert!(success, "set next leaf call failed");

        // We test verify_with_roots

        // We first try to verify against an empty buffer of roots.
        // In this case, since no root is provided, proof's root check is skipped and proof is verified if other proof values are valid
        let roots_empty: repr_c::Vec<CFr> = Vec::new().into();
        let mut witness_input_1 = Box_::new(FFI2_RLNWitnessInput {
            identity_secret: id_secret_hash.into(),
            user_message_limit: CFr::from(user_message_limit).into(),
            message_id: CFr::from(message_id).into(),
            external_nullifier: CFr::from(external_nullifier).into(),
            tree_index: identity_index as u64,
            signal: signal.to_vec().into_boxed_slice().into(),
        });
        let rln_proof_1 = match ffi2_generate_rln_proof(&rln, &mut witness_input_1) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            _ => panic!("Failed to generate proof"),
        };
        let success =
            ffi2_verify_with_roots(&rln, rln_proof_1, signal.as_slice().into(), roots_empty);
        // Proof should be valid
        assert!(success);

        // We then try to verify against some random values not containing the correct one.
        let mut roots_wrong: Vec<CFr> = Vec::new();
        for _ in 0..5 {
            roots_wrong.push(CFr::from(Fr::rand(&mut rng)));
        }
        let roots_wrong_vec: repr_c::Vec<CFr> = roots_wrong.into();
        let mut witness_input_2 = Box_::new(FFI2_RLNWitnessInput {
            identity_secret: id_secret_hash.into(),
            user_message_limit: CFr::from(user_message_limit).into(),
            message_id: CFr::from(message_id).into(),
            external_nullifier: CFr::from(external_nullifier).into(),
            tree_index: identity_index as u64,
            signal: signal.to_vec().into_boxed_slice().into(),
        });
        let rln_proof_2 = match ffi2_generate_rln_proof(&rln, &mut witness_input_2) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            _ => panic!("Failed to generate proof"),
        };
        let success =
            ffi2_verify_with_roots(&rln, rln_proof_2, signal.as_slice().into(), roots_wrong_vec);
        // Proof should be invalid.
        assert!(!success);

        // We finally include the correct root
        // We get the root of the tree obtained adding one leaf per time
        let root = get_tree_root(&rln);

        // We include the root and verify the proof
        let mut roots_correct: Vec<CFr> = Vec::new();
        for _ in 0..3 {
            roots_correct.push(CFr::from(Fr::rand(&mut rng)));
        }
        roots_correct.push(CFr::from(root));
        let roots_correct_vec: repr_c::Vec<CFr> = roots_correct.into();
        let mut witness_input_3 = Box_::new(FFI2_RLNWitnessInput {
            identity_secret: id_secret_hash.into(),
            user_message_limit: CFr::from(user_message_limit).into(),
            message_id: CFr::from(message_id).into(),
            external_nullifier: CFr::from(external_nullifier).into(),
            tree_index: identity_index as u64,
            signal: signal.to_vec().into_boxed_slice().into(),
        });
        let rln_proof_3 = match ffi2_generate_rln_proof(&rln, &mut witness_input_3) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            _ => panic!("Failed to generate proof"),
        };
        let success = ffi2_verify_with_roots(
            &rln,
            rln_proof_3,
            signal.as_slice().into(),
            roots_correct_vec,
        );
        // Proof should be valid.
        assert!(success);
    }

    #[test]
    // Creating a RLN with raw data should generate same results as using a path to resources
    fn test_rln_raw_ffi() {
        use std::fs::File;
        use std::io::Read;

        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We obtain the root from the RLN instance
        let root_rln_folder = get_tree_root(&rln_pointer);

        let zkey_path = "./resources/tree_depth_20/rln_final.arkzkey";
        let mut zkey_file = File::open(zkey_path).expect("no file found");
        let metadata = std::fs::metadata(zkey_path).expect("unable to read metadata");
        let mut zkey_buffer = vec![0; metadata.len() as usize];
        zkey_file
            .read_exact(&mut zkey_buffer)
            .expect("buffer overflow");

        let graph_data = "./resources/tree_depth_20/graph.bin";
        let mut graph_file = File::open(graph_data).expect("no file found");
        let metadata = std::fs::metadata(graph_data).expect("unable to read metadata");
        let mut graph_buffer = vec![0; metadata.len() as usize];
        graph_file
            .read_exact(&mut graph_buffer)
            .expect("buffer overflow");

        // Creating a RLN instance passing the raw data
        let tree_config = "".to_string();
        let c_str = std::ffi::CString::new(tree_config).unwrap();
        let result = ffi2_new_with_params(
            TEST_TREE_DEPTH,
            zkey_buffer.as_slice().into(),
            graph_buffer.as_slice().into(),
            c_str.as_c_str().into(),
        );
        let rln_pointer2 = match result {
            CResult {
                ok: Some(rln),
                err: None,
            } => rln,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("RLN object creation failed: {}", err),
            _ => unreachable!(),
        };

        // We obtain the root from the RLN instance containing raw data
        // And compare that the same root was generated
        let root_rln_raw = get_tree_root(&rln_pointer2);
        assert_eq!(root_rln_folder, root_rln_raw);
    }
}

#[cfg(test)]
mod general_tests {
    use rln::ffi2::ffi2_seeded_key_gen;
    use rln::utils::str_to_fr;

    #[test]
    // Tests hash to field using FFI APIs
    fn test_seeded_keygen_stateless_ffi() {
        // We generate a new identity pair from an input seed
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let res = ffi2_seeded_key_gen(seed_bytes.into());
        assert_eq!(res.len(), 2, "seeded key gen call failed");
        let identity_secret_hash = res.first().unwrap();
        let id_commitment = res.get(1).unwrap();

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
            *identity_secret_hash,
            expected_identity_secret_hash_seed_bytes.unwrap()
        );
        assert_eq!(*id_commitment, expected_id_commitment_seed_bytes.unwrap());
    }
}
