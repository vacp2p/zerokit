#[cfg(test)]
#[cfg(not(feature = "stateless"))]
mod test {
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;
    use rln::circuit::{Fr, TEST_TREE_DEPTH};
    use rln::ffi2::*;
    use rln::hashers::{hash_to_field_le, poseidon_hash as utils_poseidon_hash};
    use rln::protocol::*;
    use rln::utils::*;
    use safer_ffi::boxed::Box_;
    use safer_ffi::prelude::repr_c;
    use serde_json::json;
    use std::fs::File;
    use std::io::Read;
    use std::ops::Deref;
    use zeroize::Zeroize;

    const NO_OF_LEAVES: usize = 256;

    fn create_rln_instance() -> repr_c::Box<FFI2_RLN> {
        let input_config = json!({}).to_string();
        let c_str = std::ffi::CString::new(input_config).unwrap();
        match ffi2_new(TEST_TREE_DEPTH, c_str.as_c_str().into()) {
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

    fn set_leaves_init(ffi2_rln_pointer: &mut repr_c::Box<FFI2_RLN>, leaves: &[Fr]) {
        let leaves_vec: repr_c::Vec<CFr> = leaves
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        match ffi2_init_tree_with_leaves(ffi2_rln_pointer, &leaves_vec) {
            CResult {
                ok: Some(_),
                err: None,
            } => {
                assert_eq!(ffi2_leaves_set(ffi2_rln_pointer), leaves.len());
            }
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("init tree with leaves call failed: {}", err),
            _ => unreachable!(),
        }
    }

    fn get_random_leaves() -> Vec<Fr> {
        let mut rng = thread_rng();
        (0..NO_OF_LEAVES).map(|_| Fr::rand(&mut rng)).collect()
    }

    fn get_tree_root(ffi2_rln_pointer: &repr_c::Box<FFI2_RLN>) -> Fr {
        let root_cfr = ffi2_get_root(ffi2_rln_pointer);
        **root_cfr.deref()
    }

    fn identity_pair_gen() -> (IdSecret, Fr) {
        let key_gen = ffi2_key_gen();
        let mut id_secret_fr = *key_gen[0];
        let id_secret_hash = IdSecret::from(&mut id_secret_fr);
        let id_commitment = *key_gen[1];
        (id_secret_hash, id_commitment)
    }

    fn rln_proof_gen(
        ffi2_rln_pointer: &repr_c::Box<FFI2_RLN>,
        identity_secret: &CFr,
        user_message_limit: &CFr,
        message_id: &CFr,
        x: &CFr,
        external_nullifier: &CFr,
        leaf_index: usize,
    ) -> repr_c::Box<FFI2_RLNProof> {
        match ffi2_generate_rln_proof(
            ffi2_rln_pointer,
            identity_secret,
            user_message_limit,
            message_id,
            x,
            external_nullifier,
            leaf_index,
        ) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("generate rln proof call failed: {}", err),
            _ => unreachable!(),
        }
    }

    #[test]
    // We test merkle batch Merkle tree additions
    fn test_merkle_operations_ffi() {
        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let mut ffi2_rln_pointer = create_rln_instance();

        // We first add leaves one by one specifying the index
        for (i, leaf) in leaves.iter().enumerate() {
            // We prepare the rate_commitment and we set the leaf at provided index
            match ffi2_set_leaf(&mut ffi2_rln_pointer, i, &Box_::new(CFr::from(*leaf))) {
                CResult {
                    ok: Some(_),
                    err: None,
                } => {}
                CResult {
                    ok: None,
                    err: Some(err),
                } => panic!("set leaf call failed: {}", err),
                _ => unreachable!(),
            }
        }

        // We get the root of the tree obtained adding one leaf per time
        let root_single = get_tree_root(&ffi2_rln_pointer);

        // We reset the tree to default
        match ffi2_set_tree(&mut ffi2_rln_pointer, TEST_TREE_DEPTH) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("set tree call failed: {}", err),
            _ => unreachable!(),
        }

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            match ffi2_set_next_leaf(&mut ffi2_rln_pointer, &Box_::new(CFr::from(*leaf))) {
                CResult {
                    ok: Some(_),
                    err: None,
                } => {}
                CResult {
                    ok: None,
                    err: Some(err),
                } => panic!("set next leaf call failed: {}", err),
                _ => unreachable!(),
            }
        }

        // We get the root of the tree obtained adding leaves using the internal index
        let root_next = get_tree_root(&ffi2_rln_pointer);

        // We check if roots are the same
        assert_eq!(root_single, root_next);

        // We reset the tree to default
        match ffi2_set_tree(&mut ffi2_rln_pointer, TEST_TREE_DEPTH) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("set tree call failed: {}", err),
            _ => unreachable!(),
        }

        // We add leaves in a batch into the tree
        set_leaves_init(&mut ffi2_rln_pointer, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_batch = get_tree_root(&ffi2_rln_pointer);

        // We check if roots are the same
        assert_eq!(root_single, root_batch);

        // We now delete all leaves set and check if the root corresponds to the empty tree root
        // delete calls over indexes higher than no_of_leaves are ignored and will not increase self.tree.next_index
        for i in 0..NO_OF_LEAVES {
            match ffi2_delete_leaf(&mut ffi2_rln_pointer, i) {
                CResult {
                    ok: Some(_),
                    err: None,
                } => {}
                CResult {
                    ok: None,
                    err: Some(err),
                } => panic!("delete leaf call failed: {}", err),
                _ => unreachable!(),
            }
        }

        // We get the root of the tree obtained deleting all leaves
        let root_delete = get_tree_root(&ffi2_rln_pointer);

        // We reset the tree to default
        match ffi2_set_tree(&mut ffi2_rln_pointer, TEST_TREE_DEPTH) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("set tree call failed: {}", err),
            _ => unreachable!(),
        }

        // We get the root of the empty tree
        let root_empty = get_tree_root(&ffi2_rln_pointer);

        // We check if roots are the same
        assert_eq!(root_delete, root_empty);
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    // Uses `set_leaves_from` to set leaves in a batch
    fn test_leaf_setting_with_index_ffi() {
        // We create a RLN instance
        let mut ffi2_rln_pointer = create_rln_instance();
        assert_eq!(ffi2_leaves_set(&ffi2_rln_pointer), 0);

        // We generate a vector of random leaves
        let leaves = get_random_leaves();

        // set_index is the index from which we start setting leaves
        // random number between 0..no_of_leaves
        let mut rng = thread_rng();
        let set_index = rng.gen_range(0..NO_OF_LEAVES) as usize;
        println!("set_index: {set_index}");

        // We add leaves in a batch into the tree
        set_leaves_init(&mut ffi2_rln_pointer, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_batch_with_init = get_tree_root(&ffi2_rln_pointer);

        // `init_tree_with_leaves` resets the tree to the depth it was initialized with, using `set_tree`

        // We add leaves in a batch starting from index 0..set_index
        set_leaves_init(&mut ffi2_rln_pointer, &leaves[0..set_index]);

        // We add the remaining n leaves in a batch starting from index set_index
        let leaves_vec: repr_c::Vec<CFr> = leaves[set_index..]
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        match ffi2_set_leaves_from(&mut ffi2_rln_pointer, set_index, &leaves_vec) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("set leaves from call failed: {}", err),
            _ => unreachable!(),
        }

        // We get the root of the tree obtained adding leaves in batch
        let root_batch_with_custom_index = get_tree_root(&ffi2_rln_pointer);
        assert_eq!(
            root_batch_with_init, root_batch_with_custom_index,
            "root batch !="
        );

        // We reset the tree to default
        match ffi2_set_tree(&mut ffi2_rln_pointer, TEST_TREE_DEPTH) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("set tree call failed: {}", err),
            _ => unreachable!(),
        }

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            match ffi2_set_next_leaf(&mut ffi2_rln_pointer, &Box_::new(CFr::from(*leaf))) {
                CResult {
                    ok: Some(_),
                    err: None,
                } => {}
                CResult {
                    ok: None,
                    err: Some(err),
                } => panic!("set next leaf call failed: {}", err),
                _ => unreachable!(),
            }
        }

        // We get the root of the tree obtained adding leaves using the internal index
        let root_single_additions = get_tree_root(&ffi2_rln_pointer);
        assert_eq!(
            root_batch_with_init, root_single_additions,
            "root single additions !="
        );
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    fn test_atomic_operation_ffi() {
        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let mut ffi2_rln_pointer = create_rln_instance();

        // We add leaves in a batch into the tree
        set_leaves_init(&mut ffi2_rln_pointer, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_after_insertion = get_tree_root(&ffi2_rln_pointer);

        let last_leaf = leaves.last().unwrap();
        let last_leaf_index = NO_OF_LEAVES - 1;
        let indices: repr_c::Vec<usize> = vec![last_leaf_index].into();
        let last_leaf_vec: repr_c::Vec<CFr> = vec![CFr::from(*last_leaf)].into();

        match ffi2_atomic_operation(
            &mut ffi2_rln_pointer,
            last_leaf_index,
            &last_leaf_vec,
            &indices,
        ) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("atomic operation call failed: {}", err),
            _ => unreachable!(),
        }

        // We get the root of the tree obtained after a no-op
        let root_after_noop = get_tree_root(&ffi2_rln_pointer);
        assert_eq!(root_after_insertion, root_after_noop);
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    fn test_set_leaves_bad_index_ffi() {
        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let mut ffi2_rln_pointer = create_rln_instance();

        let mut rng = thread_rng();
        let bad_index = (1 << TEST_TREE_DEPTH) - rng.gen_range(0..NO_OF_LEAVES) as usize;

        // Get root of empty tree
        let root_empty = get_tree_root(&ffi2_rln_pointer);

        // We add leaves in a batch into the tree
        let leaves_vec: repr_c::Vec<CFr> = leaves
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        match ffi2_set_leaves_from(&mut ffi2_rln_pointer, bad_index, &leaves_vec) {
            CResult {
                ok: None,
                err: Some(_),
            } => {}
            _ => panic!("set leaves from call should have failed"),
        }

        // Get root of tree after attempted set
        let root_after_bad_set = get_tree_root(&ffi2_rln_pointer);
        assert_eq!(root_empty, root_after_bad_set);
    }

    #[test]
    // This test is similar to the one in lib, but uses only public C API
    fn test_merkle_proof_ffi() {
        let leaf_index = 3;
        // We create a RLN instance
        let mut ffi2_rln_pointer = create_rln_instance();

        // generate identity
        let mut identity_secret_hash_ = hash_to_field_le(b"test-merkle-proof");
        let identity_secret_hash = IdSecret::from(&mut identity_secret_hash_);
        let mut to_hash = [*identity_secret_hash.clone()];
        let id_commitment = utils_poseidon_hash(&to_hash);
        to_hash[0].zeroize();
        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);

        // We prepare id_commitment and we set the leaf at provided index
        match ffi2_set_leaf(
            &mut ffi2_rln_pointer,
            leaf_index,
            &Box_::new(CFr::from(rate_commitment)),
        ) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("set leaf call failed: {}", err),
            _ => unreachable!(),
        }

        // We obtain the Merkle tree root
        let root = get_tree_root(&ffi2_rln_pointer);

        use ark_ff::BigInt;
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

        // We obtain the Merkle proof
        let proof = match ffi2_get_proof(&ffi2_rln_pointer, leaf_index) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get merkle proof call failed: {}", err),
            _ => unreachable!(),
        };

        let path_elements: Vec<Fr> = proof.path_elements.iter().map(|cfr| **cfr).collect();
        let identity_path_index: Vec<u8> = proof.path_index.iter().copied().collect();

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

        // We double check that the proof computed from public API is correct
        let root_from_proof = compute_tree_root(
            &identity_secret_hash,
            &user_message_limit,
            &path_elements,
            &identity_path_index,
        );

        assert_eq!(root, root_from_proof);
    }

    #[test]
    // Creating a RLN with raw data should generate same results as using a path to resources
    fn test_rln_raw_ffi() {
        // We create a RLN instance
        let ffi2_rln_pointer = create_rln_instance();

        // We obtain the root from the RLN instance
        let root_rln_folder = get_tree_root(&ffi2_rln_pointer);

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
        let ffi2_rln_pointer2 = match ffi2_new_with_params(
            TEST_TREE_DEPTH,
            &zkey_buffer.into(),
            &graph_buffer.into(),
            c_str.as_c_str().into(),
        ) {
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
        let root_rln_raw = get_tree_root(&ffi2_rln_pointer2);
        assert_eq!(root_rln_folder, root_rln_raw);
    }

    #[test]
    // Computes and verifies an RLN ZK proof using FFI APIs
    fn test_rln_proof_ffi() {
        let user_message_limit = Fr::from(100);

        // We generate a vector of random leaves
        let mut rng = thread_rng();
        let leaves: Vec<Fr> = (0..NO_OF_LEAVES)
            .map(|_| utils_poseidon_hash(&[Fr::rand(&mut rng), Fr::from(100)]))
            .collect();

        // We create a RLN instance
        let mut ffi2_rln_pointer = create_rln_instance();

        // We add leaves in a batch into the tree
        set_leaves_init(&mut ffi2_rln_pointer, &leaves);

        // We generate a new identity pair
        let (identity_secret_hash, id_commitment) = identity_pair_gen();
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

        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);

        // We set as leaf rate_commitment, its index would be equal to no_of_leaves
        match ffi2_set_next_leaf(
            &mut ffi2_rln_pointer,
            &Box_::new(CFr::from(rate_commitment)),
        ) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("set next leaf call failed: {}", err),
            _ => unreachable!(),
        }

        // Get the merkle proof for the identity
        let _merkle_proof = match ffi2_get_proof(&ffi2_rln_pointer, identity_index) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get merkle proof call failed: {}", err),
            _ => unreachable!(),
        };

        // Hash the signal to get x
        let x = hash_to_field_le(&signal);

        // path_elements and identity_path_index are not needed in non-stateless mode
        let rln_proof = rln_proof_gen(
            &ffi2_rln_pointer,
            &CFr::from(*identity_secret_hash),
            &CFr::from(user_message_limit),
            &CFr::from(message_id),
            &CFr::from(x),
            &CFr::from(external_nullifier),
            identity_index,
        );

        let proof_is_valid =
            match ffi2_verify_rln_proof(&ffi2_rln_pointer, &rln_proof, &CFr::from(x)) {
                CResult {
                    ok: Some(success),
                    err: None,
                } => *success,
                CResult {
                    ok: None,
                    err: Some(err),
                } => panic!("verify rln proof call failed: {}", err),
                _ => unreachable!(),
            };

        assert!(proof_is_valid);
    }

    #[test]
    // Computes and verifies an RLN ZK proof by checking proof's root against an input roots buffer
    fn test_verify_with_roots_ffi() {
        let user_message_limit = Fr::from(100);

        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let mut ffi2_rln_pointer = create_rln_instance();

        // We add leaves in a batch into the tree
        set_leaves_init(&mut ffi2_rln_pointer, &leaves);

        // We generate a new identity pair
        let (identity_secret_hash, id_commitment) = identity_pair_gen();
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);
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
        match ffi2_set_next_leaf(
            &mut ffi2_rln_pointer,
            &Box_::new(CFr::from(rate_commitment)),
        ) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("set next leaf call failed: {}", err),
            _ => unreachable!(),
        }

        // Get the merkle proof for the identity
        let _merkle_proof = match ffi2_get_proof(&ffi2_rln_pointer, identity_index) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get merkle proof call failed: {}", err),
            _ => unreachable!(),
        };

        // Hash the signal to get x
        let x = hash_to_field_le(&signal);

        // path_elements and identity_path_index are not needed in non-stateless mode
        // witness input is now passed directly as parameters

        let rln_proof = rln_proof_gen(
            &ffi2_rln_pointer,
            &CFr::from(*identity_secret_hash),
            &CFr::from(user_message_limit),
            &CFr::from(message_id),
            &CFr::from(x),
            &CFr::from(external_nullifier),
            identity_index,
        );

        // We test verify_with_roots

        // We first try to verify against an empty buffer of roots.
        // In this case, since no root is provided, proof's root check is skipped and proof is verified if other proof values are valid
        let roots_empty: repr_c::Vec<CFr> = vec![].into();

        let proof_is_valid = match ffi2_verify_with_roots(
            &ffi2_rln_pointer,
            &rln_proof,
            &roots_empty,
            &CFr::from(x),
        ) {
            CResult {
                ok: Some(valid),
                err: None,
            } => *valid,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("verify with roots call failed: {}", err),
            _ => unreachable!(),
        };
        // Proof should be valid
        assert!(proof_is_valid);

        // We then try to verify against some random values not containing the correct one.
        let mut roots_random: Vec<CFr> = Vec::new();
        for _ in 0..5 {
            roots_random.push(CFr::from(Fr::rand(&mut rng)));
        }
        let roots_random_vec: repr_c::Vec<CFr> = roots_random.into();

        let proof_is_valid = match ffi2_verify_with_roots(
            &ffi2_rln_pointer,
            &rln_proof,
            &roots_random_vec,
            &CFr::from(x),
        ) {
            CResult {
                ok: Some(valid),
                err: None,
            } => *valid,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("verify with roots call failed: {}", err),
            _ => unreachable!(),
        };
        // Proof should be invalid.
        assert!(!proof_is_valid);

        // We finally include the correct root
        // We get the root of the tree obtained adding one leaf per time
        let root = get_tree_root(&ffi2_rln_pointer);

        // We include the root and verify the proof
        let mut roots_with_correct: Vec<CFr> = Vec::new();
        for _ in 0..5 {
            roots_with_correct.push(CFr::from(Fr::rand(&mut rng)));
        }
        roots_with_correct.push(CFr::from(root));
        let roots_correct_vec: repr_c::Vec<CFr> = roots_with_correct.into();

        let proof_is_valid = match ffi2_verify_with_roots(
            &ffi2_rln_pointer,
            &rln_proof,
            &roots_correct_vec,
            &CFr::from(x),
        ) {
            CResult {
                ok: Some(valid),
                err: None,
            } => *valid,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("verify with roots call failed: {}", err),
            _ => unreachable!(),
        };
        // Proof should be valid.
        assert!(proof_is_valid);
    }

    #[test]
    // Computes and verifies an RLN ZK proof using FFI APIs and recovers identity secret
    fn test_recover_id_secret_ffi() {
        // We create a RLN instance
        let mut ffi2_rln_pointer = create_rln_instance();

        // We generate a new identity pair
        let (identity_secret_hash, id_commitment) = identity_pair_gen();

        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);

        // We set as leaf rate_commitment, its index would be equal to 0 since tree is empty
        match ffi2_set_next_leaf(
            &mut ffi2_rln_pointer,
            &Box_::new(CFr::from(rate_commitment)),
        ) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("set next leaf call failed: {}", err),
            _ => unreachable!(),
        }

        let identity_index: usize = 0;

        // We generate two proofs using same epoch but different signals.

        // We generate two random signals
        let mut rng = rand::thread_rng();
        let signal1: [u8; 32] = rng.gen();
        let signal2: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field_le(b"test-epoch");
        // We generate a random rln_identifier
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        // We generate a external nullifier
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);
        // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
        let message_id = Fr::from(1);

        // Get the merkle proof for the identity
        let _merkle_proof = match ffi2_get_proof(&ffi2_rln_pointer, identity_index) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get merkle proof call failed: {}", err),
            _ => unreachable!(),
        };

        // Hash the signals to get x
        let x1 = hash_to_field_le(&signal1);
        let x2 = hash_to_field_le(&signal2);

        // path_elements and identity_path_index are not needed in non-stateless mode
        // witness input is now passed directly as parameters

        // We call generate_rln_proof for first proof values
        let rln_proof1 = rln_proof_gen(
            &ffi2_rln_pointer,
            &CFr::from(*identity_secret_hash.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(message_id),
            &CFr::from(x1),
            &CFr::from(external_nullifier),
            identity_index,
        );

        // We call generate_rln_proof for second proof values
        let rln_proof2 = rln_proof_gen(
            &ffi2_rln_pointer,
            &CFr::from(*identity_secret_hash.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(message_id),
            &CFr::from(x2),
            &CFr::from(external_nullifier),
            identity_index,
        );

        let recovered_id_secret_cfr = match ffi2_recover_id_secret(&rln_proof1, &rln_proof2) {
            CResult {
                ok: Some(secret),
                err: None,
            } => secret,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("recover id secret call failed: {}", err),
            _ => unreachable!(),
        };

        // We check if the recovered identity secret hash corresponds to the original one
        let recovered_identity_secret_hash = **recovered_id_secret_cfr;
        assert_eq!(recovered_identity_secret_hash, *identity_secret_hash);

        // We now test that computing identity_secret_hash is unsuccessful if shares computed from two different identity secret hashes but within same epoch are passed

        // We generate a new identity pair
        let (identity_secret_hash_new, id_commitment_new) = identity_pair_gen();
        let rate_commitment_new = utils_poseidon_hash(&[id_commitment_new, user_message_limit]);

        // We set as leaf id_commitment, its index would be equal to 1 since at 0 there is id_commitment
        match ffi2_set_next_leaf(
            &mut ffi2_rln_pointer,
            &Box_::new(CFr::from(rate_commitment_new)),
        ) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("set next leaf call failed: {}", err),
            _ => unreachable!(),
        }

        let identity_index_new: usize = 1;

        // We generate a random signal
        let signal3: [u8; 32] = rng.gen();
        let x3 = hash_to_field_le(&signal3);

        // Get the merkle proof for the new identity
        let _merkle_proof_new = match ffi2_get_proof(&ffi2_rln_pointer, identity_index_new) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get merkle proof call failed: {}", err),
            _ => unreachable!(),
        };

        // path_elements_new and identity_path_index_new are not needed in non-stateless mode
        // witness input is now passed directly as parameters

        // We call generate_rln_proof
        let rln_proof3 = rln_proof_gen(
            &ffi2_rln_pointer,
            &CFr::from(*identity_secret_hash_new.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(message_id),
            &CFr::from(x3),
            &CFr::from(external_nullifier),
            identity_index_new,
        );

        // We attempt to recover the secret using share1 (coming from identity_secret_hash) and share3 (coming from identity_secret_hash_new)

        let recovered_id_secret_new_cfr = match ffi2_recover_id_secret(&rln_proof1, &rln_proof3) {
            CResult {
                ok: Some(secret),
                err: None,
            } => secret,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("recover id secret call failed: {}", err),
            _ => unreachable!(),
        };

        let recovered_identity_secret_hash_new = **recovered_id_secret_new_cfr;

        // ensure that the recovered secret does not match with either of the
        // used secrets in proof generation
        assert_ne!(
            recovered_identity_secret_hash_new,
            *identity_secret_hash_new
        );
    }

    #[test]
    fn test_get_leaf_ffi() {
        // We create a RLN instance
        let no_of_leaves = 1 << TEST_TREE_DEPTH;

        // We create a RLN instance
        let mut ffi2_rln_pointer = create_rln_instance();

        // We generate a new identity tuple from an input seed
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let key_gen = ffi2_seeded_extended_key_gen(&seed_bytes.into());
        assert_eq!(key_gen.len(), 4, "seeded extended key gen call failed");
        let id_commitment = *key_gen[3];

        // We insert the id_commitment into the tree at a random index
        let mut rng = thread_rng();
        let index = rng.gen_range(0..no_of_leaves) as usize;
        match ffi2_set_leaf(
            &mut ffi2_rln_pointer,
            index,
            &Box_::new(CFr::from(id_commitment)),
        ) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("set leaf call failed: {}", err),
            _ => unreachable!(),
        }

        // We get the leaf at the same index
        let received_id_commitment_cfr = match ffi2_get_leaf(&ffi2_rln_pointer, index) {
            CResult {
                ok: Some(leaf),
                err: None,
            } => leaf,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get leaf call failed: {}", err),
            _ => unreachable!(),
        };
        let received_id_commitment = **received_id_commitment_cfr;

        // We check that the received id_commitment is the same as the one we inserted
        assert_eq!(received_id_commitment, id_commitment);
    }

    #[test]
    fn test_valid_metadata_ffi() {
        // We create a RLN instance
        let mut ffi2_rln_pointer = create_rln_instance();

        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        match ffi2_set_metadata(&mut ffi2_rln_pointer, &seed_bytes.clone().into()) {
            CResult {
                ok: Some(_),
                err: None,
            } => {}
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("set_metadata call failed: {}", err),
            _ => unreachable!(),
        }

        let metadata = match ffi2_get_metadata(&ffi2_rln_pointer) {
            CResult {
                ok: Some(data),
                err: None,
            } => data,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get_metadata call failed: {}", err),
            _ => unreachable!(),
        };

        assert_eq!(metadata.iter().copied().collect::<Vec<u8>>(), seed_bytes);
    }

    #[test]
    fn test_empty_metadata_ffi() {
        // We create a RLN instance
        let ffi2_rln_pointer = create_rln_instance();

        let metadata = match ffi2_get_metadata(&ffi2_rln_pointer) {
            CResult {
                ok: Some(data),
                err: None,
            } => data,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get_metadata call failed: {}", err),
            _ => unreachable!(),
        };

        assert_eq!(metadata.len(), 0);
    }
}

#[cfg(test)]
#[cfg(feature = "stateless")]
mod stateless_test {
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;
    use rln::circuit::{Fr, TEST_TREE_DEPTH};
    use rln::ffi2::*;
    use rln::hashers::{hash_to_field_le, poseidon_hash as utils_poseidon_hash, PoseidonHash};
    use rln::utils::*;
    use safer_ffi::prelude::repr_c;
    use utils::{OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree};

    type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

    fn create_rln_instance() -> repr_c::Box<FFI2_RLN> {
        match ffi2_new() {
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

    fn identity_pair_gen() -> (IdSecret, Fr) {
        let key_gen = ffi2_key_gen();
        let mut id_secret_fr = *key_gen[0];
        let id_secret_hash = IdSecret::from(&mut id_secret_fr);
        let id_commitment = *key_gen[1];
        (id_secret_hash, id_commitment)
    }

    // ...existing code...

    #[test]
    fn test_recover_id_secret_stateless_ffi() {
        let default_leaf = Fr::from(0);
        let mut tree: OptimalMerkleTree<PoseidonHash> = OptimalMerkleTree::new(
            TEST_TREE_DEPTH,
            default_leaf,
            ConfigOf::<OptimalMerkleTree<PoseidonHash>>::default(),
        )
        .unwrap();

        let ffi2_rln_pointer = create_rln_instance();

        // We generate a new identity pair
        let (identity_secret_hash, id_commitment) = identity_pair_gen();

        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);
        tree.update_next(rate_commitment).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field_le(b"test-epoch");
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);

        // We generate two proofs using same epoch but different signals.
        // We generate a random signal
        let mut rng = thread_rng();
        let signal1: [u8; 32] = rng.gen();
        let x1 = hash_to_field_le(&signal1);

        let signal2: [u8; 32] = rng.gen();
        let x2 = hash_to_field_le(&signal2);

        let identity_index = tree.leaves_set();
        let merkle_proof = tree.proof(identity_index).expect("proof should exist");

        let path_elements: repr_c::Vec<CFr> = merkle_proof
            .get_path_elements()
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let identity_path_index: repr_c::Vec<u8> = merkle_proof.get_path_index().to_vec().into();

        // We call generate_rln_proof for first proof values
        let rln_proof1 = match ffi2_generate_rln_proof_stateless(
            &ffi2_rln_pointer,
            &CFr::from(*identity_secret_hash.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(Fr::from(1)),
            &path_elements,
            &identity_path_index,
            &CFr::from(x1),
            &CFr::from(external_nullifier),
        ) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("generate rln proof with witness call failed: {}", err),
            _ => unreachable!(),
        };

        // We call generate_rln_proof for second proof values
        let rln_proof2 = match ffi2_generate_rln_proof_stateless(
            &ffi2_rln_pointer,
            &CFr::from(*identity_secret_hash.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(Fr::from(1)),
            &path_elements,
            &identity_path_index,
            &CFr::from(x2),
            &CFr::from(external_nullifier),
        ) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("generate rln proof with witness call failed: {}", err),
            _ => unreachable!(),
        };

        let recovered_id_secret_cfr = match ffi2_recover_id_secret(&rln_proof1, &rln_proof2) {
            CResult {
                ok: Some(secret),
                err: None,
            } => secret,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("recover id secret call failed: {}", err),
            _ => unreachable!(),
        };

        // We check if the recovered identity secret hash corresponds to the original one
        let recovered_identity_secret_hash = **recovered_id_secret_cfr;
        assert_eq!(recovered_identity_secret_hash, *identity_secret_hash);

        // We now test that computing identity_secret_hash is unsuccessful if shares computed from two different identity secret hashes but within same epoch are passed

        // We generate a new identity pair
        let (identity_secret_hash_new, id_commitment_new) = identity_pair_gen();
        let rate_commitment_new = utils_poseidon_hash(&[id_commitment_new, user_message_limit]);
        tree.update_next(rate_commitment_new).unwrap();

        // We generate a random signal
        let signal3: [u8; 32] = rng.gen();
        let x3 = hash_to_field_le(&signal3);

        let identity_index_new = tree.leaves_set();
        let merkle_proof_new = tree.proof(identity_index_new).expect("proof should exist");

        let path_elements_new: repr_c::Vec<CFr> = merkle_proof_new
            .get_path_elements()
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let identity_path_index_new: repr_c::Vec<u8> =
            merkle_proof_new.get_path_index().to_vec().into();

        // We call generate_rln_proof
        let rln_proof3 = match ffi2_generate_rln_proof_stateless(
            &ffi2_rln_pointer,
            &CFr::from(*identity_secret_hash_new.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(Fr::from(1)),
            &path_elements_new,
            &identity_path_index_new,
            &CFr::from(x3),
            &CFr::from(external_nullifier),
        ) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("generate rln proof with witness call failed: {}", err),
            _ => unreachable!(),
        };

        // We attempt to recover the secret using share1 (coming from identity_secret_hash) and share3 (coming from identity_secret_hash_new)

        let recovered_id_secret_new_cfr = match ffi2_recover_id_secret(&rln_proof1, &rln_proof3) {
            CResult {
                ok: Some(secret),
                err: None,
            } => secret,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("recover id secret call failed: {}", err),
            _ => unreachable!(),
        };

        let recovered_identity_secret_hash_new = **recovered_id_secret_new_cfr;

        // ensure that the recovered secret does not match with either of the
        // used secrets in proof generation
        assert_ne!(
            recovered_identity_secret_hash_new,
            *identity_secret_hash_new
        );
    }

    #[test]
    fn test_verify_with_roots_stateless_ffi() {
        let default_leaf = Fr::from(0);
        let mut tree: OptimalMerkleTree<PoseidonHash> = OptimalMerkleTree::new(
            TEST_TREE_DEPTH,
            default_leaf,
            ConfigOf::<OptimalMerkleTree<PoseidonHash>>::default(),
        )
        .unwrap();

        let ffi2_rln_pointer = create_rln_instance();

        // We generate a new identity pair
        let (identity_secret_hash, id_commitment) = identity_pair_gen();

        let identity_index = tree.leaves_set();
        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);
        tree.update_next(rate_commitment).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field_le(b"test-epoch");
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);

        // We generate a random signal
        let mut rng = thread_rng();
        let signal: [u8; 32] = rng.gen();
        let x = hash_to_field_le(&signal);

        let merkle_proof = tree.proof(identity_index).expect("proof should exist");

        // We prepare input for generate_rln_proof API
        let path_elements: repr_c::Vec<CFr> = merkle_proof
            .get_path_elements()
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let identity_path_index: repr_c::Vec<u8> = merkle_proof.get_path_index().to_vec().into();

        let rln_proof = match ffi2_generate_rln_proof_stateless(
            &ffi2_rln_pointer,
            &CFr::from(*identity_secret_hash.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(Fr::from(1)),
            &path_elements,
            &identity_path_index,
            &CFr::from(x),
            &CFr::from(external_nullifier),
        ) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("generate rln proof with witness call failed: {}", err),
            _ => unreachable!(),
        };

        // If no roots is provided, proof validation is skipped and if the remaining proof values are valid, the proof will be correctly verified
        let roots_empty: repr_c::Vec<CFr> = vec![].into();

        let proof_is_valid = match ffi2_verify_with_roots(
            &ffi2_rln_pointer,
            &rln_proof,
            &roots_empty,
            &CFr::from(x),
        ) {
            CResult {
                ok: Some(valid),
                err: None,
            } => *valid,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("verify with roots call failed: {}", err),
            _ => unreachable!(),
        };
        // Proof should be valid
        assert!(proof_is_valid);

        // We serialize in the roots buffer some random values and we check that the proof is not verified since doesn't contain the correct root the proof refers to
        let mut roots_random: Vec<CFr> = Vec::new();
        for _ in 0..5 {
            roots_random.push(CFr::from(Fr::rand(&mut rng)));
        }
        let roots_random_vec: repr_c::Vec<CFr> = roots_random.into();

        let proof_is_valid = match ffi2_verify_with_roots(
            &ffi2_rln_pointer,
            &rln_proof,
            &roots_random_vec,
            &CFr::from(x),
        ) {
            CResult {
                ok: Some(valid),
                err: None,
            } => *valid,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("verify with roots call failed: {}", err),
            _ => unreachable!(),
        };
        // Proof should be invalid.
        assert!(!proof_is_valid);

        // We get the root of the tree obtained adding one leaf per time
        let root = tree.root();

        // We add the real root and we check if now the proof is verified
        let mut roots_with_correct: Vec<CFr> = Vec::new();
        for _ in 0..5 {
            roots_with_correct.push(CFr::from(Fr::rand(&mut rng)));
        }
        roots_with_correct.push(CFr::from(root));
        let roots_correct_vec: repr_c::Vec<CFr> = roots_with_correct.into();

        let proof_is_valid = match ffi2_verify_with_roots(
            &ffi2_rln_pointer,
            &rln_proof,
            &roots_correct_vec,
            &CFr::from(x),
        ) {
            CResult {
                ok: Some(valid),
                err: None,
            } => *valid,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("verify with roots call failed: {}", err),
            _ => unreachable!(),
        };
        // Proof should be valid.
        assert!(proof_is_valid);
    }
}

#[cfg(test)]
mod general_tests {
    use rand::Rng;
    use rln::circuit::Fr;
    use rln::ffi2::*;
    use rln::hashers::poseidon_hash;
    use rln::utils::{fr_to_bytes_be, fr_to_bytes_le, str_to_fr, IdSecret};

    #[test]
    // Tests hash to field using FFI APIs
    fn test_seeded_keygen_stateless_ffi() {
        // We generate a new identity pair from an input seed
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let res = ffi2_seeded_key_gen(&seed_bytes.into());
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

    #[test]
    // Tests hash to field using FFI APIs
    fn test_seeded_extended_keygen_stateless_ffi() {
        // We generate a new identity tuple from an input seed
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let key_gen = ffi2_seeded_extended_key_gen(&seed_bytes.into());
        assert_eq!(key_gen.len(), 4, "seeded extended key gen call failed");
        let identity_trapdoor = *key_gen[0];
        let identity_nullifier = *key_gen[1];
        let identity_secret_hash = *key_gen[2];
        let id_commitment = *key_gen[3];

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

        assert_eq!(
            identity_trapdoor,
            expected_identity_trapdoor_seed_bytes.unwrap()
        );
        assert_eq!(
            identity_nullifier,
            expected_identity_nullifier_seed_bytes.unwrap()
        );
        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_bytes.unwrap()
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes.unwrap());
    }

    #[test]
    // Test CFr FFI functions
    fn test_cfr_ffi() {
        let cfr_zero = cfr_zero();
        let fr_zero = rln::circuit::Fr::from(0u8);
        assert_eq!(*cfr_zero, fr_zero);

        let cfr_one = cfr_one();
        let fr_one = rln::circuit::Fr::from(1u8);
        assert_eq!(*cfr_one, fr_one);

        let cfr_int = uint_to_cfr(42);
        let fr_int = rln::circuit::Fr::from(42u8);
        assert_eq!(*cfr_int, fr_int);

        let cfr_debug_str = cfr_debug(Some(&cfr_int));
        assert_eq!(cfr_debug_str.to_string(), "Some(\"42\")");

        let key_gen = ffi2_key_gen();
        let mut id_secret_fr = *key_gen[0];
        let id_secret_hash = IdSecret::from(&mut id_secret_fr);
        let id_commitment = *key_gen[1];
        let cfr_id_secret_hash = vec_cfr_get(&key_gen, 0).unwrap();
        assert_eq!(*cfr_id_secret_hash, *id_secret_hash);
        let cfr_id_commitment = vec_cfr_get(&key_gen, 1).unwrap();
        assert_eq!(*cfr_id_commitment, id_commitment);
    }

    #[test]
    // Test Vec<u8> FFI functions
    fn test_vec_u8_ffi() {
        let mut rng = rand::thread_rng();
        let signal_gen: [u8; 32] = rng.gen();
        let signal: Vec<u8> = signal_gen.to_vec();

        let bytes_le = vec_u8_to_bytes_le(&signal.clone().into());
        let expected_le = rln::utils::vec_u8_to_bytes_le(&signal);
        assert_eq!(bytes_le.iter().copied().collect::<Vec<_>>(), expected_le);

        let bytes_be = vec_u8_to_bytes_be(&signal.clone().into());
        let expected_be = rln::utils::vec_u8_to_bytes_be(&signal);
        assert_eq!(bytes_be.iter().copied().collect::<Vec<_>>(), expected_be);

        let signal_from_le = match bytes_le_to_vec_u8(&bytes_le) {
            CResult {
                ok: Some(vec_u8),
                err: None,
            } => vec_u8,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("bytes_le_to_vec_u8 call failed: {}", err),
            _ => unreachable!(),
        };
        assert_eq!(signal_from_le.iter().copied().collect::<Vec<_>>(), signal);

        let signal_from_be = match bytes_be_to_vec_u8(&bytes_be) {
            CResult {
                ok: Some(vec_u8),
                err: None,
            } => vec_u8,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("bytes_be_to_vec_u8 call failed: {}", err),
            _ => unreachable!(),
        };
        assert_eq!(signal_from_be.iter().copied().collect::<Vec<_>>(), signal);
    }

    #[test]
    // Test Vec<CFr> FFI functions
    fn test_vec_cfr_ffi() {
        let vec_fr = [Fr::from(1u8), Fr::from(2u8), Fr::from(3u8), Fr::from(4u8)];
        let vec_cfr: Vec<CFr> = vec_fr.iter().map(|fr| CFr::from(*fr)).collect();

        let bytes_le = vec_cfr_to_bytes_le(&vec_cfr.clone().into());
        let expected_le = rln::utils::vec_fr_to_bytes_le(&vec_fr);
        assert_eq!(bytes_le.iter().copied().collect::<Vec<_>>(), expected_le);

        let bytes_be = vec_cfr_to_bytes_be(&vec_cfr.clone().into());
        let expected_be = rln::utils::vec_fr_to_bytes_be(&vec_fr);
        assert_eq!(bytes_be.iter().copied().collect::<Vec<_>>(), expected_be);

        let vec_cfr_from_le = match bytes_le_to_vec_cfr(&bytes_le) {
            CResult {
                ok: Some(vec_cfr),
                err: None,
            } => vec_cfr,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("bytes_le_to_vec_cfr call failed: {}", err),
            _ => unreachable!(),
        };
        assert_eq!(vec_cfr_from_le.iter().copied().collect::<Vec<_>>(), vec_cfr);

        let vec_cfr_from_be = match bytes_be_to_vec_cfr(&bytes_be) {
            CResult {
                ok: Some(vec_cfr),
                err: None,
            } => vec_cfr,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("bytes_be_to_vec_cfr call failed: {}", err),
            _ => unreachable!(),
        };
        assert_eq!(vec_cfr_from_be.iter().copied().collect::<Vec<_>>(), vec_cfr);
    }

    #[test]
    // Tests hash to field using FFI APIs
    fn test_hash_to_field_ffi() {
        let mut rng = rand::thread_rng();
        let signal_gen: [u8; 32] = rng.gen();
        let signal: Vec<u8> = signal_gen.to_vec();

        let cfr_le_1 = ffi2_hash_to_field_le(&signal.clone().into());
        let fr_le_2 = rln::hashers::hash_to_field_le(&signal);
        assert_eq!(**cfr_le_1, fr_le_2);

        let cfr_be_1 = ffi2_hash_to_field_be(&signal.clone().into());
        let fr_be_2 = rln::hashers::hash_to_field_be(&signal);
        assert_eq!(**cfr_be_1, fr_be_2);

        assert_eq!(*cfr_le_1, **cfr_be_1);
        assert_eq!(fr_le_2, fr_be_2);

        let hash_cfr_le_1 = cfr_to_bytes_le(&cfr_le_1)
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let hash_fr_le_2 = fr_to_bytes_le(&fr_le_2);
        assert_eq!(hash_cfr_le_1, hash_fr_le_2);

        let hash_cfr_be_1 = cfr_to_bytes_be(&cfr_be_1)
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let hash_fr_be_2 = fr_to_bytes_be(&fr_be_2);
        assert_eq!(hash_cfr_be_1, hash_fr_be_2);

        assert_ne!(hash_cfr_le_1, hash_cfr_be_1);
        assert_ne!(hash_fr_le_2, hash_fr_be_2);
    }

    #[test]
    // Test Poseidon hash FFI
    fn test_poseidon_hash_pair_ffi() {
        let input_1 = Fr::from(42u8);
        let input_2 = Fr::from(99u8);

        let expected_hash = poseidon_hash(&[input_1, input_2]);
        let received_hash_cfr = ffi2_poseidon_hash_pair(&CFr::from(input_1), &CFr::from(input_2));
        assert_eq!(**received_hash_cfr, expected_hash);
    }
}
