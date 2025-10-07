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
    use std::ops::Deref;
    use std::time::{Duration, Instant};
    use zeroize::Zeroize;

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

    fn set_leaves_init(rln_pointer: &mut repr_c::Box<FFI2_RLN>, leaves: &[Fr]) {
        let leaves_cfr: repr_c::Vec<CFr> = leaves
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let result = ffi2_init_tree_with_leaves(rln_pointer, leaves_cfr);
        match result {
            CResult {
                ok: Some(_),
                err: None,
            } => {
                assert_eq!(ffi2_leaves_set(rln_pointer), leaves.len());
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

    fn get_tree_root(rln_pointer: &repr_c::Box<FFI2_RLN>) -> Fr {
        let root_cfr = ffi2_get_root(rln_pointer);
        **root_cfr.deref()
    }

    fn identity_pair_gen() -> (IdSecret, Fr) {
        let key_gen = ffi2_key_gen();
        let mut id_secret_fr = (*key_gen[0]).clone();
        let id_secret_hash = IdSecret::from(&mut id_secret_fr);
        let id_commitment = (*key_gen[1]).clone();
        (id_secret_hash, id_commitment)
    }

    fn rln_proof_gen(
        rln_pointer: &repr_c::Box<FFI2_RLN>,
        witness_input: &repr_c::Box<FFI2_RLNWitnessInput>,
    ) -> repr_c::Box<FFI2_RLNProof> {
        let result = ffi2_generate_rln_proof(rln_pointer, witness_input);
        match result {
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
        let mut rln_pointer = create_rln_instance();

        // We first add leaves one by one specifying the index
        for (i, leaf) in leaves.iter().enumerate() {
            // We prepare the rate_commitment and we set the leaf at provided index
            let result = ffi2_set_leaf(&mut rln_pointer, i, &Box_::new(CFr::from(*leaf)));
            match result {
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
        let root_single = get_tree_root(&rln_pointer);

        // We reset the tree to default
        let result = ffi2_set_tree(&mut rln_pointer, TEST_TREE_DEPTH);
        match result {
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
            let result = ffi2_set_next_leaf(&mut rln_pointer, &Box_::new(CFr::from(*leaf)));
            match result {
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
        let root_next = get_tree_root(&rln_pointer);

        // We check if roots are the same
        assert_eq!(root_single, root_next);

        // We reset the tree to default
        let result = ffi2_set_tree(&mut rln_pointer, TEST_TREE_DEPTH);
        match result {
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
        set_leaves_init(&mut rln_pointer, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_batch = get_tree_root(&rln_pointer);

        // We check if roots are the same
        assert_eq!(root_single, root_batch);

        // We now delete all leaves set and check if the root corresponds to the empty tree root
        // delete calls over indexes higher than no_of_leaves are ignored and will not increase self.tree.next_index
        for i in 0..NO_OF_LEAVES {
            let result = ffi2_delete_leaf(&mut rln_pointer, i);
            match result {
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
        let root_delete = get_tree_root(&rln_pointer);

        // We reset the tree to default
        let result = ffi2_set_tree(&mut rln_pointer, TEST_TREE_DEPTH);
        match result {
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
        let root_empty = get_tree_root(&rln_pointer);

        // We check if roots are the same
        assert_eq!(root_delete, root_empty);
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    // Uses `set_leaves_from` to set leaves in a batch
    fn test_leaf_setting_with_index_ffi() {
        // We create a RLN instance
        let mut rln_pointer = create_rln_instance();
        assert_eq!(ffi2_leaves_set(&rln_pointer), 0);

        // We generate a vector of random leaves
        let leaves = get_random_leaves();

        // set_index is the index from which we start setting leaves
        // random number between 0..no_of_leaves
        let mut rng = thread_rng();
        let set_index = rng.gen_range(0..NO_OF_LEAVES) as usize;
        println!("set_index: {set_index}");

        // We add leaves in a batch into the tree
        set_leaves_init(&mut rln_pointer, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_batch_with_init = get_tree_root(&rln_pointer);

        // `init_tree_with_leaves` resets the tree to the depth it was initialized with, using `set_tree`

        // We add leaves in a batch starting from index 0..set_index
        set_leaves_init(&mut rln_pointer, &leaves[0..set_index]);

        // We add the remaining n leaves in a batch starting from index set_index
        let leaves_n: repr_c::Vec<CFr> = leaves[set_index..]
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let result = ffi2_set_leaves_from(&mut rln_pointer, set_index, leaves_n);
        match result {
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
        let root_batch_with_custom_index = get_tree_root(&rln_pointer);
        assert_eq!(
            root_batch_with_init, root_batch_with_custom_index,
            "root batch !="
        );

        // We reset the tree to default
        let result = ffi2_set_tree(&mut rln_pointer, TEST_TREE_DEPTH);
        match result {
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
            let result = ffi2_set_next_leaf(&mut rln_pointer, &Box_::new(CFr::from(*leaf)));
            match result {
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
        let root_single_additions = get_tree_root(&rln_pointer);
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
        let mut rln_pointer = create_rln_instance();

        // We add leaves in a batch into the tree
        set_leaves_init(&mut rln_pointer, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_after_insertion = get_tree_root(&rln_pointer);

        let last_leaf = leaves.last().unwrap();
        let last_leaf_index = NO_OF_LEAVES - 1;
        let indices: repr_c::Vec<usize> = vec![last_leaf_index].into();
        let last_leaf_vec: repr_c::Vec<CFr> = vec![CFr::from(*last_leaf)].into();

        let result =
            ffi2_atomic_operation(&mut rln_pointer, last_leaf_index, last_leaf_vec, indices);
        match result {
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
        let root_after_noop = get_tree_root(&rln_pointer);
        assert_eq!(root_after_insertion, root_after_noop);
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    fn test_set_leaves_bad_index_ffi() {
        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let mut rln_pointer = create_rln_instance();

        let mut rng = thread_rng();
        let bad_index = (1 << TEST_TREE_DEPTH) - rng.gen_range(0..NO_OF_LEAVES) as usize;

        // Get root of empty tree
        let root_empty = get_tree_root(&rln_pointer);

        // We add leaves in a batch into the tree
        let leaves_cfr: repr_c::Vec<CFr> = leaves
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let result = ffi2_set_leaves_from(&mut rln_pointer, bad_index, leaves_cfr);
        match result {
            CResult {
                ok: None,
                err: Some(_),
            } => {}
            _ => panic!("set leaves from call should have failed"),
        }

        // Get root of tree after attempted set
        let root_after_bad_set = get_tree_root(&rln_pointer);
        assert_eq!(root_empty, root_after_bad_set);
    }

    #[test]
    // This test is similar to the one in lib, but uses only public C API
    fn test_merkle_proof_ffi() {
        let leaf_index = 3;
        // We create a RLN instance
        let mut rln_pointer = create_rln_instance();

        // generate identity
        let mut identity_secret_hash_ = hash_to_field_le(b"test-merkle-proof");
        let identity_secret_hash = IdSecret::from(&mut identity_secret_hash_);
        let mut to_hash = [*identity_secret_hash.clone()];
        let id_commitment = utils_poseidon_hash(&to_hash);
        to_hash[0].zeroize();
        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);

        // We prepare id_commitment and we set the leaf at provided index
        let result = ffi2_set_leaf(
            &mut rln_pointer,
            leaf_index,
            &Box_::new(CFr::from(rate_commitment)),
        );
        match result {
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
        let root = get_tree_root(&rln_pointer);

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
        let result = ffi2_get_proof(&rln_pointer, leaf_index);
        let proof = match result {
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
    // Benchmarks proof generation and verification
    fn test_groth16_proofs_performance_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We compute some benchmarks regarding proof and verify API calls
        // Note that circuit loading requires some initial overhead.
        // Once the circuit is loaded (i.e., when the RLN object is created), proof generation and verification times should be similar at each call.
        let sample_size = 100;
        let mut prove_time: u128 = 0;
        let mut verify_time: u128 = 0;

        for _ in 0..sample_size {
            // We generate random witness instances
            let rln_witness = random_rln_witness(TEST_TREE_DEPTH);

            // Convert path_elements and identity_path_index to FFI types
            let path_elements: repr_c::Vec<CFr> = rln_witness
                .path_elements
                .iter()
                .map(|fr| CFr::from(*fr))
                .collect::<Vec<_>>()
                .into();

            let identity_path_index: repr_c::Box<[u8]> = rln_witness
                .identity_path_index
                .iter()
                .copied()
                .collect::<Vec<_>>()
                .into_boxed_slice()
                .into();

            // We prepare witness input with the hashed signal
            let witness_input = Box_::new(FFI2_RLNWitnessInput {
                identity_secret: CFr::from(*rln_witness.identity_secret).into(),
                user_message_limit: CFr::from(rln_witness.user_message_limit).into(),
                message_id: CFr::from(rln_witness.message_id).into(),
                path_elements,
                identity_path_index,
                x: CFr::from(rln_witness.x).into(),
                external_nullifier: CFr::from(rln_witness.external_nullifier).into(),
            });

            let now = Instant::now();
            let result = ffi2_prove(&rln_pointer, &witness_input);
            prove_time += now.elapsed().as_nanos();

            let proof = match result {
                CResult {
                    ok: Some(proof),
                    err: None,
                } => proof,
                CResult {
                    ok: None,
                    err: Some(err),
                } => panic!("prove call failed: {}", err),
                _ => unreachable!(),
            };

            let now = Instant::now();
            let result = ffi2_verify(&rln_pointer, &proof);
            verify_time += now.elapsed().as_nanos();

            let verified = match result {
                CResult {
                    ok: Some(verified),
                    err: None,
                } => *verified,
                CResult {
                    ok: None,
                    err: Some(err),
                } => panic!("verify call failed: {}", err),
                _ => unreachable!(),
            };

            assert!(verified, "verification failed");
        }

        println!(
            "Average prove API call time: {:?}",
            Duration::from_nanos((prove_time / sample_size).try_into().unwrap())
        );
        println!(
            "Average verify API call time: {:?}",
            Duration::from_nanos((verify_time / sample_size).try_into().unwrap())
        );
    }

    #[test]
    fn test_get_leaf_ffi() {
        // We create a RLN instance
        let no_of_leaves = 1 << TEST_TREE_DEPTH;

        // We create a RLN instance
        let mut rln_pointer = create_rln_instance();

        // We generate a new identity tuple from an input seed
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let key_gen = ffi2_seeded_extended_key_gen(seed_bytes.into());
        assert_eq!(key_gen.len(), 4, "seeded extended key gen call failed");
        let id_commitment = *key_gen[3];

        // We insert the id_commitment into the tree at a random index
        let mut rng = thread_rng();
        let index = rng.gen_range(0..no_of_leaves) as usize;
        let result = ffi2_set_leaf(
            &mut rln_pointer,
            index,
            &Box_::new(CFr::from(id_commitment)),
        );
        match result {
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
        let result = ffi2_get_leaf(&rln_pointer, index);
        let received_id_commitment_cfr = match result {
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
        let mut rln_pointer = create_rln_instance();

        // We add leaves in a batch into the tree
        set_leaves_init(&mut rln_pointer, &leaves);

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
        let result = ffi2_set_next_leaf(&mut rln_pointer, &Box_::new(CFr::from(rate_commitment)));
        match result {
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
        let merkle_proof = match ffi2_get_proof(&rln_pointer, identity_index) {
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

        let witness_input = Box_::new(FFI2_RLNWitnessInput {
            identity_secret: Box_::new(CFr::from(*identity_secret_hash)),
            user_message_limit: CFr::from(user_message_limit).into(),
            message_id: CFr::from(message_id).into(),
            path_elements: merkle_proof
                .path_elements
                .iter()
                .map(|cfr| cfr.clone())
                .collect::<Vec<_>>()
                .into(),
            identity_path_index: merkle_proof
                .path_index
                .iter()
                .copied()
                .collect::<Vec<_>>()
                .into_boxed_slice()
                .into(),
            x: CFr::from(x).into(),
            external_nullifier: CFr::from(external_nullifier).into(),
        });

        let rln_proof = match ffi2_generate_rln_proof(&rln_pointer, &witness_input) {
            CResult {
                ok: Some(rln_proof),
                err: None,
            } => rln_proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("generate rln proof call failed: {}", err),
            _ => unreachable!(),
        };

        let success = match ffi2_verify_rln_proof(&rln_pointer, &rln_proof) {
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

        assert!(success);
    }

    #[test]
    fn test_valid_metadata_ffi() {
        // We create a RLN instance
        let mut rln_pointer = create_rln_instance();

        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let result = ffi2_set_metadata(&mut rln_pointer, seed_bytes.into());
        match result {
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

        let result = ffi2_get_metadata(&rln_pointer);
        let metadata = match result {
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

        assert_eq!(
            metadata.iter().copied().collect::<Vec<u8>>(),
            seed_bytes.to_vec()
        );
    }

    #[test]
    fn test_empty_metadata_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        let result = ffi2_get_metadata(&rln_pointer);
        let metadata = match result {
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
