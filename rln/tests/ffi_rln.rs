#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod test {
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;
    use rln::{
        ffi::{ffi_rln::*, ffi_utils::*},
        prelude::*,
    };
    use safer_ffi::prelude::repr_c;

    const NO_OF_LEAVES: usize = 256;

    macro_rules! unwrap_ok {
        ($result:expr, $context:expr $(,)?) => {
            match $result {
                CResult {
                    ok: Some(value),
                    err: None,
                } => value,
                CResult {
                    ok: None,
                    err: Some(err),
                } => panic!("{} failed: {}", $context, err),
                _ => unreachable!(),
            }
        };
    }

    fn assert_bool_ok(result: CBoolResult, context: &str) {
        assert!(result.err.is_none(), "{context} returned an error");
        assert!(result.ok, "{context} returned false");
    }

    fn create_rln_instance() -> repr_c::Box<FFI_RLN> {
        ffi_rln_new_with_pm_tree_default()
    }

    fn random_leaves(no_of_leaves: usize) -> Vec<CFr> {
        let mut rng = thread_rng();
        (0..no_of_leaves)
            .map(|_| CFr::from(Fr::rand(&mut rng)))
            .collect()
    }

    fn identity_pair_gen() -> (repr_c::Box<CFr>, repr_c::Box<CFr>) {
        let keys = ffi_key_gen();
        let identity_secret: repr_c::Box<CFr> = ffi_vec_cfr_get(&keys, 0).unwrap().into();
        let id_commitment: repr_c::Box<CFr> = ffi_vec_cfr_get(&keys, 1).unwrap().into();
        (identity_secret, id_commitment)
    }

    fn external_nullifier() -> repr_c::Box<CFr> {
        let epoch = ffi_hash_to_field_le(&b"test-epoch".to_vec().into());
        let rln_identifier = ffi_hash_to_field_le(&b"test-rln-identifier".to_vec().into());
        ffi_poseidon_hash_pair(&epoch, &rln_identifier)
    }

    fn random_signal_hash() -> repr_c::Box<CFr> {
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();
        ffi_hash_to_field_le(&signal.to_vec().into())
    }

    // Registers an identity, returns (identity_secret, witness) ready for proof generation
    fn setup_witness(
        rln: &mut repr_c::Box<FFI_RLN>,
        x: &CFr,
    ) -> (repr_c::Box<CFr>, repr_c::Box<FFI_RLNWitnessInput>) {
        let (identity_secret, id_commitment) = identity_pair_gen();
        let user_message_limit = ffi_uint_to_cfr(100);
        let rate_commitment = ffi_poseidon_hash_pair(&id_commitment, &user_message_limit);

        let identity_index = ffi_rln_leaves_set(rln);
        assert_bool_ok(
            ffi_rln_set_next_leaf(rln, &rate_commitment),
            "ffi_rln_set_next_leaf",
        );

        let merkle_proof = unwrap_ok!(
            ffi_rln_get_merkle_proof(rln, identity_index),
            "ffi_rln_get_merkle_proof",
        );

        let external_nullifier = external_nullifier();
        let message_id = ffi_uint_to_cfr(1);

        let witness = unwrap_ok!(
            ffi_rln_witness_input_new_single(
                &identity_secret,
                &user_message_limit,
                &message_id,
                &merkle_proof.path_elements,
                &merkle_proof.path_index,
                x,
                &external_nullifier,
            ),
            "ffi_rln_witness_input_new_single",
        );

        (identity_secret, witness)
    }

    #[test]
    fn test_merkle_operations() {
        let leaves = random_leaves(NO_OF_LEAVES);

        // We create a new RLN instance
        let mut rln = create_rln_instance();

        // We first add leaves one by one specifying the index
        for (i, leaf) in leaves.iter().enumerate() {
            assert_eq!(ffi_rln_leaves_set(&rln), i);
            assert_bool_ok(ffi_rln_set_leaf(&mut rln, i, leaf), "ffi_rln_set_leaf");
        }

        // We get the root of the tree obtained adding one leaf per time
        let root_single = ffi_rln_get_root(&rln);

        // We reset and add leaves one by one using the internal index
        let mut rln = create_rln_instance();
        for leaf in &leaves {
            assert_bool_ok(
                ffi_rln_set_next_leaf(&mut rln, leaf),
                "ffi_rln_set_next_leaf",
            );
        }
        assert_eq!(ffi_rln_leaves_set(&rln), NO_OF_LEAVES);
        let root_next = ffi_rln_get_root(&rln);
        assert_eq!(*root_single, *root_next);

        // We reset and add leaves in a batch into the tree
        let mut rln = create_rln_instance();
        assert_bool_ok(
            ffi_rln_init_tree_with_leaves(&mut rln, &leaves.clone().into()),
            "ffi_rln_init_tree_with_leaves",
        );
        assert_eq!(ffi_rln_leaves_set(&rln), NO_OF_LEAVES);
        let root_batch = ffi_rln_get_root(&rln);
        assert_eq!(*root_single, *root_batch);

        // We now delete all leaves set and check if the root corresponds to the empty tree root
        for i in 0..NO_OF_LEAVES {
            assert_bool_ok(ffi_rln_delete_leaf(&mut rln, i), "ffi_rln_delete_leaf");
        }
        assert_eq!(ffi_rln_leaves_set(&rln), NO_OF_LEAVES);
        let root_delete = ffi_rln_get_root(&rln);

        let rln_empty = create_rln_instance();
        let root_empty = ffi_rln_get_root(&rln_empty);
        assert_eq!(*root_delete, *root_empty);
    }

    #[test]
    fn test_leaf_setting_with_index() {
        let mut rng = thread_rng();
        let leaves = random_leaves(NO_OF_LEAVES);
        let set_index = rng.gen_range(0..NO_OF_LEAVES) as usize;

        // We add leaves in a single batch
        let mut rln = create_rln_instance();
        assert_bool_ok(
            ffi_rln_init_tree_with_leaves(&mut rln, &leaves.clone().into()),
            "ffi_rln_init_tree_with_leaves",
        );
        assert_eq!(ffi_rln_leaves_set(&rln), NO_OF_LEAVES);
        let root_batch_with_init = ffi_rln_get_root(&rln);

        // We add leaves in two batches: 0..set_index then set_index..
        let mut rln = create_rln_instance();
        assert_bool_ok(
            ffi_rln_init_tree_with_leaves(&mut rln, &leaves[0..set_index].to_vec().into()),
            "ffi_rln_init_tree_with_leaves",
        );
        assert_bool_ok(
            ffi_rln_set_leaves_from(&mut rln, set_index, &leaves[set_index..].to_vec().into()),
            "ffi_rln_set_leaves_from",
        );
        assert_eq!(ffi_rln_leaves_set(&rln), NO_OF_LEAVES);
        let root_batch_with_custom_index = ffi_rln_get_root(&rln);

        assert_eq!(*root_batch_with_init, *root_batch_with_custom_index);
    }

    #[test]
    fn test_atomic_operation() {
        let leaves = random_leaves(NO_OF_LEAVES);

        let mut rln = create_rln_instance();
        assert_bool_ok(
            ffi_rln_init_tree_with_leaves(&mut rln, &leaves.clone().into()),
            "ffi_rln_init_tree_with_leaves",
        );
        assert_eq!(ffi_rln_leaves_set(&rln), NO_OF_LEAVES);
        let root_after_insertion = ffi_rln_get_root(&rln);

        let last_leaf = leaves.last().unwrap();
        let last_leaf_index = NO_OF_LEAVES - 1;
        let indices: Vec<usize> = vec![last_leaf_index];
        let last_leaf_vec: Vec<CFr> = vec![CFr::from(**last_leaf)];
        assert_bool_ok(
            ffi_rln_atomic_operation(
                &mut rln,
                last_leaf_index,
                &last_leaf_vec.into(),
                &indices.into(),
            ),
            "ffi_rln_atomic_operation",
        );

        let root_after_noop = ffi_rln_get_root(&rln);
        assert_eq!(*root_after_insertion, *root_after_noop);
    }

    #[test]
    fn test_set_leaves_bad_index() {
        let mut rng = thread_rng();
        let leaves = random_leaves(NO_OF_LEAVES);
        let bad_index = (1 << DEFAULT_TREE_DEPTH) - rng.gen_range(0..NO_OF_LEAVES) as usize;

        let mut rln = create_rln_instance();
        let root_empty = ffi_rln_get_root(&rln);

        let result = ffi_rln_set_leaves_from(&mut rln, bad_index, &leaves.into());
        assert!(!result.ok);
        assert!(result.err.is_some());

        assert_eq!(ffi_rln_leaves_set(&rln), 0);
        let root_after_bad_set = ffi_rln_get_root(&rln);
        assert_eq!(*root_empty, *root_after_bad_set);
    }

    #[test]
    fn test_get_leaf() {
        let mut rng = thread_rng();
        let mut rln = create_rln_instance();

        let leaf = CFr::from(Fr::rand(&mut rng));
        let index = rng.gen_range(0..(1 << DEFAULT_TREE_DEPTH));

        assert_bool_ok(ffi_rln_set_leaf(&mut rln, index, &leaf), "ffi_rln_set_leaf");

        let received_leaf = unwrap_ok!(ffi_rln_get_leaf(&rln, index), "ffi_rln_get_leaf");
        assert_eq!(*received_leaf, *leaf);
    }

    #[test]
    fn test_valid_metadata() {
        let mut rln = create_rln_instance();

        let arbitrary_metadata: Vec<u8> = b"block_number:200000".to_vec();
        assert_bool_ok(
            ffi_rln_set_metadata(&mut rln, &arbitrary_metadata.clone().into()),
            "ffi_rln_set_metadata",
        );

        let received_metadata = match ffi_rln_get_metadata(&rln) {
            CResult {
                ok: Some(metadata),
                err: None,
            } => metadata,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("ffi_rln_get_metadata failed: {err}"),
            _ => unreachable!(),
        };
        assert_eq!(arbitrary_metadata, received_metadata.to_vec());
    }

    #[test]
    fn test_empty_metadata() {
        let rln = create_rln_instance();

        let received_metadata = match ffi_rln_get_metadata(&rln) {
            CResult {
                ok: Some(metadata),
                err: None,
            } => metadata,
            _ => panic!("ffi_rln_get_metadata failed"),
        };
        assert_eq!(received_metadata.len(), 0);
    }

    #[test]
    fn test_initialization_with_params() {
        let rln_default = create_rln_instance();
        let root_default = ffi_rln_get_root(&rln_default);

        let zkey_data = include_bytes!("../resources/tree_depth_20/rln_final.arkzkey").to_vec();
        let graph_data = include_bytes!("../resources/tree_depth_20/graph.bin").to_vec();

        let config = std::ffi::CString::new("").unwrap();
        let rln_raw = unwrap_ok!(
            ffi_rln_new_with_pm_tree(
                DEFAULT_TREE_DEPTH,
                &zkey_data.into(),
                &graph_data.into(),
                config.as_c_str().into(),
            ),
            "ffi_rln_new_with_pm_tree",
        );
        let root_raw = ffi_rln_get_root(&rln_raw);

        assert_eq!(*root_default, *root_raw);
    }

    #[test]
    fn test_stateful_rln_proof() {
        let mut rln = create_rln_instance();

        // Pre-populate the tree
        let leaves = random_leaves(NO_OF_LEAVES);
        assert_bool_ok(
            ffi_rln_init_tree_with_leaves(&mut rln, &leaves.into()),
            "ffi_rln_init_tree_with_leaves",
        );

        let x = random_signal_hash();
        let (_identity_secret, witness) = setup_witness(&mut rln, &x);

        let rln_proof = unwrap_ok!(
            ffi_rln_generate_proof(&rln, &witness),
            "ffi_rln_generate_proof",
        );

        assert_bool_ok(
            ffi_rln_verify_with_signal(&rln, &rln_proof, &x),
            "ffi_rln_verify_with_signal",
        );

        // Verification with a wrong signal fails
        let wrong_x = random_signal_hash();
        let result = ffi_rln_verify_with_signal(&rln, &rln_proof, &wrong_x);
        assert!(!result.ok);

        // Pure ZK verify accepts the proof without a signal binding
        assert_bool_ok(ffi_rln_verify(&rln, &rln_proof), "ffi_rln_verify");
    }

    #[test]
    fn test_verify_with_roots_against_real_tree_root() {
        let mut rng = thread_rng();
        let mut rln = create_rln_instance();

        let x = random_signal_hash();
        let (_identity_secret, witness) = setup_witness(&mut rln, &x);
        let rln_proof = unwrap_ok!(
            ffi_rln_generate_proof(&rln, &witness),
            "ffi_rln_generate_proof",
        );

        // Empty roots skip the root check
        let empty_roots: Vec<CFr> = vec![];
        assert_bool_ok(
            ffi_rln_verify_with_roots(&rln, &rln_proof, &empty_roots.into(), &x),
            "ffi_rln_verify_with_roots with empty roots",
        );

        // Random roots do not contain the correct root
        let random_roots: Vec<CFr> = (0..5).map(|_| CFr::from(Fr::rand(&mut rng))).collect();
        let result = ffi_rln_verify_with_roots(&rln, &rln_proof, &random_roots.clone().into(), &x);
        assert!(!result.ok);

        // Adding the real root makes verification pass
        let root = ffi_rln_get_root(&rln);
        let mut roots_with_real = random_roots;
        roots_with_real.push(*root);
        assert_bool_ok(
            ffi_rln_verify_with_roots(&rln, &rln_proof, &roots_with_real.into(), &x),
            "ffi_rln_verify_with_roots with the real root",
        );
    }

    #[test]
    fn test_recover_secret_with_tree_proof() {
        let mut rln = create_rln_instance();

        let x1 = random_signal_hash();
        let (identity_secret, witness1) = setup_witness(&mut rln, &x1);

        // Second witness: same identity, same message id, different signal
        let x2 = random_signal_hash();
        let user_message_limit = ffi_uint_to_cfr(100);
        let message_id = ffi_uint_to_cfr(1);
        let external_nullifier = external_nullifier();
        let merkle_proof = unwrap_ok!(
            ffi_rln_get_merkle_proof(&rln, 0),
            "ffi_rln_get_merkle_proof",
        );
        let witness2 = unwrap_ok!(
            ffi_rln_witness_input_new_single(
                &identity_secret,
                &user_message_limit,
                &message_id,
                &merkle_proof.path_elements,
                &merkle_proof.path_index,
                &x2,
                &external_nullifier,
            ),
            "ffi_rln_witness_input_new_single",
        );

        let proof1 = unwrap_ok!(
            ffi_rln_generate_proof(&rln, &witness1),
            "ffi_rln_generate_proof",
        );
        let proof2 = unwrap_ok!(
            ffi_rln_generate_proof(&rln, &witness2),
            "ffi_rln_generate_proof",
        );

        let proof_values_1 = ffi_rln_proof_get_values(&proof1);
        let proof_values_2 = ffi_rln_proof_get_values(&proof2);

        let recovered = unwrap_ok!(
            ffi_rln_recover_id_secret(&proof_values_1, &proof_values_2),
            "ffi_rln_recover_id_secret",
        );
        assert_eq!(*recovered, *identity_secret);

        // Recovery with proofs from two different identities fails
        let x3 = random_signal_hash();
        let (_identity_secret_new, witness3) = setup_witness(&mut rln, &x3);
        let proof3 = unwrap_ok!(
            ffi_rln_generate_proof(&rln, &witness3),
            "ffi_rln_generate_proof",
        );
        let proof_values_3 = ffi_rln_proof_get_values(&proof3);

        let recover_result = ffi_rln_recover_id_secret(&proof_values_1, &proof_values_3);
        assert!(recover_result.ok.is_none());
    }

    #[test]
    fn test_partial_and_finish_proof() {
        let mut rln = create_rln_instance();

        let x = random_signal_hash();
        let (_identity_secret, witness) = setup_witness(&mut rln, &x);

        let partial_witness = ffi_rln_witness_to_partial_witness(&witness);
        let partial_proof = unwrap_ok!(
            ffi_rln_generate_partial_proof(&rln, &partial_witness),
            "ffi_rln_generate_partial_proof",
        );
        let rln_proof = unwrap_ok!(
            ffi_rln_finish_proof(&rln, &partial_proof, &witness),
            "ffi_rln_finish_proof",
        );

        assert_bool_ok(
            ffi_rln_verify_with_signal(&rln, &rln_proof, &x),
            "ffi_rln_verify_with_signal",
        );
    }

    #[test]
    fn test_witness_and_proof_values_serialization() {
        let mut rln = create_rln_instance();
        let x = random_signal_hash();
        let (_identity_secret, witness) = setup_witness(&mut rln, &x);

        // Witness roundtrip LE + BE
        macro_rules! witness_roundtrip {
            ($to_bytes:ident, $from_bytes:ident) => {{
                let bytes = unwrap_ok!($to_bytes(&witness), "witness serialization");

                let deser = unwrap_ok!($from_bytes(&bytes), "witness deserialization");
                let roundtrip_x = ffi_rln_witness_input_get_x(&deser);
                assert_eq!(*roundtrip_x, *x);

                // Truncated bytes must be rejected
                let truncated: Vec<u8> = bytes[..bytes.len() - 1].to_vec();
                let truncated_result = $from_bytes(&truncated.into());
                assert!(truncated_result.ok.is_none());
            }};
        }
        witness_roundtrip!(ffi_rln_witness_to_bytes_le, ffi_bytes_le_to_rln_witness);
        witness_roundtrip!(ffi_rln_witness_to_bytes_be, ffi_bytes_be_to_rln_witness);

        // Proof values roundtrip LE + BE
        let rln_proof = unwrap_ok!(
            ffi_rln_generate_proof(&rln, &witness),
            "ffi_rln_generate_proof",
        );
        let proof_values = ffi_rln_proof_get_values(&rln_proof);

        macro_rules! proof_values_roundtrip {
            ($to_bytes:ident, $from_bytes:ident) => {{
                let bytes = unwrap_ok!($to_bytes(&proof_values), "proof values serialization");

                let deser = unwrap_ok!($from_bytes(&bytes), "proof values deserialization");
                let root_original = ffi_rln_proof_values_get_root(&proof_values);
                let root_roundtrip = ffi_rln_proof_values_get_root(&deser);
                assert_eq!(*root_original, *root_roundtrip);

                // Truncated bytes must be rejected
                let truncated: Vec<u8> = bytes[..bytes.len() - 1].to_vec();
                let truncated_result = $from_bytes(&truncated.into());
                assert!(truncated_result.ok.is_none());
            }};
        }
        proof_values_roundtrip!(
            ffi_rln_proof_values_to_bytes_le,
            ffi_bytes_le_to_rln_proof_values
        );
        proof_values_roundtrip!(
            ffi_rln_proof_values_to_bytes_be,
            ffi_bytes_be_to_rln_proof_values
        );
    }

    #[test]
    fn test_rln_proof_serialization() {
        let mut rln = create_rln_instance();
        let x = random_signal_hash();
        let (_identity_secret, witness) = setup_witness(&mut rln, &x);
        let rln_proof = unwrap_ok!(
            ffi_rln_generate_proof(&rln, &witness),
            "ffi_rln_generate_proof",
        );

        macro_rules! proof_roundtrip {
            ($to_bytes:ident, $from_bytes:ident) => {{
                let bytes = unwrap_ok!($to_bytes(&rln_proof), "proof serialization");

                let deser = unwrap_ok!($from_bytes(&bytes), "proof deserialization");
                assert_bool_ok(
                    ffi_rln_verify_with_signal(&rln, &deser, &x),
                    "ffi_rln_verify_with_signal on deserialized proof",
                );
            }};
        }
        proof_roundtrip!(ffi_rln_proof_to_bytes_le, ffi_bytes_le_to_rln_proof);
        proof_roundtrip!(ffi_rln_proof_to_bytes_mixed, ffi_bytes_mixed_to_rln_proof);
    }

    #[test]
    fn test_partial_witness_and_proof_serialization() {
        let mut rln = create_rln_instance();
        let x = random_signal_hash();
        let (_identity_secret, witness) = setup_witness(&mut rln, &x);

        let partial_witness = ffi_rln_witness_to_partial_witness(&witness);

        // Partial witness roundtrip LE + BE
        macro_rules! partial_witness_roundtrip {
            ($to_bytes:ident, $from_bytes:ident) => {{
                let bytes =
                    unwrap_ok!($to_bytes(&partial_witness), "partial witness serialization");

                let deser = unwrap_ok!($from_bytes(&bytes), "partial witness deserialization");
                let original_limit =
                    ffi_rln_partial_witness_input_get_user_message_limit(&partial_witness);
                let roundtrip_limit = ffi_rln_partial_witness_input_get_user_message_limit(&deser);
                assert_eq!(*original_limit, *roundtrip_limit);

                // Truncated bytes must be rejected
                let truncated: Vec<u8> = bytes[..bytes.len() - 1].to_vec();
                let truncated_result = $from_bytes(&truncated.into());
                assert!(truncated_result.ok.is_none());
            }};
        }
        partial_witness_roundtrip!(
            ffi_rln_partial_witness_to_bytes_le,
            ffi_bytes_le_to_rln_partial_witness
        );
        partial_witness_roundtrip!(
            ffi_rln_partial_witness_to_bytes_be,
            ffi_bytes_be_to_rln_partial_witness
        );

        // Partial proof roundtrip LE; the finished proof must still verify
        let partial_proof = unwrap_ok!(
            ffi_rln_generate_partial_proof(&rln, &partial_witness),
            "ffi_rln_generate_partial_proof",
        );
        let bytes = match ffi_rln_partial_proof_to_bytes_le(&partial_proof) {
            CResult {
                ok: Some(bytes),
                err: None,
            } => bytes,
            _ => panic!("partial proof serialization failed"),
        };
        let partial_proof_deser = unwrap_ok!(
            ffi_bytes_le_to_rln_partial_proof(&bytes),
            "partial proof deserialization",
        );
        let rln_proof = unwrap_ok!(
            ffi_rln_finish_proof(&rln, &partial_proof_deser, &witness),
            "ffi_rln_finish_proof",
        );
        assert_bool_ok(
            ffi_rln_verify_with_signal(&rln, &rln_proof, &x),
            "ffi_rln_verify_with_signal",
        );
    }

    #[test]
    fn test_invalid_witness_input() {
        let mut rng = thread_rng();
        let (identity_secret, _) = identity_pair_gen();
        let x = random_signal_hash();
        let external_nullifier = external_nullifier();

        let path_elements: Vec<CFr> = (0..DEFAULT_TREE_DEPTH)
            .map(|_| CFr::from(Fr::rand(&mut rng)))
            .collect();
        let identity_path_index: Vec<u8> = vec![0; DEFAULT_TREE_DEPTH];

        let user_message_limit = ffi_uint_to_cfr(100);

        // message_id >= user_message_limit fails
        let invalid_message_id = ffi_uint_to_cfr(100);
        let result = ffi_rln_witness_input_new_single(
            &identity_secret,
            &user_message_limit,
            &invalid_message_id,
            &path_elements.clone().into(),
            &identity_path_index.clone().into(),
            &x,
            &external_nullifier,
        );
        assert!(result.ok.is_none());

        // user_message_limit == 0 fails
        let zero_limit = ffi_uint_to_cfr(0);
        let zero_message_id = ffi_uint_to_cfr(0);
        let result = ffi_rln_witness_input_new_single(
            &identity_secret,
            &zero_limit,
            &zero_message_id,
            &path_elements.clone().into(),
            &identity_path_index.clone().into(),
            &x,
            &external_nullifier,
        );
        assert!(result.ok.is_none());

        // path_elements and identity_path_index length mismatch fails
        let message_id = ffi_uint_to_cfr(1);
        let short_index: Vec<u8> = vec![0; DEFAULT_TREE_DEPTH - 1];
        let result = ffi_rln_witness_input_new_single(
            &identity_secret,
            &user_message_limit,
            &message_id,
            &path_elements.into(),
            &short_index.into(),
            &x,
            &external_nullifier,
        );
        assert!(result.ok.is_none());
    }

    #[test]
    fn test_partial_witness_zero_limit() {
        let mut rng = thread_rng();
        let (identity_secret, _) = identity_pair_gen();

        let path_elements: Vec<CFr> = (0..DEFAULT_TREE_DEPTH)
            .map(|_| CFr::from(Fr::rand(&mut rng)))
            .collect();
        let identity_path_index: Vec<u8> = vec![0; DEFAULT_TREE_DEPTH];

        let zero_limit = ffi_uint_to_cfr(0);
        let result = ffi_rln_partial_witness_input_new(
            &identity_secret,
            &zero_limit,
            &path_elements.into(),
            &identity_path_index.into(),
        );
        assert!(result.ok.is_none());
    }

    #[test]
    fn test_out_of_bounds() {
        let mut rng = thread_rng();
        let mut rln = create_rln_instance();
        let max_index = 1 << DEFAULT_TREE_DEPTH;
        let leaf = CFr::from(Fr::rand(&mut rng));

        // set_leaf beyond capacity
        let result = ffi_rln_set_leaf(&mut rln, max_index, &leaf);
        assert!(!result.ok);

        // get_leaf beyond capacity
        let result = ffi_rln_get_leaf(&rln, max_index);
        assert!(result.ok.is_none());

        // get_merkle_proof beyond capacity
        let result = ffi_rln_get_merkle_proof(&rln, max_index);
        assert!(result.ok.is_none());

        // delete_leaf beyond capacity is rejected
        let result = ffi_rln_delete_leaf(&mut rln, max_index);
        assert!(!result.ok);
    }

    #[test]
    fn test_stateless_tree_ops_rejected() {
        let mut rln = ffi_rln_new_stateless_default();
        let mut rng = thread_rng();
        let leaf = CFr::from(Fr::rand(&mut rng));

        let result = ffi_rln_set_leaf(&mut rln, 0, &leaf);
        assert!(!result.ok);

        let result = ffi_rln_get_leaf(&rln, 0);
        assert!(result.ok.is_none());

        let result = ffi_rln_get_merkle_proof(&rln, 0);
        assert!(result.ok.is_none());
    }

    #[test]
    fn test_stateless_proof() {
        let mut stateful_rln = create_rln_instance();
        let stateless_rln = ffi_rln_new_stateless_default();

        let x = random_signal_hash();
        let (_identity_secret, witness) = setup_witness(&mut stateful_rln, &x);

        let rln_proof = unwrap_ok!(
            ffi_rln_generate_proof(&stateless_rln, &witness),
            "ffi_rln_generate_proof",
        );

        // Verify against the stateful tree root through verify_with_roots
        let root = ffi_rln_get_root(&stateful_rln);
        let roots: Vec<CFr> = vec![(*root)];
        assert_bool_ok(
            ffi_rln_verify_with_roots(&stateless_rln, &rln_proof, &roots.into(), &x),
            "ffi_rln_verify_with_roots on stateless instance",
        );
    }

    #[test]
    fn test_compute_id_secret() {
        let mut rln = create_rln_instance();

        let x1 = random_signal_hash();
        let (identity_secret, witness1) = setup_witness(&mut rln, &x1);

        let x2 = random_signal_hash();
        let user_message_limit = ffi_uint_to_cfr(100);
        let message_id = ffi_uint_to_cfr(1);
        let external_nullifier = external_nullifier();
        let merkle_proof = unwrap_ok!(
            ffi_rln_get_merkle_proof(&rln, 0),
            "ffi_rln_get_merkle_proof",
        );
        let witness2 = unwrap_ok!(
            ffi_rln_witness_input_new_single(
                &identity_secret,
                &user_message_limit,
                &message_id,
                &merkle_proof.path_elements,
                &merkle_proof.path_index,
                &x2,
                &external_nullifier,
            ),
            "ffi_rln_witness_input_new_single",
        );

        let proof1 = unwrap_ok!(
            ffi_rln_generate_proof(&rln, &witness1),
            "ffi_rln_generate_proof",
        );
        let proof2 = unwrap_ok!(
            ffi_rln_generate_proof(&rln, &witness2),
            "ffi_rln_generate_proof",
        );
        let proof_values_1 = ffi_rln_proof_get_values(&proof1);
        let proof_values_2 = ffi_rln_proof_get_values(&proof2);

        let y1 = unwrap_ok!(
            ffi_rln_proof_values_get_y(&proof_values_1),
            "ffi_rln_proof_values_get_y",
        );
        let y2 = unwrap_ok!(
            ffi_rln_proof_values_get_y(&proof_values_2),
            "ffi_rln_proof_values_get_y",
        );

        let recovered = unwrap_ok!(
            ffi_rln_compute_id_secret(&x1, &y1, &x2, &y2),
            "ffi_rln_compute_id_secret",
        );
        assert_eq!(*recovered, *identity_secret);
    }
}
