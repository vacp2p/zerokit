#[cfg(test)]
#[cfg(not(feature = "stateless"))]
mod test {
    use rand::Rng;
    use rln::circuit::{Fr, TEST_TREE_DEPTH};
    use rln::ffi2::{
        ffi2_generate_rln_proof, ffi2_get_root, ffi2_key_gen, ffi2_new, ffi2_new_with_params,
        ffi2_set_next_leaf, ffi2_verify_rln_proof, CFr, CResult, FFI2_RLNWitnessInput, FFI2_RLN,
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

    fn get_tree_root(rln_pointer: &repr_c::Box<FFI2_RLN>) -> Fr {
        let root_cfr = ffi2_get_root(rln_pointer);
        **root_cfr.deref()
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
