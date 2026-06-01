#![cfg(target_arch = "wasm32")]
#![cfg(not(feature = "utils"))]

#[cfg(test)]
mod test {
    use js_sys::{Date, Uint8Array};
    use rln::prelude::*;
    use rln_wasm::{
        Hasher, Identity, VecWasmFr, WasmFr, WasmRLN, WasmRLNPartialProof,
        WasmRLNPartialWitnessInput, WasmRLNProof, WasmRLNProofValues, WasmRLNWitnessInput,
    };
    use wasm_bindgen_test::{console_log, wasm_bindgen_test};
    use zerokit_utils::merkle_tree::{
        OptimalMerkleProof, OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree,
    };

    const ARKZKEY_BYTES: &[u8] =
        include_bytes!("../../rln/resources/tree_depth_20/rln_final.arkzkey");

    const GRAPH_BYTES: &[u8] = include_bytes!("../../rln/resources/tree_depth_20/graph.bin");

    fn build_witness_parts() -> (
        WasmFr,
        WasmFr,
        WasmFr,
        VecWasmFr,
        Uint8Array,
        WasmFr,
        WasmFr,
    ) {
        let mut tree: OptimalMerkleTree<PoseidonHash> =
            OptimalMerkleTree::default(DEFAULT_TREE_DEPTH).unwrap();

        let identity_pair = Identity::generate();
        let identity_secret = identity_pair.get_secret_hash();
        let id_commitment = identity_pair.get_commitment();

        let epoch = Hasher::hash_to_field_le(&Uint8Array::from(b"test-epoch" as &[u8]));
        let rln_identifier =
            Hasher::hash_to_field_le(&Uint8Array::from(b"test-rln-identifier" as &[u8]));
        let external_nullifier = Hasher::poseidon_hash_pair(&epoch, &rln_identifier);

        let identity_index = tree.leaves_set();
        let user_message_limit = WasmFr::from_uint(10);
        let rate_commitment = Hasher::poseidon_hash_pair(&id_commitment, &user_message_limit);
        tree.update_next(*rate_commitment).unwrap();

        let message_id = WasmFr::from_uint(0);
        let signal: [u8; 32] = [0; 32];
        let x = Hasher::hash_to_field_le(&Uint8Array::from(&signal[..]));

        let merkle_proof: OptimalMerkleProof<PoseidonHash> = tree.proof(identity_index).unwrap();
        let mut path_elements = VecWasmFr::new();
        for path_element in merkle_proof.get_path_elements() {
            path_elements.push(&WasmFr::from(path_element));
        }
        let path_index = Uint8Array::from(&merkle_proof.get_path_index()[..]);

        (
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            path_index,
            x,
            external_nullifier,
        )
    }

    #[wasm_bindgen_test]
    pub fn rln_wasm_benchmark() {
        let mut results = String::from("\nBenchmarks:\n");
        let iterations = 10;

        let zkey = Uint8Array::from(ARKZKEY_BYTES);
        let graph = Uint8Array::from(GRAPH_BYTES);

        // Benchmark RLN instance creation
        let start_rln_new = Date::now();
        for _ in 0..iterations {
            let _ = WasmRLN::new_with_params(&zkey, &graph).unwrap();
        }
        let rln_new_result = Date::now() - start_rln_new;

        // Create RLN instance for other benchmarks
        let rln_instance = WasmRLN::new_with_params(&zkey, &graph).unwrap();
        let mut tree: OptimalMerkleTree<PoseidonHash> =
            OptimalMerkleTree::default(DEFAULT_TREE_DEPTH).unwrap();

        // Benchmark generate identity
        let start_identity_gen = Date::now();
        for _ in 0..iterations {
            let _ = Identity::generate();
        }
        let identity_gen_result = Date::now() - start_identity_gen;

        // Generate identity for other benchmarks
        let identity_pair = Identity::generate();
        let identity_secret = identity_pair.get_secret_hash();
        let id_commitment = identity_pair.get_commitment();

        let epoch = Hasher::hash_to_field_le(&Uint8Array::from(b"test-epoch" as &[u8]));
        let rln_identifier =
            Hasher::hash_to_field_le(&Uint8Array::from(b"test-rln-identifier" as &[u8]));
        let external_nullifier = Hasher::poseidon_hash_pair(&epoch, &rln_identifier);

        let identity_index = tree.leaves_set();
        let user_message_limit = WasmFr::from_uint(10);
        let rate_commitment = Hasher::poseidon_hash_pair(&id_commitment, &user_message_limit);
        tree.update_next(*rate_commitment).unwrap();

        let message_id = WasmFr::from_uint(0);
        let signal: [u8; 32] = [0; 32];
        let x = Hasher::hash_to_field_le(&Uint8Array::from(&signal[..]));

        let merkle_proof: OptimalMerkleProof<PoseidonHash> = tree.proof(identity_index).unwrap();
        let mut path_elements = VecWasmFr::new();
        for path_element in merkle_proof.get_path_elements() {
            path_elements.push(&WasmFr::from(path_element));
        }
        let path_index = Uint8Array::from(&merkle_proof.get_path_index()[..]);

        let witness = WasmRLNWitnessInput::new_single(
            &identity_secret,
            &user_message_limit,
            &message_id,
            &path_elements,
            &path_index,
            &x,
            &external_nullifier,
        )
        .unwrap();

        // Benchmark proof generation
        let start_generate_proof = Date::now();
        for _ in 0..iterations {
            let _ = rln_instance.generate_proof(&witness).unwrap();
        }
        let generate_proof_result = Date::now() - start_generate_proof;

        // Generate proof for other benchmarks
        let proof: WasmRLNProof = rln_instance.generate_proof(&witness).unwrap();

        let root = WasmFr::from(tree.root());
        let mut roots = VecWasmFr::new();
        roots.push(&root);

        // Benchmark proof verification with the root
        let start_verify_with_roots = Date::now();
        for _ in 0..iterations {
            let _ = rln_instance.verify_with_roots(&proof, &roots, &x).unwrap();
        }
        let verify_with_roots_result = Date::now() - start_verify_with_roots;

        let is_proof_valid = rln_instance.verify_with_roots(&proof, &roots, &x).unwrap();
        assert!(is_proof_valid, "verification failed");

        // Benchmark partial proof generation
        let partial_witness = WasmRLNPartialWitnessInput::from_witness(&witness);
        let start_generate_partial_proof = Date::now();
        for _ in 0..iterations {
            let _ = rln_instance
                .generate_partial_proof(&partial_witness)
                .unwrap();
        }
        let generate_partial_proof_result = Date::now() - start_generate_partial_proof;

        // Generate partial proof for finish benchmark
        let partial_proof: WasmRLNPartialProof = rln_instance
            .generate_partial_proof(&partial_witness)
            .unwrap();

        // Benchmark finish full proof
        let start_finish_full_proof = Date::now();
        for _ in 0..iterations {
            let _ = rln_instance.finish_proof(&partial_proof, &witness).unwrap();
        }
        let finish_full_proof_result = Date::now() - start_finish_full_proof;

        let format_duration = |duration_ms: f64| -> String {
            let avg_ms = duration_ms / (iterations as f64);
            if avg_ms >= 1000.0 {
                format!("{:.3} s", avg_ms / 1000.0)
            } else {
                format!("{:.3} ms", avg_ms)
            }
        };

        results.push_str(&format!(
            "RLN instance creation: {}\n",
            format_duration(rln_new_result)
        ));
        results.push_str(&format!(
            "Identity generation: {}\n",
            format_duration(identity_gen_result)
        ));
        results.push_str(&format!(
            "Proof generation: {}\n",
            format_duration(generate_proof_result)
        ));
        results.push_str(&format!(
            "Proof verification with roots: {}\n",
            format_duration(verify_with_roots_result)
        ));
        results.push_str(&format!(
            "Partial proof generation: {}\n",
            format_duration(generate_partial_proof_result)
        ));
        results.push_str(&format!(
            "Finish full proof: {}\n",
            format_duration(finish_full_proof_result)
        ));

        console_log!("{results}");
    }

    #[wasm_bindgen_test]
    pub fn test_wasm_invalid_inputs() {
        // Invalid zkey data
        let invalid_zkey = Uint8Array::from(&[0u8; 16][..]);
        let graph = Uint8Array::from(GRAPH_BYTES);
        assert!(WasmRLN::new_with_params(&invalid_zkey, &graph).is_err());

        let (
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            path_index,
            x,
            external_nullifier,
        ) = build_witness_parts();

        // Invalid user message limit (zero)
        let zero_limit = WasmFr::zero();
        let result = WasmRLNWitnessInput::new_single(
            &identity_secret,
            &zero_limit,
            &message_id,
            &path_elements,
            &path_index,
            &x,
            &external_nullifier,
        );
        assert!(result.is_err());

        // Invalid message id (>= limit)
        let invalid_message_id = user_message_limit;
        let result = WasmRLNWitnessInput::new_single(
            &identity_secret,
            &user_message_limit,
            &invalid_message_id,
            &path_elements,
            &path_index,
            &x,
            &external_nullifier,
        );
        assert!(result.is_err());

        // Invalid merkle proof length (path elements vs path index)
        let mut shorter_path_elements = VecWasmFr::new();
        for i in 0..path_elements.length().saturating_sub(1) {
            shorter_path_elements.push(&path_elements.get(i).unwrap());
        }
        let result = WasmRLNWitnessInput::new_single(
            &identity_secret,
            &user_message_limit,
            &message_id,
            &shorter_path_elements,
            &path_index,
            &x,
            &external_nullifier,
        );
        assert!(result.is_err());

        // Witness bytes: truncated and extra data
        let valid_witness = WasmRLNWitnessInput::new_single(
            &identity_secret,
            &user_message_limit,
            &message_id,
            &path_elements,
            &path_index,
            &x,
            &external_nullifier,
        )
        .unwrap();

        let witness_le = valid_witness.to_bytes_le().unwrap();
        let witness_le_vec = witness_le.to_vec();
        let truncated_le = Uint8Array::from(&witness_le_vec[..witness_le_vec.len() - 1]);
        assert!(WasmRLNWitnessInput::from_bytes_le(&truncated_le).is_err());

        let mut extra_le_vec = witness_le_vec.clone();
        extra_le_vec.push(0);
        let extra_le = Uint8Array::from(&extra_le_vec[..]);
        assert!(WasmRLNWitnessInput::from_bytes_le(&extra_le).is_ok());

        let witness_be = valid_witness.to_bytes_be().unwrap();
        let witness_be_vec = witness_be.to_vec();
        let truncated_be = Uint8Array::from(&witness_be_vec[..witness_be_vec.len() - 1]);
        assert!(WasmRLNWitnessInput::from_bytes_be(&truncated_be).is_err());

        let mut extra_be_vec = witness_be_vec.clone();
        extra_be_vec.push(0);
        let extra_be = Uint8Array::from(&extra_be_vec[..]);
        assert!(WasmRLNWitnessInput::from_bytes_be(&extra_be).is_ok());

        // Proof values bytes: truncated and extra data
        let valid_pv = valid_witness.to_proof_values();

        let pv_le = valid_pv.to_bytes_le().unwrap();
        let pv_le_vec = pv_le.to_vec();
        let truncated_pv_le = Uint8Array::from(&pv_le_vec[..pv_le_vec.len() - 1]);
        assert!(WasmRLNProofValues::from_bytes_le(&truncated_pv_le).is_err());
        let mut extra_pv_le_vec = pv_le_vec.clone();
        extra_pv_le_vec.push(0);
        let extra_pv_le = Uint8Array::from(&extra_pv_le_vec[..]);
        assert!(WasmRLNProofValues::from_bytes_le(&extra_pv_le).is_ok());

        let pv_be = valid_pv.to_bytes_be().unwrap();
        let pv_be_vec = pv_be.to_vec();
        let truncated_pv_be = Uint8Array::from(&pv_be_vec[..pv_be_vec.len() - 1]);
        assert!(WasmRLNProofValues::from_bytes_be(&truncated_pv_be).is_err());
        let mut extra_pv_be_vec = pv_be_vec.clone();
        extra_pv_be_vec.push(0);
        let extra_pv_be = Uint8Array::from(&extra_pv_be_vec[..]);
        assert!(WasmRLNProofValues::from_bytes_be(&extra_pv_be).is_ok());

        // Proof bytes: insufficient length
        let proof = [0u8; COMPRESS_PROOF_SIZE];
        let proof = Uint8Array::from(&proof[..]);
        assert!(WasmRLNProof::from_bytes_le(&proof).is_err());
    }
}
