#![cfg(target_arch = "wasm32")]

#[cfg(test)]
mod tests {
    use js_sys::{BigInt as JsBigInt, Date, Object, Uint8Array};
    use rln::circuit::{Fr, TEST_TREE_HEIGHT};
    use rln::hashers::{hash_to_field, poseidon_hash};
    use rln::poseidon_tree::PoseidonTree;
    use rln::utils::{
        bytes_le_to_fr, fr_to_bytes_le, normalize_usize, vec_fr_to_bytes_le, vec_u8_to_bytes_le,
    };
    use rln_wasm::*;
    use wasm_bindgen::{prelude::*, JsValue};
    use wasm_bindgen_test::wasm_bindgen_test;
    use zerokit_utils::merkle_tree::merkle_tree::ZerokitMerkleTree;
    use zerokit_utils::ZerokitMerkleProof;

    #[wasm_bindgen(module = "src/utils.js")]
    extern "C" {
        #[wasm_bindgen(catch)]
        fn read_file(path: &str) -> Result<Uint8Array, JsValue>;

        #[wasm_bindgen(catch)]
        async fn calculateWitness(circom_path: &str, input: Object) -> Result<JsValue, JsValue>;
    }

    const ZKEY_PATH: &str = "../rln/resources/tree_height_20/rln_final.zkey";
    const CIRCOM_PATH: &str = "../rln/resources/tree_height_20/rln.wasm";

    #[wasm_bindgen_test]
    pub async fn rln_wasm_test() {
        let zkey = read_file(&ZKEY_PATH).unwrap();

        // Creating an instance of RLN
        let rln_instance = wasm_new(zkey).unwrap();

        let mut tree = PoseidonTree::default(TEST_TREE_HEIGHT).unwrap();

        // Creating membership key
        let mem_keys = wasm_key_gen(rln_instance).unwrap();
        let id_key = mem_keys.subarray(0, 32);
        let id_commitment = mem_keys.subarray(32, 64);

        // Prepare the message
        let signal = b"Hello World";

        let identity_index = tree.leaves_set();
        // Setting up the epoch and rln_identifier
        let epoch = hash_to_field(b"test-epoch");
        let rln_identifier = hash_to_field(b"test-rln-identifier");

        let external_nullifier = poseidon_hash(&[epoch, rln_identifier]);
        let external_nullifier = fr_to_bytes_le(&external_nullifier);

        let user_message_limit = Fr::from(100);
        let message_id = fr_to_bytes_le(&Fr::from(0));

        let (id_commitment_fr, _) = bytes_le_to_fr(&id_commitment.to_vec()[..]);
        let rate_commitment = poseidon_hash(&[id_commitment_fr, user_message_limit]);
        tree.update_next(rate_commitment).unwrap();

        let x = hash_to_field(signal);
        let merkle_proof = tree.proof(identity_index).expect("proof should exist");
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        // Serializing the message
        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut id_key.to_vec());
        serialized.append(&mut fr_to_bytes_le(&user_message_limit).to_vec());
        serialized.append(&mut message_id.to_vec());
        serialized.append(&mut vec_fr_to_bytes_le(&path_elements).unwrap());
        serialized.append(&mut vec_u8_to_bytes_le(&identity_path_index).unwrap());
        serialized.append(&mut fr_to_bytes_le(&x));
        serialized.append(&mut external_nullifier.to_vec());
        let serialized_message = Uint8Array::from(&serialized[..]);

        // Obtaining inputs that should be sent to circom witness calculator
        let json_inputs =
            wasm_rln_witness_to_json(rln_instance, serialized_message.clone()).unwrap();

        // Calculating witness with JS
        // (Using a JSON since wasm_bindgen does not like Result<Vec<JsBigInt>,JsValue>)
        let calculated_witness_json = calculateWitness(&CIRCOM_PATH, json_inputs)
            .await
            .unwrap()
            .as_string()
            .unwrap();
        let calculated_witness_vec_str: Vec<String> =
            serde_json::from_str(&calculated_witness_json).unwrap();
        let calculated_witness: Vec<JsBigInt> = calculated_witness_vec_str
            .iter()
            .map(|x| JsBigInt::new(&x.into()).unwrap())
            .collect();

        // Generating proof
        let proof = wasm_generate_rln_proof_with_witness(
            rln_instance,
            calculated_witness,
            serialized_message,
        )
        .unwrap();

        // Add signal_len | signal
        let mut proof_bytes = proof.to_vec();
        proof_bytes.append(&mut normalize_usize(signal.len()));
        proof_bytes.append(&mut signal.to_vec());

        // Validating Proof with Roots
        let root = tree.root();
        let root_le = fr_to_bytes_le(&root);
        let roots = Uint8Array::from(&root_le[..]);
        let proof_with_signal = Uint8Array::from(&proof_bytes[..]);

        let is_proof_valid = wasm_verify_with_roots(rln_instance, proof_with_signal, roots);
        assert!(is_proof_valid.unwrap(), "verifying proof with roots failed");
    }

    #[wasm_bindgen_test]
    pub async fn rln_wasm_benchmark() {
        let mut results = String::from("benchmarks:\n");
        let iterations = 10;

        // Benchmark wasm_new
        let zkey = read_file(&ZKEY_PATH).unwrap();
        let start_wasm_new = Date::now();
        for _ in 0..iterations {
            let _ = wasm_new(zkey.clone()).unwrap();
        }
        let wasm_new_result = Date::now() - start_wasm_new;

        // Initialize instance for other benchmarks
        let rln_instance = wasm_new(zkey).unwrap();

        // Benchmark wasm_key_gen
        let start_wasm_key_gen = Date::now();
        for _ in 0..iterations {
            let _ = wasm_key_gen(rln_instance);
        }
        let wasm_key_gen_result = Date::now() - start_wasm_key_gen;

        // Setup for proof generation and verification
        let tree = PoseidonTree::default(TEST_TREE_HEIGHT).unwrap();
        let mem_keys = wasm_key_gen(rln_instance).unwrap();
        let id_key = mem_keys.subarray(0, 32);
        let id_commitment = mem_keys.subarray(32, 64);
        let epoch = hash_to_field(b"test-epoch");
        let rln_identifier = hash_to_field(b"test-rln-identifier");
        let external_nullifier = poseidon_hash(&[epoch, rln_identifier]);

        // Prepare inputs for other benchmarks
        let mut benchmark_tree = tree;
        let signal = b"Hello World";
        let identity_index = benchmark_tree.leaves_set();
        let user_message_limit = Fr::from(100);
        let message_id = fr_to_bytes_le(&Fr::from(0));
        let external_nullifier_bytes = fr_to_bytes_le(&external_nullifier);

        let (id_commitment_fr, _) = bytes_le_to_fr(&id_commitment.to_vec()[..]);
        let rate_commitment = poseidon_hash(&[id_commitment_fr, user_message_limit]);
        benchmark_tree.update_next(rate_commitment).unwrap();

        let x = hash_to_field(signal);
        let merkle_proof = benchmark_tree
            .proof(identity_index)
            .expect("proof should exist");
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut id_key.to_vec());
        serialized.append(&mut fr_to_bytes_le(&user_message_limit).to_vec());
        serialized.append(&mut message_id.to_vec());
        serialized.append(&mut vec_fr_to_bytes_le(&path_elements).unwrap());
        serialized.append(&mut vec_u8_to_bytes_le(&identity_path_index).unwrap());
        serialized.append(&mut fr_to_bytes_le(&x));
        serialized.append(&mut external_nullifier_bytes.to_vec());
        let serialized_message = Uint8Array::from(&serialized[..]);

        let json_inputs =
            wasm_rln_witness_to_json(rln_instance, serialized_message.clone()).unwrap();

        // Benchmark calculateWitness
        let start_calculate_witness = Date::now();
        for _ in 0..iterations {
            let _ = calculateWitness(&CIRCOM_PATH, json_inputs.clone()).await;
        }
        let calculate_witness_result = Date::now() - start_calculate_witness;

        // Calculate witness other benchmarks
        let calculated_witness_json = calculateWitness(&CIRCOM_PATH, json_inputs)
            .await
            .unwrap()
            .as_string()
            .unwrap();
        let calculated_witness_vec_str: Vec<String> =
            serde_json::from_str(&calculated_witness_json).unwrap();
        let calculated_witness: Vec<JsBigInt> = calculated_witness_vec_str
            .iter()
            .map(|x| JsBigInt::new(&x.into()).unwrap())
            .collect();

        // Benchmark wasm_generate_rln_proof_with_witness
        let start_wasm_generate_rln_proof_with_witness = Date::now();
        for _ in 0..iterations {
            let _ = wasm_generate_rln_proof_with_witness(
                rln_instance,
                calculated_witness.clone(),
                serialized_message.clone(),
            );
        }
        let wasm_generate_rln_proof_with_witness_result =
            Date::now() - start_wasm_generate_rln_proof_with_witness;

        // Generate a proof for other benchmarks
        let proof = wasm_generate_rln_proof_with_witness(
            rln_instance,
            calculated_witness,
            serialized_message,
        )
        .unwrap();

        // Prepare verification inputs
        let mut proof_bytes = proof.to_vec();
        proof_bytes.append(&mut normalize_usize(signal.len()));
        proof_bytes.append(&mut signal.to_vec());

        let root = benchmark_tree.root();
        let root_le = fr_to_bytes_le(&root);
        let roots = Uint8Array::from(&root_le[..]);
        let proof_with_signal = Uint8Array::from(&proof_bytes[..]);

        // Benchmark wasm_verify_with_roots
        let start_wasm_verify_with_roots = Date::now();
        for _ in 0..iterations {
            let _ = wasm_verify_with_roots(rln_instance, proof_with_signal.clone(), roots.clone());
        }
        let wasm_verify_with_roots_result = Date::now() - start_wasm_verify_with_roots;

        let is_proof_valid = wasm_verify_with_roots(rln_instance, proof_with_signal, roots);
        assert!(is_proof_valid.unwrap(), "verifying proof with roots failed");

        // Format and display results
        let format_duration = |duration_ms: f64| -> String {
            let avg_ms = duration_ms / iterations as f64;
            if avg_ms >= 1000.0 {
                format!("{:.4} s", avg_ms / 1000.0)
            } else {
                format!("{:.2} ms", avg_ms)
            }
        };

        results.push_str(&format!("wasm_new: {}\n", format_duration(wasm_new_result)));
        results.push_str(&format!(
            "wasm_key_gen: {}\n",
            format_duration(wasm_key_gen_result)
        ));
        results.push_str(&format!(
            "calculateWitness: {}\n",
            format_duration(calculate_witness_result)
        ));
        results.push_str(&format!(
            "wasm_generate_rln_proof_with_witness: {}\n",
            format_duration(wasm_generate_rln_proof_with_witness_result)
        ));
        results.push_str(&format!(
            "wasm_verify_with_roots: {}\n",
            format_duration(wasm_verify_with_roots_result)
        ));

        wasm_bindgen_test::console_log!("{results}");
    }
}
