#![cfg(target_arch = "wasm32")]

#[cfg(test)]
mod tests {
    use js_sys::{BigInt as JsBigInt, Date, Object, Uint8Array};
    use rln::circuit::{Fr, TEST_TREE_HEIGHT};
    use rln::hashers::{hash_to_field_le, poseidon_hash, PoseidonHash};
    use rln::protocol::{prepare_verify_input, rln_witness_from_values, serialize_witness};
    use rln::utils::{bytes_le_to_fr, fr_to_bytes_le, IdSecret};
    use rln_wasm::{
        wasm_generate_rln_proof_with_witness, wasm_new, wasm_rln_witness_to_json,
        wasm_verify_with_roots,
    };
    use rln_wasm_utils::wasm_key_gen;
    use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
    use wasm_bindgen_test::{console_log, wasm_bindgen_test, wasm_bindgen_test_configure};
    use zerokit_utils::{
        OptimalMerkleProof, OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree,
    };

    #[cfg(feature = "parallel")]
    use {rln_wasm::init_thread_pool, wasm_bindgen_futures::JsFuture, web_sys::window};

    #[wasm_bindgen(inline_js = r#"
    export function isThreadpoolSupported() {
      return typeof SharedArrayBuffer !== 'undefined' &&
             typeof Atomics !== 'undefined' &&
             typeof crossOriginIsolated !== 'undefined' &&
             crossOriginIsolated;
    }

    export function initWitnessCalculator(jsCode) {
      const processedCode = jsCode
        .replace(/export\s+async\s+function\s+builder/, 'async function builder')
        .replace(/export\s*\{\s*builder\s*\};?/g, '');

      const moduleFunc = new Function(processedCode + '\nreturn { builder };');
      const witnessCalculatorModule = moduleFunc();

      window.witnessCalculatorBuilder = witnessCalculatorModule.builder;

      if (typeof window.witnessCalculatorBuilder !== 'function') {
        return false;
      }
      return true;
    }

    export function readFile(data) {
      return new Uint8Array(data);
    }

    export async function calculateWitness(circom_data, inputs) {
      const wasmBuffer = circom_data instanceof Uint8Array ? circom_data : new Uint8Array(circom_data);
      const witnessCalculator = await window.witnessCalculatorBuilder(wasmBuffer);
      const calculatedWitness = await witnessCalculator.calculateWitness(inputs, false);
      return JSON.stringify(calculatedWitness, (key, value) =>
        typeof value === "bigint" ? value.toString() : value
      );
    }
    "#)]
    extern "C" {
        #[wasm_bindgen(catch)]
        fn isThreadpoolSupported() -> Result<bool, JsValue>;

        #[wasm_bindgen(catch)]
        fn initWitnessCalculator(js: &str) -> Result<bool, JsValue>;

        #[wasm_bindgen(catch)]
        fn readFile(data: &[u8]) -> Result<Uint8Array, JsValue>;

        #[wasm_bindgen(catch)]
        async fn calculateWitness(circom_data: &[u8], inputs: Object) -> Result<JsValue, JsValue>;
    }

    const WITNESS_CALCULATOR_JS: &str = include_str!("../resources/witness_calculator.js");

    const ARKZKEY_BYTES: &[u8] =
        include_bytes!("../../rln/resources/tree_height_20/rln_final.arkzkey");

    const CIRCOM_BYTES: &[u8] = include_bytes!("../../rln/resources/tree_height_20/rln.wasm");

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    pub async fn rln_wasm_benchmark() {
        // Check if thread pool is supported
        #[cfg(feature = "parallel")]
        if !isThreadpoolSupported().expect("Failed to check thread pool support") {
            panic!("Thread pool is NOT supported");
        } else {
            // Initialize thread pool
            let cpu_count = window()
                .expect("Failed to get window")
                .navigator()
                .hardware_concurrency() as usize;
            JsFuture::from(init_thread_pool(cpu_count))
                .await
                .expect("Failed to initialize thread pool");
        }

        // Initialize witness calculator
        initWitnessCalculator(WITNESS_CALCULATOR_JS)
            .expect("Failed to initialize witness calculator");

        let mut results = String::from("\nbenchmarks:\n");
        let iterations = 10;

        let zkey = readFile(&ARKZKEY_BYTES).expect("Failed to read zkey file");

        // Benchmark wasm_new
        let start_wasm_new = Date::now();
        for _ in 0..iterations {
            let _ = wasm_new(zkey.clone()).expect("Failed to create RLN instance");
        }
        let wasm_new_result = Date::now() - start_wasm_new;

        // Create RLN instance for other benchmarks
        let rln_instance = wasm_new(zkey).expect("Failed to create RLN instance");
        let mut tree: OptimalMerkleTree<PoseidonHash> =
            OptimalMerkleTree::default(TEST_TREE_HEIGHT).expect("Failed to create tree");

        // Benchmark wasm_key_gen
        let start_wasm_key_gen = Date::now();
        for _ in 0..iterations {
            let _ = wasm_key_gen(true).expect("Failed to generate keys");
        }
        let wasm_key_gen_result = Date::now() - start_wasm_key_gen;

        // Generate identity pair for other benchmarks
        let mem_keys = wasm_key_gen(true).expect("Failed to generate keys");
        let id_key = mem_keys.subarray(0, 32);
        let (identity_secret_hash, _) = IdSecret::from_bytes_le(&id_key.to_vec());
        let (id_commitment, _) = bytes_le_to_fr(&mem_keys.subarray(32, 64).to_vec());

        let epoch = hash_to_field_le(b"test-epoch");
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        let external_nullifier = poseidon_hash(&[epoch, rln_identifier]);

        let identity_index = tree.leaves_set();

        let user_message_limit = Fr::from(100);

        let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]);
        tree.update_next(rate_commitment)
            .expect("Failed to update tree");

        let message_id = Fr::from(0);
        let signal: [u8; 32] = [0; 32];
        let x = hash_to_field_le(&signal);

        let merkle_proof: OptimalMerkleProof<PoseidonHash> = tree
            .proof(identity_index)
            .expect("Failed to generate merkle proof");

        let rln_witness = rln_witness_from_values(
            identity_secret_hash,
            merkle_proof.get_path_elements(),
            merkle_proof.get_path_index(),
            x,
            external_nullifier,
            user_message_limit,
            message_id,
        )
        .expect("Failed to create RLN witness");

        let serialized_witness =
            serialize_witness(&rln_witness).expect("Failed to serialize witness");
        let witness_buffer = Uint8Array::from(&serialized_witness[..]);

        let json_inputs = wasm_rln_witness_to_json(rln_instance, witness_buffer.clone())
            .expect("Failed to convert witness to JSON");

        // Benchmark calculateWitness
        let start_calculate_witness = Date::now();
        for _ in 0..iterations {
            let _ = calculateWitness(&CIRCOM_BYTES, json_inputs.clone())
                .await
                .expect("Failed to calculate witness");
        }
        let calculate_witness_result = Date::now() - start_calculate_witness;

        // Calculate witness for other benchmarks
        let calculated_witness_json = calculateWitness(&CIRCOM_BYTES, json_inputs)
            .await
            .expect("Failed to calculate witness")
            .as_string()
            .expect("Failed to convert calculated witness to string");
        let calculated_witness_vec_str: Vec<String> =
            serde_json::from_str(&calculated_witness_json).expect("Failed to parse JSON");
        let calculated_witness: Vec<JsBigInt> = calculated_witness_vec_str
            .iter()
            .map(|x| JsBigInt::new(&x.into()).expect("Failed to create JsBigInt"))
            .collect();

        // Benchmark wasm_generate_rln_proof_with_witness
        let start_wasm_generate_rln_proof_with_witness = Date::now();
        for _ in 0..iterations {
            let _ = wasm_generate_rln_proof_with_witness(
                rln_instance,
                calculated_witness.clone(),
                witness_buffer.clone(),
            )
            .expect("Failed to generate proof");
        }
        let wasm_generate_rln_proof_with_witness_result =
            Date::now() - start_wasm_generate_rln_proof_with_witness;

        // Generate a proof for other benchmarks
        let proof =
            wasm_generate_rln_proof_with_witness(rln_instance, calculated_witness, witness_buffer)
                .expect("Failed to generate proof");

        let proof_data = proof.to_vec();
        let verify_input = prepare_verify_input(proof_data, &signal);
        let input_buffer = Uint8Array::from(&verify_input[..]);

        let root = tree.root();
        let roots_serialized = fr_to_bytes_le(&root);
        let roots_buffer = Uint8Array::from(&roots_serialized[..]);

        // Benchmark wasm_verify_with_roots
        let start_wasm_verify_with_roots = Date::now();
        for _ in 0..iterations {
            let _ =
                wasm_verify_with_roots(rln_instance, input_buffer.clone(), roots_buffer.clone())
                    .expect("Failed to verify proof");
        }
        let wasm_verify_with_roots_result = Date::now() - start_wasm_verify_with_roots;

        // Verify the proof with the root
        let is_proof_valid = wasm_verify_with_roots(rln_instance, input_buffer, roots_buffer)
            .expect("Failed to verify proof");
        assert!(is_proof_valid, "verification failed");

        // Format and display results
        let format_duration = |duration_ms: f64| -> String {
            let avg_ms = duration_ms / (iterations as f64);
            if avg_ms >= 1000.0 {
                format!("{:.3} s", avg_ms / 1000.0)
            } else {
                format!("{:.3} ms", avg_ms)
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

        // Log the results
        console_log!("{results}");
    }
}
