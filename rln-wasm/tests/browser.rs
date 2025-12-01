#![cfg(target_arch = "wasm32")]
#![cfg(not(feature = "utils"))]

#[cfg(test)]
mod test {
    use js_sys::{BigInt as JsBigInt, Date, Object, Uint8Array};
    use rln::circuit::TEST_TREE_DEPTH;
    use rln::hashers::PoseidonHash;
    use rln_wasm::{
        Hasher, Identity, VecWasmFr, WasmFr, WasmRLN, WasmRLNProof, WasmRLNWitnessInput,
    };
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
        include_bytes!("../../rln/resources/tree_depth_20/rln_final.arkzkey");

    const CIRCOM_BYTES: &[u8] = include_bytes!("../../rln/resources/tree_depth_20/rln.wasm");

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

        let zkey = readFile(ARKZKEY_BYTES).expect("Failed to read zkey file");

        // Benchmark RLN instance creation
        let start_rln_new = Date::now();
        for _ in 0..iterations {
            let _ = WasmRLN::new(&zkey).expect("Failed to create RLN instance");
        }
        let rln_new_result = Date::now() - start_rln_new;

        // Create RLN instance for other benchmarks
        let rln_instance = WasmRLN::new(&zkey).expect("Failed to create RLN instance");
        let mut tree: OptimalMerkleTree<PoseidonHash> =
            OptimalMerkleTree::default(TEST_TREE_DEPTH).expect("Failed to create tree");

        // Benchmark generate identity
        let start_identity_gen = Date::now();
        for _ in 0..iterations {
            let _ = Identity::generate();
        }
        let identity_gen_result = Date::now() - start_identity_gen;

        // Generate identity for other benchmarks
        let identity_pair = Identity::generate();
        let identity_secret_hash = identity_pair.get_secret_hash();
        let id_commitment = identity_pair.get_commitment();

        let epoch = Hasher::hash_to_field_le(&Uint8Array::from(b"test-epoch" as &[u8]));
        let rln_identifier =
            Hasher::hash_to_field_le(&Uint8Array::from(b"test-rln-identifier" as &[u8]));
        let external_nullifier = Hasher::poseidon_hash_pair(&epoch, &rln_identifier);

        let identity_index = tree.leaves_set();

        let user_message_limit = WasmFr::from_uint(100);

        let rate_commitment = Hasher::poseidon_hash_pair(&id_commitment, &user_message_limit);
        tree.update_next(*rate_commitment)
            .expect("Failed to update tree");

        let message_id = WasmFr::from_uint(0);
        let signal: [u8; 32] = [0; 32];
        let x = Hasher::hash_to_field_le(&Uint8Array::from(&signal[..]));

        let merkle_proof: OptimalMerkleProof<PoseidonHash> = tree
            .proof(identity_index)
            .expect("Failed to generate merkle proof");

        let mut path_elements = VecWasmFr::new();
        for path_element in merkle_proof.get_path_elements() {
            path_elements.push(&WasmFr::from(path_element));
        }
        let path_index = Uint8Array::from(&merkle_proof.get_path_index()[..]);

        let rln_witness_input = WasmRLNWitnessInput::new(
            &identity_secret_hash,
            &user_message_limit,
            &message_id,
            &path_elements,
            &path_index,
            &x,
            &external_nullifier,
        )
        .expect("Failed to create WasmRLNWitnessInput");

        let rln_witness_input_bigint_json = rln_witness_input
            .to_bigint_json()
            .expect("Failed to convert witness to BigInt JSON");

        // Benchmark witness calculation
        let start_calculate_witness = Date::now();
        for _ in 0..iterations {
            let _ = calculateWitness(CIRCOM_BYTES, rln_witness_input_bigint_json.clone())
                .await
                .expect("Failed to calculate witness");
        }
        let calculate_witness_result = Date::now() - start_calculate_witness;

        // Calculate witness for other benchmarks
        let calculated_witness_str =
            calculateWitness(CIRCOM_BYTES, rln_witness_input_bigint_json.clone())
                .await
                .expect("Failed to calculate witness")
                .as_string()
                .expect("Failed to convert calculated witness to string");
        let calculated_witness_vec_str: Vec<String> =
            serde_json::from_str(&calculated_witness_str).expect("Failed to parse JSON");
        let calculated_witness: Vec<JsBigInt> = calculated_witness_vec_str
            .iter()
            .map(|x| JsBigInt::new(&x.into()).expect("Failed to create JsBigInt"))
            .collect();

        // Benchmark proof generation with witness
        let start_generate_proof_with_witness = Date::now();
        for _ in 0..iterations {
            let _ = rln_instance
                .generate_proof_with_witness(calculated_witness.clone(), &rln_witness_input)
                .expect("Failed to generate proof");
        }
        let generate_proof_with_witness_result = Date::now() - start_generate_proof_with_witness;

        // Generate proof with witness for other benchmarks
        let proof: WasmRLNProof = rln_instance
            .generate_proof_with_witness(calculated_witness, &rln_witness_input)
            .expect("Failed to generate proof");

        let root = WasmFr::from(tree.root());
        let mut roots = VecWasmFr::new();
        roots.push(&root);

        // Benchmark proof verification with the root
        let start_verify_with_roots = Date::now();
        for _ in 0..iterations {
            let _ = rln_instance
                .verify_with_roots(&proof, &roots, &x)
                .expect("Failed to verify proof");
        }
        let verify_with_roots_result = Date::now() - start_verify_with_roots;

        // Verify proof with the root for other benchmarks
        let is_proof_valid = rln_instance
            .verify_with_roots(&proof, &roots, &x)
            .expect("Failed to verify proof");
        assert!(is_proof_valid, "verification failed");

        // Format and display the benchmark results
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
            "Witness calculation: {}\n",
            format_duration(calculate_witness_result)
        ));
        results.push_str(&format!(
            "Proof generation with witness: {}\n",
            format_duration(generate_proof_with_witness_result)
        ));
        results.push_str(&format!(
            "Proof verification with roots: {}\n",
            format_duration(verify_with_roots_result)
        ));

        // Log the results
        console_log!("{results}");
    }
}
