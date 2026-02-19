#![cfg(target_arch = "wasm32")]
#![cfg(not(feature = "utils"))]

#[cfg(test)]
mod test {
    use js_sys::{BigInt as JsBigInt, Date, Object, Uint8Array};
    use rln::prelude::*;
    use rln_wasm::{
        Hasher, Identity, VecWasmFr, WasmFr, WasmRLN, WasmRLNProof, WasmRLNProofValues,
        WasmRLNWitnessInput,
    };
    use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
    use wasm_bindgen_test::{console_log, wasm_bindgen_test};
    use zerokit_utils::merkle_tree::{
        OptimalMerkleProof, OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree,
    };

    #[wasm_bindgen(inline_js = r#"
    const fs = require("fs");

    let witnessCalculatorModule = null;

    module.exports = {
      initWitnessCalculator: function(code) {
        const processedCode = code
          .replace(/export\s+async\s+function\s+builder/, 'async function builder')
          .replace(/export\s*\{\s*builder\s*\};?/g, '');

        const moduleFunc = new Function(processedCode + '\nreturn { builder };');
        witnessCalculatorModule = moduleFunc();

        if (typeof witnessCalculatorModule.builder !== 'function') {
          return false;
        }
        return true;
      },

      readFile: function (path) {
        return fs.readFileSync(path);
      },

      calculateWitness: async function (circom_path, inputs) {
        const wasmFile = fs.readFileSync(circom_path);
        const wasmFileBuffer = wasmFile.buffer.slice(
          wasmFile.byteOffset,
          wasmFile.byteOffset + wasmFile.byteLength
        );
        const witnessCalculator = await witnessCalculatorModule.builder(wasmFileBuffer);
        const calculatedWitness = await witnessCalculator.calculateWitness(
          inputs,
          false
        );
        return JSON.stringify(calculatedWitness, (key, value) =>
          typeof value === "bigint" ? value.toString() : value
        );
      },
    };
    "#)]
    extern "C" {
        #[wasm_bindgen(catch)]
        fn initWitnessCalculator(code: &str) -> Result<bool, JsValue>;

        #[wasm_bindgen(catch)]
        fn readFile(path: &str) -> Result<Uint8Array, JsValue>;

        #[wasm_bindgen(catch)]
        async fn calculateWitness(circom_path: &str, input: Object) -> Result<JsValue, JsValue>;
    }

    const WITNESS_CALCULATOR_JS: &str = include_str!("../resources/witness_calculator.js");

    const ARKZKEY_PATH: &str = "../rln/resources/tree_depth_20/rln_final.arkzkey";

    const CIRCOM_PATH: &str = "../rln/resources/tree_depth_20/rln.wasm";

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

        let identity_pair = Identity::generate().unwrap();
        let identity_secret = identity_pair.get_secret_hash();
        let id_commitment = identity_pair.get_commitment();

        let epoch = Hasher::hash_to_field_le(&Uint8Array::from(b"test-epoch" as &[u8])).unwrap();
        let rln_identifier =
            Hasher::hash_to_field_le(&Uint8Array::from(b"test-rln-identifier" as &[u8])).unwrap();
        let external_nullifier = Hasher::poseidon_hash_pair(&epoch, &rln_identifier).unwrap();

        let identity_index = tree.leaves_set();
        let user_message_limit = WasmFr::from_uint(10);
        let rate_commitment =
            Hasher::poseidon_hash_pair(&id_commitment, &user_message_limit).unwrap();
        tree.update_next(*rate_commitment).unwrap();

        let message_id = WasmFr::from_uint(0);
        let signal: [u8; 32] = [0; 32];
        let x = Hasher::hash_to_field_le(&Uint8Array::from(&signal[..])).unwrap();

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
    pub async fn rln_wasm_benchmark() {
        // Initialize witness calculator
        initWitnessCalculator(WITNESS_CALCULATOR_JS).unwrap();

        let mut results = String::from("\nbenchmarks:\n");
        let iterations = 10;

        let zkey = readFile(ARKZKEY_PATH).unwrap();

        // Benchmark RLN instance creation
        let start_rln_new = Date::now();
        for _ in 0..iterations {
            let _ = WasmRLN::new(&zkey).unwrap();
        }
        let rln_new_result = Date::now() - start_rln_new;

        // Create RLN instance for other benchmarks
        let rln_instance = WasmRLN::new(&zkey).unwrap();
        let mut tree: OptimalMerkleTree<PoseidonHash> =
            OptimalMerkleTree::default(DEFAULT_TREE_DEPTH).unwrap();

        // Benchmark generate identity
        let start_identity_gen = Date::now();
        for _ in 0..iterations {
            let _ = Identity::generate().unwrap();
        }
        let identity_gen_result = Date::now() - start_identity_gen;

        // Generate identity for other benchmarks
        let identity_pair = Identity::generate().unwrap();
        let identity_secret = identity_pair.get_secret_hash();
        let id_commitment = identity_pair.get_commitment();

        let epoch = Hasher::hash_to_field_le(&Uint8Array::from(b"test-epoch" as &[u8])).unwrap();
        let rln_identifier =
            Hasher::hash_to_field_le(&Uint8Array::from(b"test-rln-identifier" as &[u8])).unwrap();
        let external_nullifier = Hasher::poseidon_hash_pair(&epoch, &rln_identifier).unwrap();

        let identity_index = tree.leaves_set();

        let user_message_limit = WasmFr::from_uint(100);

        let rate_commitment =
            Hasher::poseidon_hash_pair(&id_commitment, &user_message_limit).unwrap();
        tree.update_next(*rate_commitment).unwrap();

        let message_id = WasmFr::from_uint(0);
        let signal: [u8; 32] = [0; 32];
        let x = Hasher::hash_to_field_le(&Uint8Array::from(&signal[..])).unwrap();

        let merkle_proof: OptimalMerkleProof<PoseidonHash> = tree.proof(identity_index).unwrap();

        let mut path_elements = VecWasmFr::new();
        for path_element in merkle_proof.get_path_elements() {
            path_elements.push(&WasmFr::from(path_element));
        }
        let path_index = Uint8Array::from(&merkle_proof.get_path_index()[..]);

        let witness = WasmRLNWitnessInput::new(
            &identity_secret,
            &user_message_limit,
            &message_id,
            &path_elements,
            &path_index,
            &x,
            &external_nullifier,
        )
        .unwrap();

        let bigint_json = witness.to_bigint_json().unwrap();

        // Benchmark witness calculation
        let start_calculate_witness = Date::now();
        for _ in 0..iterations {
            let _ = calculateWitness(CIRCOM_PATH, bigint_json.clone())
                .await
                .unwrap();
        }
        let calculate_witness_result = Date::now() - start_calculate_witness;

        // Calculate witness for other benchmarks
        let calculated_witness_str = calculateWitness(CIRCOM_PATH, bigint_json.clone())
            .await
            .unwrap()
            .as_string()
            .unwrap();
        let calculated_witness_vec_str: Vec<String> =
            serde_json::from_str(&calculated_witness_str).unwrap();
        let calculated_witness: Vec<JsBigInt> = calculated_witness_vec_str
            .iter()
            .map(|x| JsBigInt::new(&x.into()).unwrap())
            .collect();

        // Benchmark proof generation with witness
        let start_generate_rln_proof_with_witness = Date::now();
        for _ in 0..iterations {
            let _ = rln_instance
                .generate_rln_proof_with_witness(calculated_witness.clone(), &witness)
                .unwrap();
        }
        let generate_rln_proof_with_witness_result =
            Date::now() - start_generate_rln_proof_with_witness;

        // Generate proof with witness for other benchmarks
        let proof: WasmRLNProof = rln_instance
            .generate_rln_proof_with_witness(calculated_witness, &witness)
            .unwrap();

        let root = WasmFr::from(tree.root());
        let mut roots = VecWasmFr::new();
        roots.push(&root);

        // Benchmark proof verification with the root
        let start_verify_with_roots = Date::now();
        for _ in 0..iterations {
            let _ = rln_instance.verify_with_roots(&proof, &roots, &x).unwrap();
        }
        let verify_with_roots_result = Date::now() - start_verify_with_roots;

        // Verify proof with the root for other benchmarks
        let is_proof_valid = rln_instance.verify_with_roots(&proof, &roots, &x).unwrap();
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
            format_duration(generate_rln_proof_with_witness_result)
        ));
        results.push_str(&format!(
            "Proof verification with roots: {}\n",
            format_duration(verify_with_roots_result)
        ));

        // Log the results
        console_log!("{results}");
    }

    #[wasm_bindgen_test]
    pub fn test_wasm_invalid_inputs() {
        // Invalid zkey data
        let invalid_zkey = Uint8Array::from(&[0u8; 16][..]);
        assert!(WasmRLN::new(&invalid_zkey).is_err());

        let (identity_secret, user_message_limit, message_id, path_elements, path_index, x, external_nullifier) =
            build_witness_parts();

        // Invalid user message limit (zero)
        let zero_limit = WasmFr::zero();
        let result = WasmRLNWitnessInput::new(
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
        let result = WasmRLNWitnessInput::new(
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
        let result = WasmRLNWitnessInput::new(
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
        let valid_witness = WasmRLNWitnessInput::new(
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
        assert!(WasmRLNWitnessInput::from_bytes_le(&extra_le).is_err());

        let witness_be = valid_witness.to_bytes_be().unwrap();
        let witness_be_vec = witness_be.to_vec();
        let truncated_be = Uint8Array::from(&witness_be_vec[..witness_be_vec.len() - 1]);
        assert!(WasmRLNWitnessInput::from_bytes_be(&truncated_be).is_err());

        let mut extra_be_vec = witness_be_vec.clone();
        extra_be_vec.push(0);
        let extra_be = Uint8Array::from(&extra_be_vec[..]);
        assert!(WasmRLNWitnessInput::from_bytes_be(&extra_be).is_err());

        // Proof values bytes: insufficient length
        let short_pv = vec![0u8; FR_BYTE_SIZE * 5 - 1];
        let short_pv = Uint8Array::from(&short_pv[..]);
        assert!(WasmRLNProofValues::from_bytes_le(&short_pv).is_err());
        assert!(WasmRLNProofValues::from_bytes_be(&short_pv).is_err());

        // Proof bytes: insufficient length (no proof values)
        let short_proof = vec![0u8; COMPRESS_PROOF_SIZE];
        let short_proof = Uint8Array::from(&short_proof[..]);
        assert!(WasmRLNProof::from_bytes_le(&short_proof).is_err());
        assert!(WasmRLNProof::from_bytes_be(&short_proof).is_err());
    }
}
