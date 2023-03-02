#![cfg(target_arch = "wasm32")]

#[cfg(test)]
mod tests {
    use js_sys::{BigInt as JsBigInt, Object, Uint8Array};
    use rln::circuit::TEST_TREE_HEIGHT;
    use rln::utils::normalize_usize;
    use rln_wasm::*;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen(module = "src/utils.js")]
    extern "C" {
        #[wasm_bindgen(catch)]
        fn read_file(path: &str) -> Result<Uint8Array, JsValue>;

        #[wasm_bindgen(catch)]
        async fn calculateWitness(circom_path: &str, input: Object) -> Result<JsValue, JsValue>;
    }

    #[wasm_bindgen_test]
    pub async fn test_basic_flow() {
        let tree_height = TEST_TREE_HEIGHT;
        let circom_path = format!("../rln/resources/tree_height_{TEST_TREE_HEIGHT}/rln.wasm");
        let zkey_path = format!("../rln/resources/tree_height_{TEST_TREE_HEIGHT}/rln_final.zkey");
        let vk_path =
            format!("../rln/resources/tree_height_{TEST_TREE_HEIGHT}/verification_key.json");
        let zkey = read_file(&zkey_path).unwrap();
        let vk = read_file(&vk_path).unwrap();

        // Creating an instance of RLN
        let rln_instance = wasm_new(tree_height, zkey, vk);

        // Creating membership key
        let mem_keys = wasm_key_gen(rln_instance).unwrap();
        let idkey = mem_keys.subarray(0, 32);
        let idcommitment = mem_keys.subarray(32, 64);

        // Insert PK
        wasm_set_next_leaf(rln_instance, idcommitment).unwrap();

        // Prepare the message
        let signal = "Hello World".as_bytes();

        // Setting up the epoch (With 0s for the test)
        let epoch = Uint8Array::new_with_length(32);
        epoch.fill(0, 0, 32);

        let identity_index: usize = 0;

        // Serializing the message
        let mut serialized_vec: Vec<u8> = Vec::new();
        serialized_vec.append(&mut idkey.to_vec());
        serialized_vec.append(&mut normalize_usize(identity_index));
        serialized_vec.append(&mut epoch.to_vec());
        serialized_vec.append(&mut normalize_usize(signal.len()));
        serialized_vec.append(&mut signal.to_vec());
        let serialized_message = Uint8Array::from(&serialized_vec[..]);

        let serialized_rln_witness =
            wasm_get_serialized_rln_witness(rln_instance, serialized_message);

        // Obtaining inputs that should be sent to circom witness calculator
        let json_inputs = rln_witness_to_json(rln_instance, serialized_rln_witness.clone());

        // Calculating witness with JS
        // (Using a JSON since wasm_bindgen does not like Result<Vec<JsBigInt>,JsValue>)
        let calculated_witness_json = calculateWitness(&circom_path, json_inputs)
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
        let proof = generate_rln_proof_with_witness(
            rln_instance,
            calculated_witness.into(),
            serialized_rln_witness,
        )
        .unwrap();

        // Add signal_len | signal
        let mut proof_bytes = proof.to_vec();
        proof_bytes.append(&mut normalize_usize(signal.len()));
        proof_bytes.append(&mut signal.to_vec());
        let proof_with_signal = Uint8Array::from(&proof_bytes[..]);

        // Validate Proof
        let is_proof_valid = wasm_verify_rln_proof(rln_instance, proof_with_signal);

        assert!(
            is_proof_valid.unwrap(),
            "validating proof generated with wasm failed"
        );

        // Validating Proof with Roots
        let root = wasm_get_root(rln_instance).unwrap();
        let roots = Uint8Array::from(&root.to_vec()[..]);
        let proof_with_signal = Uint8Array::from(&proof_bytes[..]);

        let is_proof_valid = wasm_verify_with_roots(rln_instance, proof_with_signal, roots);
        assert!(is_proof_valid.unwrap(), "verifying proof with roots failed");
    }
}
