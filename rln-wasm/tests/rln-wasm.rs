#![cfg(target_arch = "wasm32")]

#[cfg(test)]
mod tests {
    use js_sys::{BigInt as JsBigInt, Object, Uint8Array};
    use rln::circuit::Fr;
    use rln::hashers::{hash_to_field, poseidon_hash};
    use rln::utils::{bytes_le_to_fr, fr_to_bytes_le, normalize_usize};
    use rln_wasm::*;
    use wasm_bindgen::{prelude::*, JsValue};
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
        // Creating an instance of RLN
        let circom_path = format!("../rln/resources/tree_height_20/rln.wasm");
        let rln_instance = wasm_new().unwrap();

        // Creating membership key
        let mem_keys = wasm_key_gen(rln_instance).unwrap();
        let id_key = mem_keys.subarray(0, 32);
        let id_commitment = mem_keys.subarray(32, 64);

        // Prepare the message
        let signal = b"Hello World";

        let identity_index: usize = 0;
        // Setting up the epoch and rln_identifier
        let epoch = hash_to_field(b"test-epoch");
        let rln_identifier = hash_to_field(b"test-rln-identifier");

        let external_nullifier = poseidon_hash(&[epoch, rln_identifier]);
        let external_nullifier = fr_to_bytes_le(&external_nullifier);

        let user_message_limit = Fr::from(100);
        let message_id = fr_to_bytes_le(&Fr::from(0));

        let (id_commitment_fr, _) = bytes_le_to_fr(&id_commitment.to_vec()[..]);
        let rate_commitment = poseidon_hash(&[id_commitment_fr, user_message_limit]);

        // Insert PK
        wasm_set_next_leaf(
            rln_instance,
            Uint8Array::from(fr_to_bytes_le(&rate_commitment).as_slice()),
        )
        .unwrap();

        // Serializing the message
        let mut serialized_vec: Vec<u8> = Vec::new();
        serialized_vec.append(&mut id_key.to_vec());
        serialized_vec.append(&mut normalize_usize(identity_index));
        serialized_vec.append(&mut fr_to_bytes_le(&user_message_limit).to_vec());
        serialized_vec.append(&mut message_id.to_vec());
        serialized_vec.append(&mut external_nullifier.to_vec());
        serialized_vec.append(&mut normalize_usize(signal.len()));
        serialized_vec.append(&mut signal.to_vec());
        let serialized_message = Uint8Array::from(&serialized_vec[..]);

        let serialized_rln_witness =
            wasm_get_serialized_rln_witness(rln_instance, serialized_message).unwrap();

        // Obtaining inputs that should be sent to circom witness calculator
        let json_inputs =
            rln_witness_to_json(rln_instance, serialized_rln_witness.clone()).unwrap();

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
    #[wasm_bindgen_test]
    fn test_metadata() {
        // Creating an instance of RLN
        let rln_instance = wasm_new().unwrap();

        let test_metadata = Uint8Array::new(&JsValue::from_str("test"));
        // Inserting random metadata
        wasm_set_metadata(rln_instance, test_metadata.clone()).unwrap();

        // Getting metadata
        let metadata = wasm_get_metadata(rln_instance).unwrap();

        assert_eq!(metadata.to_vec(), test_metadata.to_vec());
    }
}
