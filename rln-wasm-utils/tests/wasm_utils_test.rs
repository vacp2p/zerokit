#![cfg(target_arch = "wasm32")]

#[cfg(test)]
mod test {
    use ark_std::{UniformRand, rand::thread_rng};
    use rand::Rng;
    use rln::circuit::Fr;
    use rln::hashers::{ROUND_PARAMS, hash_to_field_le, poseidon_hash};
    use rln::protocol::{
        deserialize_identity_pair_be, deserialize_identity_pair_le, deserialize_identity_tuple_be,
        deserialize_identity_tuple_le,
    };
    use rln::utils::{bytes_le_to_fr, vec_fr_to_bytes_le};
    use rln_wasm_utils::{
        wasm_extended_key_gen, wasm_hash, wasm_key_gen, wasm_poseidon_hash,
        wasm_seeded_extended_key_gen, wasm_seeded_key_gen,
    };
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_wasm_key_gen() {
        let result_le = wasm_key_gen(true);
        assert!(result_le.is_ok());
        deserialize_identity_pair_le(result_le.unwrap().to_vec());

        let result_be = wasm_key_gen(false);
        assert!(result_be.is_ok());
        deserialize_identity_pair_be(result_be.unwrap().to_vec());
    }

    #[wasm_bindgen_test]
    fn test_wasm_extended_key_gen() {
        let result_le = wasm_extended_key_gen(true);
        assert!(result_le.is_ok());
        deserialize_identity_tuple_le(result_le.unwrap().to_vec());

        let result_be = wasm_extended_key_gen(false);
        assert!(result_be.is_ok());
        deserialize_identity_tuple_be(result_be.unwrap().to_vec());
    }

    #[wasm_bindgen_test]
    fn test_wasm_seeded_key_gen() {
        // Create a test seed
        let seed_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let seed = js_sys::Uint8Array::from(&seed_data[..]);

        let result_le = wasm_seeded_key_gen(seed.clone(), true);
        assert!(result_le.is_ok());
        let fr_le = deserialize_identity_pair_le(result_le.unwrap().to_vec());

        let result_be = wasm_seeded_key_gen(seed, false);
        assert!(result_be.is_ok());
        let fr_be = deserialize_identity_pair_be(result_be.unwrap().to_vec());

        assert_eq!(fr_le, fr_be);
    }

    #[wasm_bindgen_test]
    fn test_wasm_seeded_extended_key_gen() {
        // Create a test seed
        let seed_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let seed = js_sys::Uint8Array::from(&seed_data[..]);

        let result_le = wasm_seeded_extended_key_gen(seed.clone(), true);
        assert!(result_le.is_ok());
        let fr_le = deserialize_identity_tuple_le(result_le.unwrap().to_vec());

        let result_be = wasm_seeded_extended_key_gen(seed, false);
        assert!(result_be.is_ok());
        let fr_be = deserialize_identity_tuple_be(result_be.unwrap().to_vec());

        assert_eq!(fr_le, fr_be);
    }

    #[wasm_bindgen_test]
    fn test_wasm_hash() {
        // Create test input data
        let signal: [u8; 32] = [0; 32];
        let input = js_sys::Uint8Array::from(&signal[..]);

        let result_le = wasm_hash(input.clone(), true);
        assert!(result_le.is_ok());

        let serialized_hash = result_le.unwrap().to_vec();
        let (hash1, _) = bytes_le_to_fr(&serialized_hash);

        let hash2 = hash_to_field_le(&signal);

        assert_eq!(hash1, hash2);
    }

    #[wasm_bindgen_test]
    fn test_wasm_poseidon_hash() {
        let mut rng = thread_rng();
        let number_of_inputs = rng.gen_range(1..ROUND_PARAMS.len());
        let mut inputs = Vec::with_capacity(number_of_inputs);
        for _ in 0..number_of_inputs {
            inputs.push(Fr::rand(&mut rng));
        }
        let inputs_ser = vec_fr_to_bytes_le(&inputs);
        let input = js_sys::Uint8Array::from(&inputs_ser[..]);

        let expected_hash = poseidon_hash(inputs.as_ref());

        let result_le = wasm_poseidon_hash(input.clone(), true);
        assert!(result_le.is_ok());

        let serialized_hash = result_le.unwrap().to_vec();
        let (received_hash, _) = bytes_le_to_fr(&serialized_hash);

        assert_eq!(received_hash, expected_hash);
    }
}
