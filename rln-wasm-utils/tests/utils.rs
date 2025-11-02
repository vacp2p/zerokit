#![cfg(target_arch = "wasm32")]

#[cfg(test)]
mod test {
    use ark_std::rand::thread_rng;
    use js_sys::Uint8Array;
    use rand::Rng;
    use rln::circuit::Fr;
    use rln::hashers::poseidon_hash;
    use rln::utils::{fr_to_bytes_be, fr_to_bytes_le, str_to_fr, IdSecret};
    use rln_wasm_utils::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn bad_test() {
        let x = get_value();
        assert_eq!(x, 42);
    }

    fn get_value() -> i32 {
        return 42;
    }

    #[wasm_bindgen_test]
    // Tests seeded key generation using WASM APIs
    fn test_seeded_keygen_wasm() {
        // We generate a new identity pair from an input seed
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let seed = Uint8Array::from(&seed_bytes[..]);

        let res = wasm_seeded_key_gen(&seed);
        assert_eq!(res.len(), 2, "seeded key gen call failed");

        let identity_secret_hash = *res[0];
        let id_commitment = *res[1];

        // We check against expected values
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        )
        .unwrap();
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0xbf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f",
            16,
        )
        .unwrap();

        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_bytes
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes);
    }

    #[wasm_bindgen_test]
    // Tests seeded extended key generation using WASM APIs
    fn test_seeded_extended_keygen_wasm() {
        // We generate a new identity tuple from an input seed
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let seed = Uint8Array::from(&seed_bytes[..]);

        let key_gen = wasm_seeded_extended_key_gen(&seed);
        assert_eq!(key_gen.len(), 4, "seeded extended key gen call failed");

        let identity_trapdoor = *key_gen[0];
        let identity_nullifier = *key_gen[1];
        let identity_secret_hash = *key_gen[2];
        let id_commitment = *key_gen[3];

        // We check against expected values
        let expected_identity_trapdoor_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        )
        .unwrap();
        let expected_identity_nullifier_seed_bytes = str_to_fr(
            "0x1f18714c7bc83b5bca9e89d404cf6f2f585bc4c0f7ed8b53742b7e2b298f50b4",
            16,
        )
        .unwrap();
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x2aca62aaa7abaf3686fff2caf00f55ab9462dc12db5b5d4bcf3994e671f8e521",
            16,
        )
        .unwrap();
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0x68b66aa0a8320d2e56842581553285393188714c48f9b17acd198b4f1734c5c",
            16,
        )
        .unwrap();

        assert_eq!(identity_trapdoor, expected_identity_trapdoor_seed_bytes);
        assert_eq!(identity_nullifier, expected_identity_nullifier_seed_bytes);
        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_bytes
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes);
    }

    #[wasm_bindgen_test]
    // Test WasmFr FFI functions
    fn test_wasmfr() {
        let wasmfr_zero = wasmfr_zero();
        let fr_zero = Fr::from(0u8);
        assert_eq!(*wasmfr_zero, fr_zero);

        let wasmfr_one = wasmfr_one();
        let fr_one = Fr::from(1u8);
        assert_eq!(*wasmfr_one, fr_one);

        let wasmfr_int = uint_to_wasmfr(42);
        let fr_int = Fr::from(42u8);
        assert_eq!(*wasmfr_int, fr_int);

        let wasmfr_debug_str = wasmfr_debug(&wasmfr_int);
        assert!(wasmfr_debug_str.contains("42"));

        let key_gen = wasm_key_gen();
        let mut id_secret_fr = *key_gen[0];
        let id_secret_hash = IdSecret::from(&mut id_secret_fr);
        let id_commitment = *key_gen[1];

        let wasmfr_id_secret_hash = *key_gen[0];
        assert_eq!(wasmfr_id_secret_hash, *id_secret_hash);
        let wasmfr_id_commitment = *key_gen[1];
        assert_eq!(wasmfr_id_commitment, id_commitment);
    }

    #[wasm_bindgen_test]
    // Test Vec<WasmFr> functions
    fn test_vec_wasmfr() {
        let vec_fr = vec![Fr::from(1u8), Fr::from(2u8), Fr::from(3u8), Fr::from(4u8)];

        let bytes_le = rln::utils::vec_fr_to_bytes_le(&vec_fr);
        let bytes_le_array = Uint8Array::from(&bytes_le[..]);

        let vec_wasmfr_from_le = match bytes_le_to_vec_wasmfr(&bytes_le_array) {
            Ok(v) => v,
            Err(err) => panic!("bytes_le_to_vec_wasmfr call failed: {}", err),
        };
        assert_eq!(vec_wasmfr_from_le.len(), 4);

        for i in 0..4 {
            let fr = *vec_wasmfr_from_le[i];
            assert_eq!(fr, vec_fr[i]);
        }

        let vec_wasmfr_from_le_clone = vec_wasmfr_from_le.clone();
        let bytes_le_out = vec_wasmfr_to_bytes_le(vec_wasmfr_from_le_clone);
        assert_eq!(bytes_le_out.to_vec(), bytes_le);

        // let bytes_be = rln::utils::vec_fr_to_bytes_be(&vec_fr);
        // let bytes_be_array = Uint8Array::from(&bytes_be[..]);

        // let vec_wasmfr_from_be = match bytes_be_to_vec_wasmfr(&bytes_be_array) {
        //     Ok(v) => v,
        //     Err(err) => panic!("bytes_be_to_vec_wasmfr call failed: {}", err),
        // };
        // assert_eq!(vec_wasmfr_from_be.len(), 4);

        // for i in 0..4 {
        //     let fr = *vec_wasmfr_from_be[i];
        //     assert_eq!(fr, vec_fr[i]);
        // }

        // let vec_wasmfr_from_be_clone = vec_wasmfr_from_be.clone();
        // let bytes_be_out = vec_wasmfr_to_bytes_be(vec_wasmfr_from_be_clone);
        // assert_eq!(bytes_be_out.to_vec(), bytes_be);
    }

    #[wasm_bindgen_test]
    // Tests hash to field using WASM APIs
    fn test_hash_to_field_wasm() {
        let mut rng = thread_rng();
        let signal_gen: [u8; 32] = rng.gen();
        let signal = Uint8Array::from(&signal_gen[..]);

        let wasmfr_le = wasm_hash_to_field_le(&signal);
        let fr_le_native = rln::hashers::hash_to_field_le(&signal_gen);
        assert_eq!(*wasmfr_le, fr_le_native);

        let wasmfr_be = wasm_hash_to_field_be(&signal);
        let fr_be_native = rln::hashers::hash_to_field_be(&signal_gen);
        assert_eq!(*wasmfr_be, fr_be_native);

        assert_eq!(*wasmfr_le, *wasmfr_be);
        assert_eq!(fr_le_native, fr_be_native);

        let hash_wasmfr_le = wasmfr_to_bytes_le(&wasmfr_le);
        let hash_fr_le_native = fr_to_bytes_le(&fr_le_native);
        assert_eq!(hash_wasmfr_le.to_vec(), hash_fr_le_native);

        let hash_wasmfr_be = wasmfr_to_bytes_be(&wasmfr_be);
        let hash_fr_be_native = fr_to_bytes_be(&fr_be_native);
        assert_eq!(hash_wasmfr_be.to_vec(), hash_fr_be_native);

        assert_ne!(hash_wasmfr_le.to_vec(), hash_wasmfr_be.to_vec());
        assert_ne!(hash_fr_le_native, hash_fr_be_native);
    }

    #[wasm_bindgen_test]
    // Test Poseidon hash pair WASM
    fn test_poseidon_hash_pair_wasm() {
        let input_1 = Fr::from(42u8);
        let input_2 = Fr::from(99u8);

        let expected_hash = poseidon_hash(&[input_1, input_2]);
        let wasmfr_1 = uint_to_wasmfr(42);
        let wasmfr_2 = uint_to_wasmfr(99);
        let received_hash = wasm_poseidon_hash_pair(&wasmfr_1, &wasmfr_2);

        assert_eq!(*received_hash, expected_hash);
    }

    #[wasm_bindgen_test]
    // Test Poseidon hash vec WASM
    fn test_poseidon_hash_vec_wasm() {
        let inputs = vec![Fr::from(1u8), Fr::from(2u8), Fr::from(3u8)];
        let expected_hash = poseidon_hash(&inputs);

        let received_hash = wasm_poseidon_hash(inputs.iter().map(|&fr| WasmFr::from(fr)).collect());
        assert_eq!(*received_hash, expected_hash);
    }

    #[wasm_bindgen_test]
    // Test key generation WASM
    fn test_keygen_wasm() {
        let key_gen = wasm_key_gen();
        assert_eq!(key_gen.len(), 2);

        let identity_secret_hash = *key_gen[0];
        let id_commitment = *key_gen[1];

        assert_ne!(identity_secret_hash, Fr::from(0u8));
        assert_ne!(id_commitment, Fr::from(0u8));
    }

    #[wasm_bindgen_test]
    // Test extended key generation WASM
    fn test_extended_keygen_wasm() {
        let key_gen = wasm_extended_key_gen();
        assert_eq!(key_gen.len(), 4);

        let identity_trapdoor = *key_gen[0];
        let identity_nullifier = *key_gen[1];
        let identity_secret_hash = *key_gen[2];
        let id_commitment = *key_gen[3];

        assert_ne!(identity_trapdoor, Fr::from(0u8));
        assert_ne!(identity_nullifier, Fr::from(0u8));
        assert_ne!(identity_secret_hash, Fr::from(0u8));
        assert_ne!(id_commitment, Fr::from(0u8));
    }
}
