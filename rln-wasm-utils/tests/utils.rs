#![cfg(target_arch = "wasm32")]

#[cfg(test)]
mod test {
    use ark_std::rand::thread_rng;
    use js_sys::Uint8Array;
    use rand::Rng;
    use rln::circuit::Fr;
    use rln::hashers::poseidon_hash;
    use rln::utils::{IdSecret, fr_to_bytes_be, fr_to_bytes_le, str_to_fr};
    use rln_wasm_utils::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_seeded_keygen_wasm() {
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let seed = Uint8Array::from(&seed_bytes[..]);

        let res = wasm_seeded_key_gen(&seed);
        assert_eq!(wasm_vec_fr_len(&res), 2, "seeded key gen call failed");

        let identity_secret_hash = wasm_vec_fr_get(&res, 0).unwrap();
        let id_commitment = wasm_vec_fr_get(&res, 1).unwrap();

        let expected_identity_secret_hash = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        )
        .unwrap();
        let expected_id_commitment = str_to_fr(
            "0xbf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f",
            16,
        )
        .unwrap();

        assert_eq!(*identity_secret_hash, expected_identity_secret_hash);
        assert_eq!(*id_commitment, expected_id_commitment);
    }

    #[wasm_bindgen_test]
    fn test_seeded_extended_keygen_wasm() {
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let seed = Uint8Array::from(&seed_bytes[..]);

        let key_gen = wasm_seeded_extended_key_gen(&seed);
        assert_eq!(
            wasm_vec_fr_len(&key_gen),
            4,
            "seeded extended key gen call failed"
        );

        let identity_trapdoor = wasm_vec_fr_get(&key_gen, 0).unwrap();
        let identity_nullifier = wasm_vec_fr_get(&key_gen, 1).unwrap();
        let identity_secret_hash = wasm_vec_fr_get(&key_gen, 2).unwrap();
        let id_commitment = wasm_vec_fr_get(&key_gen, 3).unwrap();

        let expected_identity_trapdoor = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        )
        .unwrap();
        let expected_identity_nullifier = str_to_fr(
            "0x1f18714c7bc83b5bca9e89d404cf6f2f585bc4c0f7ed8b53742b7e2b298f50b4",
            16,
        )
        .unwrap();
        let expected_identity_secret_hash = str_to_fr(
            "0x2aca62aaa7abaf3686fff2caf00f55ab9462dc12db5b5d4bcf3994e671f8e521",
            16,
        )
        .unwrap();
        let expected_id_commitment = str_to_fr(
            "0x68b66aa0a8320d2e56842581553285393188714c48f9b17acd198b4f1734c5c",
            16,
        )
        .unwrap();

        assert_eq!(*identity_trapdoor, expected_identity_trapdoor);
        assert_eq!(*identity_nullifier, expected_identity_nullifier);
        assert_eq!(*identity_secret_hash, expected_identity_secret_hash);
        assert_eq!(*id_commitment, expected_id_commitment);
    }

    #[wasm_bindgen_test]
    fn test_wasm_fr() {
        let fr_zero_wasm = wasm_fr_zero();
        let fr_zero = Fr::from(0u8);
        assert_eq!(*fr_zero_wasm, fr_zero);

        let fr_one_wasm = wasm_fr_one();
        let fr_one = Fr::from(1u8);
        assert_eq!(*fr_one_wasm, fr_one);

        let fr_int_wasm = wasm_fr_from_uint(42);
        let fr_int = Fr::from(42u8);
        assert_eq!(*fr_int_wasm, fr_int);

        let fr_debug_str = wasm_fr_debug(&fr_int_wasm);
        assert!(fr_debug_str.contains("42"));

        let key_gen = wasm_key_gen();
        let mut id_secret_fr = *wasm_vec_fr_get(&key_gen, 0).unwrap();
        let id_secret_hash = IdSecret::from(&mut id_secret_fr);
        let id_commitment = wasm_vec_fr_get(&key_gen, 1).unwrap();

        let fr_id_secret_hash = wasm_vec_fr_get(&key_gen, 0).unwrap();
        assert_eq!(*fr_id_secret_hash, *id_secret_hash);
        let fr_id_commitment = wasm_vec_fr_get(&key_gen, 1).unwrap();
        assert_eq!(*fr_id_commitment, *id_commitment);
    }

    #[wasm_bindgen_test]
    fn test_wasm_vec_fr() {
        let vec_fr = vec![Fr::from(1u8), Fr::from(2u8), Fr::from(3u8), Fr::from(4u8)];

        let bytes_le = rln::utils::vec_fr_to_bytes_le(&vec_fr);
        let bytes_le_array = Uint8Array::from(&bytes_le[..]);

        let vec_fr_from_le = wasm_vec_fr_from_bytes_le(&bytes_le_array).unwrap();
        assert_eq!(wasm_vec_fr_len(&vec_fr_from_le), 4);

        for i in 0..4 {
            let fr = wasm_vec_fr_get(&vec_fr_from_le, i).unwrap();
            assert_eq!(*fr, vec_fr[i]);
        }

        let bytes_be = rln::utils::vec_fr_to_bytes_be(&vec_fr);
        let bytes_be_array = Uint8Array::from(&bytes_be[..]);

        let vec_fr_from_be = wasm_vec_fr_from_bytes_be(&bytes_be_array).unwrap();
        assert_eq!(wasm_vec_fr_len(&vec_fr_from_be), 4);

        for i in 0..4 {
            let fr = wasm_vec_fr_get(&vec_fr_from_be, i).unwrap();
            assert_eq!(*fr, vec_fr[i]);
        }

        let bytes_le_out = wasm_vec_fr_to_bytes_le(&vec_fr_from_le);
        assert_eq!(bytes_le_out, bytes_le);

        let bytes_be_out = wasm_vec_fr_to_bytes_be(&vec_fr_from_be);
        assert_eq!(bytes_be_out, bytes_be);
    }

    #[wasm_bindgen_test]
    fn test_hash_to_field_wasm() {
        let mut rng = thread_rng();
        let signal_gen: [u8; 32] = rng.r#gen();
        let signal = Uint8Array::from(&signal_gen[..]);

        let fr_le_wasm = wasm_hash_to_field_le(&signal);
        let fr_le_native = rln::hashers::hash_to_field_le(&signal_gen);
        assert_eq!(*fr_le_wasm, fr_le_native);

        let fr_be_wasm = wasm_hash_to_field_be(&signal);
        let fr_be_native = rln::hashers::hash_to_field_be(&signal_gen);
        assert_eq!(*fr_be_wasm, fr_be_native);

        assert_eq!(*fr_le_wasm, *fr_be_wasm);
        assert_eq!(fr_le_native, fr_be_native);

        let hash_le_wasm = wasm_fr_to_bytes_le(&fr_le_wasm);
        let hash_le_native = fr_to_bytes_le(&fr_le_native);
        assert_eq!(hash_le_wasm, hash_le_native);

        let hash_be_wasm = wasm_fr_to_bytes_be(&fr_be_wasm);
        let hash_be_native = fr_to_bytes_be(&fr_be_native);
        assert_eq!(hash_be_wasm, hash_be_native);

        assert_ne!(hash_le_wasm, hash_be_wasm);
        assert_ne!(hash_le_native, hash_be_native);
    }

    #[wasm_bindgen_test]
    fn test_poseidon_hash_pair_wasm() {
        let input_1 = Fr::from(42u8);
        let input_2 = Fr::from(99u8);

        let expected_hash = poseidon_hash(&[input_1, input_2]);
        let fr_1 = wasm_fr_from_uint(42);
        let fr_2 = wasm_fr_from_uint(99);
        let received_hash = wasm_poseidon_hash_pair(&fr_1, &fr_2);

        assert_eq!(*received_hash, expected_hash);
    }

    #[wasm_bindgen_test]
    fn test_poseidon_hash_vec_wasm() {
        let inputs = vec![Fr::from(1u8), Fr::from(2u8), Fr::from(3u8)];
        let expected_hash = poseidon_hash(&inputs);

        let bytes = rln::utils::vec_fr_to_bytes_le(&inputs);
        let bytes_array = Uint8Array::from(&bytes[..]);
        let vec_fr = wasm_vec_fr_from_bytes_le(&bytes_array).unwrap();

        let received_hash = wasm_poseidon_hash_vec(&vec_fr);
        assert_eq!(*received_hash, expected_hash);
    }

    #[wasm_bindgen_test]
    fn test_keygen_wasm() {
        let key_gen = wasm_key_gen();
        assert_eq!(wasm_vec_fr_len(&key_gen), 2);

        let identity_secret_hash = wasm_vec_fr_get(&key_gen, 0).unwrap();
        let id_commitment = wasm_vec_fr_get(&key_gen, 1).unwrap();

        assert_ne!(*identity_secret_hash, Fr::from(0u8));
        assert_ne!(*id_commitment, Fr::from(0u8));
    }

    #[wasm_bindgen_test]
    fn test_extended_keygen_wasm() {
        let key_gen = wasm_extended_key_gen();
        assert_eq!(wasm_vec_fr_len(&key_gen), 4);

        let identity_trapdoor = wasm_vec_fr_get(&key_gen, 0).unwrap();
        let identity_nullifier = wasm_vec_fr_get(&key_gen, 1).unwrap();
        let identity_secret_hash = wasm_vec_fr_get(&key_gen, 2).unwrap();
        let id_commitment = wasm_vec_fr_get(&key_gen, 3).unwrap();

        assert_ne!(*identity_trapdoor, Fr::from(0u8));
        assert_ne!(*identity_nullifier, Fr::from(0u8));
        assert_ne!(*identity_secret_hash, Fr::from(0u8));
        assert_ne!(*id_commitment, Fr::from(0u8));
    }
}
