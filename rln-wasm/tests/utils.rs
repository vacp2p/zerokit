#![cfg(target_arch = "wasm32")]

#[cfg(test)]
mod test {
    use std::assert_eq;

    use ark_std::rand::thread_rng;
    use js_sys::Uint8Array;
    use num_bigint::BigUint;
    use num_traits::Num;
    use rand::Rng;
    use rln::prelude::*;
    use rln_wasm::{
        wasm_hash_to_field_be, wasm_hash_to_field_le, wasm_poseidon_hash_pair, VecWasmFr,
        WasmExtendedIdentityKeys, WasmFr, WasmIdentityKeys,
    };
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn test_keygen_wasm() {
        let identity = WasmIdentityKeys::generate();
        let identity_secret = **identity.get_secret().inner();
        let id_commitment = *identity.get_commitment();

        assert_ne!(identity_secret, Fr::from(0u8));
        assert_ne!(id_commitment, Fr::from(0u8));

        let bytes = identity.to_bytes_le().unwrap();
        let restored = WasmIdentityKeys::from_bytes_le(&bytes).unwrap();

        assert_eq!(**restored.get_secret().inner(), identity_secret);
        assert_eq!(*restored.get_commitment(), id_commitment);
    }

    #[wasm_bindgen_test]
    fn test_extended_keygen_wasm() {
        let identity = WasmExtendedIdentityKeys::generate();

        let identity_trapdoor = **identity.get_trapdoor().inner();
        let identity_nullifier = **identity.get_nullifier().inner();
        let identity_secret = **identity.get_secret().inner();
        let id_commitment = *identity.get_commitment();

        assert_ne!(identity_trapdoor, Fr::from(0u8));
        assert_ne!(identity_nullifier, Fr::from(0u8));
        assert_ne!(identity_secret, Fr::from(0u8));
        assert_ne!(id_commitment, Fr::from(0u8));

        let bytes = identity.to_bytes_le().unwrap();
        let restored = WasmExtendedIdentityKeys::from_bytes_le(&bytes).unwrap();

        assert_eq!(**restored.get_trapdoor().inner(), identity_trapdoor);
        assert_eq!(**restored.get_nullifier().inner(), identity_nullifier);
        assert_eq!(**restored.get_secret().inner(), identity_secret);
        assert_eq!(*restored.get_commitment(), id_commitment);
    }

    #[wasm_bindgen_test]
    fn test_seeded_keygen_wasm() {
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let seed = Uint8Array::from(&seed_bytes[..]);

        let identity = WasmIdentityKeys::generate_seeded(&seed);
        let identity_secret = **identity.get_secret().inner();
        let id_commitment = *identity.get_commitment();

        let expected_identity_secret_seed_bytes = Fr::from(
            BigUint::from_str_radix(
                "766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
                16,
            )
            .unwrap(),
        );
        let expected_id_commitment_seed_bytes = Fr::from(
            BigUint::from_str_radix(
                "bf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f",
                16,
            )
            .unwrap(),
        );

        assert_eq!(identity_secret, expected_identity_secret_seed_bytes);
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes);
    }

    #[wasm_bindgen_test]
    fn test_seeded_extended_keygen_wasm() {
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let seed = Uint8Array::from(&seed_bytes[..]);

        let identity = WasmExtendedIdentityKeys::generate_seeded(&seed);

        let identity_trapdoor = **identity.get_trapdoor().inner();
        let identity_nullifier = **identity.get_nullifier().inner();
        let identity_secret = **identity.get_secret().inner();
        let id_commitment = *identity.get_commitment();

        let expected_identity_trapdoor_seed_bytes = Fr::from(
            BigUint::from_str_radix(
                "766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
                16,
            )
            .unwrap(),
        );
        let expected_identity_nullifier_seed_bytes = Fr::from(
            BigUint::from_str_radix(
                "1f18714c7bc83b5bca9e89d404cf6f2f585bc4c0f7ed8b53742b7e2b298f50b4",
                16,
            )
            .unwrap(),
        );
        let expected_identity_secret_seed_bytes = Fr::from(
            BigUint::from_str_radix(
                "2aca62aaa7abaf3686fff2caf00f55ab9462dc12db5b5d4bcf3994e671f8e521",
                16,
            )
            .unwrap(),
        );
        let expected_id_commitment_seed_bytes = Fr::from(
            BigUint::from_str_radix(
                "68b66aa0a8320d2e56842581553285393188714c48f9b17acd198b4f1734c5c",
                16,
            )
            .unwrap(),
        );

        assert_eq!(identity_trapdoor, expected_identity_trapdoor_seed_bytes);
        assert_eq!(identity_nullifier, expected_identity_nullifier_seed_bytes);
        assert_eq!(identity_secret, expected_identity_secret_seed_bytes);
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes);
    }

    #[wasm_bindgen_test]
    fn test_wasmfr() {
        let wasmfr_zero = WasmFr::zero();
        let fr_zero = Fr::from(0u8);
        assert_eq!(*wasmfr_zero, fr_zero);

        let wasmfr_one = WasmFr::one();
        let fr_one = Fr::from(1u8);
        assert_eq!(*wasmfr_one, fr_one);

        let wasmfr_int = WasmFr::from_uint(42);
        let fr_int = Fr::from(42u8);
        assert_eq!(*wasmfr_int, fr_int);

        let wasmfr_debug_str = wasmfr_int.debug();
        assert_eq!(wasmfr_debug_str.to_string(), "42");

        let identity = WasmIdentityKeys::generate();
        let id_secret = **identity.get_secret().inner();
        let id_commitment = *identity.get_commitment();

        assert_eq!(**identity.get_secret().inner(), id_secret);
        assert_eq!(*identity.get_commitment(), id_commitment);
    }

    #[wasm_bindgen_test]
    fn test_vec_wasmfr() {
        let vec_fr = vec![Fr::from(1u8), Fr::from(2u8), Fr::from(3u8), Fr::from(4u8)];
        let mut vec_wasmfr = VecWasmFr::new();
        for fr in &vec_fr {
            vec_wasmfr.push(&WasmFr::from(*fr));
        }

        let bytes_le = vec_wasmfr.to_bytes_le().unwrap();
        let mut expected_le = Vec::new();
        vec_fr.serialize_compressed(&mut expected_le).unwrap();
        assert_eq!(bytes_le.to_vec(), expected_le);

        let bytes_be = vec_wasmfr.to_bytes_be().unwrap();
        let mut expected_be = Vec::new();
        CanonicalSerializeBE::serialize(&vec_fr, &mut expected_be).unwrap();
        assert_eq!(bytes_be.to_vec(), expected_be);

        let vec_wasmfr_from_le = match VecWasmFr::from_bytes_le(&bytes_le) {
            Ok(v) => v,
            Err(err) => panic!("VecWasmFr::from_bytes_le call failed: {}", err),
        };
        assert_eq!(vec_wasmfr_from_le.length(), vec_wasmfr.length());
        for i in 0..vec_wasmfr.length() {
            assert_eq!(
                *vec_wasmfr_from_le.get(i).unwrap(),
                *vec_wasmfr.get(i).unwrap()
            );
        }

        let vec_wasmfr_from_be = match VecWasmFr::from_bytes_be(&bytes_be) {
            Ok(v) => v,
            Err(err) => panic!("VecWasmFr::from_bytes_be call failed: {}", err),
        };
        for i in 0..vec_wasmfr.length() {
            assert_eq!(
                *vec_wasmfr_from_be.get(i).unwrap(),
                *vec_wasmfr.get(i).unwrap()
            );
        }
    }

    #[wasm_bindgen_test]
    fn test_hash_to_field_wasm() {
        let mut rng = thread_rng();
        let signal_gen: [u8; 32] = rng.gen();
        let signal = Uint8Array::from(&signal_gen[..]);

        let wasmfr_le_1 = wasm_hash_to_field_le(&signal);
        let fr_le_2 = hash_to_field_le(&signal_gen);
        assert_eq!(*wasmfr_le_1, fr_le_2);

        let wasmfr_be_1 = wasm_hash_to_field_be(&signal);
        let fr_be_2 = hash_to_field_be(&signal_gen);
        assert_eq!(*wasmfr_be_1, fr_be_2);

        assert_ne!(*wasmfr_le_1, *wasmfr_be_1);
        assert_ne!(fr_le_2, fr_be_2);

        let hash_wasmfr_le_1 = wasmfr_le_1.to_bytes_le().unwrap();
        let mut hash_fr_le_2 = Vec::new();
        fr_le_2.serialize_compressed(&mut hash_fr_le_2).unwrap();
        assert_eq!(hash_wasmfr_le_1.to_vec(), hash_fr_le_2);

        let hash_wasmfr_be_1 = wasmfr_be_1.to_bytes_be().unwrap();
        let mut hash_fr_be_2 = Vec::new();
        CanonicalSerializeBE::serialize(&fr_be_2, &mut hash_fr_be_2).unwrap();
        assert_eq!(hash_wasmfr_be_1.to_vec(), hash_fr_be_2);
    }

    #[wasm_bindgen_test]
    fn test_poseidon_hash_pair_wasm() {
        let input_1 = Fr::from(42u8);
        let input_2 = Fr::from(99u8);

        let expected_hash = Hasher::<PoseidonHash>::hash_pair(input_1, input_2);
        let wasmfr_1 = WasmFr::from_uint(42);
        let wasmfr_2 = WasmFr::from_uint(99);
        let received_hash = wasm_poseidon_hash_pair(&wasmfr_1, &wasmfr_2);

        assert_eq!(*received_hash, expected_hash);
    }
}
