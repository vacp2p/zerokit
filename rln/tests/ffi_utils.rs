#[cfg(test)]
mod test {
    use num_bigint::BigUint;
    use num_traits::Num;
    use rand::Rng;
    use rln::{ffi::ffi_utils::*, prelude::*};

    #[test]
    fn test_seeded_keygen_ffi() {
        // We generate a new identity pair from an input seed
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let identity_keys = ffi_identity_keys_generate_seeded(&seed_bytes.into());
        let identity_secret = ffi_identity_keys_get_secret(&identity_keys);
        let id_commitment = ffi_identity_keys_get_commitment(&identity_keys);

        // We check against expected values
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

        assert_eq!(
            **identity_secret.inner(),
            expected_identity_secret_seed_bytes
        );
        assert_eq!(**id_commitment, expected_id_commitment_seed_bytes);
    }

    #[test]
    fn test_seeded_extended_keygen_ffi() {
        // We generate a new identity tuple from an input seed
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let identity_keys = ffi_extended_identity_keys_generate_seeded(&seed_bytes.into());
        let identity_trapdoor = ffi_extended_identity_keys_get_trapdoor(&identity_keys);
        let identity_nullifier = ffi_extended_identity_keys_get_nullifier(&identity_keys);
        let identity_secret = ffi_extended_identity_keys_get_secret(&identity_keys);
        let id_commitment = ffi_extended_identity_keys_get_commitment(&identity_keys);

        // We check against expected values
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

        assert_eq!(
            **identity_trapdoor.inner(),
            expected_identity_trapdoor_seed_bytes
        );
        assert_eq!(
            **identity_nullifier.inner(),
            expected_identity_nullifier_seed_bytes
        );
        assert_eq!(
            **identity_secret.inner(),
            expected_identity_secret_seed_bytes
        );
        assert_eq!(**id_commitment, expected_id_commitment_seed_bytes);
    }

    #[test]
    fn test_fr_ffi() {
        let ffi_fr_zero = ffi_fr_zero();
        let fr_zero = Fr::from(0u8);
        assert_eq!(*ffi_fr_zero, fr_zero);

        let ffi_fr_one = ffi_fr_one();
        let fr_one = Fr::from(1u8);
        assert_eq!(*ffi_fr_one, fr_one);

        let ffi_fr_int = ffi_uint_to_fr(42);
        let fr_int = Fr::from(42u8);
        assert_eq!(*ffi_fr_int, fr_int);

        let ffi_fr_debug_str = ffi_fr_debug(Some(&ffi_fr_int));
        assert_eq!(ffi_fr_debug_str.to_string(), "42");

        let identity_keys = ffi_identity_keys_generate();
        let identity_secret = ffi_identity_keys_get_secret(&identity_keys);
        let expected_id_commitment = Hasher::<PoseidonHash>::hash_single(**identity_secret.inner());
        assert_eq!(
            **ffi_identity_keys_get_commitment(&identity_keys),
            expected_id_commitment
        );
    }

    #[test]
    fn test_secret_fr_ffi() {
        // The debug string must stay redacted so the secret never prints
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let identity_keys = ffi_identity_keys_generate_seeded(&seed_bytes.clone().into());
        let secret = ffi_identity_keys_get_secret(&identity_keys);
        assert_eq!(
            ffi_secret_fr_debug(Some(&secret)).to_string(),
            "SecretFr(********)"
        );

        // Two secrets from the same seed compare equal without revealing either
        let same_keys = ffi_identity_keys_generate_seeded(&seed_bytes.into());
        let same = ffi_identity_keys_get_secret(&same_keys);
        assert!(ffi_secret_fr_eq(Some(&secret), Some(&same)));

        // A secret from a fresh random identity compares unequal
        let other_keys = ffi_identity_keys_generate();
        let other = ffi_identity_keys_get_secret(&other_keys);
        assert!(!ffi_secret_fr_eq(Some(&secret), Some(&other)));

        // Null pointers never compare equal and print "None"
        assert!(!ffi_secret_fr_eq(Some(&secret), None));
        assert!(!ffi_secret_fr_eq(None, None));
        assert_eq!(ffi_secret_fr_debug(None).to_string(), "None");
    }

    #[test]
    fn test_identity_keys_roundtrip_ffi() {
        let identity_keys = ffi_identity_keys_generate();
        let bytes = match ffi_identity_keys_to_bytes_le(&identity_keys) {
            FFI_Result {
                ok: Some(bytes),
                err: None,
            } => bytes,
            FFI_Result { err: Some(err), .. } => {
                panic!("ffi_identity_keys_to_bytes_le call failed: {}", err)
            }
            _ => unreachable!(),
        };
        let restored_keys = match ffi_identity_keys_from_bytes_le(&bytes) {
            FFI_Result {
                ok: Some(identity_keys),
                err: None,
            } => identity_keys,
            FFI_Result { err: Some(err), .. } => {
                panic!("ffi_identity_keys_from_bytes_le call failed: {}", err)
            }
            _ => unreachable!(),
        };
        assert_eq!(
            **ffi_identity_keys_get_secret(&restored_keys).inner(),
            **ffi_identity_keys_get_secret(&identity_keys).inner()
        );
        assert_eq!(
            **ffi_identity_keys_get_commitment(&restored_keys),
            **ffi_identity_keys_get_commitment(&identity_keys)
        );
    }

    #[test]
    fn test_extended_identity_keys_roundtrip_ffi() {
        let identity_keys = ffi_extended_identity_keys_generate();
        let bytes = match ffi_extended_identity_keys_to_bytes_le(&identity_keys) {
            FFI_Result {
                ok: Some(bytes),
                err: None,
            } => bytes,
            FFI_Result { err: Some(err), .. } => {
                panic!(
                    "ffi_extended_identity_keys_to_bytes_le call failed: {}",
                    err
                )
            }
            _ => unreachable!(),
        };
        let restored_keys = match ffi_extended_identity_keys_from_bytes_le(&bytes) {
            FFI_Result {
                ok: Some(identity_keys),
                err: None,
            } => identity_keys,
            FFI_Result { err: Some(err), .. } => {
                panic!(
                    "ffi_extended_identity_keys_from_bytes_le call failed: {}",
                    err
                )
            }
            _ => unreachable!(),
        };
        assert_eq!(
            **ffi_extended_identity_keys_get_trapdoor(&restored_keys).inner(),
            **ffi_extended_identity_keys_get_trapdoor(&identity_keys).inner()
        );
        assert_eq!(
            **ffi_extended_identity_keys_get_nullifier(&restored_keys).inner(),
            **ffi_extended_identity_keys_get_nullifier(&identity_keys).inner()
        );
        assert_eq!(
            **ffi_extended_identity_keys_get_secret(&restored_keys).inner(),
            **ffi_extended_identity_keys_get_secret(&identity_keys).inner()
        );
        assert_eq!(
            **ffi_extended_identity_keys_get_commitment(&restored_keys),
            **ffi_extended_identity_keys_get_commitment(&identity_keys)
        );
    }

    #[test]
    fn test_vec_u8_ffi() {
        let mut rng = rand::thread_rng();
        let signal_gen: [u8; 32] = rng.gen();
        let signal: Vec<u8> = signal_gen.to_vec();

        let bytes_le = match ffi_vec_u8_to_bytes_le(&signal.clone().into()) {
            FFI_Result {
                ok: Some(bytes),
                err: None,
            } => bytes,
            FFI_Result { err: Some(err), .. } => {
                panic!("ffi_vec_u8_to_bytes_le call failed: {}", err)
            }
            _ => unreachable!(),
        };
        let mut expected_le = Vec::new();
        signal.serialize_compressed(&mut expected_le).unwrap();
        assert_eq!(bytes_le.iter().copied().collect::<Vec<_>>(), expected_le);

        let bytes_be = match ffi_vec_u8_to_bytes_be(&signal.clone().into()) {
            FFI_Result {
                ok: Some(bytes),
                err: None,
            } => bytes,
            FFI_Result { err: Some(err), .. } => {
                panic!("ffi_vec_u8_to_bytes_be call failed: {}", err)
            }
            _ => unreachable!(),
        };
        let mut expected_be = Vec::new();
        CanonicalSerializeBE::serialize(&signal, &mut expected_be).unwrap();
        assert_eq!(bytes_be.iter().copied().collect::<Vec<_>>(), expected_be);

        let signal_from_le = match ffi_vec_u8_from_bytes_le(&bytes_le) {
            FFI_Result {
                ok: Some(vec_u8),
                err: None,
            } => vec_u8,
            FFI_Result { err: Some(err), .. } => {
                panic!("ffi_vec_u8_from_bytes_le call failed: {}", err)
            }
            _ => unreachable!(),
        };
        assert_eq!(signal_from_le.iter().copied().collect::<Vec<_>>(), signal);

        let signal_from_be = match ffi_vec_u8_from_bytes_be(&bytes_be) {
            FFI_Result {
                ok: Some(vec_u8),
                err: None,
            } => vec_u8,
            FFI_Result { err: Some(err), .. } => {
                panic!("ffi_vec_u8_from_bytes_be call failed: {}", err)
            }
            _ => unreachable!(),
        };
        assert_eq!(signal_from_be.iter().copied().collect::<Vec<_>>(), signal);
    }

    #[test]
    fn test_vec_fr_ffi() {
        let vec_fr = [Fr::from(1u8), Fr::from(2u8), Fr::from(3u8), Fr::from(4u8)];
        let ffi_vec_fr: Vec<FFI_Fr> = vec_fr.iter().map(|fr| FFI_Fr::from(*fr)).collect();

        let bytes_le = match ffi_vec_fr_to_bytes_le(&ffi_vec_fr.clone().into()) {
            FFI_Result {
                ok: Some(bytes),
                err: None,
            } => bytes,
            FFI_Result { err: Some(err), .. } => {
                panic!("ffi_vec_fr_to_bytes_le call failed: {}", err)
            }
            _ => unreachable!(),
        };
        let mut expected_le = Vec::new();
        vec_fr
            .to_vec()
            .serialize_compressed(&mut expected_le)
            .unwrap();
        assert_eq!(bytes_le.iter().copied().collect::<Vec<_>>(), expected_le);

        let bytes_be = match ffi_vec_fr_to_bytes_be(&ffi_vec_fr.clone().into()) {
            FFI_Result {
                ok: Some(bytes),
                err: None,
            } => bytes,
            FFI_Result { err: Some(err), .. } => {
                panic!("ffi_vec_fr_to_bytes_be call failed: {}", err)
            }
            _ => unreachable!(),
        };
        let mut expected_be = Vec::new();
        CanonicalSerializeBE::serialize(&vec_fr.to_vec(), &mut expected_be).unwrap();
        assert_eq!(bytes_be.iter().copied().collect::<Vec<_>>(), expected_be);

        let ffi_vec_fr_from_le = match ffi_vec_fr_from_bytes_le(&bytes_le) {
            FFI_Result {
                ok: Some(ffi_vec_fr),
                err: None,
            } => ffi_vec_fr,
            FFI_Result { err: Some(err), .. } => {
                panic!("ffi_vec_fr_from_bytes_le call failed: {}", err)
            }
            _ => unreachable!(),
        };
        assert_eq!(
            ffi_vec_fr_from_le.iter().copied().collect::<Vec<_>>(),
            ffi_vec_fr
        );

        let ffi_vec_fr_from_be = match ffi_vec_fr_from_bytes_be(&bytes_be) {
            FFI_Result {
                ok: Some(ffi_vec_fr),
                err: None,
            } => ffi_vec_fr,
            FFI_Result { err: Some(err), .. } => {
                panic!("ffi_vec_fr_from_bytes_be call failed: {}", err)
            }
            _ => unreachable!(),
        };
        assert_eq!(
            ffi_vec_fr_from_be.iter().copied().collect::<Vec<_>>(),
            ffi_vec_fr
        );
    }

    #[test]
    fn test_hash_to_field_ffi() {
        let mut rng = rand::thread_rng();
        let signal_gen: [u8; 32] = rng.gen();
        let signal: Vec<u8> = signal_gen.to_vec();

        let ffi_fr_le = ffi_hash_to_field_le(&signal.clone().into());
        let fr_le = hash_to_field_le(&signal);
        assert_eq!(*ffi_fr_le, fr_le);

        let ffi_fr_be = ffi_hash_to_field_be(&signal.clone().into());
        let fr_be = hash_to_field_be(&signal);
        assert_eq!(*ffi_fr_be, fr_be);

        assert_ne!(*ffi_fr_le, *ffi_fr_be);
        assert_ne!(fr_le, fr_be);

        let ffi_fr_le_bytes = match ffi_fr_to_bytes_le(&ffi_fr_le) {
            FFI_Result {
                ok: Some(bytes),
                err: None,
            } => bytes.iter().copied().collect::<Vec<_>>(),
            FFI_Result { err: Some(err), .. } => {
                panic!("ffi_fr_to_bytes_le call failed: {}", err)
            }
            _ => unreachable!(),
        };
        let mut fr_le_bytes = Vec::new();
        fr_le.serialize_compressed(&mut fr_le_bytes).unwrap();
        assert_eq!(ffi_fr_le_bytes, fr_le_bytes);

        let ffi_fr_be_bytes = match ffi_fr_to_bytes_be(&ffi_fr_be) {
            FFI_Result {
                ok: Some(bytes),
                err: None,
            } => bytes.iter().copied().collect::<Vec<_>>(),
            FFI_Result { err: Some(err), .. } => {
                panic!("ffi_fr_to_bytes_be call failed: {}", err)
            }
            _ => unreachable!(),
        };
        let mut fr_be_bytes = Vec::new();
        CanonicalSerializeBE::serialize(&fr_be, &mut fr_be_bytes).unwrap();
        assert_eq!(ffi_fr_be_bytes, fr_be_bytes);
    }

    #[test]
    fn test_poseidon_hash_pair_ffi() {
        let input_1 = Fr::from(42u8);
        let input_2 = Fr::from(99u8);

        let expected_hash = Hasher::<PoseidonHash>::hash_pair(input_1, input_2);
        let ffi_received_hash =
            ffi_poseidon_hash_pair(&FFI_Fr::from(input_1), &FFI_Fr::from(input_2));
        assert_eq!(*ffi_received_hash, expected_hash);
    }
}
