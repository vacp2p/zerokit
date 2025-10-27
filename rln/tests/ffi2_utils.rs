#[cfg(test)]
mod test {
    use rand::Rng;
    use rln::circuit::Fr;
    use rln::ffi2::ffi_utils::*;
    use rln::hashers::poseidon_hash;
    use rln::utils::{fr_to_bytes_be, fr_to_bytes_le, str_to_fr, IdSecret};

    #[test]
    // Tests hash to field using FFI APIs
    fn test_seeded_keygen_stateless_ffi() {
        // We generate a new identity pair from an input seed
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let res = ffi2_seeded_key_gen(&seed_bytes.into());
        assert_eq!(res.len(), 2, "seeded key gen call failed");
        let identity_secret_hash = res.first().unwrap();
        let id_commitment = res.get(1).unwrap();

        // We check against expected values
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        );
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0xbf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f",
            16,
        );

        assert_eq!(
            *identity_secret_hash,
            expected_identity_secret_hash_seed_bytes.unwrap()
        );
        assert_eq!(*id_commitment, expected_id_commitment_seed_bytes.unwrap());
    }

    #[test]
    // Tests hash to field using FFI APIs
    fn test_seeded_extended_keygen_stateless_ffi() {
        // We generate a new identity tuple from an input seed
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let key_gen = ffi2_seeded_extended_key_gen(&seed_bytes.into());
        assert_eq!(key_gen.len(), 4, "seeded extended key gen call failed");
        let identity_trapdoor = *key_gen[0];
        let identity_nullifier = *key_gen[1];
        let identity_secret_hash = *key_gen[2];
        let id_commitment = *key_gen[3];

        // We check against expected values
        let expected_identity_trapdoor_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        );
        let expected_identity_nullifier_seed_bytes = str_to_fr(
            "0x1f18714c7bc83b5bca9e89d404cf6f2f585bc4c0f7ed8b53742b7e2b298f50b4",
            16,
        );
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x2aca62aaa7abaf3686fff2caf00f55ab9462dc12db5b5d4bcf3994e671f8e521",
            16,
        );
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0x68b66aa0a8320d2e56842581553285393188714c48f9b17acd198b4f1734c5c",
            16,
        );

        assert_eq!(
            identity_trapdoor,
            expected_identity_trapdoor_seed_bytes.unwrap()
        );
        assert_eq!(
            identity_nullifier,
            expected_identity_nullifier_seed_bytes.unwrap()
        );
        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_bytes.unwrap()
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes.unwrap());
    }

    #[test]
    // Test CFr FFI functions
    fn test_cfr_ffi() {
        let cfr_zero = cfr_zero();
        let fr_zero = rln::circuit::Fr::from(0u8);
        assert_eq!(*cfr_zero, fr_zero);

        let cfr_one = cfr_one();
        let fr_one = rln::circuit::Fr::from(1u8);
        assert_eq!(*cfr_one, fr_one);

        let cfr_int = uint_to_cfr(42);
        let fr_int = rln::circuit::Fr::from(42u8);
        assert_eq!(*cfr_int, fr_int);

        let cfr_debug_str = cfr_debug(Some(&cfr_int));
        assert_eq!(cfr_debug_str.to_string(), "Some(\"42\")");

        let key_gen = ffi2_key_gen();
        let mut id_secret_fr = *key_gen[0];
        let id_secret_hash = IdSecret::from(&mut id_secret_fr);
        let id_commitment = *key_gen[1];
        let cfr_id_secret_hash = vec_cfr_get(&key_gen, 0).unwrap();
        assert_eq!(*cfr_id_secret_hash, *id_secret_hash);
        let cfr_id_commitment = vec_cfr_get(&key_gen, 1).unwrap();
        assert_eq!(*cfr_id_commitment, id_commitment);
    }

    #[test]
    // Test Vec<u8> FFI functions
    fn test_vec_u8_ffi() {
        let mut rng = rand::thread_rng();
        let signal_gen: [u8; 32] = rng.gen();
        let signal: Vec<u8> = signal_gen.to_vec();

        let bytes_le = vec_u8_to_bytes_le(&signal.clone().into());
        let expected_le = rln::utils::vec_u8_to_bytes_le(&signal);
        assert_eq!(bytes_le.iter().copied().collect::<Vec<_>>(), expected_le);

        let bytes_be = vec_u8_to_bytes_be(&signal.clone().into());
        let expected_be = rln::utils::vec_u8_to_bytes_be(&signal);
        assert_eq!(bytes_be.iter().copied().collect::<Vec<_>>(), expected_be);

        let signal_from_le = match bytes_le_to_vec_u8(&bytes_le) {
            CResult {
                ok: Some(vec_u8),
                err: None,
            } => vec_u8,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("bytes_le_to_vec_u8 call failed: {}", err),
            _ => unreachable!(),
        };
        assert_eq!(signal_from_le.iter().copied().collect::<Vec<_>>(), signal);

        let signal_from_be = match bytes_be_to_vec_u8(&bytes_be) {
            CResult {
                ok: Some(vec_u8),
                err: None,
            } => vec_u8,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("bytes_be_to_vec_u8 call failed: {}", err),
            _ => unreachable!(),
        };
        assert_eq!(signal_from_be.iter().copied().collect::<Vec<_>>(), signal);
    }

    #[test]
    // Test Vec<CFr> FFI functions
    fn test_vec_cfr_ffi() {
        let vec_fr = [Fr::from(1u8), Fr::from(2u8), Fr::from(3u8), Fr::from(4u8)];
        let vec_cfr: Vec<CFr> = vec_fr.iter().map(|fr| CFr::from(*fr)).collect();

        let bytes_le = vec_cfr_to_bytes_le(&vec_cfr.clone().into());
        let expected_le = rln::utils::vec_fr_to_bytes_le(&vec_fr);
        assert_eq!(bytes_le.iter().copied().collect::<Vec<_>>(), expected_le);

        let bytes_be = vec_cfr_to_bytes_be(&vec_cfr.clone().into());
        let expected_be = rln::utils::vec_fr_to_bytes_be(&vec_fr);
        assert_eq!(bytes_be.iter().copied().collect::<Vec<_>>(), expected_be);

        let vec_cfr_from_le = match bytes_le_to_vec_cfr(&bytes_le) {
            CResult {
                ok: Some(vec_cfr),
                err: None,
            } => vec_cfr,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("bytes_le_to_vec_cfr call failed: {}", err),
            _ => unreachable!(),
        };
        assert_eq!(vec_cfr_from_le.iter().copied().collect::<Vec<_>>(), vec_cfr);

        let vec_cfr_from_be = match bytes_be_to_vec_cfr(&bytes_be) {
            CResult {
                ok: Some(vec_cfr),
                err: None,
            } => vec_cfr,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("bytes_be_to_vec_cfr call failed: {}", err),
            _ => unreachable!(),
        };
        assert_eq!(vec_cfr_from_be.iter().copied().collect::<Vec<_>>(), vec_cfr);
    }

    #[test]
    // Tests hash to field using FFI APIs
    fn test_hash_to_field_ffi() {
        let mut rng = rand::thread_rng();
        let signal_gen: [u8; 32] = rng.gen();
        let signal: Vec<u8> = signal_gen.to_vec();

        let cfr_le_1 = ffi2_hash_to_field_le(&signal.clone().into());
        let fr_le_2 = rln::hashers::hash_to_field_le(&signal);
        assert_eq!(**cfr_le_1, fr_le_2);

        let cfr_be_1 = ffi2_hash_to_field_be(&signal.clone().into());
        let fr_be_2 = rln::hashers::hash_to_field_be(&signal);
        assert_eq!(**cfr_be_1, fr_be_2);

        assert_eq!(*cfr_le_1, **cfr_be_1);
        assert_eq!(fr_le_2, fr_be_2);

        let hash_cfr_le_1 = cfr_to_bytes_le(&cfr_le_1)
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let hash_fr_le_2 = fr_to_bytes_le(&fr_le_2);
        assert_eq!(hash_cfr_le_1, hash_fr_le_2);

        let hash_cfr_be_1 = cfr_to_bytes_be(&cfr_be_1)
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let hash_fr_be_2 = fr_to_bytes_be(&fr_be_2);
        assert_eq!(hash_cfr_be_1, hash_fr_be_2);

        assert_ne!(hash_cfr_le_1, hash_cfr_be_1);
        assert_ne!(hash_fr_le_2, hash_fr_be_2);
    }

    #[test]
    // Test Poseidon hash FFI
    fn test_poseidon_hash_pair_ffi() {
        let input_1 = Fr::from(42u8);
        let input_2 = Fr::from(99u8);

        let expected_hash = poseidon_hash(&[input_1, input_2]);
        let received_hash_cfr = ffi2_poseidon_hash_pair(&CFr::from(input_1), &CFr::from(input_2));
        assert_eq!(**received_hash_cfr, expected_hash);
    }
}
