#[cfg(test)]
mod test {
    use ark_ff::{BigInteger, PrimeField};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::{rand::thread_rng, UniformRand};
    use num_bigint::BigUint;
    use rln::{
        circuit::{Fr, PartialProof, Proof, DEFAULT_TREE_DEPTH},
        error::UtilsError,
        prelude::{
            generate_partial_zk_proof, generate_zk_proof, keygen, CanonicalDeserializeBE,
            CanonicalSerializeBE, RLNPartialWitnessInput, RLNPartialWitnessInputV3,
            RLNProofValuesMulti, RLNProofValuesSingle, RLNProofValuesV3, RLNWitnessInput,
            RLNWitnessInputMulti, RLNWitnessInputSingle, RLNWitnessInputV3, FR_BYTE_SIZE,
        },
        protocol::{ENUM_TAG_MULTI, ENUM_TAG_SINGLE},
        utils::IdSecret,
    };

    #[test]
    fn test_fr_be_roundtrip() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            let fr = Fr::rand(&mut rng);
            let mut buf = Vec::new();
            fr.serialize(&mut buf).unwrap();
            let deser = Fr::deserialize(buf.as_slice()).unwrap();
            assert_eq!(fr, deser);
            assert_eq!(buf.len(), CanonicalSerializeBE::serialized_size(&fr));
        }
    }

    #[test]
    fn test_fr_be_byte_order() {
        // BE: MSB at index 0 — Fr(1) should have last byte == 1, all others 0
        let one = Fr::from(1u64);
        let mut buf = Vec::new();
        one.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), FR_BYTE_SIZE);
        assert_eq!(
            buf[FR_BYTE_SIZE - 1],
            1,
            "LSB must be at index FR_BYTE_SIZE-1"
        );
        assert!(buf[..FR_BYTE_SIZE - 1].iter().all(|&b| b == 0));

        // Fr(256) — second-to-last byte should be 1
        let v = Fr::from(256u64);
        let mut buf2 = Vec::new();
        v.serialize(&mut buf2).unwrap();
        assert_eq!(buf2[FR_BYTE_SIZE - 2], 1);
        assert_eq!(buf2[FR_BYTE_SIZE - 1], 0);
    }

    #[test]
    fn test_fr_be_non_canonical_rejected() {
        let modulus = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());

        let to_be = |val: &BigUint| -> Vec<u8> {
            let mut bytes = val.to_bytes_be();
            let pad = FR_BYTE_SIZE.saturating_sub(bytes.len());
            if pad > 0 {
                bytes.splice(0..0, std::iter::repeat_n(0, pad));
            }
            bytes
        };

        // Modulus itself must be rejected
        let modulus_be = to_be(&modulus);
        let err = Fr::deserialize(modulus_be.as_slice()).unwrap_err();
        assert!(matches!(err, UtilsError::NonCanonicalFieldElement));

        // Modulus + 1 must be rejected
        let plus_one_be = to_be(&(&modulus + 1u32));
        assert!(matches!(
            Fr::deserialize(plus_one_be.as_slice()).unwrap_err(),
            UtilsError::NonCanonicalFieldElement
        ));

        // All 0xFF must be rejected
        let max_bytes = vec![0xFF; FR_BYTE_SIZE];
        assert!(matches!(
            Fr::deserialize(max_bytes.as_slice()).unwrap_err(),
            UtilsError::NonCanonicalFieldElement
        ));

        // Modulus - 1 must succeed and round-trip
        let minus_one_be = to_be(&(&modulus - 1u32));
        let fr_max = Fr::deserialize(minus_one_be.as_slice()).unwrap();
        let mut roundtrip = Vec::new();
        fr_max.serialize(&mut roundtrip).unwrap();
        assert_eq!(roundtrip, minus_one_be);
    }

    #[test]
    fn test_fr_be_insufficient_data_rejected() {
        let short = vec![0u8; FR_BYTE_SIZE - 1];
        assert!(Fr::deserialize(short.as_slice()).is_err());
        assert!(Fr::deserialize([].as_slice()).is_err());
    }

    #[test]
    fn test_vec_fr_be_roundtrip() {
        let mut rng = thread_rng();
        for size in [0, 1, 5, 10] {
            let v: Vec<Fr> = (0..size).map(|_| Fr::rand(&mut rng)).collect();
            let mut buf = Vec::new();
            v.serialize(&mut buf).unwrap();
            let deser = Vec::<Fr>::deserialize(buf.as_slice()).unwrap();
            assert_eq!(v, deser);
            assert_eq!(buf.len(), CanonicalSerializeBE::serialized_size(&v));
        }
    }

    #[test]
    fn test_vec_fr_be_non_canonical_element_rejected() {
        // Craft a length-1 vec with modulus as the element — must be rejected
        let modulus = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
        let mut bytes = modulus.to_bytes_be();
        let pad = FR_BYTE_SIZE.saturating_sub(bytes.len());
        if pad > 0 {
            bytes.splice(0..0, std::iter::repeat_n(0, pad));
        }
        // Prepend length=1 as 8-byte BE
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u64.to_be_bytes());
        buf.extend_from_slice(&bytes);
        assert!(Vec::<Fr>::deserialize(buf.as_slice()).is_err());
    }

    #[test]
    fn test_vec_fr_be_insufficient_data_rejected() {
        // Length prefix says 2 but only 1 element present
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u64.to_be_bytes());
        buf.extend_from_slice(&[0u8; FR_BYTE_SIZE]); // only one element
        assert!(Vec::<Fr>::deserialize(buf.as_slice()).is_err());
    }

    #[test]
    fn test_vec_u8_be_roundtrip() {
        let test_cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0],
            vec![255],
            vec![1, 2, 3, 4, 5],
            vec![0, 255, 128, 64, 32, 16, 8, 4, 2, 1],
            (0..100).collect(),
        ];
        for v in test_cases {
            let mut buf = Vec::new();
            v.serialize(&mut buf).unwrap();
            let deser = Vec::<u8>::deserialize(buf.as_slice()).unwrap();
            assert_eq!(v, deser);
            assert_eq!(buf.len(), CanonicalSerializeBE::serialized_size(&v));
        }
    }

    #[test]
    fn test_vec_u8_be_insufficient_data_rejected() {
        // Length prefix says 5 but no data follows
        let mut buf = Vec::new();
        buf.extend_from_slice(&5u64.to_be_bytes());
        assert!(Vec::<u8>::deserialize(buf.as_slice()).is_err());
    }

    #[test]
    fn test_vec_bool_be_roundtrip() {
        let test_cases = vec![
            vec![],
            vec![true],
            vec![false],
            vec![true, false, true, false, true],
            vec![true; 50],
            (0..50).map(|i| i % 2 == 0).collect::<Vec<bool>>(),
        ];
        for v in test_cases {
            let mut buf = Vec::new();
            v.serialize(&mut buf).unwrap();
            let deser = Vec::<bool>::deserialize(buf.as_slice()).unwrap();
            assert_eq!(v, deser);
            assert_eq!(buf.len(), CanonicalSerializeBE::serialized_size(&v));
        }
    }

    #[test]
    fn test_vec_bool_be_insufficient_data_rejected() {
        // Length prefix says 3 but no data follows
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u64.to_be_bytes());
        assert!(Vec::<bool>::deserialize(buf.as_slice()).is_err());
    }

    #[test]
    fn test_id_secret_be_roundtrip() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            let secret = IdSecret::rand(&mut rng);
            let mut buf = Vec::new();
            secret.serialize(&mut buf).unwrap();
            let deser = IdSecret::deserialize(buf.as_slice()).unwrap();
            assert_eq!(secret, deser);
            assert_eq!(buf.len(), CanonicalSerializeBE::serialized_size(&secret));
        }
    }

    #[test]
    fn test_id_secret_be_known_value() {
        // IdSecret(42) BE should match Fr(42) BE — same field element
        let secret = IdSecret::from(&mut Fr::from(42u64));
        let mut secret_buf = Vec::new();
        secret.serialize(&mut secret_buf).unwrap();

        let fr = Fr::from(42u64);
        let mut fr_buf = Vec::new();
        fr.serialize(&mut fr_buf).unwrap();

        assert_eq!(secret_buf, fr_buf);
    }

    #[test]
    fn test_id_secret_be_non_canonical_rejected() {
        let modulus = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());

        let to_be = |val: &BigUint| -> Vec<u8> {
            let mut bytes = val.to_bytes_be();
            let pad = FR_BYTE_SIZE.saturating_sub(bytes.len());
            if pad > 0 {
                bytes.splice(0..0, std::iter::repeat_n(0, pad));
            }
            bytes
        };

        // Modulus must be rejected
        let modulus_be = to_be(&modulus);
        assert!(matches!(
            IdSecret::deserialize(modulus_be.as_slice()).unwrap_err(),
            UtilsError::NonCanonicalFieldElement
        ));

        // All 0xFF must be rejected
        let max_bytes = vec![0xFF; FR_BYTE_SIZE];
        assert!(matches!(
            IdSecret::deserialize(max_bytes.as_slice()).unwrap_err(),
            UtilsError::NonCanonicalFieldElement
        ));

        // Modulus - 1 must succeed
        let minus_one_be = to_be(&(&modulus - 1u32));
        assert!(IdSecret::deserialize(minus_one_be.as_slice()).is_ok());
    }

    #[test]
    fn test_id_secret_be_insufficient_data_rejected() {
        let short = vec![0u8; FR_BYTE_SIZE - 1];
        assert!(IdSecret::deserialize(short.as_slice()).is_err());
        assert!(IdSecret::deserialize([].as_slice()).is_err());
    }

    fn make_witness_input_single() -> RLNWitnessInputV3 {
        RLNWitnessInputV3::Single(RLNWitnessInputSingle::new(
            IdSecret::from(&mut Fr::from(42u64)),
            Fr::from(10u64),
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![0u8, 1u8],
            Fr::from(5u64),
            Fr::from(7u64),
            Fr::from(3u64),
        ).unwrap())
    }

    fn make_witness_input_multi() -> RLNWitnessInputV3 {
        RLNWitnessInputV3::Multi(RLNWitnessInputMulti::new(
            IdSecret::from(&mut Fr::from(99u64)),
            Fr::from(10u64),
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![0u8, 1u8],
            Fr::from(5u64),
            Fr::from(7u64),
            vec![Fr::from(0u64), Fr::from(1u64)],
            vec![true, false],
        ).unwrap())
    }

    fn make_partial_witness() -> RLNPartialWitnessInputV3 {
        RLNPartialWitnessInputV3::new(
            IdSecret::from(&mut Fr::from(42u64)),
            Fr::from(10u64),
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![0u8, 1u8],
        ).unwrap()
    }

    fn make_proof_values_single() -> RLNProofValuesV3 {
        RLNProofValuesV3::Single(RLNProofValuesSingle {
            root: Fr::from(1u64),
            x: Fr::from(2u64),
            external_nullifier: Fr::from(3u64),
            y: Fr::from(4u64),
            nullifier: Fr::from(5u64),
        })
    }

    fn make_proof_values_multi() -> RLNProofValuesV3 {
        RLNProofValuesV3::Multi(RLNProofValuesMulti {
            root: Fr::from(10u64),
            x: Fr::from(20u64),
            external_nullifier: Fr::from(30u64),
            ys: vec![Fr::from(40u64), Fr::from(50u64)],
            nullifiers: vec![Fr::from(60u64), Fr::from(70u64)],
            selector_used: vec![true, false],
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn make_proof() -> Proof {
        let (identity_secret, _) = keygen();
        let path_elements = vec![Fr::from(0); DEFAULT_TREE_DEPTH];
        let identity_path_index = vec![0; DEFAULT_TREE_DEPTH];
        let witness = RLNWitnessInput::new_single(
            identity_secret,
            Fr::from(100),
            Fr::from(1),
            path_elements,
            identity_path_index,
            Fr::from(1),
            Fr::from(100),
        )
        .unwrap();
        generate_zk_proof(
            rln::circuit::zkey_single_v1(),
            &witness,
            rln::circuit::graph_single_v1(),
        )
        .unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn make_partial_proof() -> PartialProof {
        let (identity_secret, _) = keygen();
        let path_elements = vec![Fr::from(0); DEFAULT_TREE_DEPTH];
        let identity_path_index = vec![0; DEFAULT_TREE_DEPTH];
        let partial_witness = RLNPartialWitnessInput::new(
            identity_secret,
            Fr::from(100),
            path_elements,
            identity_path_index,
        )
        .unwrap();
        generate_partial_zk_proof(
            rln::circuit::zkey_single_v1(),
            &partial_witness,
            rln::circuit::graph_single_v1(),
        )
        .unwrap()
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_proof_le_compressed_roundtrip() {
        let proof = make_proof();
        let mut buf = Vec::new();
        proof.serialize_compressed(&mut buf).unwrap();
        let deser = Proof::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(proof, deser);
        assert_eq!(proof.compressed_size(), buf.len());
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_partial_proof_le_compressed_roundtrip() {
        let partial = make_partial_proof();
        let mut buf = Vec::new();
        partial.serialize_compressed(&mut buf).unwrap();
        let deser = PartialProof::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(partial, deser);
        assert_eq!(partial.compressed_size(), buf.len());
    }

    #[test]
    fn test_witness_v3_single_le_compressed_roundtrip() {
        let w = make_witness_input_single();
        let mut buf = Vec::new();
        w.serialize_compressed(&mut buf).unwrap();
        let deser = RLNWitnessInputV3::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(w, deser);
        assert_eq!(w.compressed_size(), buf.len());
        assert_eq!(buf[0], ENUM_TAG_SINGLE);
    }

    #[test]
    fn test_witness_v3_multi_le_compressed_roundtrip() {
        let w = make_witness_input_multi();
        let mut buf = Vec::new();
        w.serialize_compressed(&mut buf).unwrap();
        let deser = RLNWitnessInputV3::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(w, deser);
        assert_eq!(w.compressed_size(), buf.len());
        assert_eq!(buf[0], ENUM_TAG_MULTI);
    }

    #[test]
    fn test_witness_v3_le_uncompressed_roundtrip() {
        for w in [make_witness_input_single(), make_witness_input_multi()] {
            let mut buf = Vec::new();
            w.serialize_uncompressed(&mut buf).unwrap();
            let deser = RLNWitnessInputV3::deserialize_uncompressed(buf.as_slice()).unwrap();
            assert_eq!(w, deser);
            assert_eq!(w.uncompressed_size(), buf.len());
        }
    }

    #[test]
    fn test_witness_v3_le_invalid_tag_rejected() {
        let mut bad = vec![99u8]; // unknown tag
        bad.extend_from_slice(&[0u8; 32]);
        assert!(RLNWitnessInputV3::deserialize_compressed(bad.as_slice()).is_err());
    }

    #[test]
    fn test_witness_v3_single_be_roundtrip() {
        let w = make_witness_input_single();
        let mut buf = Vec::new();
        w.serialize(&mut buf).unwrap();
        assert_eq!(buf[0], ENUM_TAG_SINGLE);
        assert_eq!(buf.len(), CanonicalSerializeBE::serialized_size(&w));
        let deser = RLNWitnessInputV3::deserialize(buf.as_slice()).unwrap();
        assert_eq!(w, deser);
    }

    #[test]
    fn test_witness_v3_multi_be_roundtrip() {
        let w = make_witness_input_multi();
        let mut buf = Vec::new();
        w.serialize(&mut buf).unwrap();
        assert_eq!(buf[0], ENUM_TAG_MULTI);
        assert_eq!(buf.len(), CanonicalSerializeBE::serialized_size(&w));
        let deser = RLNWitnessInputV3::deserialize(buf.as_slice()).unwrap();
        assert_eq!(w, deser);
    }

    #[test]
    fn test_witness_v3_be_invalid_tag_rejected() {
        let w = make_witness_input_single();
        let mut buf = Vec::new();
        w.serialize(&mut buf).unwrap();
        buf[0] = 99; // unknown tag
        assert!(RLNWitnessInputV3::deserialize(buf.as_slice()).is_err());
    }

    #[test]
    fn test_partial_witness_v3_le_compressed_roundtrip() {
        let pw = make_partial_witness();
        let mut buf = Vec::new();
        pw.serialize_compressed(&mut buf).unwrap();
        let deser = RLNPartialWitnessInputV3::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(pw, deser);
        assert_eq!(pw.compressed_size(), buf.len());
    }

    #[test]
    fn test_partial_witness_v3_be_roundtrip() {
        let pw = make_partial_witness();
        let mut buf = Vec::new();
        pw.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), CanonicalSerializeBE::serialized_size(&pw));
        let deser = RLNPartialWitnessInputV3::deserialize(buf.as_slice()).unwrap();
        assert_eq!(pw, deser);
    }

    #[test]
    fn test_proof_values_v3_single_le_compressed_roundtrip() {
        let pv = make_proof_values_single();
        let mut buf = Vec::new();
        pv.serialize_compressed(&mut buf).unwrap();
        let deser = RLNProofValuesV3::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(pv, deser);
        assert_eq!(pv.compressed_size(), buf.len());
        assert_eq!(buf[0], ENUM_TAG_SINGLE);
    }

    #[test]
    fn test_proof_values_v3_multi_le_compressed_roundtrip() {
        let pv = make_proof_values_multi();
        let mut buf = Vec::new();
        pv.serialize_compressed(&mut buf).unwrap();
        let deser = RLNProofValuesV3::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(pv, deser);
        assert_eq!(pv.compressed_size(), buf.len());
        assert_eq!(buf[0], ENUM_TAG_MULTI);
    }

    #[test]
    fn test_proof_values_v3_le_uncompressed_roundtrip() {
        for pv in [make_proof_values_single(), make_proof_values_multi()] {
            let mut buf = Vec::new();
            pv.serialize_uncompressed(&mut buf).unwrap();
            let deser = RLNProofValuesV3::deserialize_uncompressed(buf.as_slice()).unwrap();
            assert_eq!(pv, deser);
            assert_eq!(pv.uncompressed_size(), buf.len());
        }
    }

    #[test]
    fn test_proof_values_v3_single_le_invalid_tag_rejected() {
        let pv = make_proof_values_single();
        let mut buf = Vec::new();
        pv.serialize_compressed(&mut buf).unwrap();
        buf[0] = 99; // unknown tag
        assert!(RLNProofValuesV3::deserialize_compressed(buf.as_slice()).is_err());
    }

    #[test]
    fn test_proof_values_v3_single_be_roundtrip() {
        let pv = make_proof_values_single();
        let mut buf = Vec::new();
        pv.serialize(&mut buf).unwrap();
        assert_eq!(buf[0], ENUM_TAG_SINGLE);
        assert_eq!(buf.len(), CanonicalSerializeBE::serialized_size(&pv));
        let deser = RLNProofValuesV3::deserialize(buf.as_slice()).unwrap();
        assert_eq!(pv, deser);
    }

    #[test]
    fn test_proof_values_v3_multi_be_roundtrip() {
        let pv = make_proof_values_multi();
        let mut buf = Vec::new();
        pv.serialize(&mut buf).unwrap();
        assert_eq!(buf[0], ENUM_TAG_MULTI);
        assert_eq!(buf.len(), CanonicalSerializeBE::serialized_size(&pv));
        let deser = RLNProofValuesV3::deserialize(buf.as_slice()).unwrap();
        assert_eq!(pv, deser);
    }

    #[test]
    fn test_proof_values_v3_multi_be_invalid_tag_rejected() {
        let pv = make_proof_values_multi();
        let mut buf = Vec::new();
        pv.serialize(&mut buf).unwrap();
        buf[0] = 99; // unknown tag
        assert!(RLNProofValuesV3::deserialize(buf.as_slice()).is_err());
    }
}
