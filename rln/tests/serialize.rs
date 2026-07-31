#[cfg(test)]
mod test {
    use ark_ff::{BigInteger, PrimeField};
    use ark_std::{
        rand::{rngs::ThreadRng, thread_rng},
        UniformRand,
    };
    use num_bigint::BigUint;
    use rln::prelude::*;

    #[test]
    fn test_fr_roundtrip() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            let fr = Fr::rand(&mut rng);

            let mut be_buf = Vec::new();
            fr.serialize(&mut be_buf).unwrap();
            assert_eq!(Fr::deserialize(be_buf.as_slice()).unwrap(), fr);
            assert_eq!(be_buf.len(), CanonicalSerializeBE::serialized_size(&fr));

            let mut le_buf = Vec::new();
            fr.serialize_compressed(&mut le_buf).unwrap();
            assert_eq!(Fr::deserialize_compressed(le_buf.as_slice()).unwrap(), fr);
            assert_eq!(le_buf.len(), fr.compressed_size());
        }
    }

    #[test]
    fn test_fr_be_byte_order() {
        // BE: most significant byte at index 0 - Fr(1) should have last byte == 1, all others 0
        let one = Fr::from(1u64);
        let mut buf = Vec::new();
        one.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), 32);
        assert_eq!(buf[31], 1, "least significant byte must be last");
        assert!(buf[..31].iter().all(|&b| b == 0));

        // Fr(256) - second-to-last byte should be 1
        let v = Fr::from(256u64);
        let mut buf2 = Vec::new();
        v.serialize(&mut buf2).unwrap();
        assert_eq!(buf2[30], 1);
        assert_eq!(buf2[31], 0);
    }

    #[test]
    fn test_fr_non_canonical_rejected() {
        let modulus = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());

        let to_be = |val: &BigUint| -> Vec<u8> {
            let mut bytes = val.to_bytes_be();
            let pad = 32usize.saturating_sub(bytes.len());
            if pad > 0 {
                bytes.splice(0..0, std::iter::repeat_n(0, pad));
            }
            bytes
        };
        let to_le = |val: &BigUint| -> Vec<u8> {
            let mut bytes = val.to_bytes_le();
            bytes.resize(32, 0);
            bytes
        };

        // Modulus itself must be rejected
        assert!(matches!(
            Fr::deserialize(to_be(&modulus).as_slice()).unwrap_err(),
            SerializationError::NonCanonicalFieldElement
        ));
        assert!(Fr::deserialize_compressed(to_le(&modulus).as_slice()).is_err());

        // Modulus + 1 must be rejected
        let plus_one = &modulus + 1u32;
        assert!(matches!(
            Fr::deserialize(to_be(&plus_one).as_slice()).unwrap_err(),
            SerializationError::NonCanonicalFieldElement
        ));
        assert!(Fr::deserialize_compressed(to_le(&plus_one).as_slice()).is_err());

        // All 0xFF must be rejected
        let max_bytes = [0xFF; 32];
        assert!(matches!(
            Fr::deserialize(max_bytes.as_slice()).unwrap_err(),
            SerializationError::NonCanonicalFieldElement
        ));
        assert!(Fr::deserialize_compressed(max_bytes.as_slice()).is_err());

        // Modulus - 1 must succeed and round-trip in both endiannesses
        let minus_one = &modulus - 1u32;
        let minus_one_be = to_be(&minus_one);
        let fr_max = Fr::deserialize(minus_one_be.as_slice()).unwrap();
        let mut be_roundtrip = Vec::new();
        fr_max.serialize(&mut be_roundtrip).unwrap();
        assert_eq!(be_roundtrip, minus_one_be);

        let minus_one_le = to_le(&minus_one);
        let fr_max = Fr::deserialize_compressed(minus_one_le.as_slice()).unwrap();
        let mut le_roundtrip = Vec::new();
        fr_max.serialize_compressed(&mut le_roundtrip).unwrap();
        assert_eq!(le_roundtrip, minus_one_le);
    }

    #[test]
    fn test_fr_be_insufficient_data_rejected() {
        let short = [0u8; 31];
        assert!(Fr::deserialize(short.as_slice()).is_err());
        assert!(Fr::deserialize([].as_slice()).is_err());
    }

    #[test]
    fn test_endianness_differences() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            let fr = Fr::rand(&mut rng);

            let mut le_bytes = Vec::new();
            fr.serialize_compressed(&mut le_bytes).unwrap();
            let mut be_bytes = Vec::new();
            CanonicalSerializeBE::serialize(&fr, &mut be_bytes).unwrap();

            // LE is the byte-reversal of BE for a 32-byte field element
            let mut reversed_be = be_bytes.clone();
            reversed_be.reverse();
            assert_eq!(le_bytes, reversed_be);

            // Both reconstruct the same field element
            let from_le = Fr::deserialize_compressed(le_bytes.as_slice()).unwrap();
            let from_be = <Fr as CanonicalDeserializeBE>::deserialize(be_bytes.as_slice()).unwrap();
            assert_eq!(from_le, fr);
            assert_eq!(from_be, fr);
        }

        // Zero serializes identically in both endiannesses
        let zero = Fr::from(0);
        let mut zero_le = Vec::new();
        zero.serialize_compressed(&mut zero_le).unwrap();
        let mut zero_be = Vec::new();
        CanonicalSerializeBE::serialize(&zero, &mut zero_be).unwrap();
        assert_eq!(zero_le, zero_be);
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
        // Craft a length-1 vec with modulus as the element - must be rejected
        let modulus = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
        let mut bytes = modulus.to_bytes_be();
        let pad = 32usize.saturating_sub(bytes.len());
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
        buf.extend_from_slice(&[0u8; 32]); // only one element
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
    fn test_vec_bool_be_non_canonical_byte_rejected() {
        // Any byte other than 0x00 or 0x01 must be rejected
        for bad in [0x02u8, 0x05, 0xff] {
            let mut buf = Vec::new();
            buf.extend_from_slice(&1u64.to_be_bytes()); // length = 1
            buf.push(bad);
            assert!(
                Vec::<bool>::deserialize(buf.as_slice()).is_err(),
                "byte {bad:#04x} should have been rejected"
            );
        }
    }

    #[test]
    fn test_secret_fr_be_roundtrip() {
        let mut rng = thread_rng();
        for _ in 0..10 {
            let secret = SecretFr::rand(&mut rng);
            let mut buf = Vec::new();
            secret.serialize(&mut buf).unwrap();
            let deser = SecretFr::deserialize(buf.as_slice()).unwrap();
            assert_eq!(secret, deser);
            assert_eq!(buf.len(), CanonicalSerializeBE::serialized_size(&secret));
        }
    }

    #[test]
    fn test_secret_fr_be_known_value() {
        // SecretFr(42) BE should match Fr(42) BE - same field element
        let secret = SecretFr::from(&mut Fr::from(42u64));
        let mut secret_buf = Vec::new();
        secret.serialize(&mut secret_buf).unwrap();

        let fr = Fr::from(42u64);
        let mut fr_buf = Vec::new();
        fr.serialize(&mut fr_buf).unwrap();

        assert_eq!(secret_buf, fr_buf);
    }

    #[test]
    fn test_secret_fr_be_non_canonical_rejected() {
        let modulus = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());

        let to_be = |val: &BigUint| -> Vec<u8> {
            let mut bytes = val.to_bytes_be();
            let pad = 32usize.saturating_sub(bytes.len());
            if pad > 0 {
                bytes.splice(0..0, std::iter::repeat_n(0, pad));
            }
            bytes
        };

        // Modulus must be rejected
        let modulus_be = to_be(&modulus);
        assert!(matches!(
            SecretFr::deserialize(modulus_be.as_slice()).unwrap_err(),
            SerializationError::NonCanonicalFieldElement
        ));

        // All 0xFF must be rejected
        let max_bytes = [0xFF; 32];
        assert!(matches!(
            SecretFr::deserialize(max_bytes.as_slice()).unwrap_err(),
            SerializationError::NonCanonicalFieldElement
        ));

        // Modulus - 1 must succeed
        let minus_one_be = to_be(&(&modulus - 1u32));
        assert!(SecretFr::deserialize(minus_one_be.as_slice()).is_ok());
    }

    #[test]
    fn test_secret_fr_be_insufficient_data_rejected() {
        let short = [0u8; 31];
        assert!(SecretFr::deserialize(short.as_slice()).is_err());
        assert!(SecretFr::deserialize([].as_slice()).is_err());
    }

    fn make_witness_input_single() -> RLNWitnessInput {
        RLNWitnessInput::new_single()
            .identity_secret(SecretFr::from(&mut Fr::from(42u64)))
            .user_message_limit(Fr::from(10u64))
            .merkle_proof(RLNMerkleProof::new(
                vec![Fr::from(1u64), Fr::from(2u64)],
                vec![0u8, 1u8],
            ))
            .x(Fr::from(5u64))
            .external_nullifier(Fr::from(7u64))
            .message_id(Fr::from(3u64))
            .build()
            .unwrap()
    }

    fn make_witness_input_multi() -> RLNWitnessInput {
        RLNWitnessInput::new_multi()
            .identity_secret(SecretFr::from(&mut Fr::from(99u64)))
            .user_message_limit(Fr::from(10u64))
            .merkle_proof(RLNMerkleProof::new(
                vec![Fr::from(1u64), Fr::from(2u64)],
                vec![0u8, 1u8],
            ))
            .x(Fr::from(5u64))
            .external_nullifier(Fr::from(7u64))
            .message_ids(vec![Fr::from(0u64), Fr::from(1u64)])
            .selector_used(vec![true, false])
            .build()
            .unwrap()
    }

    fn make_partial_witness() -> RLNPartialWitnessInput {
        RLNPartialWitnessInput::new()
            .identity_secret(SecretFr::from(&mut Fr::from(42u64)))
            .user_message_limit(Fr::from(10u64))
            .merkle_proof(RLNMerkleProof::new(
                vec![Fr::from(1u64), Fr::from(2u64)],
                vec![0u8, 1u8],
            ))
            .build()
            .unwrap()
    }

    fn make_proof_values_single() -> RLNProofValues {
        RLNProofValues::new_single()
            .root(Fr::from(1u64))
            .x(Fr::from(2u64))
            .external_nullifier(Fr::from(3u64))
            .y(Fr::from(4u64))
            .nullifier(Fr::from(5u64))
            .build()
    }

    fn make_proof_values_multi() -> RLNProofValues {
        RLNProofValues::new_multi()
            .root(Fr::from(10u64))
            .x(Fr::from(20u64))
            .external_nullifier(Fr::from(30u64))
            .ys(vec![Fr::from(40u64), Fr::from(50u64)])
            .nullifiers(vec![Fr::from(60u64), Fr::from(70u64)])
            .selector_used(vec![true, false])
            .build()
            .unwrap()
    }

    fn make_proof() -> Proof {
        let rln = RLNBuilder::stateless().build();
        let identity_secret =
            IdentityKeys::generate::<PoseidonHash, ThreadRng>(&mut thread_rng()).identity_secret();
        let witness = RLNWitnessInput::new_single()
            .identity_secret(identity_secret)
            .user_message_limit(Fr::from(100))
            .merkle_proof(RLNMerkleProof::new(
                vec![Fr::from(0); DEFAULT_TREE_DEPTH],
                vec![0; DEFAULT_TREE_DEPTH],
            ))
            .x(Fr::from(1))
            .external_nullifier(Fr::from(100))
            .message_id(Fr::from(1))
            .build()
            .unwrap();
        let (proof, _) = rln.generate_proof(&witness).unwrap();
        proof
    }

    fn make_partial_proof() -> PartialProof {
        let rln = RLNBuilder::stateless().build();
        let identity_secret =
            IdentityKeys::generate::<PoseidonHash, ThreadRng>(&mut thread_rng()).identity_secret();
        let partial_witness = RLNPartialWitnessInput::new()
            .identity_secret(identity_secret)
            .user_message_limit(Fr::from(100))
            .merkle_proof(RLNMerkleProof::new(
                vec![Fr::from(0); DEFAULT_TREE_DEPTH],
                vec![0; DEFAULT_TREE_DEPTH],
            ))
            .build()
            .unwrap();
        rln.generate_partial_proof(&partial_witness).unwrap()
    }

    #[test]
    fn test_merkle_proof_roundtrip() {
        let merkle_proof =
            RLNMerkleProof::new(vec![Fr::from(1u64), Fr::from(2u64)], vec![0u8, 1u8]);

        let mut le_buf = Vec::new();
        merkle_proof.serialize_compressed(&mut le_buf).unwrap();
        assert_eq!(le_buf.len(), merkle_proof.compressed_size());
        assert_eq!(
            RLNMerkleProof::deserialize_compressed(le_buf.as_slice()).unwrap(),
            merkle_proof
        );

        let mut be_buf = Vec::new();
        CanonicalSerializeBE::serialize(&merkle_proof, &mut be_buf).unwrap();
        assert_eq!(
            be_buf.len(),
            CanonicalSerializeBE::serialized_size(&merkle_proof)
        );
        assert_eq!(
            <RLNMerkleProof as CanonicalDeserializeBE>::deserialize(be_buf.as_slice()).unwrap(),
            merkle_proof
        );

        // Truncated bytes must be rejected
        assert!(RLNMerkleProof::deserialize_compressed(&le_buf[..le_buf.len() - 1]).is_err());
        assert!(<RLNMerkleProof as CanonicalDeserializeBE>::deserialize(
            &be_buf[..be_buf.len() - 1]
        )
        .is_err());
    }

    #[test]
    fn test_witness_single_roundtrip() {
        let w = make_witness_input_single();

        let mut be_buf = Vec::new();
        w.serialize(&mut be_buf).unwrap();
        assert_eq!(be_buf[0], 0, "Single variant tag byte");
        assert_eq!(be_buf.len(), CanonicalSerializeBE::serialized_size(&w));
        assert_eq!(RLNWitnessInput::deserialize(be_buf.as_slice()).unwrap(), w);

        let mut le_buf = Vec::new();
        w.serialize_compressed(&mut le_buf).unwrap();
        assert_eq!(le_buf[0], 0, "Single variant tag byte");
        assert_eq!(le_buf.len(), w.compressed_size());
        assert_eq!(
            RLNWitnessInput::deserialize_compressed(le_buf.as_slice()).unwrap(),
            w
        );
    }

    #[test]
    fn test_witness_multi_roundtrip() {
        let w = make_witness_input_multi();

        let mut be_buf = Vec::new();
        w.serialize(&mut be_buf).unwrap();
        assert_eq!(be_buf[0], 1, "Multi variant tag byte");
        assert_eq!(be_buf.len(), CanonicalSerializeBE::serialized_size(&w));
        assert_eq!(RLNWitnessInput::deserialize(be_buf.as_slice()).unwrap(), w);

        let mut le_buf = Vec::new();
        w.serialize_compressed(&mut le_buf).unwrap();
        assert_eq!(le_buf[0], 1, "Multi variant tag byte");
        assert_eq!(le_buf.len(), w.compressed_size());
        assert_eq!(
            RLNWitnessInput::deserialize_compressed(le_buf.as_slice()).unwrap(),
            w
        );
    }

    #[test]
    fn test_witness_le_uncompressed_roundtrip() {
        for w in [make_witness_input_single(), make_witness_input_multi()] {
            let mut buf = Vec::new();
            w.serialize_uncompressed(&mut buf).unwrap();
            let deser = RLNWitnessInput::deserialize_uncompressed(buf.as_slice()).unwrap();
            assert_eq!(w, deser);
            assert_eq!(w.uncompressed_size(), buf.len());
        }
    }

    #[test]
    fn test_witness_invalid_tag_rejected() {
        let w = make_witness_input_single();

        let mut be_buf = Vec::new();
        w.serialize(&mut be_buf).unwrap();
        be_buf[0] = 99; // unknown tag
        assert!(RLNWitnessInput::deserialize(be_buf.as_slice()).is_err());

        let mut le_buf = Vec::new();
        w.serialize_compressed(&mut le_buf).unwrap();
        le_buf[0] = 99; // unknown tag
        assert!(RLNWitnessInput::deserialize_compressed(le_buf.as_slice()).is_err());
    }

    #[test]
    fn test_witness_truncated_rejected() {
        for w in [make_witness_input_single(), make_witness_input_multi()] {
            let mut be_buf = Vec::new();
            w.serialize(&mut be_buf).unwrap();
            assert!(RLNWitnessInput::deserialize(&be_buf[..be_buf.len() - 1]).is_err());

            let mut le_buf = Vec::new();
            w.serialize_compressed(&mut le_buf).unwrap();
            assert!(RLNWitnessInput::deserialize_compressed(&le_buf[..le_buf.len() - 1]).is_err());
        }
    }

    #[test]
    fn test_witness_extra_bytes_accepted() {
        for w in [make_witness_input_single(), make_witness_input_multi()] {
            let mut be_buf = Vec::new();
            w.serialize(&mut be_buf).unwrap();
            be_buf.push(0xff);
            assert!(RLNWitnessInput::deserialize(be_buf.as_slice()).is_ok());

            let mut le_buf = Vec::new();
            w.serialize_compressed(&mut le_buf).unwrap();
            le_buf.push(0xff);
            assert!(RLNWitnessInput::deserialize_compressed(le_buf.as_slice()).is_ok());
        }
    }

    #[test]
    fn test_partial_witness_roundtrip() {
        let pw = make_partial_witness();

        let mut be_buf = Vec::new();
        pw.serialize(&mut be_buf).unwrap();
        assert_eq!(be_buf.len(), CanonicalSerializeBE::serialized_size(&pw));
        assert_eq!(
            RLNPartialWitnessInput::deserialize(be_buf.as_slice()).unwrap(),
            pw
        );

        let mut le_buf = Vec::new();
        pw.serialize_compressed(&mut le_buf).unwrap();
        assert_eq!(le_buf.len(), pw.compressed_size());
        assert_eq!(
            RLNPartialWitnessInput::deserialize_compressed(le_buf.as_slice()).unwrap(),
            pw
        );
    }

    #[test]
    fn test_partial_witness_truncated_rejected() {
        let pw = make_partial_witness();

        let mut be_buf = Vec::new();
        pw.serialize(&mut be_buf).unwrap();
        assert!(RLNPartialWitnessInput::deserialize(&be_buf[..be_buf.len() - 1]).is_err());

        let mut le_buf = Vec::new();
        pw.serialize_compressed(&mut le_buf).unwrap();
        assert!(
            RLNPartialWitnessInput::deserialize_compressed(&le_buf[..le_buf.len() - 1]).is_err()
        );
    }

    #[test]
    fn test_partial_witness_extra_bytes_accepted() {
        let pw = make_partial_witness();

        let mut be_buf = Vec::new();
        pw.serialize(&mut be_buf).unwrap();
        be_buf.push(0xff);
        assert!(RLNPartialWitnessInput::deserialize(be_buf.as_slice()).is_ok());

        let mut le_buf = Vec::new();
        pw.serialize_compressed(&mut le_buf).unwrap();
        le_buf.push(0xff);
        assert!(RLNPartialWitnessInput::deserialize_compressed(le_buf.as_slice()).is_ok());
    }

    #[test]
    fn test_proof_values_single_roundtrip() {
        let pv = make_proof_values_single();

        let mut be_buf = Vec::new();
        pv.serialize(&mut be_buf).unwrap();
        assert_eq!(be_buf[0], 0, "Single variant tag byte");
        assert_eq!(be_buf.len(), CanonicalSerializeBE::serialized_size(&pv));
        assert_eq!(RLNProofValues::deserialize(be_buf.as_slice()).unwrap(), pv);

        let mut le_buf = Vec::new();
        pv.serialize_compressed(&mut le_buf).unwrap();
        assert_eq!(le_buf[0], 0, "Single variant tag byte");
        assert_eq!(le_buf.len(), pv.compressed_size());
        assert_eq!(
            RLNProofValues::deserialize_compressed(le_buf.as_slice()).unwrap(),
            pv
        );
    }

    #[test]
    fn test_proof_values_multi_roundtrip() {
        let pv = make_proof_values_multi();

        let mut be_buf = Vec::new();
        pv.serialize(&mut be_buf).unwrap();
        assert_eq!(be_buf[0], 1, "Multi variant tag byte");
        assert_eq!(be_buf.len(), CanonicalSerializeBE::serialized_size(&pv));
        assert_eq!(RLNProofValues::deserialize(be_buf.as_slice()).unwrap(), pv);

        let mut le_buf = Vec::new();
        pv.serialize_compressed(&mut le_buf).unwrap();
        assert_eq!(le_buf[0], 1, "Multi variant tag byte");
        assert_eq!(le_buf.len(), pv.compressed_size());
        assert_eq!(
            RLNProofValues::deserialize_compressed(le_buf.as_slice()).unwrap(),
            pv
        );
    }

    #[test]
    fn test_proof_values_le_uncompressed_roundtrip() {
        for pv in [make_proof_values_single(), make_proof_values_multi()] {
            let mut buf = Vec::new();
            pv.serialize_uncompressed(&mut buf).unwrap();
            let deser = RLNProofValues::deserialize_uncompressed(buf.as_slice()).unwrap();
            assert_eq!(pv, deser);
            assert_eq!(pv.uncompressed_size(), buf.len());
        }
    }

    #[test]
    fn test_proof_values_invalid_tag_rejected() {
        let pv = make_proof_values_multi();

        let mut be_buf = Vec::new();
        pv.serialize(&mut be_buf).unwrap();
        be_buf[0] = 99; // unknown tag
        assert!(RLNProofValues::deserialize(be_buf.as_slice()).is_err());

        let mut le_buf = Vec::new();
        pv.serialize_compressed(&mut le_buf).unwrap();
        le_buf[0] = 99; // unknown tag
        assert!(RLNProofValues::deserialize_compressed(le_buf.as_slice()).is_err());
    }

    #[test]
    fn test_proof_values_truncated_rejected() {
        for pv in [make_proof_values_single(), make_proof_values_multi()] {
            let mut be_buf = Vec::new();
            pv.serialize(&mut be_buf).unwrap();
            assert!(RLNProofValues::deserialize(&be_buf[..be_buf.len() - 1]).is_err());

            let mut le_buf = Vec::new();
            pv.serialize_compressed(&mut le_buf).unwrap();
            assert!(RLNProofValues::deserialize_compressed(&le_buf[..le_buf.len() - 1]).is_err());
        }
    }

    #[test]
    fn test_proof_values_extra_bytes_accepted() {
        for pv in [make_proof_values_single(), make_proof_values_multi()] {
            let mut be_buf = Vec::new();
            pv.serialize(&mut be_buf).unwrap();
            be_buf.push(0xff);
            assert!(RLNProofValues::deserialize(be_buf.as_slice()).is_ok());

            let mut le_buf = Vec::new();
            pv.serialize_compressed(&mut le_buf).unwrap();
            le_buf.push(0xff);
            assert!(RLNProofValues::deserialize_compressed(le_buf.as_slice()).is_ok());
        }
    }

    #[test]
    fn test_proof_le_compressed_roundtrip() {
        let proof = make_proof();
        let mut buf = Vec::new();
        proof.serialize_compressed(&mut buf).unwrap();
        let deser = Proof::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(proof, deser);
        assert_eq!(proof.compressed_size(), buf.len());
    }

    #[test]
    fn test_partial_proof_le_compressed_roundtrip() {
        let partial = make_partial_proof();
        let mut buf = Vec::new();
        partial.serialize_compressed(&mut buf).unwrap();
        let deser = PartialProof::deserialize_compressed(buf.as_slice()).unwrap();
        assert_eq!(partial, deser);
        assert_eq!(partial.compressed_size(), buf.len());
    }

    #[test]
    fn test_rln_proof_le_roundtrip() {
        for values in [make_proof_values_single(), make_proof_values_multi()] {
            let rln_proof = RLNProof {
                proof: make_proof(),
                values,
            };
            let mut buf = Vec::new();
            rln_proof.serialize_compressed(&mut buf).unwrap();
            let deser = RLNProof::deserialize_compressed(buf.as_slice()).unwrap();
            assert_eq!(rln_proof, deser);
        }
    }

    #[test]
    fn test_rln_proof_mixed_roundtrip_single() {
        let rln_proof = RLNProof {
            proof: make_proof(),
            values: make_proof_values_single(),
        };
        let mut buf = Vec::new();
        CanonicalSerializeMixed::serialize(&rln_proof, &mut buf).unwrap();
        assert_eq!(
            buf.len(),
            CanonicalSerializeMixed::serialized_size(&rln_proof)
        );
        let deser = <RLNProof as CanonicalDeserializeMixed>::deserialize(buf.as_slice()).unwrap();
        assert_eq!(rln_proof, deser);
    }

    #[test]
    fn test_rln_proof_mixed_roundtrip_multi() {
        let rln_proof = RLNProof {
            proof: make_proof(),
            values: make_proof_values_multi(),
        };
        let mut buf = Vec::new();
        CanonicalSerializeMixed::serialize(&rln_proof, &mut buf).unwrap();
        assert_eq!(
            buf.len(),
            CanonicalSerializeMixed::serialized_size(&rln_proof)
        );
        let deser = <RLNProof as CanonicalDeserializeMixed>::deserialize(buf.as_slice()).unwrap();
        assert_eq!(rln_proof, deser);
    }

    #[test]
    fn test_rln_proof_mixed_wire_format() {
        let values = make_proof_values_single();
        let rln_proof = RLNProof {
            proof: make_proof(),
            values: values.clone(),
        };
        let mut mixed_buf = Vec::new();
        CanonicalSerializeMixed::serialize(&rln_proof, &mut mixed_buf).unwrap();

        let proof_le_bytes = {
            let mut b = Vec::new();
            rln_proof.proof.serialize_compressed(&mut b).unwrap();
            b
        };
        let values_be_bytes = {
            let mut b = Vec::new();
            CanonicalSerializeBE::serialize(&values, &mut b).unwrap();
            b
        };

        assert_eq!(
            &mixed_buf[..proof_le_bytes.len()],
            proof_le_bytes.as_slice()
        );
        assert_eq!(
            &mixed_buf[proof_le_bytes.len()..],
            values_be_bytes.as_slice()
        );
    }

    #[test]
    fn test_rln_proof_mixed_truncated_rejected() {
        let rln_proof = RLNProof {
            proof: make_proof(),
            values: make_proof_values_single(),
        };
        let mut buf = Vec::new();
        CanonicalSerializeMixed::serialize(&rln_proof, &mut buf).unwrap();
        assert!(
            <RLNProof as CanonicalDeserializeMixed>::deserialize(&buf[..buf.len() - 1]).is_err()
        );
    }
}
