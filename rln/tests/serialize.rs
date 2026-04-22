#[cfg(test)]
mod test {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use rln::{
        circuit::{Fr, PartialProof, Proof, DEFAULT_TREE_DEPTH, UNCOMPRESSED_PROOF_SIZE},
        prelude::{
            generate_partial_zk_proof, generate_zk_proof, keygen, CanonicalDeserializeBE,
            CanonicalSerializeBE, RLNPartialWitnessInput, RLNPartialWitnessInputV3,
            RLNProofValuesMulti, RLNProofValuesSingle, RLNProofValuesV3, RLNWitnessInput,
            RLNWitnessInputMulti, RLNWitnessInputSingle, RLNWitnessInputV3,
        },
        protocol::{ENUM_TAG_MULTI, ENUM_TAG_SINGLE},
        utils::IdSecret,
    };

    fn make_witness_input_single() -> RLNWitnessInputV3 {
        RLNWitnessInputV3::Single(RLNWitnessInputSingle::new(
            IdSecret::from(&mut Fr::from(42u64)),
            Fr::from(10u64),
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![0u8, 1u8],
            Fr::from(5u64),
            Fr::from(7u64),
            Fr::from(3u64),
        ))
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
        ))
    }

    fn make_partial_witness() -> RLNPartialWitnessInputV3 {
        RLNPartialWitnessInputV3::new(
            IdSecret::from(&mut Fr::from(42u64)),
            Fr::from(10u64),
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![0u8, 1u8],
        )
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
    fn test_proof_be_roundtrip() {
        let proof = make_proof();
        let mut buf = Vec::new();
        CanonicalSerializeBE::serialize(&proof, &mut buf).unwrap();
        assert_eq!(buf.len(), UNCOMPRESSED_PROOF_SIZE);
        let deser = Proof::deserialize(buf.as_slice()).unwrap();
        assert_eq!(proof, deser);
        assert_eq!(
            CanonicalSerializeBE::serialized_size(&proof),
            UNCOMPRESSED_PROOF_SIZE
        );
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
    #[cfg(not(target_arch = "wasm32"))]
    fn test_partial_proof_be_roundtrip() {
        let partial = make_partial_proof();
        let mut buf = Vec::new();
        CanonicalSerializeBE::serialize(&partial, &mut buf).unwrap();
        let deser = PartialProof::deserialize(buf.as_slice()).unwrap();
        assert_eq!(partial, deser);
        assert_eq!(CanonicalSerializeBE::serialized_size(&partial), buf.len());
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
