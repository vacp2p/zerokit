#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod test {
    use rln::prelude::*;

    fn make_rln(zkey: &Zkey, graph: &Graph) -> RLNV3<Stateless, ArkGroth16Backend> {
        RLNV3::<Stateless, ArkGroth16Backend>::new(ArkGroth16Backend::new(
            zkey.clone(),
            graph.clone(),
        ))
    }

    fn make_backend(zkey: &Zkey, graph: &Graph) -> ArkGroth16Backend {
        ArkGroth16Backend::new(zkey.clone(), graph.clone())
    }

    fn single_witness(
        id: IdSecret,
        path_elements: Vec<Fr>,
        message_id: Fr,
        x: Fr,
        external_nullifier: Fr,
    ) -> RLNWitnessInputV3 {
        let depth = path_elements.len();
        RLNWitnessInputV3::Single(
            RLNWitnessInputSingle::new(
                id,
                Fr::from(10u64),
                path_elements,
                vec![0u8; depth],
                x,
                external_nullifier,
                message_id,
            )
            .unwrap(),
        )
    }

    fn multi_witness(
        id: IdSecret,
        path_elements: Vec<Fr>,
        message_ids: Vec<Fr>,
        selector_used: Vec<bool>,
        x: Fr,
        external_nullifier: Fr,
    ) -> RLNWitnessInputV3 {
        let depth = path_elements.len();
        RLNWitnessInputV3::Multi(
            RLNWitnessInputMulti::new(
                id,
                Fr::from(10u64),
                path_elements,
                vec![0u8; depth],
                x,
                external_nullifier,
                message_ids,
                selector_used,
            )
            .unwrap(),
        )
    }

    fn default_path() -> Vec<Fr> {
        vec![Fr::from(0u64); DEFAULT_TREE_DEPTH]
    }

    fn default_message_ids() -> Vec<Fr> {
        (1..=DEFAULT_MAX_OUT).map(|i| Fr::from(i as u64)).collect()
    }

    #[test]
    fn test_generate_and_verify_single() {
        let backend = make_backend(zkey_single_v1(), graph_single_v1());
        let witness = single_witness(
            keygen().0,
            default_path(),
            Fr::from(1u64),
            Fr::from(42u64),
            Fr::from(100u64),
        );
        let (proof, vals) = backend.generate_proof(&witness).unwrap();
        assert!(backend.verify(&proof, &vals).unwrap());
    }

    #[test]
    fn test_wrong_proof_fails_verification() {
        let backend = make_backend(zkey_single_v1(), graph_single_v1());
        let w1 = single_witness(
            keygen().0,
            default_path(),
            Fr::from(1u64),
            Fr::from(42u64),
            Fr::from(100u64),
        );
        let w2 = single_witness(
            keygen().0,
            default_path(),
            Fr::from(1u64),
            Fr::from(99u64),
            Fr::from(100u64),
        );
        let (proof1, _) = backend.generate_proof(&w1).unwrap();
        let vals2 = RLNProofValuesV3::from(&w2);
        assert!(!backend.verify(&proof1, &vals2).unwrap());
    }

    #[test]
    fn test_tree_depth_mismatch_fails() {
        let backend = make_backend(zkey_single_v1(), graph_single_v1());
        let witness = single_witness(
            keygen().0,
            vec![Fr::from(0u64); DEFAULT_TREE_DEPTH + 1],
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(1u64),
        );
        assert!(backend.generate_proof(&witness).is_err());
    }

    #[test]
    fn test_generate_and_verify_multi() {
        let backend = make_backend(zkey_multi_v1(), graph_multi_v1());
        let witness = multi_witness(
            keygen().0,
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(42u64),
            Fr::from(100u64),
        );
        let (proof, vals) = backend.generate_proof(&witness).unwrap();
        assert!(backend.verify(&proof, &vals).unwrap());
    }

    #[test]
    fn test_generate_and_verify_multi_partial_selector() {
        let backend = make_backend(zkey_multi_v1(), graph_multi_v1());
        let witness = multi_witness(
            keygen().0,
            default_path(),
            default_message_ids(),
            vec![true, false, true, false],
            Fr::from(42u64),
            Fr::from(100u64),
        );
        let (proof, vals) = backend.generate_proof(&witness).unwrap();
        assert!(backend.verify(&proof, &vals).unwrap());
    }

    #[test]
    fn test_multi_message_ids_wrong_count_fails() {
        let backend = make_backend(zkey_multi_v1(), graph_multi_v1());
        let witness = multi_witness(
            keygen().0,
            default_path(),
            vec![Fr::from(1u64), Fr::from(2u64)],
            vec![true, true],
            Fr::from(42u64),
            Fr::from(100u64),
        );
        assert!(backend.generate_proof(&witness).is_err());
    }

    #[test]
    fn test_recover_secret_single_x_single() {
        let (id, _) = keygen();
        let v1 = RLNProofValuesV3::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(11u64),
            Fr::from(200u64),
        ));
        let v2 = RLNProofValuesV3::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(22u64),
            Fr::from(200u64),
        ));
        assert_eq!(*v1.recover_secret(&v2).unwrap(), *id);
    }

    #[test]
    fn test_recover_secret_mismatched_nullifier_fails() {
        let (id, _) = keygen();
        let v1 = RLNProofValuesV3::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(11u64),
            Fr::from(200u64),
        ));
        let v2 = RLNProofValuesV3::from(&single_witness(
            id,
            default_path(),
            Fr::from(2u64),
            Fr::from(22u64),
            Fr::from(200u64),
        ));
        assert!(v1.recover_secret(&v2).is_err());
    }

    #[test]
    fn test_recover_secret_multi_x_multi() {
        let (id, _) = keygen();
        let v1 = RLNProofValuesV3::from(&multi_witness(
            id.clone(),
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(11u64),
            Fr::from(200u64),
        ));
        let v2 = RLNProofValuesV3::from(&multi_witness(
            id.clone(),
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(22u64),
            Fr::from(200u64),
        ));
        assert_eq!(*v1.recover_secret(&v2).unwrap(), *id);
    }

    #[test]
    fn test_recover_secret_multi_mismatched_nullifier_fails() {
        let (id, _) = keygen();
        let ids2: Vec<Fr> = (1..=DEFAULT_MAX_OUT)
            .map(|i| Fr::from((i + DEFAULT_MAX_OUT) as u64))
            .collect();
        let v1 = RLNProofValuesV3::from(&multi_witness(
            id.clone(),
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(11u64),
            Fr::from(200u64),
        ));
        let v2 = RLNProofValuesV3::from(&multi_witness(
            id,
            default_path(),
            ids2,
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(22u64),
            Fr::from(200u64),
        ));
        assert!(v1.recover_secret(&v2).is_err());
    }

    #[test]
    fn test_recover_secret_single_x_multi() {
        let (id, _) = keygen();
        let ext = Fr::from(300u64);
        let sv = RLNProofValuesV3::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(11u64),
            ext,
        ));
        let mv = RLNProofValuesV3::from(&multi_witness(
            id.clone(),
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(22u64),
            ext,
        ));
        assert_eq!(*sv.recover_secret(&mv).unwrap(), *id);
        assert_eq!(*mv.recover_secret(&sv).unwrap(), *id);
    }

    #[test]
    fn test_rlnv3_stateless_single_generate_and_verify() {
        let rln = make_rln(zkey_single_v1(), graph_single_v1());
        let witness = single_witness(
            keygen().0,
            default_path(),
            Fr::from(1u64),
            Fr::from(42u64),
            Fr::from(100u64),
        );
        let (proof, vals) = rln.generate_proof(&witness).unwrap();
        assert!(rln.verify(&proof, &vals).unwrap());
    }

    #[test]
    fn test_rlnv3_stateless_multi_generate_and_verify() {
        let rln = make_rln(zkey_multi_v1(), graph_multi_v1());
        let witness = multi_witness(
            keygen().0,
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(42u64),
            Fr::from(100u64),
        );
        let (proof, vals) = rln.generate_proof(&witness).unwrap();
        assert!(rln.verify(&proof, &vals).unwrap());
    }

    #[test]
    fn test_rlnv3_stateless_recover_secret_single() {
        let (id, _) = keygen();
        let v1 = RLNProofValuesV3::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(11u64),
            Fr::from(200u64),
        ));
        let v2 = RLNProofValuesV3::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(22u64),
            Fr::from(200u64),
        ));
        assert_eq!(*v1.recover_secret(&v2).unwrap(), *id);
    }

    #[test]
    fn test_rlnv3_stateless_recover_secret_cross_mode() {
        let (id, _) = keygen();
        let ext = Fr::from(300u64);
        let sv = RLNProofValuesV3::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(11u64),
            ext,
        ));
        let mv = RLNProofValuesV3::from(&multi_witness(
            id.clone(),
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(22u64),
            ext,
        ));
        assert_eq!(*sv.recover_secret(&mv).unwrap(), *id);
        assert_eq!(*mv.recover_secret(&sv).unwrap(), *id);
    }

    #[test]
    fn test_v3_partial_and_finish_single() {
        let rln = make_rln(zkey_single_v1(), graph_single_v1());
        let (id, _) = keygen();
        let witness = single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(42u64),
            Fr::from(100u64),
        );
        let partial = RLNPartialWitnessInputV3::new(
            id,
            Fr::from(10u64),
            default_path(),
            vec![0u8; DEFAULT_TREE_DEPTH],
        )
        .unwrap();
        let partial_proof = rln.generate_partial_proof(&partial).unwrap();
        let (proof, vals) = rln.finish_proof(&partial_proof, &witness).unwrap();
        assert!(rln.verify(&proof, &vals).unwrap());
    }

    #[test]
    fn test_v3_partial_and_finish_multi() {
        let rln = make_rln(zkey_multi_v1(), graph_multi_v1());
        let (id, _) = keygen();
        let witness = multi_witness(
            id.clone(),
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(42u64),
            Fr::from(100u64),
        );
        let partial = RLNPartialWitnessInputV3::new(
            id,
            Fr::from(10u64),
            default_path(),
            vec![0u8; DEFAULT_TREE_DEPTH],
        )
        .unwrap();
        let partial_proof = rln.generate_partial_proof(&partial).unwrap();
        let (proof, vals) = rln.finish_proof(&partial_proof, &witness).unwrap();
        assert!(rln.verify(&proof, &vals).unwrap());
    }

    #[test]
    fn test_v3_partial_and_finish_verifies() {
        let rln = make_rln(zkey_single_v1(), graph_single_v1());
        let (id, _) = keygen();
        let witness = single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(55u64),
            Fr::from(999u64),
        );
        let partial = RLNPartialWitnessInputV3::new(
            id,
            Fr::from(10u64),
            default_path(),
            vec![0u8; DEFAULT_TREE_DEPTH],
        )
        .unwrap();
        let partial_proof = rln.generate_partial_proof(&partial).unwrap();
        let (proof, vals) = rln.finish_proof(&partial_proof, &witness).unwrap();
        assert!(rln.verify(&proof, &vals).unwrap());
    }

    #[test]
    fn test_partial_witness_depth_mismatch_fails() {
        let rln = make_rln(zkey_single_v1(), graph_single_v1());
        let (id, _) = keygen();
        let partial = RLNPartialWitnessInputV3::new(
            id,
            Fr::from(10u64),
            vec![Fr::from(0u64); DEFAULT_TREE_DEPTH + 1],
            vec![0u8; DEFAULT_TREE_DEPTH + 1],
        )
        .unwrap();
        assert!(rln.generate_partial_proof(&partial).is_err());
    }

    #[test]
    fn test_finish_proof_wrong_witness_depth_fails() {
        let rln = make_rln(zkey_single_v1(), graph_single_v1());
        let (id, _) = keygen();
        let partial = RLNPartialWitnessInputV3::new(
            id.clone(),
            Fr::from(10u64),
            default_path(),
            vec![0u8; DEFAULT_TREE_DEPTH],
        )
        .unwrap();
        let partial_proof = rln.generate_partial_proof(&partial).unwrap();
        let bad_witness = single_witness(
            id,
            vec![Fr::from(0u64); DEFAULT_TREE_DEPTH + 1],
            Fr::from(1u64),
            Fr::from(42u64),
            Fr::from(100u64),
        );
        assert!(rln.finish_proof(&partial_proof, &bad_witness).is_err());
    }

    #[test]
    fn test_v3_verify_with_roots_empty_skips_root_check() {
        let rln = make_rln(zkey_single_v1(), graph_single_v1());
        let x = Fr::from(42u64);
        let witness = single_witness(
            keygen().0,
            default_path(),
            Fr::from(1u64),
            x,
            Fr::from(100u64),
        );
        let (proof, vals) = rln.generate_proof(&witness).unwrap();
        assert!(rln.verify_with_roots(&proof, &vals, &x, &[]).unwrap());
    }

    #[test]
    fn test_v3_verify_with_roots_correct_root_passes() {
        let rln = make_rln(zkey_single_v1(), graph_single_v1());
        let x = Fr::from(42u64);
        let witness = single_witness(
            keygen().0,
            default_path(),
            Fr::from(1u64),
            x,
            Fr::from(100u64),
        );
        let (proof, vals) = rln.generate_proof(&witness).unwrap();
        let root = vals.root();
        assert!(rln.verify_with_roots(&proof, &vals, &x, &[root]).unwrap());
    }

    #[test]
    fn test_v3_verify_with_roots_wrong_root_fails() {
        let rln = make_rln(zkey_single_v1(), graph_single_v1());
        let x = Fr::from(42u64);
        let witness = single_witness(
            keygen().0,
            default_path(),
            Fr::from(1u64),
            x,
            Fr::from(100u64),
        );
        let (proof, vals) = rln.generate_proof(&witness).unwrap();
        assert!(matches!(
            rln.verify_with_roots(&proof, &vals, &x, &[Fr::from(9999u64)]),
            Err(RLNErrorV3::Verify(VerifyError::InvalidRoot))
        ));
    }

    #[test]
    fn test_v3_verify_with_roots_wrong_signal_fails() {
        let rln = make_rln(zkey_single_v1(), graph_single_v1());
        let x = Fr::from(42u64);
        let witness = single_witness(
            keygen().0,
            default_path(),
            Fr::from(1u64),
            x,
            Fr::from(100u64),
        );
        let (proof, vals) = rln.generate_proof(&witness).unwrap();
        assert!(matches!(
            rln.verify_with_roots(&proof, &vals, &Fr::from(9999u64), &[]),
            Err(RLNErrorV3::Verify(VerifyError::InvalidSignal))
        ));
    }

    #[test]
    fn test_v3_verify_with_roots_multi_correct_root_passes() {
        let rln = make_rln(zkey_multi_v1(), graph_multi_v1());
        let x = Fr::from(42u64);
        let witness = multi_witness(
            keygen().0,
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            x,
            Fr::from(100u64),
        );
        let (proof, vals) = rln.generate_proof(&witness).unwrap();
        let root = vals.root();
        assert!(rln.verify_with_roots(&proof, &vals, &x, &[root]).unwrap());
    }

    #[test]
    fn test_v3_verify_with_roots_multi_wrong_root_fails() {
        let rln = make_rln(zkey_multi_v1(), graph_multi_v1());
        let x = Fr::from(42u64);
        let witness = multi_witness(
            keygen().0,
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            x,
            Fr::from(100u64),
        );
        let (proof, vals) = rln.generate_proof(&witness).unwrap();
        assert!(matches!(
            rln.verify_with_roots(&proof, &vals, &x, &[Fr::from(9999u64)]),
            Err(RLNErrorV3::Verify(VerifyError::InvalidRoot))
        ));
    }

    #[test]
    fn test_v3_recover_id_secret_single() {
        let (id, _) = keygen();
        let ext = Fr::from(100u64);
        let v1 = RLNProofValuesV3::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(11u64),
            ext,
        ));
        let v2 = RLNProofValuesV3::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(22u64),
            ext,
        ));
        assert_eq!(*v1.recover_secret(&v2).unwrap(), *id);
    }

    #[test]
    fn test_v3_recover_id_secret_multi() {
        let (id, _) = keygen();
        let ext = Fr::from(100u64);
        let v1 = RLNProofValuesV3::from(&multi_witness(
            id.clone(),
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(11u64),
            ext,
        ));
        let v2 = RLNProofValuesV3::from(&multi_witness(
            id.clone(),
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(22u64),
            ext,
        ));
        assert_eq!(*v1.recover_secret(&v2).unwrap(), *id);
    }

    #[test]
    fn test_v3_recover_id_secret_cross_mode() {
        let (id, _) = keygen();
        let ext = Fr::from(300u64);
        let sv = RLNProofValuesV3::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(11u64),
            ext,
        ));
        let mv = RLNProofValuesV3::from(&multi_witness(
            id.clone(),
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(22u64),
            ext,
        ));
        assert_eq!(*sv.recover_secret(&mv).unwrap(), *id);
        assert_eq!(*mv.recover_secret(&sv).unwrap(), *id);
    }

    #[test]
    fn test_v3_new_with_params_invalid_zkey() {
        assert!(matches!(
            RLNV3::<Stateless, ArkGroth16Backend>::new_with_params(vec![], vec![1, 2, 3]),
            Err(InitErrorV3::ZKey(_))
        ));
    }

    #[test]
    fn test_v3_new_with_params_invalid_graph() {
        let valid_zkey = include_bytes!("../resources/tree_depth_20/rln_final.arkzkey").to_vec();
        assert!(matches!(
            RLNV3::<Stateless, ArkGroth16Backend>::new_with_params(valid_zkey, vec![0u8; 50],),
            Err(InitErrorV3::Graph(_))
        ));
    }
}
