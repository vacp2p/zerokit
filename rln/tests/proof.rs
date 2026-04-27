#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod test_rlnv3 {
    use rln::{
        circuit::{
            graph_multi_v1, graph_single_v1, zkey_multi_v1, zkey_single_v1, ArkGroth16Backend, Fr,
            DEFAULT_MAX_OUT, DEFAULT_TREE_DEPTH,
        },
        prelude::{
            keygen, RLNWitnessInputMulti, RLNWitnessInputSingle, RLNWitnessInputV3, Stateless,
            RLNV3,
        },
        protocol::RecoverSecret,
        utils::IdSecret,
    };

    fn make_rln_single() -> RLNV3<Stateless, ArkGroth16Backend> {
        RLNV3::<Stateless, ArkGroth16Backend>::new(ArkGroth16Backend::new(
            zkey_single_v1().clone(),
            graph_single_v1().clone(),
        ))
    }

    fn make_rln_multi() -> RLNV3<Stateless, ArkGroth16Backend> {
        RLNV3::<Stateless, ArkGroth16Backend>::new(ArkGroth16Backend::new(
            zkey_multi_v1().clone(),
            graph_multi_v1().clone(),
        ))
    }

    fn make_single_witness(
        identity_secret: IdSecret,
        path_elements: Vec<Fr>,
        message_id: Fr,
        x: Fr,
        external_nullifier: Fr,
    ) -> RLNWitnessInputV3 {
        let depth = path_elements.len();
        RLNWitnessInputV3::Single(RLNWitnessInputSingle::new(
            identity_secret,
            Fr::from(10u64),
            path_elements,
            vec![0u8; depth],
            x,
            external_nullifier,
            message_id,
        ))
    }

    fn make_multi_witness(
        identity_secret: IdSecret,
        path_elements: Vec<Fr>,
        message_ids: Vec<Fr>,
        selector_used: Vec<bool>,
        x: Fr,
        external_nullifier: Fr,
    ) -> RLNWitnessInputV3 {
        let depth = path_elements.len();
        RLNWitnessInputV3::Multi(RLNWitnessInputMulti::new(
            identity_secret,
            Fr::from(10u64),
            path_elements,
            vec![0u8; depth],
            x,
            external_nullifier,
            message_ids,
            selector_used,
        ))
    }

    #[test]
    fn test_rlnv3_stateless_single_generate_and_verify() {
        let (identity_secret, _) = keygen();
        let witness = make_single_witness(
            identity_secret,
            vec![Fr::from(0u64); DEFAULT_TREE_DEPTH],
            Fr::from(1u64),
            Fr::from(42u64),
            Fr::from(100u64),
        );

        let rln = make_rln_single();
        let (proof, values) = rln.generate_proof(witness).unwrap();
        assert!(rln.verify_proof(&proof, &values).unwrap());
    }

    #[test]
    fn test_rlnv3_stateless_multi_generate_and_verify() {
        let (identity_secret, _) = keygen();
        let message_ids: Vec<Fr> = (1..=DEFAULT_MAX_OUT).map(|i| Fr::from(i as u64)).collect();
        let witness = make_multi_witness(
            identity_secret,
            vec![Fr::from(0u64); DEFAULT_TREE_DEPTH],
            message_ids,
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(42u64),
            Fr::from(100u64),
        );

        let rln = make_rln_multi();
        let (proof, values) = rln.generate_proof(witness).unwrap();
        assert!(rln.verify_proof(&proof, &values).unwrap());
    }

    #[test]
    fn test_rlnv3_stateless_recover_secret_single() {
        let (identity_secret, _) = keygen();
        let path = vec![Fr::from(0u64); DEFAULT_TREE_DEPTH];

        let w1 = make_single_witness(
            identity_secret.clone(),
            path.clone(),
            Fr::from(1u64),
            Fr::from(11u64),
            Fr::from(200u64),
        );
        let w2 = make_single_witness(
            identity_secret.clone(),
            path,
            Fr::from(1u64),
            Fr::from(22u64),
            Fr::from(200u64),
        );

        let rln = make_rln_single();
        let (_, v1) = rln.generate_proof(w1).unwrap();
        let (_, v2) = rln.generate_proof(w2).unwrap();

        let recovered = v1.recover_secret(&v2).unwrap();
        assert_eq!(recovered, *identity_secret);
    }

    #[test]
    fn test_rlnv3_stateless_recover_secret_cross_mode() {
        let (identity_secret, _) = keygen();
        let path = vec![Fr::from(0u64); DEFAULT_TREE_DEPTH];
        let external_nullifier = Fr::from(300u64);

        let w_single = make_single_witness(
            identity_secret.clone(),
            path.clone(),
            Fr::from(1u64),
            Fr::from(11u64),
            external_nullifier,
        );
        let message_ids: Vec<Fr> = (1..=DEFAULT_MAX_OUT).map(|i| Fr::from(i as u64)).collect();
        let w_multi = make_multi_witness(
            identity_secret.clone(),
            path,
            message_ids,
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(22u64),
            external_nullifier,
        );

        let rln_single = make_rln_single();
        let rln_multi = make_rln_multi();

        let (_, sv) = rln_single.generate_proof(w_single).unwrap();
        let (_, mv) = rln_multi.generate_proof(w_multi).unwrap();

        assert_eq!(sv.recover_secret(&mv).unwrap(), *identity_secret);
        assert_eq!(mv.recover_secret(&sv).unwrap(), *identity_secret);
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod test {
    use rln::{
        circuit::{
            graph_multi_v1, graph_single_v1, zkey_multi_v1, zkey_single_v1, ArkGroth16Backend, Fr,
            DEFAULT_MAX_OUT, DEFAULT_TREE_DEPTH,
        },
        prelude::{keygen, RLNWitnessInputMulti, RLNWitnessInputSingle, RLNWitnessInputV3},
        protocol::{RLNZkProof, RecoverSecret},
        utils::IdSecret,
    };

    fn make_backend() -> ArkGroth16Backend {
        ArkGroth16Backend::new(zkey_single_v1().clone(), graph_single_v1().clone())
    }

    fn make_multi_backend() -> ArkGroth16Backend {
        ArkGroth16Backend::new(zkey_multi_v1().clone(), graph_multi_v1().clone())
    }

    fn make_multi_witness(
        identity_secret: IdSecret,
        path_elements: Vec<Fr>,
        message_ids: Vec<Fr>,
        selector_used: Vec<bool>,
        x: Fr,
        external_nullifier: Fr,
    ) -> RLNWitnessInputV3 {
        let depth = path_elements.len();
        RLNWitnessInputV3::Multi(RLNWitnessInputMulti::new(
            identity_secret,
            Fr::from(10u64),
            path_elements,
            vec![0u8; depth],
            x,
            external_nullifier,
            message_ids,
            selector_used,
        ))
    }

    fn make_single_witness(
        identity_secret: IdSecret,
        path_elements: Vec<Fr>,
        message_id: Fr,
        x: Fr,
        external_nullifier: Fr,
    ) -> RLNWitnessInputV3 {
        let depth = path_elements.len();
        RLNWitnessInputV3::Single(RLNWitnessInputSingle::new(
            identity_secret,
            Fr::from(10u64),
            path_elements,
            vec![0u8; depth],
            x,
            external_nullifier,
            message_id,
        ))
    }

    #[test]
    fn test_generate_and_verify_single() {
        let (identity_secret, _) = keygen();
        let path_elements = vec![Fr::from(0u64); DEFAULT_TREE_DEPTH];
        let witness = make_single_witness(
            identity_secret,
            path_elements,
            Fr::from(1u64),
            Fr::from(42u64),
            Fr::from(100u64),
        );

        let backend = make_backend();
        let (proof, values) = backend.generate_proof(witness).unwrap();
        let verified = backend.verify(&proof, &values).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_wrong_proof_fails_verification() {
        let (id1, _) = keygen();
        let (id2, _) = keygen();
        let path_elements = vec![Fr::from(0u64); DEFAULT_TREE_DEPTH];

        let w1 = make_single_witness(
            id1,
            path_elements.clone(),
            Fr::from(1u64),
            Fr::from(42u64),
            Fr::from(100u64),
        );
        let w2 = make_single_witness(
            id2,
            path_elements,
            Fr::from(1u64),
            Fr::from(99u64),
            Fr::from(100u64),
        );

        let backend = make_backend();
        let (proof1, _) = backend.generate_proof(w1).unwrap();
        let (_, values2) = backend.generate_proof(w2).unwrap();

        // proof1 with values2 — should not verify
        let verified = backend.verify(&proof1, &values2).unwrap();
        assert!(!verified);
    }

    #[test]
    fn test_recover_secret_single_x_single() {
        let (identity_secret, _) = keygen();
        let path_elements = vec![Fr::from(0u64); DEFAULT_TREE_DEPTH];

        // Two proofs: same identity, same epoch+message_id (same nullifier), different signal x
        let w1 = make_single_witness(
            identity_secret.clone(),
            path_elements.clone(),
            Fr::from(1u64),
            Fr::from(11u64), // x1
            Fr::from(200u64),
        );
        let w2 = make_single_witness(
            identity_secret.clone(),
            path_elements,
            Fr::from(1u64),
            Fr::from(22u64), // x2 ≠ x1
            Fr::from(200u64),
        );

        let backend = make_backend();
        let (_, values1) = backend.generate_proof(w1).unwrap();
        let (_, values2) = backend.generate_proof(w2).unwrap();

        let recovered = values1.recover_secret(&values2).unwrap();
        assert_eq!(recovered, *identity_secret);
    }

    #[test]
    fn test_recover_secret_mismatched_nullifier_fails() {
        let (id, _) = keygen();
        let path_elements = vec![Fr::from(0u64); DEFAULT_TREE_DEPTH];

        // Different message_ids → different nullifiers → can't recover
        let w1 = make_single_witness(
            id.clone(),
            path_elements.clone(),
            Fr::from(1u64),
            Fr::from(11u64),
            Fr::from(200u64),
        );
        let w2 = make_single_witness(
            id,
            path_elements,
            Fr::from(2u64),
            Fr::from(22u64),
            Fr::from(200u64),
        );

        let backend = make_backend();
        let (_, v1) = backend.generate_proof(w1).unwrap();
        let (_, v2) = backend.generate_proof(w2).unwrap();

        assert!(v1.recover_secret(&v2).is_err());
    }

    #[test]
    fn test_tree_depth_mismatch_fails() {
        let (id, _) = keygen();
        // path_elements has wrong depth
        let path_elements = vec![Fr::from(0u64); DEFAULT_TREE_DEPTH + 1];
        let witness = make_single_witness(
            id,
            path_elements,
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(1u64),
        );

        let backend = make_backend();
        assert!(backend.generate_proof(witness).is_err());
    }

    #[test]
    fn test_generate_and_verify_multi() {
        let (identity_secret, _) = keygen();
        let path_elements = vec![Fr::from(0u64); DEFAULT_TREE_DEPTH];
        let message_ids: Vec<Fr> = (1..=DEFAULT_MAX_OUT).map(|i| Fr::from(i as u64)).collect();
        let selector_used = vec![true; DEFAULT_MAX_OUT];

        let witness = make_multi_witness(
            identity_secret,
            path_elements,
            message_ids,
            selector_used,
            Fr::from(42u64),
            Fr::from(100u64),
        );

        let backend = make_multi_backend();
        let (proof, values) = backend.generate_proof(witness).unwrap();
        let verified = backend.verify(&proof, &values).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_generate_and_verify_multi_partial_selector() {
        // Verifies that proofs with only some slots active (selector_used has false entries)
        // generate and verify correctly. This catches selector-multiplication bugs in proof values.
        let (identity_secret, _) = keygen();
        let path_elements = vec![Fr::from(0u64); DEFAULT_TREE_DEPTH];
        // Only slots 0 and 2 active (out of 4)
        let message_ids: Vec<Fr> = (1..=DEFAULT_MAX_OUT).map(|i| Fr::from(i as u64)).collect();
        let selector_used = vec![true, false, true, false];

        let witness = make_multi_witness(
            identity_secret,
            path_elements,
            message_ids,
            selector_used,
            Fr::from(42u64),
            Fr::from(100u64),
        );

        let backend = make_multi_backend();
        let (proof, values) = backend.generate_proof(witness).unwrap();
        let verified = backend.verify(&proof, &values).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_recover_secret_multi_x_multi() {
        let (identity_secret, _) = keygen();
        let path_elements = vec![Fr::from(0u64); DEFAULT_TREE_DEPTH];

        // Two multi proofs: same identity + external_nullifier, same message_id[0], different x
        let message_ids: Vec<Fr> = (1..=DEFAULT_MAX_OUT).map(|i| Fr::from(i as u64)).collect();
        let selector_used = vec![true; DEFAULT_MAX_OUT];

        let w1 = make_multi_witness(
            identity_secret.clone(),
            path_elements.clone(),
            message_ids.clone(),
            selector_used.clone(),
            Fr::from(11u64), // x1
            Fr::from(200u64),
        );
        let w2 = make_multi_witness(
            identity_secret.clone(),
            path_elements,
            message_ids,
            selector_used,
            Fr::from(22u64), // x2 ≠ x1
            Fr::from(200u64),
        );

        let backend = make_multi_backend();
        let (_, values1) = backend.generate_proof(w1).unwrap();
        let (_, values2) = backend.generate_proof(w2).unwrap();

        let recovered = values1.recover_secret(&values2).unwrap();
        assert_eq!(recovered, *identity_secret);
    }

    #[test]
    fn test_recover_secret_single_x_multi() {
        let (identity_secret, _) = keygen();
        let path_elements = vec![Fr::from(0u64); DEFAULT_TREE_DEPTH];
        let external_nullifier = Fr::from(300u64);

        // Single proof using message_id=1
        let w_single = make_single_witness(
            identity_secret.clone(),
            path_elements.clone(),
            Fr::from(1u64), // message_id
            Fr::from(11u64),
            external_nullifier,
        );

        // Multi proof with message_ids including 1, same external_nullifier, different x
        let message_ids: Vec<Fr> = (1..=DEFAULT_MAX_OUT).map(|i| Fr::from(i as u64)).collect();
        let selector_used = vec![true; DEFAULT_MAX_OUT];
        let w_multi = make_multi_witness(
            identity_secret.clone(),
            path_elements,
            message_ids,
            selector_used,
            Fr::from(22u64),
            external_nullifier,
        );

        let single_backend = make_backend();
        let multi_backend = make_multi_backend();

        let (_, single_values) = single_backend.generate_proof(w_single).unwrap();
        let (_, multi_values) = multi_backend.generate_proof(w_multi).unwrap();

        // single × multi
        let recovered = single_values.recover_secret(&multi_values).unwrap();
        assert_eq!(recovered, *identity_secret);

        // multi × single (symmetric)
        let recovered2 = multi_values.recover_secret(&single_values).unwrap();
        assert_eq!(recovered2, *identity_secret);
    }

    #[test]
    fn test_recover_secret_multi_mismatched_nullifier_fails() {
        let (id, _) = keygen();
        let path_elements = vec![Fr::from(0u64); DEFAULT_TREE_DEPTH];

        // Two multi proofs with non-overlapping message_ids
        let message_ids1: Vec<Fr> = (1..=DEFAULT_MAX_OUT).map(|i| Fr::from(i as u64)).collect();
        let message_ids2: Vec<Fr> = (1..=DEFAULT_MAX_OUT)
            .map(|i| Fr::from((i + 100) as u64))
            .collect();
        let selector_used = vec![true; DEFAULT_MAX_OUT];

        let w1 = make_multi_witness(
            id.clone(),
            path_elements.clone(),
            message_ids1,
            selector_used.clone(),
            Fr::from(11u64),
            Fr::from(200u64),
        );
        let w2 = make_multi_witness(
            id,
            path_elements,
            message_ids2,
            selector_used,
            Fr::from(22u64),
            Fr::from(200u64),
        );

        let backend = make_multi_backend();
        let (_, v1) = backend.generate_proof(w1).unwrap();
        let (_, v2) = backend.generate_proof(w2).unwrap();

        assert!(v1.recover_secret(&v2).is_err());
    }
}
