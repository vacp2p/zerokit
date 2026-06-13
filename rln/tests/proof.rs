#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod test {
    use std::sync::Arc;

    use rln::prelude::*;
    use zeroize::Zeroize;
    use zerokit_utils::merkle_tree::{FullMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree};

    fn make_backend(zkey: &Arc<Zkey>, graph: &Arc<Graph>) -> ArkGroth16Backend {
        ArkGroth16Backend::new(zkey.clone(), graph.clone())
    }

    fn make_rln(zkey: &Arc<Zkey>, graph: &Arc<Graph>) -> RLN<Stateless, ArkGroth16Backend> {
        RLNBuilder::stateless()
            .graph(graph.clone())
            .zkey(zkey.clone())
            .build()
    }

    fn default_path() -> Vec<Fr> {
        vec![Fr::from(0u64); DEFAULT_TREE_DEPTH]
    }

    fn default_message_ids() -> Vec<Fr> {
        (1..=DEFAULT_MAX_OUT).map(|i| Fr::from(i as u64)).collect()
    }

    fn single_witness(
        id: IdSecret,
        path_elements: Vec<Fr>,
        message_id: Fr,
        x: Fr,
        external_nullifier: Fr,
    ) -> RLNWitnessInput {
        let depth = path_elements.len();
        RLNWitnessInput::new_single()
            .identity_secret(id)
            .user_message_limit(Fr::from(10u64))
            .path_elements(path_elements)
            .identity_path_index(vec![0u8; depth])
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(message_id)
            .build()
            .unwrap()
    }

    fn multi_witness(
        id: IdSecret,
        path_elements: Vec<Fr>,
        message_ids: Vec<Fr>,
        selector_used: Vec<bool>,
        x: Fr,
        external_nullifier: Fr,
    ) -> RLNWitnessInput {
        let depth = path_elements.len();
        RLNWitnessInput::new_multi()
            .identity_secret(id)
            .user_message_limit(Fr::from(10u64))
            .path_elements(path_elements)
            .identity_path_index(vec![0u8; depth])
            .x(x)
            .external_nullifier(external_nullifier)
            .message_ids(message_ids)
            .selector_used(selector_used)
            .build()
            .unwrap()
    }

    fn fr_from_hex(hex: &str) -> Fr {
        hex.trim_start_matches("0x")
            .chars()
            .fold(Fr::from(0), |acc, c| {
                acc * Fr::from(16) + Fr::from(c.to_digit(16).unwrap())
            })
    }

    fn tree_witness_and_root() -> (RLNWitnessInput, Fr) {
        let leaf_index = 3;
        let (identity_secret, id_commitment) = keygen();
        let user_message_limit = Fr::from(100);
        let rate_commitment = poseidon_hash_pair(id_commitment, user_message_limit);

        let mut tree = FullMerkleTree::<PoseidonHash>::default(DEFAULT_TREE_DEPTH).unwrap();
        tree.set(leaf_index, rate_commitment).unwrap();
        let root = tree.root();

        let merkle_proof = tree.proof(leaf_index).unwrap();

        let x = hash_to_field_le(b"hey hey");
        let epoch = hash_to_field_le(b"test-epoch");
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        let external_nullifier = poseidon_hash_pair(epoch, rln_identifier);

        let witness = RLNWitnessInput::new_single()
            .identity_secret(identity_secret)
            .user_message_limit(user_message_limit)
            .path_elements(merkle_proof.get_path_elements())
            .identity_path_index(merkle_proof.get_path_index())
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(Fr::from(1))
            .build()
            .unwrap();
        (witness, root)
    }

    #[test]
    fn test_generate_and_verify_single() {
        let backend = make_backend(default_zkey_single(), default_graph_single());
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
    fn test_generate_and_verify_multi() {
        let backend = make_backend(default_zkey_multi(), default_graph_multi());
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
        let backend = make_backend(default_zkey_multi(), default_graph_multi());
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
    fn test_wrong_proof_fails_verification() {
        let backend = make_backend(default_zkey_single(), default_graph_single());
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
        let vals2 = RLNProofValues::from(&w2);
        assert!(!backend.verify(&proof1, &vals2).unwrap());
    }

    #[test]
    fn test_rln_generate_and_verify_single() {
        let rln = make_rln(default_zkey_single(), default_graph_single());
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
    fn test_rln_generate_and_verify_multi() {
        let rln = make_rln(default_zkey_multi(), default_graph_multi());
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
    fn test_partial_and_finish_single() {
        let rln = make_rln(default_zkey_single(), default_graph_single());
        let (id, _) = keygen();
        let witness = single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(42u64),
            Fr::from(100u64),
        );
        let partial_witness = RLNPartialWitnessInput::new()
            .identity_secret(id)
            .user_message_limit(Fr::from(10u64))
            .path_elements(default_path())
            .identity_path_index(vec![0u8; DEFAULT_TREE_DEPTH])
            .build()
            .unwrap();
        let partial_proof = rln.generate_partial_proof(&partial_witness).unwrap();
        let (proof, vals) = rln.finish_proof(&partial_proof, &witness).unwrap();
        assert!(rln.verify(&proof, &vals).unwrap());
    }

    #[test]
    fn test_partial_and_finish_multi() {
        let rln = make_rln(default_zkey_multi(), default_graph_multi());
        let (id, _) = keygen();
        let witness = multi_witness(
            id.clone(),
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(42u64),
            Fr::from(100u64),
        );
        let partial_witness = RLNPartialWitnessInput::new()
            .identity_secret(id)
            .user_message_limit(Fr::from(10u64))
            .path_elements(default_path())
            .identity_path_index(vec![0u8; DEFAULT_TREE_DEPTH])
            .build()
            .unwrap();
        let partial_proof = rln.generate_partial_proof(&partial_witness).unwrap();
        let (proof, vals) = rln.finish_proof(&partial_proof, &witness).unwrap();
        assert!(rln.verify(&proof, &vals).unwrap());
    }

    #[test]
    fn test_partial_proof_values_match_full_proof_values() {
        let rln = make_rln(default_zkey_single(), default_graph_single());
        let (id, _) = keygen();
        let witness = single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(42u64),
            Fr::from(100u64),
        );

        let (_proof_full, values_full) = rln.generate_proof(&witness).unwrap();

        let partial_witness = RLNPartialWitnessInput::from(&witness);
        let partial_proof = rln.generate_partial_proof(&partial_witness).unwrap();
        let (_proof_finish, values_finish) = rln.finish_proof(&partial_proof, &witness).unwrap();

        assert_eq!(values_full, values_finish);
    }

    #[test]
    fn test_recover_secret_single() {
        let (id, _) = keygen();
        let v1 = RLNProofValues::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(11u64),
            Fr::from(200u64),
        ));
        let v2 = RLNProofValues::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(22u64),
            Fr::from(200u64),
        ));
        assert_eq!(*v1.recover_secret(&v2).unwrap(), *id);
    }

    #[test]
    fn test_recover_secret_single_mismatched_nullifier_fails() {
        let (id, _) = keygen();
        let v1 = RLNProofValues::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(11u64),
            Fr::from(200u64),
        ));
        let v2 = RLNProofValues::from(&single_witness(
            id,
            default_path(),
            Fr::from(2u64),
            Fr::from(22u64),
            Fr::from(200u64),
        ));
        assert!(v1.recover_secret(&v2).is_err());
    }

    #[test]
    fn test_recover_secret_multi() {
        let (id, _) = keygen();
        let v1 = RLNProofValues::from(&multi_witness(
            id.clone(),
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(11u64),
            Fr::from(200u64),
        ));
        let v2 = RLNProofValues::from(&multi_witness(
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
        let v1 = RLNProofValues::from(&multi_witness(
            id.clone(),
            default_path(),
            default_message_ids(),
            vec![true; DEFAULT_MAX_OUT],
            Fr::from(11u64),
            Fr::from(200u64),
        ));
        let v2 = RLNProofValues::from(&multi_witness(
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
    fn test_recover_secret_cross_mode() {
        let (id, _) = keygen();
        let ext = Fr::from(300u64);
        let sv = RLNProofValues::from(&single_witness(
            id.clone(),
            default_path(),
            Fr::from(1u64),
            Fr::from(11u64),
            ext,
        ));
        let mv = RLNProofValues::from(&multi_witness(
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
    fn test_verify_with_roots_empty_skips_root_check() {
        let rln = make_rln(default_zkey_single(), default_graph_single());
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
    fn test_verify_with_roots_correct_root_passes_single() {
        let rln = make_rln(default_zkey_single(), default_graph_single());
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
    fn test_verify_with_roots_wrong_root_fails_single() {
        let rln = make_rln(default_zkey_single(), default_graph_single());
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
            Err(VerifyProofError::InvalidRoot)
        ));
    }

    #[test]
    fn test_verify_with_roots_wrong_signal_fails_single() {
        let rln = make_rln(default_zkey_single(), default_graph_single());
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
            Err(VerifyProofError::InvalidSignal)
        ));
    }

    #[test]
    fn test_verify_with_roots_correct_root_passes_multi() {
        let rln = make_rln(default_zkey_multi(), default_graph_multi());
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
    fn test_verify_with_roots_wrong_root_fails_multi() {
        let rln = make_rln(default_zkey_multi(), default_graph_multi());
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
            Err(VerifyProofError::InvalidRoot)
        ));
    }

    #[test]
    fn test_merkle_proof_hardcoded() {
        let leaf_index = 3;

        let identity_secret_seed = hash_to_field_le(b"test-merkle-proof");
        let identity_secret = IdSecret::from(&mut identity_secret_seed.clone());
        let mut to_hash = [*identity_secret.clone()];
        let id_commitment = poseidon_hash(&to_hash);
        to_hash[0].zeroize();
        let rate_commitment = poseidon_hash_pair(id_commitment, Fr::from(100));

        let mut tree = FullMerkleTree::<PoseidonHash>::default(DEFAULT_TREE_DEPTH).unwrap();
        tree.set(leaf_index, rate_commitment).unwrap();

        let root = tree.root();
        assert_eq!(
            root,
            ark_ff::BigInt([
                4939322235247991215,
                5110804094006647505,
                4427606543677101242,
                910933464535675827
            ])
            .into()
        );

        let merkle_proof = tree.proof(leaf_index).unwrap();
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        let expected_path_elements: Vec<Fr> = [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
            "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1",
            "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238",
            "0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a",
            "0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55",
            "0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78",
            "0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d",
            "0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61",
            "0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747",
            "0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2",
            "0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636",
            "0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a",
            "0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0",
            "0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c",
            "0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92",
            "0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323",
            "0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992",
            "0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f",
            "0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca",
        ]
        .map(fr_from_hex)
        .to_vec();

        let expected_identity_path_index: Vec<u8> =
            vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(path_elements, expected_path_elements);
        assert_eq!(identity_path_index, expected_identity_path_index);

        assert!(tree.verify(&rate_commitment, &merkle_proof).unwrap());
    }

    #[test]
    fn test_end_to_end_with_tree_witness() {
        let rln = RLNBuilder::stateless().build();
        let (witness, root) = tree_witness_and_root();

        let (proof, proof_values) = rln.generate_proof(&witness).unwrap();
        assert_eq!(proof_values.root(), root);
        assert!(rln.verify(&proof, &proof_values).unwrap());

        let partial_witness = RLNPartialWitnessInput::from(&witness);
        let partial_proof = rln.generate_partial_proof(&partial_witness).unwrap();
        let (finished_proof, finished_values) = rln.finish_proof(&partial_proof, &witness).unwrap();
        assert_eq!(finished_values, proof_values);
        assert!(rln.verify(&finished_proof, &finished_values).unwrap());
    }

    #[test]
    fn test_proof_values_root_matches_merkle_tree_root() {
        let (witness, root) = tree_witness_and_root();
        let proof_values = RLNProofValues::from(&witness);
        assert_eq!(proof_values.root(), root);
    }

    #[test]
    fn test_verify_with_modified_public_values_fails() {
        let rln = RLNBuilder::stateless().build();
        let (witness, _) = tree_witness_and_root();
        let (proof, proof_values) = rln.generate_proof(&witness).unwrap();
        assert!(rln.verify(&proof, &proof_values).unwrap());

        let RLNProofValues::Single(values) = proof_values else {
            panic!("expected single proof values");
        };

        let mutations: Vec<RLNProofValuesSingle> = vec![
            RLNProofValuesSingle {
                root: values.root + Fr::from(1),
                ..values.clone()
            },
            RLNProofValuesSingle {
                x: values.x + Fr::from(1),
                ..values.clone()
            },
            RLNProofValuesSingle {
                external_nullifier: values.external_nullifier + Fr::from(1),
                ..values.clone()
            },
            RLNProofValuesSingle {
                y: values.y + Fr::from(1),
                ..values.clone()
            },
            RLNProofValuesSingle {
                nullifier: values.nullifier + Fr::from(1),
                ..values.clone()
            },
        ];
        for mutated in mutations {
            assert!(!rln
                .verify(&proof, &RLNProofValues::Single(mutated))
                .unwrap());
        }
    }
}
