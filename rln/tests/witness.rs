#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod test {
    use rand::{thread_rng, Rng};
    use rln::prelude::*;

    fn random_merkle_proof(depth: usize) -> RLNMerkleProof {
        let mut rng = thread_rng();
        let mut path_elements = Vec::new();
        let mut identity_path_index = Vec::new();
        for _ in 0..depth {
            path_elements.push(hash_to_field_le(&rng.gen::<[u8; 32]>()));
            identity_path_index.push(rng.gen_range(0..2) as u8);
        }
        RLNMerkleProof::new(path_elements, identity_path_index)
    }

    fn mismatched_merkle_proof(merkle_proof: &RLNMerkleProof) -> RLNMerkleProof {
        RLNMerkleProof::new(
            merkle_proof.path_elements().to_vec(),
            merkle_proof.identity_path_index()[..merkle_proof.identity_path_index().len() - 1]
                .to_vec(),
        )
    }

    #[test]
    fn test_single_witness_validation() {
        let mut rng = thread_rng();
        let identity_secret = SecretFr::rand(&mut rng);
        let user_message_limit = Fr::from(100);
        let merkle_proof = random_merkle_proof(DEFAULT_TREE_DEPTH);
        let x = hash_to_field_le(&rng.gen::<[u8; 32]>());
        let external_nullifier = hash_to_field_le(&rng.gen::<[u8; 32]>());

        // Valid witness input
        let result = RLNWitnessInput::new_single()
            .identity_secret(identity_secret.clone())
            .user_message_limit(user_message_limit)
            .merkle_proof(merkle_proof.clone())
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(Fr::from(50))
            .build();
        assert!(result.is_ok());

        // message_id == user_message_limit fails
        let result = RLNWitnessInput::new_single()
            .identity_secret(identity_secret.clone())
            .user_message_limit(user_message_limit)
            .merkle_proof(merkle_proof.clone())
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(Fr::from(100))
            .build();
        assert!(matches!(
            result,
            Err(WitnessInputSingleError::InvalidMessageId(_, _))
        ));

        // message_id > user_message_limit fails
        let result = RLNWitnessInput::new_single()
            .identity_secret(identity_secret.clone())
            .user_message_limit(user_message_limit)
            .merkle_proof(merkle_proof.clone())
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(Fr::from(150))
            .build();
        assert!(matches!(
            result,
            Err(WitnessInputSingleError::InvalidMessageId(_, _))
        ));

        // user_message_limit == 0 fails
        let result = RLNWitnessInput::new_single()
            .identity_secret(identity_secret.clone())
            .user_message_limit(Fr::from(0))
            .merkle_proof(merkle_proof.clone())
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(Fr::from(0))
            .build();
        assert!(matches!(
            result,
            Err(WitnessInputSingleError::ZeroUserMessageLimit)
        ));

        // path_elements and identity_path_index length mismatch fails
        let result = RLNWitnessInput::new_single()
            .identity_secret(identity_secret)
            .user_message_limit(user_message_limit)
            .merkle_proof(mismatched_merkle_proof(&merkle_proof))
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(Fr::from(50))
            .build();
        assert!(matches!(
            result,
            Err(WitnessInputSingleError::PathLengthMismatch(_, _))
        ));
    }

    #[test]
    fn test_multi_witness_validation() {
        let mut rng = thread_rng();
        let identity_secret = SecretFr::rand(&mut rng);
        let user_message_limit = Fr::from(10);
        let merkle_proof = random_merkle_proof(DEFAULT_TREE_DEPTH);
        let x = hash_to_field_le(&rng.gen::<[u8; 32]>());
        let external_nullifier = hash_to_field_le(&rng.gen::<[u8; 32]>());

        let new_multi = |message_ids: Vec<Fr>,
                         selector_used: Vec<bool>,
                         user_message_limit: Fr|
         -> Result<RLNWitnessInput, WitnessInputMultiError> {
            RLNWitnessInput::new_multi()
                .identity_secret(identity_secret.clone())
                .user_message_limit(user_message_limit)
                .merkle_proof(merkle_proof.clone())
                .x(x)
                .external_nullifier(external_nullifier)
                .message_ids(message_ids)
                .selector_used(selector_used)
                .build()
        };

        // Empty message_ids fails
        assert!(matches!(
            new_multi(vec![], vec![], user_message_limit).unwrap_err(),
            WitnessInputMultiError::EmptyMessageIds
        ));

        // Mismatched selector_used length to message_ids length fails
        assert!(matches!(
            new_multi(
                vec![Fr::from(0), Fr::from(1)],
                vec![true],
                user_message_limit
            )
            .unwrap_err(),
            WitnessInputMultiError::SelectorLengthMismatch(_, _)
        ));

        // Active message_id >= limit fails
        assert!(matches!(
            new_multi(
                vec![Fr::from(0), Fr::from(10)],
                vec![true, true],
                user_message_limit
            )
            .unwrap_err(),
            WitnessInputMultiError::InvalidMessageId(_, _)
        ));

        // Inactive message_id >= limit succeeds
        assert!(new_multi(
            vec![Fr::from(0), Fr::from(10)],
            vec![true, false],
            user_message_limit
        )
        .is_ok());

        // Zero user_message_limit fails
        assert!(matches!(
            new_multi(vec![Fr::from(0)], vec![true], Fr::from(0)).unwrap_err(),
            WitnessInputMultiError::ZeroUserMessageLimit
        ));

        // Duplicate active message_ids fails
        assert!(matches!(
            new_multi(
                vec![Fr::from(5), Fr::from(5), Fr::from(1), Fr::from(2)],
                vec![true, true, false, false],
                user_message_limit
            )
            .unwrap_err(),
            WitnessInputMultiError::DuplicateMessageIds
        ));

        // Duplicate message_ids when inactive succeeds (only active IDs are checked)
        assert!(new_multi(
            vec![Fr::from(0), Fr::from(0), Fr::from(1), Fr::from(2)],
            vec![false, false, true, true],
            user_message_limit
        )
        .is_ok());

        // All selectors false fails
        assert!(matches!(
            new_multi(
                vec![Fr::from(0), Fr::from(1), Fr::from(2), Fr::from(3)],
                vec![false, false, false, false],
                user_message_limit
            )
            .unwrap_err(),
            WitnessInputMultiError::NoActiveSelectorUsed
        ));

        // Valid multi-message witness
        assert!(new_multi(
            vec![Fr::from(0), Fr::from(1), Fr::from(2), Fr::from(3)],
            vec![true, true, false, false],
            user_message_limit
        )
        .is_ok());
    }

    #[test]
    fn test_partial_witness_validation() {
        let mut rng = thread_rng();
        let identity_secret = SecretFr::rand(&mut rng);
        let merkle_proof = random_merkle_proof(DEFAULT_TREE_DEPTH);

        // Valid partial witness
        let result = RLNPartialWitnessInput::new()
            .identity_secret(identity_secret.clone())
            .user_message_limit(Fr::from(10))
            .merkle_proof(merkle_proof.clone())
            .build();
        assert!(result.is_ok());

        // Zero user_message_limit fails
        let result = RLNPartialWitnessInput::new()
            .identity_secret(identity_secret.clone())
            .user_message_limit(Fr::from(0))
            .merkle_proof(merkle_proof.clone())
            .build();
        assert!(matches!(
            result,
            Err(PartialWitnessInputError::ZeroUserMessageLimit)
        ));

        // path_elements and identity_path_index length mismatch fails
        let result = RLNPartialWitnessInput::new()
            .identity_secret(identity_secret)
            .user_message_limit(Fr::from(10))
            .merkle_proof(mismatched_merkle_proof(&merkle_proof))
            .build();
        assert!(matches!(
            result,
            Err(PartialWitnessInputError::PathLengthMismatch(_, _))
        ));
    }

    #[test]
    fn test_witness_tree_depth_mismatch_against_graph_fails() {
        let rln = RLNBuilder::stateless().build();
        let mut rng = thread_rng();
        let witness = RLNWitnessInput::new_single()
            .identity_secret(SecretFr::rand(&mut rng))
            .user_message_limit(Fr::from(10))
            .merkle_proof(random_merkle_proof(DEFAULT_TREE_DEPTH + 1))
            .x(Fr::from(1))
            .external_nullifier(Fr::from(1))
            .message_id(Fr::from(1))
            .build()
            .unwrap();
        assert!(matches!(
            rln.generate_proof(&witness),
            Err(GenerateProofError::PathElementsLengthMismatch(_, _))
        ));
    }

    #[test]
    fn test_multi_witness_on_single_graph_fails() {
        let rln = RLNBuilder::stateless().build();
        let mut rng = thread_rng();
        let witness = RLNWitnessInput::new_multi()
            .identity_secret(SecretFr::rand(&mut rng))
            .user_message_limit(Fr::from(10))
            .merkle_proof(random_merkle_proof(DEFAULT_TREE_DEPTH))
            .x(Fr::from(1))
            .external_nullifier(Fr::from(1))
            .message_ids(vec![Fr::from(1), Fr::from(2)])
            .selector_used(vec![true, true])
            .build()
            .unwrap();
        assert!(matches!(
            rln.generate_proof(&witness),
            Err(GenerateProofError::MessageIdsLengthMismatch(_, _))
        ));
    }

    #[test]
    fn test_multi_witness_wrong_message_ids_count_fails() {
        let rln = RLNBuilder::stateless()
            .graph(default_graph_multi().clone())
            .zkey(default_zkey_multi().clone())
            .build();
        let mut rng = thread_rng();
        let witness = RLNWitnessInput::new_multi()
            .identity_secret(SecretFr::rand(&mut rng))
            .user_message_limit(Fr::from(10))
            .merkle_proof(random_merkle_proof(DEFAULT_TREE_DEPTH))
            .x(Fr::from(42))
            .external_nullifier(Fr::from(100))
            .message_ids(vec![Fr::from(1), Fr::from(2)])
            .selector_used(vec![true, true])
            .build()
            .unwrap();
        assert!(matches!(
            rln.generate_proof(&witness),
            Err(GenerateProofError::MessageIdsLengthMismatch(_, _))
        ));
    }

    #[test]
    fn test_partial_witness_tree_depth_mismatch_against_graph_fails() {
        let rln = RLNBuilder::stateless().build();
        let mut rng = thread_rng();
        let partial_witness = RLNPartialWitnessInput::new()
            .identity_secret(SecretFr::rand(&mut rng))
            .user_message_limit(Fr::from(10))
            .merkle_proof(random_merkle_proof(DEFAULT_TREE_DEPTH + 1))
            .build()
            .unwrap();
        assert!(rln.generate_partial_proof(&partial_witness).is_err());
    }

    #[test]
    fn test_finish_proof_wrong_witness_depth_fails() {
        let rln = RLNBuilder::stateless().build();
        let mut rng = thread_rng();
        let identity_secret = SecretFr::rand(&mut rng);
        let partial_witness = RLNPartialWitnessInput::new()
            .identity_secret(identity_secret.clone())
            .user_message_limit(Fr::from(10))
            .merkle_proof(random_merkle_proof(DEFAULT_TREE_DEPTH))
            .build()
            .unwrap();
        let partial_proof = rln.generate_partial_proof(&partial_witness).unwrap();

        let bad_witness = RLNWitnessInput::new_single()
            .identity_secret(identity_secret)
            .user_message_limit(Fr::from(10))
            .merkle_proof(random_merkle_proof(DEFAULT_TREE_DEPTH + 1))
            .x(Fr::from(42))
            .external_nullifier(Fr::from(100))
            .message_id(Fr::from(1))
            .build()
            .unwrap();
        assert!(rln.finish_proof(&partial_proof, &bad_witness).is_err());
    }
}
