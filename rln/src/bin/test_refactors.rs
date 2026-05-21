use rln::prelude::*;

fn main() -> Result<(), RLNError> {
    // Stateless Single
    let backend =
        ArkGroth16BackendWithGraph::new(zkey_single_v1().to_owned(), graph_single_v1().to_owned());
    let rln = RLNV3::<Stateless, ArkGroth16BackendWithGraph>::new(backend);

    let (identity_secret, _) = keygen();
    let witness_single1 = RLNWitnessInputSingle::new(
        identity_secret.clone(),
        Fr::from(10),
        vec![Fr::from(0); DEFAULT_TREE_DEPTH],
        vec![0u8; DEFAULT_TREE_DEPTH],
        Fr::from(42),
        Fr::from(100),
        Fr::from(1),
    )?
    .into();

    let proof = rln.generate_proof_from_witness(&witness_single1)?;
    let values_single1 = RLNProofValuesV3::try_from(witness_single1)?;
    assert!(rln.verify(&proof, &values_single1)?);

    let witness_single2: RLNWitnessInputV3 = RLNWitnessInputSingle::new(
        identity_secret.clone(),
        Fr::from(10),
        vec![Fr::from(0); DEFAULT_TREE_DEPTH],
        vec![0u8; DEFAULT_TREE_DEPTH],
        Fr::from(11),
        Fr::from(100),
        Fr::from(1),
    )?
    .into();
    let values_single2 = RLNProofValuesV3::try_from(witness_single2)?;
    let recovered = values_single1.recover_secret(&values_single2)?;
    assert_eq!(recovered, identity_secret);

    // Stateless Multi
    let multi_backend =
        ArkGroth16BackendWithGraph::new(zkey_multi_v1().to_owned(), graph_multi_v1().to_owned());
    let rln_multi = RLNV3::<Stateless, ArkGroth16BackendWithGraph>::new(multi_backend);

    let (identity_secret, _) = keygen();

    let witness_multi = RLNWitnessInputMulti::new(
        identity_secret.clone(),
        Fr::from(10),
        vec![Fr::from(0); DEFAULT_TREE_DEPTH],
        vec![0u8; DEFAULT_TREE_DEPTH],
        Fr::from(42),
        Fr::from(100),
        (1..=DEFAULT_MAX_OUT as u64).map(Fr::from).collect(),
        vec![true; DEFAULT_MAX_OUT],
    )?
    .into();
    let proof = rln_multi.generate_proof_from_witness(&witness_multi)?;
    let values_multi = RLNProofValuesV3::try_from(witness_multi)?;
    assert!(rln_multi.verify(&proof, &values_multi)?);

    // Cross-mode slashing: Stateless Single × Stateless Multi
    let (identity_secret, _) = keygen();
    let external_nullifier = Fr::from(300);

    let witness_single: RLNWitnessInputV3 = RLNWitnessInputSingle::new(
        identity_secret.clone(),
        Fr::from(10),
        vec![Fr::from(0); DEFAULT_TREE_DEPTH],
        vec![0u8; DEFAULT_TREE_DEPTH],
        Fr::from(11),
        external_nullifier,
        Fr::from(1),
    )?
    .into();
    let witness_multi: RLNWitnessInputV3 = RLNWitnessInputMulti::new(
        identity_secret.clone(),
        Fr::from(10),
        vec![Fr::from(0); DEFAULT_TREE_DEPTH],
        vec![0u8; DEFAULT_TREE_DEPTH],
        Fr::from(22),
        external_nullifier,
        (1..=DEFAULT_MAX_OUT as u64).map(Fr::from).collect(),
        vec![true; DEFAULT_MAX_OUT],
    )?
    .into();

    let values_single = RLNProofValuesV3::try_from(witness_single)?;
    let values_multi = RLNProofValuesV3::try_from(witness_multi)?;

    assert_eq!(
        values_single.recover_secret(&values_multi)?,
        identity_secret
    );
    assert_eq!(
        values_multi.recover_secret(&values_single)?,
        identity_secret
    );

    // Partial Proof — Single
    let backend_partial =
        ArkGroth16BackendWithGraph::new(zkey_single_v1().to_owned(), graph_single_v1().to_owned());
    let rln_partial = RLNV3::<Stateless, ArkGroth16BackendWithGraph>::new(backend_partial);

    let (identity_secret, _) = keygen();
    let witness_for_partial: RLNWitnessInputV3 = RLNWitnessInputSingle::new(
        identity_secret.clone(),
        Fr::from(10),
        vec![Fr::from(0); DEFAULT_TREE_DEPTH],
        vec![0u8; DEFAULT_TREE_DEPTH],
        Fr::from(55),
        Fr::from(200),
        Fr::from(1),
    )?
    .into();

    let partial_witness = RLNPartialWitnessInputV3::from(&witness_for_partial);
    let partial_proof = rln_partial.generate_partial_proof(partial_witness)?;
    let values_partial = RLNProofValuesV3::try_from(witness_for_partial.clone())?;
    let proof_from_partial = rln_partial.finish_proof(partial_proof, witness_for_partial)?;
    assert!(rln_partial.verify(&proof_from_partial, &values_partial)?);

    // Partial Proof — Multi
    let backend_partial_multi =
        ArkGroth16BackendWithGraph::new(zkey_multi_v1().to_owned(), graph_multi_v1().to_owned());
    let rln_partial_multi =
        RLNV3::<Stateless, ArkGroth16BackendWithGraph>::new(backend_partial_multi);

    let (identity_secret, _) = keygen();
    let witness_for_partial_multi: RLNWitnessInputV3 = RLNWitnessInputMulti::new(
        identity_secret.clone(),
        Fr::from(10),
        vec![Fr::from(0); DEFAULT_TREE_DEPTH],
        vec![0u8; DEFAULT_TREE_DEPTH],
        Fr::from(77),
        Fr::from(400),
        (1..=DEFAULT_MAX_OUT as u64).map(Fr::from).collect(),
        vec![true; DEFAULT_MAX_OUT],
    )?
    .into();

    let partial_witness_multi = RLNPartialWitnessInputV3::from(&witness_for_partial_multi);
    let partial_proof_multi = rln_partial_multi.generate_partial_proof(partial_witness_multi)?;
    let values_partial_multi = RLNProofValuesV3::try_from(witness_for_partial_multi.clone())?;
    let proof_from_partial_multi =
        rln_partial_multi.finish_proof(partial_proof_multi, witness_for_partial_multi)?;
    assert!(rln_partial_multi.verify(&proof_from_partial_multi, &values_partial_multi)?);

    Ok(())
}
