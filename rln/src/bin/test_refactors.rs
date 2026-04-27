use rln::prelude::*;

fn main() -> Result<(), RLNError> {
    // Stateless Single
    let backend = ArkGroth16Backend::new(zkey_single_v1().to_owned(), graph_single_v1().to_owned());
    let rln = RLNV3::<Stateless, ArkGroth16Backend>::new(backend);

    let (identity_secret, _) = keygen();
    let witness_single1 = RLNWitnessInputV3::Single(RLNWitnessInputSingle::new(
        identity_secret.clone(),
        Fr::from(10),
        vec![Fr::from(0); DEFAULT_TREE_DEPTH],
        vec![0u8; DEFAULT_TREE_DEPTH],
        Fr::from(42),
        Fr::from(100),
        Fr::from(1),
    ));

    let (proof, values_single1) = rln.generate_proof(witness_single1)?;
    assert!(rln.verify(&proof, &values_single1)?);

    let witness_single2 = RLNWitnessInputV3::Single(RLNWitnessInputSingle::new(
        identity_secret.clone(),
        Fr::from(10),
        vec![Fr::from(0); DEFAULT_TREE_DEPTH],
        vec![0u8; DEFAULT_TREE_DEPTH],
        Fr::from(11),
        Fr::from(100),
        Fr::from(1),
    ));
    let (_, values_single2) = rln.generate_proof(witness_single2)?;
    let recovered = values_single1.recover_secret(&values_single2)?;
    assert_eq!(recovered, *identity_secret);

    // Stateless Multi
    let multi_backend =
        ArkGroth16Backend::new(zkey_multi_v1().to_owned(), graph_multi_v1().to_owned());
    let rln_multi = RLNV3::<Stateless, ArkGroth16Backend>::new(multi_backend);

    let (identity_secret, _) = keygen();

    let witness_multi = RLNWitnessInputV3::Multi(RLNWitnessInputMulti::new(
        identity_secret.clone(),
        Fr::from(10),
        vec![Fr::from(0); DEFAULT_TREE_DEPTH],
        vec![0u8; DEFAULT_TREE_DEPTH],
        Fr::from(42),
        Fr::from(100),
        (1..=DEFAULT_MAX_OUT as u64).map(Fr::from).collect(),
        vec![true; DEFAULT_MAX_OUT],
    ));
    let (proof, values_multi) = rln_multi.generate_proof(witness_multi)?;
    assert!(rln_multi.verify(&proof, &values_multi)?);

    // Cross-mode slashing: Single × Multi
    let backend_s =
        ArkGroth16Backend::new(zkey_single_v1().to_owned(), graph_single_v1().to_owned());
    let rln_single = RLNV3::<Stateless, ArkGroth16Backend>::new(backend_s);
    let backend_m = ArkGroth16Backend::new(zkey_multi_v1().to_owned(), graph_multi_v1().to_owned());
    let rln_multi2 = RLNV3::<Stateless, ArkGroth16Backend>::new(backend_m);

    let (identity_secret, _) = keygen();
    let external_nullifier = Fr::from(300);

    let witness_single = RLNWitnessInputV3::Single(RLNWitnessInputSingle::new(
        identity_secret.clone(),
        Fr::from(10),
        vec![Fr::from(0); DEFAULT_TREE_DEPTH],
        vec![0u8; DEFAULT_TREE_DEPTH],
        Fr::from(11),
        external_nullifier,
        Fr::from(1),
    ));
    let witness_multi = RLNWitnessInputV3::Multi(RLNWitnessInputMulti::new(
        identity_secret.clone(),
        Fr::from(10),
        vec![Fr::from(0); DEFAULT_TREE_DEPTH],
        vec![0u8; DEFAULT_TREE_DEPTH],
        Fr::from(22),
        external_nullifier,
        (1..=DEFAULT_MAX_OUT as u64).map(Fr::from).collect(),
        vec![true; DEFAULT_MAX_OUT],
    ));

    let (_, values_single) = rln_single.generate_proof(witness_single)?;
    let (_, values_multi) = rln_multi2.generate_proof(witness_multi)?;

    assert_eq!(
        values_single.recover_secret(&values_multi)?,
        *identity_secret
    );
    assert_eq!(
        values_multi.recover_secret(&values_single)?,
        *identity_secret
    );

    Ok(())
}
