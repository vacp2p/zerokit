use rln::prelude::*;
use zerokit_utils::merkle_tree::{
    FullMerkleTree, Hasher, OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Stateless Single
    let rln = RLNBuilder::stateless()
        .graph(default_graph_single().clone())
        .zkey(default_zkey_single().clone())
        .build();

    let (identity_secret, _) = keygen();
    let witness_single1 = RLNWitnessInputV3::new_single()
        .identity_secret(identity_secret.clone())
        .user_message_limit(Fr::from(10))
        .path_elements(vec![Fr::from(0); DEFAULT_TREE_DEPTH])
        .identity_path_index(vec![0u8; DEFAULT_TREE_DEPTH])
        .x(Fr::from(42))
        .external_nullifier(Fr::from(100))
        .message_id(Fr::from(1))
        .build()?;

    let (proof, values_single1) = rln.generate_proof(&witness_single1)?;
    assert!(rln.verify(&proof, &values_single1)?);

    let witness_single2 = RLNWitnessInputV3::new_single()
        .identity_secret(identity_secret.clone())
        .user_message_limit(Fr::from(10))
        .path_elements(vec![Fr::from(0); DEFAULT_TREE_DEPTH])
        .identity_path_index(vec![0u8; DEFAULT_TREE_DEPTH])
        .x(Fr::from(11))
        .external_nullifier(Fr::from(100))
        .message_id(Fr::from(1))
        .build()?;
    let values_single2 = RLNProofValuesV3::from(&witness_single2);
    let recovered = values_single1.recover_secret(&values_single2)?;
    assert_eq!(recovered, identity_secret);

    // Stateless Multi
    let rln_multi = RLNBuilder::stateless()
        .graph(default_graph_multi().clone())
        .zkey(default_zkey_multi().clone())
        .build();

    let (identity_secret, _) = keygen();

    let witness_multi = RLNWitnessInputV3::new_multi()
        .identity_secret(identity_secret)
        .user_message_limit(Fr::from(10))
        .path_elements(vec![Fr::from(0); DEFAULT_TREE_DEPTH])
        .identity_path_index(vec![0u8; DEFAULT_TREE_DEPTH])
        .x(Fr::from(42))
        .external_nullifier(Fr::from(100))
        .message_ids((1..=DEFAULT_MAX_OUT as u64).map(Fr::from).collect())
        .selector_used(vec![true; DEFAULT_MAX_OUT])
        .build()?;
    let (proof, values_multi) = rln_multi.generate_proof(&witness_multi)?;
    assert!(rln_multi.verify(&proof, &values_multi)?);

    // Cross-mode slashing: Stateless Single × Stateless Multi
    let (identity_secret, _) = keygen();
    let external_nullifier = Fr::from(300);

    let witness_single = RLNWitnessInputV3::new_single()
        .identity_secret(identity_secret.clone())
        .user_message_limit(Fr::from(10))
        .path_elements(vec![Fr::from(0); DEFAULT_TREE_DEPTH])
        .identity_path_index(vec![0u8; DEFAULT_TREE_DEPTH])
        .x(Fr::from(11))
        .external_nullifier(external_nullifier)
        .message_id(Fr::from(1))
        .build()?;
    let witness_multi = RLNWitnessInputV3::new_multi()
        .identity_secret(identity_secret.clone())
        .user_message_limit(Fr::from(10))
        .path_elements(vec![Fr::from(0); DEFAULT_TREE_DEPTH])
        .identity_path_index(vec![0u8; DEFAULT_TREE_DEPTH])
        .x(Fr::from(22))
        .external_nullifier(external_nullifier)
        .message_ids((1..=DEFAULT_MAX_OUT as u64).map(Fr::from).collect())
        .selector_used(vec![true; DEFAULT_MAX_OUT])
        .build()?;

    let values_single = RLNProofValuesV3::from(&witness_single);
    let values_multi = RLNProofValuesV3::from(&witness_multi);

    assert_eq!(
        values_single.recover_secret(&values_multi)?,
        identity_secret
    );
    assert_eq!(
        values_multi.recover_secret(&values_single)?,
        identity_secret
    );

    // Partial Proof - Single
    let rln_partial = RLNBuilder::stateless()
        .graph(default_graph_single().clone())
        .zkey(default_zkey_single().clone())
        .build();

    let (identity_secret, _) = keygen();
    let witness_for_partial = RLNWitnessInputV3::new_single()
        .identity_secret(identity_secret)
        .user_message_limit(Fr::from(10))
        .path_elements(vec![Fr::from(0); DEFAULT_TREE_DEPTH])
        .identity_path_index(vec![0u8; DEFAULT_TREE_DEPTH])
        .x(Fr::from(55))
        .external_nullifier(Fr::from(200))
        .message_id(Fr::from(1))
        .build()?;

    let partial_witness = RLNPartialWitnessInputV3::from(&witness_for_partial);
    let partial_proof = rln_partial.generate_partial_proof(&partial_witness)?;
    let (proof_from_partial, values_partial) =
        rln_partial.finish_proof(&partial_proof, &witness_for_partial)?;
    assert!(rln_partial.verify(&proof_from_partial, &values_partial)?);

    // Partial Proof - Multi
    let rln_partial_multi = RLNBuilder::stateless()
        .graph(default_graph_multi().clone())
        .zkey(default_zkey_multi().clone())
        .build();

    let (identity_secret, _) = keygen();
    let witness_for_partial_multi = RLNWitnessInputV3::new_multi()
        .identity_secret(identity_secret)
        .user_message_limit(Fr::from(10))
        .path_elements(vec![Fr::from(0); DEFAULT_TREE_DEPTH])
        .identity_path_index(vec![0u8; DEFAULT_TREE_DEPTH])
        .x(Fr::from(77))
        .external_nullifier(Fr::from(400))
        .message_ids((1..=DEFAULT_MAX_OUT as u64).map(Fr::from).collect())
        .selector_used(vec![true; DEFAULT_MAX_OUT])
        .build()?;

    let partial_witness_multi = RLNPartialWitnessInputV3::from(&witness_for_partial_multi);
    let partial_proof_multi = rln_partial_multi.generate_partial_proof(&partial_witness_multi)?;
    let (proof_from_partial_multi, values_partial_multi) =
        rln_partial_multi.finish_proof(&partial_proof_multi, &witness_for_partial_multi)?;
    assert!(rln_partial_multi.verify(&proof_from_partial_multi, &values_partial_multi)?);

    // Stateful Single - FullMerkleTree
    let full_merkle_tree = FullMerkleTree::<PoseidonHash>::new(
        DEFAULT_TREE_DEPTH,
        PoseidonHash::default_leaf(),
        Default::default(),
    )?;
    let mut rln_stateful = RLNBuilder::stateful()
        .tree(full_merkle_tree)
        .graph(default_graph_single().clone())
        .zkey(default_zkey_single().clone())
        .build();

    let (identity_secret, id_commitment) = keygen();
    let user_message_limit = Fr::from(10);
    let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]);
    let leaf_index = 0usize;

    rln_stateful.set_leaf(leaf_index, rate_commitment)?;

    let x = Fr::from(42);
    let external_nullifier = Fr::from(100);
    let message_id = Fr::from(1);

    let merkle_proof = rln_stateful.get_merkle_proof(leaf_index)?;
    let witness_stateful = RLNWitnessInputV3::new_single()
        .identity_secret(identity_secret)
        .user_message_limit(user_message_limit)
        .path_elements(merkle_proof.get_path_elements())
        .identity_path_index(merkle_proof.get_path_index())
        .x(x)
        .external_nullifier(external_nullifier)
        .message_id(message_id)
        .build()?;

    let (proof_stateful, values_stateful) = rln_stateful.generate_proof(&witness_stateful)?;
    assert!(rln_stateful.verify(&proof_stateful, &values_stateful)?);
    assert!(rln_stateful.verify_with_roots(
        &proof_stateful,
        &values_stateful,
        &x,
        &[rln_stateful.get_root()],
    )?);

    // Stateful tree ops
    assert_eq!(rln_stateful.tree_depth(), DEFAULT_TREE_DEPTH);
    let _ = rln_stateful.leaves_set();
    let _ = rln_stateful.get_leaf(leaf_index)?;
    let _ = rln_stateful.get_subtree_root(0, 0)?;
    let _ = rln_stateful.get_empty_leaves_indices();
    rln_stateful.set_next_leaf(rate_commitment)?;
    rln_stateful.delete_leaf(leaf_index)?;
    rln_stateful.init_tree_with_leaves(vec![rate_commitment])?;

    // Stateful Multi - OptimalMerkleTree
    let optimal_merkle_tree =
        <OptimalMerkleTree<PoseidonHash> as ZerokitMerkleTree>::default(DEFAULT_TREE_DEPTH)?;
    let mut rln_stateful_multi = RLNBuilder::stateful()
        .tree(optimal_merkle_tree)
        .graph(default_graph_multi().clone())
        .zkey(default_zkey_multi().clone())
        .build();

    let (identity_secret_multi, id_commitment_multi) = keygen();
    let user_message_limit_multi = Fr::from(10);
    let rate_commitment_multi = poseidon_hash(&[id_commitment_multi, user_message_limit_multi]);
    rln_stateful_multi.set_leaf(0, rate_commitment_multi)?;

    let x_multi = Fr::from(77);
    let external_nullifier_multi = Fr::from(200);
    let merkle_proof_multi = rln_stateful_multi.get_merkle_proof(0)?;

    let witness_stateful_multi = RLNWitnessInputV3::new_multi()
        .identity_secret(identity_secret_multi)
        .user_message_limit(user_message_limit_multi)
        .path_elements(merkle_proof_multi.get_path_elements())
        .identity_path_index(merkle_proof_multi.get_path_index())
        .x(x_multi)
        .external_nullifier(external_nullifier_multi)
        .message_ids((1..=DEFAULT_MAX_OUT as u64).map(Fr::from).collect())
        .selector_used(vec![true; DEFAULT_MAX_OUT])
        .build()?;

    let (proof_stateful_multi, values_stateful_multi) =
        rln_stateful_multi.generate_proof(&witness_stateful_multi)?;
    assert!(rln_stateful_multi.verify(&proof_stateful_multi, &values_stateful_multi)?);
    assert!(rln_stateful_multi.verify_with_roots(
        &proof_stateful_multi,
        &values_stateful_multi,
        &x_multi,
        &[rln_stateful_multi.get_root()],
    )?);

    // Stateful Partial Proof - PmTree with custom config
    let pm_tree_config = PmTreeConfig::new()
        .tree_depth(DEFAULT_TREE_DEPTH)
        .temporary(true)
        .cache_capacity(1024 * 1024)
        .build()?;
    let pm_tree = <PmTree as ZerokitMerkleTree>::new(
        DEFAULT_TREE_DEPTH,
        PoseidonHash::default_leaf(),
        pm_tree_config,
    )?;
    let mut rln_stateful_partial = RLNBuilder::stateful()
        .tree(pm_tree)
        .graph(default_graph_single().clone())
        .zkey(default_zkey_single().clone())
        .build();

    let (identity_secret_p, id_commitment_p) = keygen();
    let user_message_limit_p = Fr::from(10);
    let rate_commitment_p = poseidon_hash(&[id_commitment_p, user_message_limit_p]);
    rln_stateful_partial.set_leaf(0, rate_commitment_p)?;

    let x_p = Fr::from(55);
    let merkle_proof_p = rln_stateful_partial.get_merkle_proof(0)?;
    let witness_stateful_p = RLNWitnessInputV3::new_single()
        .identity_secret(identity_secret_p)
        .user_message_limit(user_message_limit_p)
        .path_elements(merkle_proof_p.get_path_elements())
        .identity_path_index(merkle_proof_p.get_path_index())
        .x(x_p)
        .external_nullifier(Fr::from(300))
        .message_id(Fr::from(1))
        .build()?;

    let partial_witness_stateful = RLNPartialWitnessInputV3::from(&witness_stateful_p);
    let partial_proof_stateful =
        rln_stateful_partial.generate_partial_proof(&partial_witness_stateful)?;
    let (proof_from_partial_stateful, values_stateful_p) =
        rln_stateful_partial.finish_proof(&partial_proof_stateful, &witness_stateful_p)?;
    assert!(rln_stateful_partial.verify(&proof_from_partial_stateful, &values_stateful_p)?);

    Ok(())
}
