use rln::prelude::*;
use zerokit_utils::merkle_tree::ZerokitMerkleTree;

fn main() -> Result<(), RLNError> {
    let zkey = zkey_single_v1().to_owned();
    let graph = graph_single_v1().to_owned();
    let backend = ArkGroth16Backend::new(zkey, graph);

    let rln_stateless = RLNV3::<Stateless, ArkGroth16Backend>::new(backend.clone());

    let witness1 = RLNWitnessInputV3::Single(RLNWitnessInputSingle::new()?);
    let (proof1, proof_values1) = rln_stateless.generate_proof(witness1)?;
    let ok = rln_stateless.verify_proof(&proof1, &proof_values1)?;
    assert!(ok);

    let merkle_tree = PmTree::default(DEFAULT_TREE_DEPTH).unwrap();
    let rln_stateful = RLNV3::<Stateful<PmTree>, ArkGroth16Backend>::new(merkle_tree, backend);
    let witness2 = RLNWitnessInputV3::Multi(RLNWitnessInputMulti::new()?);
    let (proof2, proof_values2) = rln_stateful.generate_proof(witness2)?;
    let ok = rln_stateful.verify_proof(&proof2, &proof_values2)?;
    assert!(ok);

    Ok(())
}
