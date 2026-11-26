// Finding 20261125T233601-3a2c47/3 (re-check of F-8e9d9348)
// Spec (Witness Construction): witness inputs are "built through validating builders";
// (Proof Generation): `generate_proof` "Fails with `GenerateProofError` on witness/graph
// inconsistency or backend fault".
use rand::thread_rng;
use rln::prelude::*;

fn outcome(first_index: u8) -> Option<bool> {
    let rln = RLNBuilder::stateless().build();
    let mut index = vec![0u8; DEFAULT_TREE_DEPTH];
    index[0] = first_index;
    let built = RLNWitnessInput::new_single()
        .identity_secret(SecretFr::rand(&mut thread_rng()))
        .user_message_limit(Fr::from(10u64))
        .merkle_proof(RLNMerkleProof::new(
            vec![Fr::from(0u64); DEFAULT_TREE_DEPTH],
            index,
        ))
        .x(Fr::from(7u64))
        .external_nullifier(Fr::from(9u64))
        .message_id(Fr::from(3u64))
        .build();
    let witness = built.ok()?; // rejected by the builder: fine
    let (proof, values) = rln.generate_proof(&witness).ok()?; // rejected by generation: fine
    Some(rln.verify(&proof, &values).unwrap())
}

#[test]
fn non_bit_identity_path_index_is_rejected_or_proves() {
    assert_eq!(outcome(1), Some(true), "control: a path bit of 1 proves");
    // 2 is not a path bit.
    let verified = outcome(2);
    assert!(
        verified != Some(false),
        "identity_path_index entry 2 passed build() and generate_proof(), yet the proof is invalid"
    );
}
