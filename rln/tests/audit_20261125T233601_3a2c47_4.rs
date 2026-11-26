// Finding 20261125T233601-3a2c47/4 (re-check of F-f49a1646)
// Spec (Proof Generation): `finish_proof(partial_proof, witness)` "completes the partial proof
// with the full witness and returns `(proof, proof_values)`"; errors are `GenerateProofError`
// "(witness/circuit mismatch or backend fault)".
use rand::thread_rng;
use rln::prelude::*;

fn witness() -> RLNWitnessInput {
    RLNWitnessInput::new_single()
        .identity_secret(SecretFr::rand(&mut thread_rng()))
        .user_message_limit(Fr::from(10u64))
        .merkle_proof(RLNMerkleProof::new(
            vec![Fr::from(0u64); DEFAULT_TREE_DEPTH],
            vec![0u8; DEFAULT_TREE_DEPTH],
        ))
        .x(Fr::from(7u64))
        .external_nullifier(Fr::from(9u64))
        .message_id(Fr::from(3u64))
        .build()
        .unwrap()
}

#[test]
fn finish_proof_with_foreign_partial_proof_errors_or_proves() {
    let rln = RLNBuilder::stateless().build();
    let a = witness();
    let b = witness(); // different identity secret

    let partial_a = rln
        .generate_partial_proof(&RLNPartialWitnessInput::from(&a))
        .unwrap();
    let (proof, values) = rln.finish_proof(&partial_a, &a).unwrap();
    assert!(
        rln.verify(&proof, &values).unwrap(),
        "control: matching pair proves"
    );

    // The partial proof was precomputed for identity `a`; the full witness is identity `b`.
    let Ok((proof, values)) = rln.finish_proof(&partial_a, &b) else {
        return; // an error is an acceptable outcome
    };
    assert!(
        rln.verify(&proof, &values).unwrap(),
        "finish_proof returned Ok for a partial proof that does not belong to the witness, \
         and the returned proof is invalid"
    );
}
