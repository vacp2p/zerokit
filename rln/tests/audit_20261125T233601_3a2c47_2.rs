// Finding 20261125T233601-3a2c47/2 (re-check of F-69400794)
// Spec (Witness Construction): `build()` checks the structural invariants (non-zero
// `user_message_limit`, matching path lengths, `message_id < user_message_limit`).
// Spec (Proof Generation): `generate_proof` "Fails with `GenerateProofError` on witness/graph
// inconsistency or backend fault"; (Epoch and Rate Limit): "Each `message_id` MUST be less than
// `user_message_limit`" is the only bound stated.
use rand::thread_rng;
use rln::prelude::*;

fn prove_and_verify(limit: u64, message_id: u64) -> bool {
    let rln = RLNBuilder::stateless().build();
    let witness = RLNWitnessInput::new_single()
        .identity_secret(SecretFr::rand(&mut thread_rng()))
        .user_message_limit(Fr::from(limit))
        .merkle_proof(RLNMerkleProof::new(
            vec![Fr::from(0u64); DEFAULT_TREE_DEPTH],
            vec![0u8; DEFAULT_TREE_DEPTH],
        ))
        .x(Fr::from(7u64))
        .external_nullifier(Fr::from(9u64))
        .message_id(Fr::from(message_id))
        .build()
        .expect("witness satisfies every invariant the spec lists");
    let (proof, values) = rln
        .generate_proof(&witness)
        .expect("generate_proof returned Ok for this witness");
    rln.verify(&proof, &values).unwrap()
}

#[test]
fn spec_valid_witness_with_large_limit_yields_a_valid_proof() {
    assert!(prove_and_verify(10, 3), "control: small limit proves");
    // message_id (3) < user_message_limit (100000): accepted by build(), accepted by
    // generate_proof(), so the returned proof must verify.
    assert!(
        prove_and_verify(100_000, 3),
        "build() and generate_proof() both returned Ok, but the proof verifies as false"
    );
}
