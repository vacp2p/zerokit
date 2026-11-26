// Finding 20261125T233601-3a2c47/1 (re-check of F-d058ac14)
// Spec (Proof Verification): "The `Ok(bool)` value is the zkSNARK verification verdict: an
// invalid proof is reported as `Ok(false)`, not as an error. `Err` is reserved for caller-input
// mismatch (`InvalidSignal`, `InvalidRoot`) and backend faults."
use rand::thread_rng;
use rln::prelude::*;

#[test]
fn verify_reports_wrong_shape_proof_values_as_ok_false() {
    let single = RLNBuilder::stateless().build();
    let multi = RLNBuilder::stateless()
        .graph(default_graph_multi().clone())
        .zkey(default_zkey_multi().clone())
        .build();

    let witness = RLNWitnessInput::new_single()
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
        .unwrap();
    let (proof, values) = single.generate_proof(&witness).unwrap();
    assert!(
        single.verify(&proof, &values).unwrap(),
        "control: proof is valid"
    );

    // A peer sends this well-formed payload over the wire to a Multi-mode verifier.
    let mut wire = Vec::new();
    CanonicalSerializeMixed::serialize(&RLNProof::new(proof, values), &mut wire).unwrap();
    let received = <RLNProof as CanonicalDeserializeMixed>::deserialize(&wire[..]).unwrap();

    // The proof cannot be valid for the Multi circuit: it is an invalid proof.
    let verdict = multi.verify(&received.proof, &received.values);
    assert!(
        matches!(verdict, Ok(false)),
        "an invalid proof must be reported as Ok(false), got {verdict:?}"
    );
}
