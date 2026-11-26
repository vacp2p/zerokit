// Finding 20261125T233601-3a2c47/10
// Spec (Security/Privacy Considerations): "Identity secrets are kept confidential and never
// transmitted or logged"; "all secret field elements are carried as `SecretFr`".
// Spec (Witness Construction): witness inputs "are built through validating builders".
//
// The share is `y = identity_secret + x * a_1`. With the signal `x = 0` the public proof value
// `y` IS the identity secret. No builder, deserializer or `generate_proof` rejects `x = 0`.
use rand::thread_rng;
use rln::prelude::*;

/// Returns the public `y` when the whole pipeline accepts the witness and the proof verifies,
/// `None` when any stage rejects it.
fn public_y(secret: &SecretFr, x: Fr) -> Option<Fr> {
    let rln = RLNBuilder::stateless().build();
    let witness = RLNWitnessInput::new_single()
        .identity_secret(secret.clone())
        .user_message_limit(Fr::from(10u64))
        .merkle_proof(RLNMerkleProof::new(
            vec![Fr::from(0u64); DEFAULT_TREE_DEPTH],
            vec![0u8; DEFAULT_TREE_DEPTH],
        ))
        .x(x)
        .external_nullifier(Fr::from(9u64))
        .message_id(Fr::from(3u64))
        .build()
        .ok()?;
    let (proof, values) = rln.generate_proof(&witness).ok()?;
    // The payload a peer would receive.
    let mut wire = Vec::new();
    CanonicalSerializeMixed::serialize(&RLNProof::new(proof, values), &mut wire).unwrap();
    let received = <RLNProof as CanonicalDeserializeMixed>::deserialize(&wire[..]).ok()?;
    if !rln.verify(&received.proof, &received.values).ok()? {
        return None;
    }
    received.values.y()
}

#[test]
fn public_proof_values_never_carry_the_identity_secret() {
    let secret = SecretFr::rand(&mut thread_rng());

    // Control: an ordinary signal yields a share that is not the secret.
    let y = public_y(&secret, Fr::from(7u64)).expect("control: ordinary witness proves");
    assert!(y != *secret, "control");

    // `x = 0`: rejecting it at any stage is fine; emitting the secret as a public value is not.
    if let Some(y) = public_y(&secret, Fr::from(0u64)) {
        assert!(
            y != *secret,
            "x = 0 passed build(), generate_proof() and verify(), and the public proof value y \
             on the wire equals the plaintext identity secret"
        );
    }
}
