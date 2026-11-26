// Finding 20261125T233601-3a2c47/6 (re-check of F-fc160c69)
// Spec (Serialization): "Deserialization enforces the same structural invariants as
// construction". Spec (Witness Construction): `build()` rejects a zero `user_message_limit`.
use rand::thread_rng;
use rln::prelude::*;

#[test]
fn unchecked_le_deserialize_still_enforces_structural_invariants() {
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
    let mut le = Vec::new();
    witness.serialize_compressed(&mut le).unwrap();
    le[33..65].fill(0); // user_message_limit = 0, which build() rejects

    assert!(
        RLNWitnessInput::deserialize_compressed(&le[..]).is_err(),
        "control: checked path rejects"
    );
    let unchecked = RLNWitnessInput::deserialize_compressed_unchecked(&le[..]);
    // Nothing downstream re-validates: the zero-limit witness is also accepted for proving.
    let proved = unchecked.as_ref().ok().map(|w| {
        RLNBuilder::stateless()
            .build()
            .generate_proof(w)
            .map(|_| ())
            .map_err(|e| e.to_string())
    });
    assert!(
        unchecked.is_err(),
        "a witness with user_message_limit = 0 was materialised through the public \
         CanonicalDeserialize impl (limit read back: {:?}; generate_proof on it: {:?})",
        unchecked.as_ref().map(|w| w.user_message_limit()),
        proved
    );
}
