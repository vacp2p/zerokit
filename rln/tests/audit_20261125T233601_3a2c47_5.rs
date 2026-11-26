// Finding 20261125T233601-3a2c47/5 (re-check of F-028276a9)
// Spec (Serialization): "Deserialization enforces the same structural invariants as
// construction and returns typed validation errors through `SerializationError`."
// Spec (Error Handling): `SerializationError`: "deserialization failures, including the
// construction-time validation errors surfaced through typed wrap variants."
use rand::thread_rng;
use rln::prelude::*;

#[test]
fn le_deserialize_returns_typed_validation_error() {
    let witness = RLNWitnessInput::new_single()
        .identity_secret(SecretFr::rand(&mut thread_rng()))
        .user_message_limit(Fr::from(10u64))
        .merkle_proof(RLNMerkleProof::new(vec![Fr::from(0u64); 2], vec![0u8; 2]))
        .x(Fr::from(7u64))
        .external_nullifier(Fr::from(9u64))
        .message_id(Fr::from(3u64))
        .build()
        .unwrap();

    // Big-endian control: tag(1) | identity_secret(32) | user_message_limit(32) | ...
    let mut be = Vec::new();
    CanonicalSerializeBE::serialize(&witness, &mut be).unwrap();
    be[33..65].fill(0);
    let be_err = <RLNWitnessInput as CanonicalDeserializeBE>::deserialize(&be[..]).unwrap_err();
    assert!(
        matches!(
            be_err,
            SerializationError::InvalidWitnessSingle(WitnessInputSingleError::ZeroUserMessageLimit)
        ),
        "control: BE path is typed, got {be_err:?}"
    );

    // Little-endian (the spec's first usage example): same layout prefix, same violation.
    let mut le = Vec::new();
    witness.serialize_compressed(&mut le).unwrap();
    le[33..65].fill(0);
    let ark_err = RLNWitnessInput::deserialize_compressed(&le[..]).unwrap_err();
    let le_err = SerializationError::from(ark_err);
    assert!(
        matches!(
            le_err,
            SerializationError::InvalidWitnessSingle(WitnessInputSingleError::ZeroUserMessageLimit)
        ),
        "LE deserialization must surface the typed validation error, got {le_err:?}"
    );
}
