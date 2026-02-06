use rln::prelude::{hash_to_field_le, keygen, poseidon_hash, Fr, RLNWitnessInput, RLN};

fn main() {
    // 1. Initialize RLN with parameters:
    // - the tree depth;
    // - the tree config, if it is not defined, the default value will be set
    let tree_depth = 20;
    let mut rln = RLN::new(tree_depth, "").unwrap();

    // 2. Generate an identity keypair
    let (identity_secret, id_commitment) = keygen().unwrap();

    // 3. Add a rate commitment to the Merkle tree
    let leaf_index = 10;
    let user_message_limit = Fr::from(10);
    let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();
    rln.set_leaf(leaf_index, rate_commitment).unwrap();

    // 4. Get the Merkle proof for the added commitment
    let (path_elements, identity_path_index) = rln.get_merkle_proof(leaf_index).unwrap();

    // 5. Set up external nullifier (epoch + app identifier)
    // We generate epoch from a date seed and we ensure is
    // mapped to a field element by hashing-to-field its content
    let epoch = hash_to_field_le(b"Today at noon, this year").unwrap();
    // We generate rln_identifier from an application identifier and
    // we ensure is mapped to a field element by hashing-to-field its content
    let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
    // We generate a external nullifier
    let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();
    // We choose a message_id satisfy 0 <= message_id < user_message_limit
    let message_id = Fr::from(1);

    // 6. Define the message signal
    let signal = b"RLN is awesome";

    // 7. Compute x from the signal
    let x = hash_to_field_le(signal).unwrap();

    // 8. Create witness input for RLN proof generation
    #[cfg(not(feature = "multi-message-id"))]
    let witness = RLNWitnessInput::new(
        identity_secret,
        user_message_limit,
        message_id,
        path_elements,
        identity_path_index,
        x,
        external_nullifier,
    )
    .unwrap();

    #[cfg(feature = "multi-message-id")]
    let witness = RLNWitnessInput::new(
        identity_secret,
        user_message_limit,
        Some(message_id),
        None,
        path_elements,
        identity_path_index,
        x,
        external_nullifier,
        None,
    )
    .unwrap();

    // 9. Generate a RLN proof
    // We generate proof and proof values from the witness
    let (proof, proof_values) = rln.generate_rln_proof(&witness).unwrap();

    // 10. Verify the RLN proof
    // We verify the proof using the proof and proof values and the hashed signal x
    let verified = rln.verify_rln_proof(&proof, &proof_values, &x).unwrap();
    assert!(verified);
}
