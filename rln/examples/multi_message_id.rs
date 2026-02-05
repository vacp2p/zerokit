use rln::prelude::{
    hash_to_field_le, keygen, poseidon_hash, Fr, PmtreeConfigBuilder, RLNWitnessInput,
    DEFAULT_TREE_DEPTH, RLN,
};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};
use zerokit_utils::pm_tree::Mode;

fn main() {
    // 1. Initialize RLN with parameters
    let mut resources: Vec<Vec<u8>> = Vec::new();
    let resources_path: PathBuf =
        format!("../resources/tree_depth_{DEFAULT_TREE_DEPTH}/multi_message_id").into();
    let filenames = ["rln_final.arkzkey", "graph.bin"];
    for filename in filenames {
        let fullpath = resources_path.join(Path::new(filename));
        let mut file = File::open(&fullpath).unwrap();
        let metadata = std::fs::metadata(&fullpath).unwrap();
        let mut output_buffer = vec![0; metadata.len() as usize];
        file.read_exact(&mut output_buffer).unwrap();
        resources.push(output_buffer);
    }
    let tree_config = PmtreeConfigBuilder::new()
        .path("./database")
        .temporary(false)
        .cache_capacity(1073741824)
        .flush_every_ms(500)
        .mode(Mode::HighThroughput)
        .use_compression(false)
        .build()
        .unwrap();

    let mut rln = RLN::new_with_params(
        DEFAULT_TREE_DEPTH,
        resources[0].clone(),
        resources[1].clone(),
        tree_config,
    )
    .unwrap();

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
    // We choose message_ids that satisfy 0 <= message_ids < user_message_limit
    let message_ids = vec![Fr::from(0), Fr::from(1), Fr::from(2), Fr::from(3)];
    // We set selector to indicate which message slots are (2 active, 2 unused)
    let selector_used = vec![0, 1, 1, 0];

    // 6. Define the message signal
    let signal = b"RLN is awesome";

    // 7. Compute x from the signal
    let x = hash_to_field_le(signal).unwrap();

    // 8. Create witness input for RLN proof generation
    let witness = RLNWitnessInput::new(
        identity_secret,
        user_message_limit,
        None,              // No single message_id in multi-message mode
        Some(message_ids), // Multiple message_ids
        path_elements,
        identity_path_index,
        x,
        external_nullifier,
        Some(selector_used), // Selector mask for active messages
    )
    .unwrap();

    // 9. Generate a RLN proof
    let (proof, proof_values) = rln.generate_rln_proof(&witness).unwrap();

    // 10. Verify the RLN proof
    let verified = rln.verify_rln_proof(&proof, &proof_values, &x).unwrap();
    assert!(verified);
}
