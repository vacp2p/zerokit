use std::io::Cursor;

use rln::{
    circuit::{Fr, TEST_TREE_HEIGHT},
    hashers::{hash_to_field, poseidon_hash},
    poseidon_tree::PoseidonTree,
    protocol::{keygen, rln_witness_from_values, serialize_witness},
    public::RLN,
    utils::{bytes_le_to_fr, fr_to_bytes_le, normalize_usize},
};
use zerokit_utils::ZerokitMerkleTree;

type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("RLN Stateless Example");

    // Create RLN instance
    #[cfg(feature = "stateless")]
    let mut rln = RLN::new()?;
    println!("1. Created stateless RLN instance");

    // Create Merkle tree outside of RLN instance
    let default_leaf = Fr::from(0);
    let mut tree = PoseidonTree::new(
        TEST_TREE_HEIGHT,
        default_leaf,
        ConfigOf::<PoseidonTree>::default(),
    )?;
    println!("2. Created Merkle tree outside of RLN instance with height: {TEST_TREE_HEIGHT}");

    // Generate user identity with user message limit
    let (identity_secret_hash, id_commitment) = keygen();
    println!("3. Generated user identity with secret hash: {identity_secret_hash}");

    let message_limit: u32 = 1;
    let user_message_limit: Fr = Fr::from(message_limit);
    let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]);
    println!("4. Generated rate commitment with message limit: {message_limit}");

    // Add user to tree
    let identity_index = tree.leaves_set();
    tree.update_next(rate_commitment)?;
    let merkle_proof = tree.proof(identity_index)?;
    println!("5. Added user to tree with identity index: {identity_index}");

    // Get tree root
    let tree_root = tree.root();
    println!("6. Tree root: {tree_root}");

    // Setup nullifier components
    let epoch = hash_to_field(b"epoch");
    let rln_identifier = hash_to_field(b"rln-identifier");
    let external_nullifier = poseidon_hash(&[epoch, rln_identifier]);

    // Prepare root buffer - Handle correctly for stateless verification
    let root_serialized = fr_to_bytes_le(&tree_root);
    let mut root_buffer = Cursor::new(root_serialized);
    println!("7. Set up external nullifier and root buffer");

    // Generate first message signal
    let mut signal_1 = b"signal_1".to_vec();
    println!("8. Created first message signal");

    // Create message_id for first message
    let message_id_1 = Fr::from(0);
    let x_1 = hash_to_field(&signal_1);

    // Create witness for first message
    let rln_witness_1 = rln_witness_from_values(
        identity_secret_hash,
        &merkle_proof,
        x_1,
        external_nullifier,
        user_message_limit,
        message_id_1,
    )?;

    // Serialize witness
    let serialized_1 = serialize_witness(&rln_witness_1)?;
    let mut input_buffer_1 = Cursor::new(serialized_1);

    // Output data:  [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32>]
    let mut output_buffer_1 = Cursor::new(Vec::new());

    // Generate proof for first message with witness in stateless mode
    rln.generate_rln_proof_with_witness(&mut input_buffer_1, &mut output_buffer_1)?;
    println!("9. Generated proof for first message");

    // Input proof data: [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var>]
    let mut proof_data_1 = output_buffer_1.into_inner();
    proof_data_1.append(&mut normalize_usize(signal_1.len()));
    proof_data_1.append(&mut signal_1);

    // Verify first proof with stateless verification
    let mut input_buffer = Cursor::new(proof_data_1.clone());
    let verified = rln.verify_with_roots(&mut input_buffer, &mut root_buffer)?;

    println!(
        "10. Stateless verification of first message: {}",
        if verified { "VALID" } else { "INVALID" }
    );

    // Generate second message signal (now the second in sequence)
    let mut signal_2 = b"signal_2".to_vec();
    println!("11. Created second message signal");

    // Create message_id for second message (now second in sequence)
    // Using a valid message_id=1 which is at the limit of our message_limit=1
    let message_id_2 = Fr::from(1);
    let x_2 = hash_to_field(&signal_2);

    // Create witness for second message
    let rln_witness_2 = rln_witness_from_values(
        identity_secret_hash,
        &merkle_proof,
        x_2,
        external_nullifier,
        user_message_limit,
        message_id_2,
    )?;

    // Serialize witness
    let serialized_2 = serialize_witness(&rln_witness_2)?;
    let mut input_buffer_2 = Cursor::new(serialized_2);

    // Output data:  [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32>]
    let mut output_buffer_2 = Cursor::new(Vec::new());

    // Generate proof for second message with witness in stateless mode
    rln.generate_rln_proof_with_witness(&mut input_buffer_2, &mut output_buffer_2)?;
    println!("12. Generated proof for second message with message_id=1");

    // Input proof data: [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var>]
    let mut proof_data_2 = output_buffer_2.into_inner();
    proof_data_2.append(&mut normalize_usize(signal_2.len()));
    proof_data_2.append(&mut signal_2);

    // Verify second proof with stateless verification
    let mut input_buffer = Cursor::new(proof_data_2.clone());
    let verified = rln.verify_with_roots(&mut input_buffer, &mut root_buffer)?;

    println!(
        "13. Stateless verification of second message: {}",
        if verified {
            "VALID (message_id=1 is within our message_limit=1)"
        } else {
            "INVALID (message_id must satisfy 0 <= message_id < MESSAGE_LIMIT)"
        }
    );

    // Generate third message signal (now third in sequence)
    let mut signal_3 = b"signal_3".to_vec();
    println!("14. Created third message signal (duplicate message_id demonstration)");

    // Duplicate message_id! Creating a double-post situation for third message
    let message_id_3 = Fr::from(0); // Reusing message_id=0 which was already used for the first message
    let x_3 = hash_to_field(&signal_3);

    // Create witness for third message
    let rln_witness_3 = rln_witness_from_values(
        identity_secret_hash,
        &merkle_proof,
        x_3,
        external_nullifier,
        user_message_limit,
        message_id_3,
    )?;

    // Serialize witness
    let serialized_3 = serialize_witness(&rln_witness_3)?;
    let mut input_buffer_3 = Cursor::new(serialized_3);

    // Output data:  [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32>]
    let mut output_buffer_3 = Cursor::new(Vec::new());

    // Generate proof for third message with witness in stateless mode
    rln.generate_rln_proof_with_witness(&mut input_buffer_3, &mut output_buffer_3)?;
    println!("15. Generated proof for third message (with duplicate message_id=0)");

    // Input proof data: [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var>]
    let mut proof_data_3 = output_buffer_3.into_inner();
    proof_data_3.append(&mut normalize_usize(signal_3.len()));
    proof_data_3.append(&mut signal_3);

    // Verify third proof with stateless verification
    let mut input_buffer = Cursor::new(proof_data_3.clone());
    let verified = rln.verify_with_roots(&mut input_buffer, &mut root_buffer)?;

    println!(
        "16. Stateless verification of third message: {}",
        if verified { "VALID" } else { "INVALID" }
    );

    // Recover identity from double-posting
    let mut input_1 = Cursor::new(proof_data_1);
    let mut input_3 = Cursor::new(proof_data_3);
    let mut output = Cursor::new(Vec::new());
    rln.recover_id_secret(&mut input_1, &mut input_3, &mut output)?;
    let recovered_data = output.into_inner();
    let (recovered_identity, _) = bytes_le_to_fr(&recovered_data);

    print!("17. Revealed identity secret hash: {}", recovered_identity);
    println!(
        " is{}MATCH the original",
        if identity_secret_hash == recovered_identity {
            " "
        } else {
            " NOT "
        }
    );

    Ok(())
}
