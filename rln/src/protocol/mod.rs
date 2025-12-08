// This crate collects all the underlying primitives used to implement RLN

mod keygen;
mod proof;
mod slashing;
mod witness;

pub use keygen::{extended_keygen, extended_seeded_keygen, keygen, seeded_keygen};
pub use proof::{
    bytes_be_to_rln_proof, bytes_be_to_rln_proof_values, bytes_le_to_rln_proof,
    bytes_le_to_rln_proof_values, generate_zk_proof, generate_zk_proof_with_witness,
    rln_proof_to_bytes_be, rln_proof_to_bytes_le, rln_proof_values_to_bytes_be,
    rln_proof_values_to_bytes_le, verify_zk_proof, RLNProof, RLNProofValues,
};
pub use slashing::recover_id_secret;
pub use witness::{
    bytes_be_to_rln_witness, bytes_le_to_rln_witness, compute_tree_root, proof_values_from_witness,
    rln_witness_to_bigint_json, rln_witness_to_bytes_be, rln_witness_to_bytes_le, RLNWitnessInput,
};
