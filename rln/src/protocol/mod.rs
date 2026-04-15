// This crate collects all the underlying primitives used to implement RLN

mod keygen;
mod mode;
mod proof;
mod serialize;
mod slashing;
mod state;
mod witness;
mod zk;

pub use keygen::{extended_keygen, extended_seeded_keygen, keygen, seeded_keygen};
pub use mode::{MessageMode, MultiMessage, SingleMessage};
pub use proof::{
    bytes_be_to_rln_partial_proof, bytes_be_to_rln_proof, bytes_be_to_rln_proof_values,
    bytes_le_to_rln_partial_proof, bytes_le_to_rln_proof, bytes_le_to_rln_proof_values,
    generate_zk_proof_with_witness, rln_partial_proof_to_bytes_be, rln_partial_proof_to_bytes_le,
    rln_proof_to_bytes_be, rln_proof_to_bytes_le, rln_proof_values_to_bytes_be,
    rln_proof_values_to_bytes_le, verify_zk_proof, RLNProof, RLNProofValues, RLNProofValuesMulti,
    RLNProofValuesSingle, RLNProofValuesV3,
};
#[cfg(not(target_arch = "wasm32"))]
pub use proof::{
    finish_zk_proof, finish_zk_proof_with_rs, generate_partial_zk_proof, generate_zk_proof,
    generate_zk_proof_with_rs,
};
pub use serialize::{CanonicalDeserializeBE, CanonicalSerializeBE};
pub use slashing::{compute_id_secret, recover_id_secret};
pub use state::{Stateful, Stateless};
pub use witness::{
    bytes_be_to_rln_partial_witness, bytes_be_to_rln_witness, bytes_le_to_rln_partial_witness,
    bytes_le_to_rln_witness, compute_tree_root, proof_values_from_witness,
    rln_partial_witness_to_bytes_be, rln_partial_witness_to_bytes_le, rln_witness_to_bigint_json,
    rln_witness_to_bytes_be, rln_witness_to_bytes_le, RLNPartialWitnessInput,
    RLNPartialWitnessInputV3, RLNWitnessInput, RLNWitnessInputMulti, RLNWitnessInputSingle,
    RLNWitnessInputV3,
};
pub use zk::{RLNPartialZkProof, RLNZkProof, RecoverSecret};
