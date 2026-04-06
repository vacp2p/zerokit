// This crate collects all the underlying primitives used to implement RLN

mod keygen;
mod mode;
mod proof;
mod slashing;
mod witness;

pub use keygen::{extended_keygen, extended_seeded_keygen, keygen, seeded_keygen};
pub use mode::{MessageMode, RlnSerialize};
#[cfg(not(target_arch = "wasm32"))]
pub use proof::{
    finish_zk_proof, finish_zk_proof_with_rs, generate_partial_zk_proof, generate_zk_proof,
    generate_zk_proof_with_rs,
};
pub use proof::{generate_zk_proof_with_witness, verify_zk_proof, RLNProof, RLNProofValues};
pub use slashing::{compute_id_secret, recover_id_secret};
pub use witness::{compute_tree_root, RLNPartialWitnessInput, RLNWitnessInput};
