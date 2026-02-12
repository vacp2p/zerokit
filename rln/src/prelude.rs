// This module re-exports the most commonly used types and functions from the RLN library

#[cfg(not(target_arch = "wasm32"))]
pub use crate::circuit::{graph_from_folder, zkey_from_folder};
#[cfg(feature = "pmtree-ft")]
pub use crate::pm_tree_adapter::{FrOf, PmTree, PmTreeProof, PmtreeConfig, PmtreeConfigBuilder};
#[cfg(not(feature = "stateless"))]
pub use crate::poseidon_tree::{MerkleProof, PoseidonTree};
#[cfg(not(feature = "stateless"))]
pub use crate::protocol::compute_tree_root;
#[cfg(not(target_arch = "wasm32"))]
pub use crate::protocol::{generate_zk_proof, verify_zk_proof};
pub use crate::{
    circuit::{
        graph_from_raw, zkey_from_raw, Curve, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine,
        G2Projective, Graph, Proof, VerifyingKey, Zkey, COMPRESS_PROOF_SIZE, DEFAULT_TREE_DEPTH,
    },
    error::{ProtocolError, RLNError, UtilsError, VerifyError},
    hashers::{hash_to_field_be, hash_to_field_le, poseidon_hash, PoseidonHash},
    protocol::{
        bytes_be_to_rln_proof, bytes_be_to_rln_proof_values, bytes_be_to_rln_witness,
        bytes_le_to_rln_proof, bytes_le_to_rln_proof_values, bytes_le_to_rln_witness,
        extended_keygen, extended_seeded_keygen, generate_zk_proof_with_witness, keygen,
        generate_partial_zk_proof, generate_zk_proof_with_rs, finish_zk_proof, finish_zk_proof_with_rs,
        proof_values_from_witness, recover_id_secret, rln_proof_to_bytes_be, rln_proof_to_bytes_le,
        rln_proof_values_to_bytes_be, rln_proof_values_to_bytes_le, rln_witness_to_bigint_json,
        rln_witness_to_bytes_be, rln_witness_to_bytes_le, seeded_keygen, RLNProof, RLNProofValues,
        RLNWitnessInput, RLNPartialWitnessInput, bytes_le_to_rln_partial_witness, bytes_be_to_rln_partial_witness,
        rln_partial_witness_to_bytes_be, rln_partial_witness_to_bytes_le, rln_partial_proof_to_bytes_le,
        bytes_le_to_rln_partial_proof,
    },
    public::RLN,
    utils::{
        bytes_be_to_fr, bytes_be_to_vec_fr, bytes_be_to_vec_u8, bytes_be_to_vec_usize,
        bytes_le_to_fr, bytes_le_to_vec_fr, bytes_le_to_vec_u8, bytes_le_to_vec_usize,
        fr_to_bytes_be, fr_to_bytes_le, normalize_usize_be, normalize_usize_le, str_to_fr,
        to_bigint, vec_fr_to_bytes_be, vec_fr_to_bytes_le, vec_u8_to_bytes_be, vec_u8_to_bytes_le,
        IdSecret, FR_BYTE_SIZE,
    },
};
