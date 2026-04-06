// This module re-exports the most commonly used types and functions from the RLN library

#[cfg(not(target_arch = "wasm32"))]
pub use crate::circuit::{graph_multi_v1, graph_single_v1, zkey_multi_v1, zkey_single_v1};
#[cfg(feature = "pmtree-ft")]
pub use crate::pm_tree_adapter::{FrOf, PmTree, PmTreeProof, PmtreeConfig, PmtreeConfigBuilder};
#[cfg(not(feature = "stateless"))]
pub use crate::poseidon_tree::{MerkleProof, PoseidonTree};
#[cfg(not(feature = "stateless"))]
pub use crate::protocol::compute_tree_root;
#[cfg(not(target_arch = "wasm32"))]
pub use crate::{
    circuit::{graph_from_raw, Graph},
    protocol::{
        finish_zk_proof, finish_zk_proof_with_rs, generate_partial_zk_proof, generate_zk_proof,
        generate_zk_proof_with_rs, verify_zk_proof,
    },
};
pub use crate::{
    circuit::{
        zkey_from_raw, Curve, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
        PartialProof, Proof, VerifyingKey, Zkey, COMPRESS_PROOF_SIZE, DEFAULT_MAX_OUT,
        DEFAULT_TREE_DEPTH,
    },
    error::{ProtocolError, RLNError, RecoverSecretError, UtilsError, VerifyError},
    hashers::{
        hash_to_field_be, hash_to_field_le, poseidon_hash, poseidon_hash_pair,
        poseidon_hash_try_from, PoseidonHash,
    },
    protocol::{
        compute_id_secret, extended_keygen, extended_seeded_keygen, generate_zk_proof_with_witness,
        keygen, recover_id_secret, seeded_keygen, MessageMode, RLNPartialWitnessInput, RLNProof,
        RLNProofValues, RLNWitnessInput, RlnSerialize,
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
