// This module re-exports the most commonly used types and functions from the RLN library

pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[cfg(not(target_arch = "wasm32"))]
pub use crate::circuit::{
    default_graph_multi, default_graph_single, default_zkey_multi, default_zkey_single,
};
#[cfg(not(target_arch = "wasm32"))]
pub use crate::pm_tree::{FrOf, PmTree, PmTreeConfig, PmTreeProof};
pub use crate::{
    circuit::{
        graph_from_raw, zkey_from_raw, ArkGroth16Backend, Curve, Fq, Fq2, Fr, G1Affine,
        G1Projective, G2Affine, G2Projective, Graph, IdSecret, PartialProof, Proof, VerifyingKey,
        Zkey, COMPRESS_PROOF_SIZE, DEFAULT_MAX_OUT, DEFAULT_TREE_DEPTH,
    },
    error::{
        GenerateProofError, RLNPartialWitnessInputError, RLNWitnessInputMultiError,
        RLNWitnessInputSingleError, RecoverSecretError, SerializationError, VerifyProofError,
    },
    hashers::{
        hash_to_field_be, hash_to_field_le, poseidon_hash, poseidon_hash_pair,
        poseidon_hash_try_from, PoseidonHash,
    },
    protocol::{
        compute_id_secret, extended_keygen, extended_seeded_keygen, keygen, seeded_keygen,
        CanonicalDeserializeBE, CanonicalDeserializeMixed, CanonicalSerializeBE,
        CanonicalSerializeMixed, RLNPartialWitnessInput, RLNPartialZkProof, RLNProof,
        RLNProofValues, RLNProofValuesMulti, RLNProofValuesSingle, RLNWitnessInput,
        RLNWitnessInputMulti, RLNWitnessInputSingle, RLNZkProof, RecoverSecret, ENUM_TAG_MULTI,
        ENUM_TAG_SINGLE, ENUM_TAG_SIZE, FR_BYTE_SIZE, FR_LIMB_BYTE_SIZE, VEC_LEN_BYTE_SIZE,
    },
    public::{RLNBuilder, Stateful, Stateless, RLN},
};
