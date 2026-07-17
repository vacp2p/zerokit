// This module re-exports the most commonly used types and functions from the RLN library

pub use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[cfg(not(target_arch = "wasm32"))]
pub use crate::{
    circuit::{default_graph_multi, default_graph_single, default_zkey_multi, default_zkey_single},
    pm_tree::{
        PmTree, PmTreeBackendConfig, PmTreeError, PmTreeMode, PmTreeProof, PmTreeSledConfig, SledDB,
    },
};
pub use crate::{
    circuit::{
        graph_from_raw, zkey_from_raw, ArkGroth16Backend, Curve, Fq, Fq2, Fr, G1Affine,
        G1Projective, G2Affine, G2Projective, Graph, PartialProof, Proof, SecretFr, VerifyingKey,
        Zkey, DEFAULT_MAX_OUT, DEFAULT_TREE_DEPTH,
    },
    error::{
        GenerateProofError, PartialWitnessInputError, RecoverSecretError, SerializationError,
        VerifyProofError, WitnessInputMultiError, WitnessInputSingleError,
    },
    hashers::{hash_to_field_be, hash_to_field_le, Hasher, PoseidonHash},
    protocol::{
        compute_id_secret, CanonicalDeserializeBE, CanonicalDeserializeMixed, CanonicalSerializeBE,
        CanonicalSerializeMixed, ExtendedIdentityKeys, IdentityKeys, RLNMerkleProof,
        RLNPartialWitnessInput, RLNPartialZkProof, RLNProof, RLNProofValues, RLNProofValuesMulti,
        RLNProofValuesSingle, RLNWitnessInput, RLNWitnessInputMulti, RLNWitnessInputSingle,
        RLNZkProof, RecoverSecret,
    },
    public::{RLNBuilder, Stateful, Stateless, RLN},
};
