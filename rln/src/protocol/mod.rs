// This module collects all the underlying primitives used to implement RLN

mod keygen;
mod proof;
mod secret;
mod serialize;
mod slashing;
mod witness;
mod zk;

pub use keygen::{ExtendedIdentityKeys, IdentityKeys};
pub use proof::{RLNProof, RLNProofValues, RLNProofValuesMulti, RLNProofValuesSingle};
pub use serialize::{
    CanonicalDeserializeBE, CanonicalDeserializeMixed, CanonicalSerializeBE,
    CanonicalSerializeMixed, COMPRESS_PROOF_SIZE, ENUM_TAG_MULTI, ENUM_TAG_SINGLE, ENUM_TAG_SIZE,
    FR_BYTE_SIZE, FR_LIMB_BYTE_SIZE, VEC_LEN_BYTE_SIZE,
};
pub use slashing::compute_id_secret;
pub use witness::{
    RLNMerkleProof, RLNPartialWitnessInput, RLNWitnessInput, RLNWitnessInputMulti,
    RLNWitnessInputSingle,
};
pub use zk::{RLNPartialZkProof, RLNZkProof, RecoverSecret};
