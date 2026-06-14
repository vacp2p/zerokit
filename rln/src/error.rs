use std::{array::TryFromSliceError, num::TryFromIntError};

use ark_relations::r1cs::SynthesisError;
use ark_serialize::SerializationError as ArkSerializationError;

use crate::circuit::{error::WitnessCalcError, Fr};

/// Errors that can occur when recovering an identity secret from shares
#[derive(Debug, thiserror::Error)]
pub enum RecoverSecretError {
    #[error("Cannot recover secret: division by zero (shares have the same x value)")]
    DivisionByZero,
    #[error("External nullifiers mismatch: {0} != {1}")]
    ExternalNullifierMismatch(Fr, Fr),
    #[error("No matching nullifier found across the provided proof values")]
    NoMatchingNullifier,
}

/// Errors that can occur while serializing and deserializing RLN types.
#[derive(Debug, thiserror::Error)]
pub enum SerializationError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Arkworks canonical serialization error: {0}")]
    Serialize(#[from] ArkSerializationError),
    #[error("Non-canonical field element: value is not in [0, r-1]")]
    NonCanonicalFieldElement,
    #[error("Non-canonical bool byte: expected 0x00 or 0x01, got {0:#04x}")]
    NonCanonicalBool(u8),
    #[error("Failed to convert from slice: {0}")]
    FromSlice(#[from] TryFromSliceError),
    #[error("Failed to convert to usize: {0}")]
    ToUsize(#[from] TryFromIntError),
}

/// Errors that can occur while constructing an [`RLNWitnessInputSingle`].
#[derive(Debug, thiserror::Error)]
pub enum RLNWitnessInputSingleError {
    #[error("User message limit cannot be zero")]
    ZeroUserMessageLimit,
    #[error(
        "Field `path_elements` has length {0}, but field `identity_path_index` has length {1}"
    )]
    PathLengthMismatch(usize, usize),
    #[error("Message id ({0}) is not within user_message_limit ({1})")]
    InvalidMessageId(Fr, Fr),
}

/// Errors that can occur while constructing an [`RLNWitnessInputMulti`].
#[derive(Debug, thiserror::Error)]
pub enum RLNWitnessInputMultiError {
    #[error("User message limit cannot be zero")]
    ZeroUserMessageLimit,
    #[error(
        "Field `path_elements` has length {0}, but field `identity_path_index` has length {1}"
    )]
    PathLengthMismatch(usize, usize),
    #[error("The field `message_ids` must contain at least one message_id")]
    EmptyMessageIds,
    #[error("Field `message_ids` has length {0}, but field `selector_used` has length {1}")]
    SelectorLengthMismatch(usize, usize),
    #[error("At least one value in `selector_used` must be true")]
    NoActiveSelectorUsed,
    #[error("Duplicate message ID found in `message_ids`")]
    DuplicateMessageIds,
    #[error("Message id ({0}) is not within user_message_limit ({1})")]
    InvalidMessageId(Fr, Fr),
}

/// Errors that can occur while constructing an [`RLNPartialWitnessInput`].
#[derive(Debug, thiserror::Error)]
pub enum RLNPartialWitnessInputError {
    #[error("User message limit cannot be zero")]
    ZeroUserMessageLimit,
    #[error(
        "Field `path_elements` has length {0}, but field `identity_path_index` has length {1}"
    )]
    PathLengthMismatch(usize, usize),
}

/// Errors that can occur while generating a proof.
#[derive(Debug, thiserror::Error)]
pub enum GenerateProofError {
    #[error("Field `path_elements` has length {1}, but circuit tree_depth is {0}")]
    PathElementsLengthMismatch(usize, usize),
    #[error("Field `identity_path_index` has length {1}, but circuit tree_depth is {0}")]
    IdentityPathIndexLengthMismatch(usize, usize),
    #[error("Field `message_ids` has length {1}, but circuit max_out is {0}")]
    MessageIdsLengthMismatch(usize, usize),
    #[error("Field `selector_used` has length {1}, but circuit max_out is {0}")]
    SelectorUsedLengthMismatch(usize, usize),
    #[error("Witness calculation error: {0}")]
    WitnessCalc(#[from] WitnessCalcError),
    #[error("Synthesis error: {0}")]
    Synthesis(#[from] SynthesisError),
}

/// Errors that can occur while verifying a proof.
#[derive(Debug, thiserror::Error)]
pub enum VerifyProofError {
    #[error("Invalid proof provided")]
    InvalidProof,
    #[error("Expected one of the provided roots")]
    InvalidRoot,
    #[error("Signal value does not match")]
    InvalidSignal,
    #[error("Synthesis error: {0}")]
    Synthesis(#[from] SynthesisError),
}
