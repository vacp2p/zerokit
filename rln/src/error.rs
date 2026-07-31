use std::{array::TryFromSliceError, num::TryFromIntError};

use ark_relations::r1cs::SynthesisError;
use ark_serialize::SerializationError as ArkSerializationError;

use crate::circuit::{error::WitnessCalcError, Fr};

/// Errors that can occur when recovering an identity secret from shares.
#[derive(Debug, thiserror::Error)]
pub enum RecoverSecretError {
    /// The shares have the same `x` value, so the secret cannot be recovered.
    #[error("Cannot recover secret: division by zero (shares have the same x value)")]
    DivisionByZero,
    /// The two proofs were generated for different external nullifiers.
    #[error("External nullifiers mismatch: {0} != {1}")]
    ExternalNullifierMismatch(Fr, Fr),
    /// No matching nullifier was found across the provided proof values.
    #[error("No matching nullifier found across the provided proof values")]
    NoMatchingNullifier,
    /// The provided proof values are structurally invalid.
    #[error("Invalid proof values: {0}")]
    InvalidProofValues(#[from] ProofValuesMultiError),
}

/// Errors that can occur while serializing and deserializing RLN types.
#[derive(Debug, thiserror::Error)]
pub enum SerializationError {
    /// An underlying I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// An arkworks canonical (de)serialization error occurred.
    #[error("Arkworks canonical serialization error: {0}")]
    Serialize(#[from] ArkSerializationError),
    /// A field element was not in the canonical range `[0, r - 1]`.
    #[error("Non-canonical field element: value is not in [0, r-1]")]
    NonCanonicalFieldElement,
    /// A boolean byte was neither `0x00` nor `0x01`.
    #[error("Non-canonical bool byte: expected 0x00 or 0x01, got {0:#04x}")]
    NonCanonicalBool(u8),
    /// A slice could not be converted to a fixed-size array.
    #[error("Failed to convert from slice: {0}")]
    FromSlice(#[from] TryFromSliceError),
    /// An integer could not be converted to `usize`.
    #[error("Failed to convert to usize: {0}")]
    ToUsize(#[from] TryFromIntError),
    /// A deserialized Single message-id witness failed structural validation.
    #[error("Invalid Single message-id witness: {0}")]
    InvalidWitnessSingle(#[from] WitnessInputSingleError),
    /// A deserialized Multi message-id witness failed structural validation.
    #[error("Invalid Multi message-id witness: {0}")]
    InvalidWitnessMulti(#[from] WitnessInputMultiError),
    /// A deserialized partial witness failed structural validation.
    #[error("Invalid partial witness: {0}")]
    InvalidPartialWitness(#[from] PartialWitnessInputError),
    /// A deserialized multi proof-values failed structural validation.
    #[error("Invalid proof values: {0}")]
    InvalidProofValues(#[from] ProofValuesMultiError),
}

/// Errors that can occur while constructing an
/// [`RLNWitnessInputSingle`](crate::protocol::RLNWitnessInputSingle).
#[derive(Debug, thiserror::Error)]
pub enum WitnessInputSingleError {
    /// The user message limit was zero.
    #[error("User message limit cannot be zero")]
    ZeroUserMessageLimit,
    /// Field `path_elements` and `identity_path_index` have different lengths.
    #[error(
        "Field `path_elements` has length {0}, but field `identity_path_index` has length {1}"
    )]
    PathLengthMismatch(usize, usize),
    /// The message id was not within the user message limit.
    #[error("Message id ({0}) is not within user_message_limit ({1})")]
    InvalidMessageId(Fr, Fr),
}

/// Errors that can occur while constructing an
/// [`RLNWitnessInputMulti`](crate::protocol::RLNWitnessInputMulti).
#[derive(Debug, thiserror::Error)]
pub enum WitnessInputMultiError {
    /// The user message limit was zero.
    #[error("User message limit cannot be zero")]
    ZeroUserMessageLimit,
    /// Field `path_elements` and `identity_path_index` have different lengths.
    #[error(
        "Field `path_elements` has length {0}, but field `identity_path_index` has length {1}"
    )]
    PathLengthMismatch(usize, usize),
    /// Field `message_ids` was empty.
    #[error("Field `message_ids` must contain at least one message_id")]
    EmptyMessageIds,
    /// Field `message_ids` and `selector_used` have different lengths.
    #[error("Field `message_ids` has length {0}, but field `selector_used` has length {1}")]
    SelectorLengthMismatch(usize, usize),
    /// No entry in `selector_used` was `true`.
    #[error("At least one value in `selector_used` must be true")]
    NoActiveSelectorUsed,
    /// Field `message_ids` contained a duplicate active message id.
    #[error("Duplicate message ID found in `message_ids`")]
    DuplicateMessageIds,
    /// A message id was not within the user message limit.
    #[error("Message id ({0}) is not within user_message_limit ({1})")]
    InvalidMessageId(Fr, Fr),
}

/// Errors that can occur while constructing an
/// [`RLNPartialWitnessInput`](crate::protocol::RLNPartialWitnessInput).
#[derive(Debug, thiserror::Error)]
pub enum PartialWitnessInputError {
    /// The user message limit was zero.
    #[error("User message limit cannot be zero")]
    ZeroUserMessageLimit,
    /// Field `path_elements` and `identity_path_index` have different lengths.
    #[error(
        "Field `path_elements` has length {0}, but field `identity_path_index` has length {1}"
    )]
    PathLengthMismatch(usize, usize),
}

/// Errors that can occur while constructing an
/// [`RLNProofValuesMulti`](crate::protocol::RLNProofValuesMulti).
#[derive(Debug, thiserror::Error)]
pub enum ProofValuesMultiError {
    /// Fields `ys`, `nullifiers`, and `selector_used` have different lengths.
    #[error(
        "Field `ys` has length {0}, but field `nullifiers` has length {1} and field `selector_used` has length {2}"
    )]
    LengthMismatch(usize, usize, usize),
    /// The per-slot vectors were empty.
    #[error("Multi proof values must contain at least one per-slot entry")]
    EmptyProofValues,
}

/// Errors that can occur while generating a proof.
#[derive(Debug, thiserror::Error)]
pub enum GenerateProofError {
    /// Field `path_elements` length does not match the circuit tree depth.
    #[error("Field `path_elements` has length {1}, but circuit tree_depth is {0}")]
    PathElementsLengthMismatch(usize, usize),
    /// Field `identity_path_index` length does not match the circuit tree depth.
    #[error("Field `identity_path_index` has length {1}, but circuit tree_depth is {0}")]
    IdentityPathIndexLengthMismatch(usize, usize),
    /// Field `message_ids` length does not match the circuit `max_out`.
    #[error("Field `message_ids` has length {1}, but circuit max_out is {0}")]
    MessageIdsLengthMismatch(usize, usize),
    /// Field `selector_used` length does not match the circuit `max_out`.
    #[error("Field `selector_used` has length {1}, but circuit max_out is {0}")]
    SelectorUsedLengthMismatch(usize, usize),
    /// The witness calculation failed.
    #[error("Witness calculation error: {0}")]
    WitnessCalc(#[from] WitnessCalcError),
    /// The circuit synthesis failed.
    #[error("Synthesis error: {0}")]
    Synthesis(#[from] SynthesisError),
}

/// Errors that can occur while verifying a proof.
#[derive(Debug, thiserror::Error)]
pub enum VerifyProofError {
    /// The proof root was not among the provided roots.
    #[error("Expected one of the provided roots")]
    InvalidRoot,
    /// The signal `x` did not match the value bound in the proof.
    #[error("Signal value does not match")]
    InvalidSignal,
    /// The circuit synthesis failed.
    #[error("Synthesis error: {0}")]
    Synthesis(#[from] SynthesisError),
}
