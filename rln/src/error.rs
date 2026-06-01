use std::{array::TryFromSliceError, io::Error, num::TryFromIntError};

use ark_relations::r1cs::SynthesisError;
use ark_serialize::SerializationError;
use num_bigint::{BigInt, ParseBigIntError};
use zerokit_utils::merkle_tree::{FromConfigError, ZerokitMerkleTreeError};

use crate::{
    circuit::{
        error::{GraphReadError, WitnessCalcError, ZKeyReadError},
        Fr,
    },
    protocol::MessageMode,
};

/// Errors that can occur during RLN utility operations (conversions, parsing, etc.)
#[derive(Debug, thiserror::Error)]
pub enum UtilsError {
    #[error("IO error: {0}")]
    IoError(#[from] Error),
    #[error("Expected radix 10 or 16")]
    WrongRadix,
    #[error("Failed to parse big integer: {0}")]
    ParseBigInt(#[from] ParseBigIntError),
    #[error("Failed to convert to usize: {0}")]
    ToUsize(#[from] TryFromIntError),
    #[error("Failed to convert from slice: {0}")]
    FromSlice(#[from] TryFromSliceError),
    #[error("Input data too short: expected at least {expected} bytes, got {actual} bytes")]
    InsufficientData { expected: usize, actual: usize },
    #[error("Non-canonical field element: value is not in [0, r-1]")]
    NonCanonicalFieldElement,
    #[error("Non-canonical bool byte: expected 0x00 or 0x01, got {0:#04x}")]
    NonCanonicalBool(u8),
}

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

/// Errors that can occur during RLN protocol operations (proof generation, verification, etc.)
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("IO error: {0}")]
    IoError(#[from] Error),
    #[error("Error producing proof: {0}")]
    Synthesis(#[from] SynthesisError),
    #[error("RLN utility error: {0}")]
    Utils(#[from] UtilsError),
    #[error("Error calculating witness: {0}")]
    WitnessCalc(#[from] WitnessCalcError),
    #[error("Expected to read {0} bytes but read {1} bytes")]
    InvalidReadLen(usize, usize),
    #[error("Cannot convert bigint {0:?} to biguint")]
    BigUintConversion(BigInt),
    #[error("Message id ({0}) is not within user_message_limit ({1})")]
    InvalidMessageId(Fr, Fr),
    #[error("User message limit cannot be zero")]
    ZeroUserMessageLimit,
    #[error("Merkle proof length mismatch: expected {0}, got {1}")]
    InvalidMerkleProofLength(usize, usize),
    #[error("The field message_ids must contain at least one message_id")]
    EmptyMessageIds,
    #[error("Duplicate message ID found in message_ids")]
    DuplicateMessageIds,
    #[error("At least one selector_used value must be true")]
    NoActiveSelectorUsed,
    #[error("The field {0} has length {1}, but the field {2} has length {3}")]
    FieldLengthMismatch(&'static str, usize, &'static str, usize),
    #[error("Identity secret recovery error: {0}")]
    IdSecretRecovery(#[from] RecoverSecretError),
    #[error("Constraint system is not initialized")]
    UninitializedConstraintSystem,
    #[error("Merkle tree operation error: {0}")]
    MerkleTree(#[from] ZerokitMerkleTreeError),
    #[error("Proof serialization error: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("Unknown message mode version byte: {0:#04x}")]
    UnknownMessageModeVersionByte(u8),
    #[error("Witness message mode {witness_mode} does not match graph mode {graph_mode}")]
    MessageModeAndGraphMismatch {
        witness_mode: MessageMode,
        graph_mode: MessageMode,
    },
    #[error("Field `{field}` does not exist on the `{variant}` variant")]
    FieldNotInVariant {
        field: &'static str,
        variant: &'static str,
    },
}

/// Errors that can occur during proof verification
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("Invalid proof provided")]
    InvalidProof,
    #[error("Expected one of the provided roots")]
    InvalidRoot,
    #[error("Signal value does not match")]
    InvalidSignal,
}

/// Top-level RLN error type encompassing all RLN operations
#[derive(Debug, thiserror::Error)]
pub enum RLNError {
    #[error("Configuration error: {0}")]
    Config(#[from] FromConfigError),
    #[error("Merkle tree error: {0}")]
    MerkleTree(#[from] ZerokitMerkleTreeError),
    #[error("ZKey error: {0}")]
    ZKey(#[from] ZKeyReadError),
    #[error("Graph error: {0}")]
    Graph(#[from] GraphReadError),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Verification error: {0}")]
    Verify(#[from] VerifyError),
}

// TODO(PR10): delete UtilsError, ProtocolError, RLNError and strip V3 suffixes

/// Errors that can occur during witness input operations
#[derive(Debug, thiserror::Error)]
pub enum WitnessInputErrorV3 {
    #[error("User message limit cannot be zero")]
    ZeroUserMessageLimit,
    #[error("Message id ({message_id}) is not within user_message_limit ({user_message_limit})")]
    InvalidMessageId {
        message_id: Fr,
        user_message_limit: Fr,
    },
    #[error("The field message_ids must contain at least one message_id")]
    EmptyMessageIds,
    #[error("Duplicate message ID found in message_ids")]
    DuplicateMessageIds,
    #[error("At least one selector_used value must be true")]
    NoActiveSelectorUsed,
    #[error("The field {field1} has length {len1}, but the field {field2} has length {len2}")]
    FieldLengthMismatch {
        field1: &'static str,
        len1: usize,
        field2: &'static str,
        len2: usize,
    },
    #[error("Field `{field}` does not exist on the `{variant}` variant")]
    FieldNotInVariant {
        field: &'static str,
        variant: &'static str,
    },
}

/// Errors that can occur during proof values operations
#[derive(Debug, thiserror::Error)]
pub enum ProofValuesErrorV3 {
    #[error("Field `{field}` does not exist on the `{variant}` proof values variant")]
    FieldNotInVariant {
        field: &'static str,
        variant: &'static str,
    },
}

/// Errors that can occur during serialization and deserialization of RLN types
#[derive(Debug, thiserror::Error)]
pub enum SerializationErrorV3 {
    #[error("IO error: {0}")]
    Io(#[from] Error),
    #[error("Arkworks canonical serialization error: {0}")]
    ArkworksSerializationError(#[from] SerializationError),
    #[error("Non-canonical field element: value is not in [0, r-1]")]
    NonCanonicalFieldElement,
    #[error("Non-canonical bool byte: expected 0x00 or 0x01, got {0:#04x}")]
    NonCanonicalBool(u8),
    #[error("Failed to convert from slice: {0}")]
    FromSlice(#[from] TryFromSliceError),
    #[error("Failed to convert to usize: {0}")]
    ToUsize(#[from] TryFromIntError),
}

/// Errors that can occur during RLN instance initialization
#[derive(Debug, thiserror::Error)]
pub enum InitErrorV3 {
    #[error("ZKey error: {0}")]
    ZKey(#[from] ZKeyReadError),
    #[error("Graph error: {0}")]
    Graph(#[from] GraphReadError),
    #[error("Configuration error: {0}")]
    Config(#[from] FromConfigError),
}

/// Top-level error type for all V3 RLN operations
#[derive(Debug, thiserror::Error)]
pub enum RLNErrorV3 {
    #[error("Initialization error: {0}")]
    Init(#[from] InitErrorV3),
    #[error("Witness input error: {0}")]
    WitnessInput(#[from] WitnessInputErrorV3),
    #[error("Proof values error: {0}")]
    ProofValues(#[from] ProofValuesErrorV3),
    #[error("Witness calculation error: {0}")]
    WitnessCalc(#[from] WitnessCalcError),
    #[error("Synthesis error: {0}")]
    Synthesis(#[from] SynthesisError),
    #[error("Merkle tree error: {0}")]
    MerkleTree(#[from] ZerokitMerkleTreeError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationErrorV3),
    #[error("Verification error: {0}")]
    Verify(#[from] VerifyError),
    #[error("Secret recovery error: {0}")]
    RecoverSecret(#[from] RecoverSecretError),
}
