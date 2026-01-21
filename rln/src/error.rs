use std::{array::TryFromSliceError, num::TryFromIntError};

use ark_relations::r1cs::SynthesisError;
use num_bigint::{BigInt, ParseBigIntError};
use thiserror::Error;
use zerokit_utils::error::{FromConfigError, HashError, ZerokitMerkleTreeError};

use crate::circuit::{
    error::{GraphReadError, WitnessCalcError, ZKeyReadError},
    Fr,
};

/// Errors that can occur during RLN utility operations (conversions, parsing, etc.)
#[derive(Debug, thiserror::Error)]
pub enum UtilsError {
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
}

/// Errors that can occur during RLN protocol operations (proof generation, verification, etc.)
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Error producing proof: {0}")]
    Synthesis(#[from] SynthesisError),
    #[error("RLN utility error: {0}")]
    Utils(#[from] UtilsError),
    #[error("Error calculating witness: {0}")]
    WitnessCalc(#[from] WitnessCalcError),
    #[error("Expected to read {0} bytes but read only {1} bytes")]
    InvalidReadLen(usize, usize),
    #[error("Cannot convert bigint {0:?} to biguint")]
    BigUintConversion(BigInt),
    #[error("Message id ({0}) is not within user_message_limit ({1})")]
    InvalidMessageId(Fr, Fr),
    #[error("User message limit cannot be zero")]
    ZeroUserMessageLimit,
    #[error("Merkle proof length mismatch: expected {0}, got {1}")]
    InvalidMerkleProofLength(usize, usize),
    #[error("External nullifiers mismatch: {0} != {1}")]
    ExternalNullifierMismatch(Fr, Fr),
    #[error("Cannot recover secret: division by zero")]
    DivisionByZero,
    #[error("Merkle tree operation error: {0}")]
    MerkleTree(#[from] ZerokitMerkleTreeError),
    #[error("Hash computation error: {0}")]
    Hash(#[from] HashError),
    #[error("Proof serialization error: {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

/// Errors that can occur during proof verification
#[derive(Error, Debug)]
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
    #[error("Hash error: {0}")]
    Hash(#[from] HashError),
    #[error("ZKey error: {0}")]
    ZKey(#[from] ZKeyReadError),
    #[error("Graph error: {0}")]
    Graph(#[from] GraphReadError),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Verification error: {0}")]
    Verify(#[from] VerifyError),
}
