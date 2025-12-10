use std::{array::TryFromSliceError, num::TryFromIntError};

use ark_relations::r1cs::SynthesisError;
use num_bigint::{BigInt, ParseBigIntError};
use thiserror::Error;
use utils::error::{FromConfigError, ZerokitMerkleTreeError};

use crate::circuit::{
    error::{WitnessCalcError, ZKeyReadError},
    Fr,
};

#[derive(Debug, thiserror::Error)]
pub enum UtilsError {
    #[error("Expected radix 10 or 16")]
    WrongRadix,
    #[error("{0}")]
    ParseBigInt(#[from] ParseBigIntError),
    #[error("{0}")]
    ToUsize(#[from] TryFromIntError),
    #[error("{0}")]
    FromSlice(#[from] TryFromSliceError),
    #[error("Input data too short: expected at least {expected} bytes, got {actual} bytes")]
    InsufficientData { expected: usize, actual: usize },
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Error producing proof: {0}")]
    Synthesis(#[from] SynthesisError),
    #[error("{0}")]
    Utils(#[from] UtilsError),
    #[error("Error calculating witness: {0}")]
    WitnessCalc(#[from] WitnessCalcError),
    #[error("Expected to read {0} bytes but read only {1} bytes")]
    InvalidReadLen(usize, usize),
    #[error("Cannot convert bigint {0:?} to biguint")]
    BigUintConversion(BigInt),
    #[error("Message id ({0}) is not within user_message_limit ({1})")]
    InvalidMessageId(Fr, Fr),
    #[error("Merkle proof length mismatch: expected {0}, got {1}")]
    InvalidMerkleProofLength(usize, usize),
    #[error("External nullifiers mismatch: {0} != {1}")]
    ExternalNullifierMismatch(Fr, Fr),
    #[error("Cannot recover secret: division by zero")]
    DivisionByZero,
    #[error("Merkle tree error: {0}")]
    MerkleTree(#[from] ZerokitMerkleTreeError),
}

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Invalid proof provided")]
    InvalidProof,
    #[error("Expected one of the provided roots")]
    InvalidRoot,
    #[error("Signal value does not match")]
    InvalidSignal,
}

#[derive(Debug, thiserror::Error)]
pub enum RLNError {
    #[error("Config error: {0}")]
    Config(#[from] FromConfigError),
    #[error("Merkle tree error: {0}")]
    MerkleTree(#[from] ZerokitMerkleTreeError),
    #[error("ZKey error: {0}")]
    ZKey(#[from] ZKeyReadError),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Verify error: {0}")]
    Verify(#[from] VerifyError),
}
