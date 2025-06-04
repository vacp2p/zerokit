use crate::circuit::error::ZKeyReadError;
use ark_bn254::Fr;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::SerializationError;
use num_bigint::{BigInt, ParseBigIntError};
use std::array::TryFromSliceError;
use std::num::TryFromIntError;
use std::string::FromUtf8Error;
use thiserror::Error;
use utils::error::{FromConfigError, ZerokitMerkleTreeError};

#[derive(Debug, thiserror::Error)]
pub enum ConversionError {
    #[error("Expected radix 10 or 16")]
    WrongRadix,
    #[error("{0}")]
    ParseBigInt(#[from] ParseBigIntError),
    #[error("{0}")]
    ToUsize(#[from] TryFromIntError),
    #[error("{0}")]
    FromSlice(#[from] TryFromSliceError),
}

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("{0}")]
    ProtocolError(#[from] ProtocolError),
    #[error("Error producing proof: {0}")]
    SynthesisError(#[from] SynthesisError),
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("{0}")]
    Conversion(#[from] ConversionError),
    #[error("Expected to read {0} bytes but read only {1} bytes")]
    InvalidReadLen(usize, usize),
    #[error("Cannot convert bigint {0:?} to biguint")]
    BigUintConversion(BigInt),
    #[error("{0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Message id ({0}) is not within user_message_limit ({1})")]
    InvalidMessageId(Fr, Fr),
}

#[derive(Debug, thiserror::Error)]
pub enum ComputeIdSecretError {
    /// Usually it means that the same signal is used to recover the user secret hash
    #[error("Cannot recover secret: division by zero")]
    DivisionByZero,
}

#[derive(Debug, thiserror::Error)]
pub enum RLNError {
    #[error("I/O error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Utf8 error: {0}")]
    Utf8(#[from] FromUtf8Error),
    #[error("Serde json error: {0}")]
    JSON(#[from] serde_json::Error),
    #[error("Config error: {0}")]
    Config(#[from] FromConfigError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] SerializationError),
    #[error("Merkle tree error: {0}")]
    MerkleTree(#[from] ZerokitMerkleTreeError),
    #[error("ZKey error: {0}")]
    ZKey(#[from] ZKeyReadError),
    #[error("Conversion error: {0}")]
    Conversion(#[from] ConversionError),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Proof error: {0}")]
    Proof(#[from] ProofError),
    #[error("Unable to extract secret")]
    RecoverSecret(#[from] ComputeIdSecretError),
}
