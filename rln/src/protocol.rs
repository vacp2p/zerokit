// This crate collects all the underlying primitives used to implement RLN
#[cfg(not(feature = "stateless"))]
use {crate::error::ConversionError, crate::poseidon_tree::PoseidonTree};

use crate::circuit::{calculate_rln_witness, qap::CircomReduction, Curve};
use crate::error::{ComputeIdSecretError, ProofError, ProtocolError};
use crate::hashers::{hash_to_field_be, hash_to_field_le, poseidon_hash, PoseidonHash};
use crate::utils::{
    bytes_be_to_fr, bytes_be_to_vec_fr, bytes_be_to_vec_u8, bytes_le_to_fr, bytes_le_to_vec_fr,
    bytes_le_to_vec_u8, fr_byte_size, fr_to_bytes_be, fr_to_bytes_le, normalize_usize_be,
    normalize_usize_le, to_bigint, vec_fr_to_bytes_be, vec_fr_to_bytes_le, vec_u8_to_bytes_be,
    vec_u8_to_bytes_le, FrOrSecret, IdSecret,
};
use ark_bn254::{Fr, FrConfig};
use ark_ff::{AdditiveGroup, Fp, MontBackend};
use ark_groth16::{prepare_verifying_key, Groth16, Proof as ArkProof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::thread_rng, UniformRand};
use num_bigint::BigInt;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::time::Instant;
use tiny_keccak::{Hasher as _, Keccak};
use utils::{OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree};
use zeroize::Zeroize;
///////////////////////////////////////////////////////
// RLN Witness data structure and utility functions
///////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RLNWitnessInput {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    identity_secret: IdSecret,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    user_message_limit: Fr,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    message_id: Fr,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    path_elements: Vec<Fr>,
    identity_path_index: Vec<u8>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    x: Fr,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    external_nullifier: Fr,
}

#[derive(Debug, PartialEq)]
pub struct RLNProofValues {
    // Public outputs:
    pub y: Fr,
    pub nullifier: Fr,
    pub root: Fr,
    // Public Inputs:
    pub x: Fr,
    pub external_nullifier: Fr,
}

pub fn serialize_field_element(element: Fr) -> Vec<u8> {
    fr_to_bytes_le(&element)
}

pub fn serialize_field_element_be(element: Fr) -> Vec<u8> {
    fr_to_bytes_be(&element)
}

pub fn deserialize_field_element(serialized: Vec<u8>) -> Fr {
    let (element, _) = bytes_le_to_fr(&serialized);
    element
}

pub fn deserialize_field_element_be(serialized: Vec<u8>) -> Fr {
    let (element, _) = bytes_be_to_fr(&serialized);
    element
}

pub fn deserialize_identity_pair_le(serialized: Vec<u8>) -> (IdSecret, Fr) {
    let (identity_secret, read) = IdSecret::from_bytes_le(&serialized);
    let (id_commitment, _) = bytes_le_to_fr(&serialized[read..]);

    (identity_secret, id_commitment)
}

/// Deserializes an identity pair in big endian format
///
/// The identity pair is deserialized from a byte vector in big endian format.
/// Data expected to be in the following order:
/// - identity_secret: 32 bytes
/// - id_commitment: 32 bytes
pub fn deserialize_identity_pair_be(serialized: Vec<u8>) -> (IdSecret, Fr) {
    let (identity_secret, read) = IdSecret::from_bytes_be(&serialized);
    let (id_commitment, _) = bytes_be_to_fr(&serialized[read..]);

    (identity_secret, id_commitment)
}

pub fn deserialize_identity_tuple_le(serialized: Vec<u8>) -> (Fr, Fr, Fr, Fr) {
    let mut all_read = 0;

    let (identity_trapdoor, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (identity_nullifier, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (identity_secret_hash, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (identity_commitment, _) = bytes_le_to_fr(&serialized[all_read..]);

    (
        identity_trapdoor,
        identity_nullifier,
        identity_secret_hash,
        identity_commitment,
    )
}

/// Deserializes an identity tuple in big endian format
///
/// The identity tuple is deserialized from a byte vector in big endian format.
/// Data expected to be in the following order:
/// - identity_trapdoor: 32 bytes
/// - identity_nullifier: 32 bytes
/// - identity_secret_hash: 32 bytes
/// - identity_commitment: 32 bytes
pub fn deserialize_identity_tuple_be(serialized: Vec<u8>) -> (Fr, Fr, Fr, Fr) {
    let mut all_read = 0;

    let (identity_trapdoor, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (identity_nullifier, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (identity_secret_hash, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (identity_commitment, _) = bytes_be_to_fr(&serialized[all_read..]);

    (
        identity_trapdoor,
        identity_nullifier,
        identity_secret_hash,
        identity_commitment,
    )
}

/// Serializes witness in little endian format
///
/// The witness is serialized as a byte vector in little endian format.
/// The witness is serialized as follows:
/// - identity_secret: 32 bytes
/// - user_message_limit: 32 bytes
/// - message_id: 32 bytes
/// - path_elements length: 8 bytes
/// - path_elements: variable number of 32 bytes
/// - identity_path_index length: 8 bytes
/// - identity_path_index: variable number of 8 bytes
/// - x: 32 bytes
/// - external_nullifier: 32 bytes
///
/// # Errors
///
/// Returns an error if `rln_witness.message_id` is not within `rln_witness.user_message_limit`.
pub fn serialize_witness_le(rln_witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    // Check if message_id is within user_message_limit
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    // Calculate capacity for Vec:
    // - 5 fixed field elements: identity_secret, user_message_limit, message_id, x, external_nullifier
    // - variable number of path elements where each element is a field element
    // - identity_path_index (variable size)
    let mut serialized: Vec<u8> = Vec::with_capacity(
        fr_byte_size() * (5 + rln_witness.path_elements.len())
            + rln_witness.identity_path_index.len(),
    );
    serialized.extend_from_slice(&rln_witness.identity_secret.to_bytes_le());
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_witness.user_message_limit));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_witness.message_id));
    serialized.extend_from_slice(&vec_fr_to_bytes_le(&rln_witness.path_elements));
    serialized.extend_from_slice(&vec_u8_to_bytes_le(&rln_witness.identity_path_index));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_witness.x));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_witness.external_nullifier));

    Ok(serialized)
}

/// Serializes witness in big endian format
///
/// The witness is serialized as a byte vector in big endian format.
/// The witness is serialized as follows:
/// - identity_secret: 32 bytes
/// - user_message_limit: 32 bytes
/// - message_id: 32 bytes
/// - path_elements length: 8 bytes
/// - path_elements: variable number of 32 bytes
/// - identity_path_index length: 8 bytes
/// - identity_path_index: variable number of 8 bytes
/// - x: 32 bytes
/// - external_nullifier: 32 bytes
///
/// # Errors
///
/// Returns an error if `rln_witness.message_id` is not within `rln_witness.user_message_limit`.
pub fn serialize_witness_be(rln_witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    // Check if message_id is within user_message_limit
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    // Calculate capacity for Vec:
    // - 5 fixed field elements: identity_secret, user_message_limit, message_id, x, external_nullifier
    // - variable number of path elements where each element is a field element
    // - identity_path_index (variable size)
    let mut serialized: Vec<u8> = Vec::with_capacity(
        fr_byte_size() * (5 + rln_witness.path_elements.len())
            + rln_witness.identity_path_index.len(),
    );
    serialized.extend_from_slice(&rln_witness.identity_secret.to_bytes_be());
    serialized.extend_from_slice(&fr_to_bytes_be(&rln_witness.user_message_limit));
    serialized.extend_from_slice(&fr_to_bytes_be(&rln_witness.message_id));
    serialized.extend_from_slice(&vec_fr_to_bytes_be(&rln_witness.path_elements));
    serialized.extend_from_slice(&vec_u8_to_bytes_be(&rln_witness.identity_path_index));
    serialized.extend_from_slice(&fr_to_bytes_be(&rln_witness.x));
    serialized.extend_from_slice(&fr_to_bytes_be(&rln_witness.external_nullifier));

    Ok(serialized)
}

/// Deserializes witness in little endian format
///
/// The witness is deserialized from a byte vector in little endian format.
/// The input witness vector MUST be constructed as follows:
/// - identity_secret: 32 bytes
/// - user_message_limit: 32 bytes
/// - message_id: 32 bytes
/// - path_elements length: 8 bytes
/// - path_elements: variable number of 32 bytes
/// - identity_path_index length: 8 bytes
/// - identity_path_index: variable number of 8 bytes
/// - x: 32 bytes
/// - external_nullifier: 32 bytes
///
/// # Errors
/// - `ProtocolError::MessageIdRangeCheck` if `message_id` is not within `user_message_limit`.
/// - `ProtocolError::InvalidReadLen` if the input witness vector is not constructed as specified above.
pub fn deserialize_witness_le(
    serialized: &[u8],
) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    let mut all_read: usize = 0;

    let (identity_secret, read) = IdSecret::from_bytes_le(&serialized[all_read..]);
    all_read += read;

    let (user_message_limit, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (message_id, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    message_id_range_check(&message_id, &user_message_limit)?;

    let (path_elements, read) = bytes_le_to_vec_fr(&serialized[all_read..])?;
    all_read += read;

    let (identity_path_index, read) = bytes_le_to_vec_u8(&serialized[all_read..])?;
    all_read += read;

    let (x, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (external_nullifier, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    invalid_read_len_check(serialized.len(), all_read)?;

    Ok((
        RLNWitnessInput {
            identity_secret,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            user_message_limit,
            message_id,
        },
        all_read,
    ))
}

/// Deserializes witness in big endian format
///
/// The witness is deserialized from a byte vector in big endian format.
/// The input witness vector MUST be constructed as follows:
/// - identity_secret: 32 bytes
/// - user_message_limit: 32 bytes
/// - message_id: 32 bytes
/// - path_elements length: 8 bytes
/// - path_elements: variable number of 32 bytes
/// - identity_path_index length: 8 bytes
/// - identity_path_index: variable number of 8 bytes
/// - x: 32 bytes
/// - external_nullifier: 32 bytes
///
/// # Errors
/// - `ProtocolError::MessageIdRangeCheck` if `message_id` is not within `user_message_limit`.
/// - `ProtocolError::InvalidReadLen` if the input witness vector is not constructed as specified above.
pub fn deserialize_witness_be(
    serialized: &[u8],
) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    let mut all_read: usize = 0;

    let (identity_secret, read) = IdSecret::from_bytes_be(&serialized[all_read..]);
    all_read += read;

    let (user_message_limit, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (message_id, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    message_id_range_check(&message_id, &user_message_limit)?;

    let (path_elements, read) = bytes_be_to_vec_fr(&serialized[all_read..])?;
    all_read += read;

    let (identity_path_index, read) = bytes_be_to_vec_u8(&serialized[all_read..])?;
    all_read += read;

    let (x, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (external_nullifier, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    invalid_read_len_check(serialized.len(), all_read)?;

    Ok((
        RLNWitnessInput {
            identity_secret,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            user_message_limit,
            message_id,
        },
        all_read,
    ))
}

/// This function deserializes input for [kilic's rln generate_proof](https://github.com/kilic/rln/blob/7ac74183f8b69b399e3bc96c1ae8ab61c026dc43/src/public.rs#L148) public API
///
/// The input proof vector MUST be constructed as follows:
/// - identity_secret: 32 bytes
/// - id_index: 8 bytes
/// - user_message_limit: 32 bytes
/// - message_id: 32 bytes
/// - external_nullifier: 32 bytes
/// - signal_len: 8 bytes
/// - signal: variable number of bytes
///
/// Also, function required a related merkle tree to get the path elements and identity path index.
///
/// # Errors
/// - `ProtocolError::MessageIdRangeCheck` if `message_id` is not within `user_message_limit`.
/// - `ProtocolError::InvalidReadLen` if the input witness vector is not constructed as specified above.
/// - `ProtocolError::MerkleTree` if getting the merkle tree proof fails.
/// - `ProtocolError::Conversion` if converting the u64 to usize fails.
#[cfg(not(feature = "stateless"))]
pub fn proof_inputs_to_rln_witness_le(
    tree: &mut PoseidonTree,
    serialized: &[u8],
) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    let mut all_read: usize = 0;

    let (identity_secret, read) = IdSecret::from_bytes_le(&serialized[all_read..]);
    all_read += read;

    let id_index = usize::try_from(u64::from_le_bytes(
        serialized[all_read..all_read + 8]
            .try_into()
            .map_err(ConversionError::FromSlice)?,
    ))
    .map_err(ConversionError::ToUsize)?;
    all_read += 8;

    let (user_message_limit, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (message_id, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    message_id_range_check(&message_id, &user_message_limit)?;

    let (external_nullifier, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let signal_len = usize::try_from(u64::from_le_bytes(
        serialized[all_read..all_read + 8]
            .try_into()
            .map_err(ConversionError::FromSlice)?,
    ))
    .map_err(ConversionError::ToUsize)?;
    all_read += 8;

    let signal: Vec<u8> = serialized[all_read..all_read + signal_len].to_vec();

    invalid_read_len_check(serialized.len(), all_read + signal_len)?;

    let merkle_proof = tree.proof(id_index).map_err(ProtocolError::MerkleTree)?;
    let path_elements = merkle_proof.get_path_elements();
    let identity_path_index = merkle_proof.get_path_index();

    let x = hash_to_field_le(&signal);

    Ok((
        RLNWitnessInput {
            identity_secret,
            path_elements,
            identity_path_index,
            user_message_limit,
            message_id,
            x,
            external_nullifier,
        },
        all_read,
    ))
}

/// This function deserializes input for [kilic's rln generate_proof](https://github.com/kilic/rln/blob/7ac74183f8b69b399e3bc96c1ae8ab61c026dc43/src/public.rs#L148) public API
///
/// The input proof vector MUST be constructed as follows:
/// - identity_secret: 32 bytes
/// - id_index: 8 bytes
/// - user_message_limit: 32 bytes
/// - message_id: 32 bytes
/// - external_nullifier: 32 bytes
/// - signal_len: 8 bytes
/// - signal: variable number of bytes
///
/// Also, function required a related merkle tree to get the path elements and identity path index.
///
/// # Errors
/// - `ProtocolError::MessageIdRangeCheck` if `message_id` is not within `user_message_limit`.
/// - `ProtocolError::InvalidReadLen` if the input witness vector is not constructed as specified above.
/// - `ProtocolError::MerkleTree` if getting the merkle tree proof fails.
/// - `ProtocolError::Conversion` if converting the u64 to usize fails.
#[cfg(not(feature = "stateless"))]
pub fn proof_inputs_to_rln_witness_be(
    tree: &mut PoseidonTree,
    serialized: &[u8],
) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    use crate::hashers::hash_to_field_be;

    let mut all_read: usize = 0;

    let (identity_secret, read) = IdSecret::from_bytes_be(&serialized[all_read..]);
    all_read += read;

    let id_index = usize::try_from(u64::from_be_bytes(
        serialized[all_read..all_read + 8]
            .try_into()
            .map_err(ConversionError::FromSlice)?,
    ))
    .map_err(ConversionError::ToUsize)?;
    all_read += 8;

    let (user_message_limit, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (message_id, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    message_id_range_check(&message_id, &user_message_limit)?;

    let (external_nullifier, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let signal_len = usize::try_from(u64::from_be_bytes(
        serialized[all_read..all_read + 8]
            .try_into()
            .map_err(ConversionError::FromSlice)?,
    ))
    .map_err(ConversionError::ToUsize)?;
    all_read += 8;

    let signal: Vec<u8> = serialized[all_read..all_read + signal_len].to_vec();

    invalid_read_len_check(serialized.len(), all_read + signal_len)?;

    let merkle_proof = tree.proof(id_index).map_err(ProtocolError::MerkleTree)?;
    let path_elements = merkle_proof.get_path_elements();
    let identity_path_index = merkle_proof.get_path_index();

    let x = hash_to_field_be(&signal);

    Ok((
        RLNWitnessInput {
            identity_secret,
            path_elements,
            identity_path_index,
            user_message_limit,
            message_id,
            x,
            external_nullifier,
        },
        all_read,
    ))
}

/// Generates proof values from a witness.
///
/// # Errors
/// - `ProtocolError::MessageIdRangeCheck` if `message_id` is not within `user_message_limit`.
pub fn proof_values_from_witness(
    rln_witness: &RLNWitnessInput,
) -> Result<RLNProofValues, ProtocolError> {
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    // y share
    let a_0 = &rln_witness.identity_secret;
    let mut to_hash = [
        *(a_0.clone()),
        rln_witness.external_nullifier,
        rln_witness.message_id,
    ];
    let a_1 = poseidon_hash(&to_hash);
    let y = *(a_0.clone()) + rln_witness.x * a_1;

    // Nullifier
    let nullifier = poseidon_hash(&[a_1]);
    to_hash[0].zeroize();

    // Merkle tree root computations
    let root = compute_tree_root(
        &rln_witness.identity_secret,
        &rln_witness.user_message_limit,
        &rln_witness.path_elements,
        &rln_witness.identity_path_index,
    );

    Ok(RLNProofValues {
        y,
        nullifier,
        root,
        x: rln_witness.x,
        external_nullifier: rln_witness.external_nullifier,
    })
}

/// Serializes proof values in little endian format.
///
/// The proof values are serialized into a byte vector in little endian format.
/// The output byte vector MUST be constructed as follows:
/// - root: 32 bytes
/// - external_nullifier: 32 bytes
/// - x: 32 bytes
/// - y: 32 bytes
/// - nullifier: 32 bytes
pub fn serialize_proof_values_le(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    // Calculate capacity for Vec:
    // 5 field elements: root, external_nullifier, x, y, nullifier
    let mut serialized = Vec::with_capacity(fr_byte_size() * 5);

    serialized.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.root));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.external_nullifier));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.x));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.y));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.nullifier));

    serialized
}

/// Serializes proof values in big endian format.
///
/// The proof values are serialized into a byte vector in big endian format.
/// The output byte vector MUST be constructed as follows:
/// - root: 32 bytes
/// - external_nullifier: 32 bytes
/// - x: 32 bytes
/// - y: 32 bytes
/// - nullifier: 32 bytes
pub fn serialize_proof_values_be(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    // Calculate capacity for Vec:
    // 5 field elements: root, external_nullifier, x, y, nullifier
    let mut serialized = Vec::with_capacity(fr_byte_size() * 5);

    serialized.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.root));
    serialized.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.external_nullifier));
    serialized.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.x));
    serialized.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.y));
    serialized.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.nullifier));

    serialized
}

/// Deserializes proof values in little endian format.
///
/// Note: don't forget to skip the 128 bytes representing the ZK proof.
///
/// The proof values are deserialized from a byte vector in little endian format.
/// The input byte vector MUST be constructed as follows:
/// - root: 32 bytes
/// - external_nullifier: 32 bytes
/// - x: 32 bytes
/// - y: 32 bytes
/// - nullifier: 32 bytes
pub fn deserialize_proof_values_le(serialized: &[u8]) -> (RLNProofValues, usize) {
    let mut all_read: usize = 0;

    let (root, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (external_nullifier, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (x, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (y, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (nullifier, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    (
        RLNProofValues {
            y,
            nullifier,
            root,
            x,
            external_nullifier,
        },
        all_read,
    )
}

/// Deserializes proof values in big endian format.
///
/// Note: don't forget to skip the 128 bytes representing the ZK proof.
///
/// The proof values are deserialized from a byte vector in big endian format.
/// The input byte vector MUST be constructed as follows:
/// - root: 32 bytes
/// - external_nullifier: 32 bytes
/// - x: 32 bytes
/// - y: 32 bytes
/// - nullifier: 32 bytes
pub fn deserialize_proof_values_be(serialized: &[u8]) -> (RLNProofValues, usize) {
    let mut all_read: usize = 0;

    let (root, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (external_nullifier, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (x, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (y, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (nullifier, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    (
        RLNProofValues {
            y,
            nullifier,
            root,
            x,
            external_nullifier,
        },
        all_read,
    )
}

///////////////////////////////////////////////////////
// Merkle tree utility functions
///////////////////////////////////////////////////////

/// Computes the tree root from the identity secret, user message limit, path elements and identity path index.
///
/// The tree root is computed as follows:
/// - id_commitment = PoseidonHash(identity_secret)
/// - initial root = PoseidonHash(id_commitment, user_message_limit)
/// - for each path element, if the identity path index is 0, root = PoseidonHash(root, path_element)
/// - for each path element, if the identity path index is 1, root = PoseidonHash(path_element, root)
/// - return root
pub fn compute_tree_root(
    identity_secret: &IdSecret,
    user_message_limit: &Fr,
    path_elements: &[Fr],
    identity_path_index: &[u8],
) -> Fr {
    let mut to_hash = [*identity_secret.clone()];
    let id_commitment = poseidon_hash(&to_hash);
    to_hash[0].zeroize();

    let mut root = poseidon_hash(&[id_commitment, *user_message_limit]);

    for i in 0..identity_path_index.len() {
        if identity_path_index[i] == 0 {
            root = poseidon_hash(&[root, path_elements[i]]);
        } else {
            root = poseidon_hash(&[path_elements[i], root]);
        }
    }

    root
}

///////////////////////////////////////////////////////
// Protocol utility functions
///////////////////////////////////////////////////////

/// Generates a tuple (identity_secret_hash, id_commitment) where
/// - identity_secret_hash is a random field element generated using thread_rng()
/// - id_commitment = PoseidonHash(identity_secret_hash)
pub fn keygen() -> (IdSecret, Fr) {
    let mut rng = thread_rng();
    let identity_secret_hash = IdSecret::rand(&mut rng);
    let mut to_hash = [*identity_secret_hash.clone()];
    let id_commitment = poseidon_hash(&to_hash);
    to_hash[0].zeroize();
    (identity_secret_hash, id_commitment)
}

/// Generates a tuple (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) where
/// - identity_trapdoor and identity_nullifier are random field elements generated using thread_rng()
/// - identity_secret_hash = PoseidonHash(identity_trapdoor, identity_nullifier)
/// - id_commitment = PoseidonHash(identity_secret_hash)
///
/// Generated credentials are compatible with Semaphore credentials
pub fn extended_keygen() -> (Fr, Fr, Fr, Fr) {
    let mut rng = thread_rng();
    let identity_trapdoor = Fr::rand(&mut rng);
    let identity_nullifier = Fr::rand(&mut rng);
    let identity_secret_hash = poseidon_hash(&[identity_trapdoor, identity_nullifier]);
    let id_commitment = poseidon_hash(&[identity_secret_hash]);
    (
        identity_trapdoor,
        identity_nullifier,
        identity_secret_hash,
        id_commitment,
    )
}

/// Generates a tuple (identity_secret_hash, id_commitment) where
/// - identity_secret_hash is a random field element generated
///   using 20 rounds of ChaCha seeded with the hash of the input_seed
/// - id_commitment = PoseidonHash(identity_secret_hash)
pub fn seeded_keygen(input_seed: &[u8]) -> (Fr, Fr) {
    // ChaCha20 requires a seed of exactly 32 bytes.
    // We first hash the input seed signal to a 32 bytes array and pass this as seed to ChaCha20
    let mut seed = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(input_seed);
    hasher.finalize(&mut seed);

    let mut rng = ChaCha20Rng::from_seed(seed);
    let identity_secret_hash = Fr::rand(&mut rng);
    let id_commitment = poseidon_hash(&[identity_secret_hash]);
    (identity_secret_hash, id_commitment)
}

/// Generates a tuple (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) where
/// - identity_trapdoor and identity_nullifier are random field elements generated
///   using 20 rounds of ChaCha seeded with the hash of the input_seed
/// - identity_secret_hash = PoseidonHash(identity_trapdoor, identity_nullifier)
/// - id_commitment = PoseidonHash(identity_secret_hash)
///
/// Generated credentials are compatible with Semaphore credentials
pub fn extended_seeded_keygen(input_seed: &[u8]) -> (Fr, Fr, Fr, Fr) {
    // ChaCha20 requires a seed of exactly 32 bytes.
    // We first hash the input seed signal to a 32 bytes array and pass this as seed to ChaCha20
    let mut seed = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(input_seed);
    hasher.finalize(&mut seed);

    let mut rng = ChaCha20Rng::from_seed(seed);
    let identity_trapdoor = Fr::rand(&mut rng);
    let identity_nullifier = Fr::rand(&mut rng);
    let identity_secret_hash = poseidon_hash(&[identity_trapdoor, identity_nullifier]);
    let id_commitment = poseidon_hash(&[identity_secret_hash]);
    (
        identity_trapdoor,
        identity_nullifier,
        identity_secret_hash,
        id_commitment,
    )
}

/// Computes the identity secret from two shares.
///
/// # Errors
/// - `ComputeIdSecretError::DivisionByZero` if the two input shares were computed for
///   the same external_nullifier and identity secret.
pub fn compute_id_secret(
    share1: (Fr, Fr),
    share2: (Fr, Fr),
) -> Result<IdSecret, ComputeIdSecretError> {
    // Assuming a0 is the identity secret and a1 = poseidonHash([a0, external_nullifier]),
    // a (x,y) share satisfies the following relation
    // y = a_0 + x * a_1
    let (x1, y1) = share1;
    let (x2, y2) = share2;

    // If the two input shares were computed for the same external_nullifier and identity secret,
    // we can recover the latter.
    // y1 = a_0 + x1 * a_1
    // y2 = a_0 + x2 * a_1

    if (x1 - x2) != Fr::ZERO {
        let a_1 = (y1 - y2) / (x1 - x2);
        let mut a_0 = y1 - x1 * a_1;

        // If shares come from the same polynomial, a0 is correctly recovered and a1 = poseidonHash([a0, external_nullifier])
        let id_secret = IdSecret::from(&mut a_0);
        Ok(id_secret)
    } else {
        Err(ComputeIdSecretError::DivisionByZero)
    }
}

///////////////////////////////////////////////////////
// zkSNARK utility functions
///////////////////////////////////////////////////////

/// Calculates the witness element from the witness vector of BigInts.
///
/// # Errors
/// - `ProtocolError::BigUintConversion` if converting the BigInt to E::ScalarField fails.
#[cfg(target_arch = "wasm32")]
fn prepare_witness_for_wasm_proof<E: ark_ec::pairing::Pairing>(
    witness: Vec<BigInt>,
) -> Result<Vec<E::ScalarField>, ProtocolError> {
    use ark_ff::PrimeField;
    let modulus = <E::ScalarField as PrimeField>::MODULUS;

    // convert it to field elements
    use num_traits::Signed;
    let mut witness_vec = vec![];
    for w in witness.into_iter() {
        let w = if w.sign() == num_bigint::Sign::Minus {
            // Need to negate the witness element if negative
            modulus.into()
                - w.abs()
                    .to_biguint()
                    .ok_or(ProtocolError::BigUintConversion(w))?
        } else {
            w.to_biguint().ok_or(ProtocolError::BigUintConversion(w))?
        };
        witness_vec.push(E::ScalarField::from(w))
    }

    Ok(witness_vec)
}

/// Generates a proof with a calculated witness.
/// As inputs it takes a witness vector of BigInts and a proving key.
/// The witness vector is converted to a vector of field elements and
/// then the proof is generated using the Groth16 proof system.
///
/// # Errors
/// - `ProofError::ProtocolError` if converting the BigInt to E::ScalarField fails.
/// - `ProofError::SynthesisError` if generating the proof fails.
#[cfg(target_arch = "wasm32")]
pub fn generate_proof_with_calculated_witness(
    witness: Vec<BigInt>,
    proving_key: &(ProvingKey<Curve>, ConstraintMatrices<Fr>),
) -> Result<ArkProof<Curve>, ProofError> {
    // If in debug mode, we measure and later print time take to compute witness
    #[cfg(test)]
    let now = Instant::now();

    let full_assignment = prepare_witness_for_wasm_proof::<Curve>(witness)?;

    #[cfg(test)]
    println!("witness generation took: {:.2?}", now.elapsed());

    // Random Values
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    // If in debug mode, we measure and later print time take to compute proof
    #[cfg(test)]
    let now = Instant::now();

    let proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
        &proving_key.0,
        r,
        s,
        &proving_key.1,
        proving_key.1.num_instance_variables,
        proving_key.1.num_constraints,
        full_assignment.as_slice(),
    )?;

    #[cfg(test)]
    println!("proof generation took: {:.2?}", now.elapsed());

    Ok(proof)
}

/// Formats inputs for witness calculation
///
/// The inputs are formatted as follows:
/// - "identitySecret": vec![FrOrSecret::IdSecret(rln_witness.identity_secret)]
/// - "userMessageLimit": vec![FrOrSecret::Fr(rln_witness.user_message_limit)]
/// - "messageId": vec![FrOrSecret::Fr(rln_witness.message_id)]
/// - "pathElements": Vec<FrOrSecret::Fr(rln_witness.path_elements)>
/// - "identityPathIndex": Vec<FrOrSecret::Fr(rln_witness.identity_path_index)>
/// - "x": vec![FrOrSecret::Fr(rln_witness.x)]
/// - "externalNullifier": vec![FrOrSecret::Fr(rln_witness.external_nullifier)]
///
/// # Errors
/// - `ProtocolError::InvalidMessageId` if `rln_witness.message_id` is not within `rln_witness.user_message_limit`.
#[cfg(not(target_arch = "wasm32"))]
pub fn prepare_inputs_for_witness_calculation(
    rln_witness: &RLNWitnessInput,
) -> Result<[(&str, Vec<FrOrSecret>); 7], ProtocolError> {
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    let mut identity_path_index = Vec::with_capacity(rln_witness.identity_path_index.len());
    rln_witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(Fr::from(*v)));

    Ok([
        (
            "identitySecret",
            vec![rln_witness.identity_secret.clone().into()],
        ),
        (
            "userMessageLimit",
            vec![rln_witness.user_message_limit.into()],
        ),
        ("messageId", vec![rln_witness.message_id.into()]),
        (
            "pathElements",
            rln_witness
                .path_elements
                .iter()
                .cloned()
                .map(Into::into)
                .collect(),
        ),
        (
            "identityPathIndex",
            identity_path_index.into_iter().map(Into::into).collect(),
        ),
        ("x", vec![rln_witness.x.into()]),
        (
            "externalNullifier",
            vec![rln_witness.external_nullifier.into()],
        ),
    ])
}

/// Generates a RLN proof with a witness.
///
/// As inputs it takes a proving key, a witness and a graph data.
/// The witness is prepared for the witness calculation and then
/// the witness is used to generate a full assignment based on the graph data.
///
/// The proof is generated using the Groth16 proof system.
///
/// # Errors
/// - [`ProofError::ProtocolError`] if preparing the inputs for witness calculation fails.
/// - [`ProofError::SynthesisError`] if generating the proof fails.
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_proof(
    proving_key: &(ProvingKey<Curve>, ConstraintMatrices<Fr>),
    rln_witness: &RLNWitnessInput,
    graph_data: &[u8],
) -> Result<ArkProof<Curve>, ProofError> {
    let inputs = prepare_inputs_for_witness_calculation(rln_witness)?
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));

    // If in debug mode, we measure and later print time take to compute witness
    #[cfg(test)]
    let now = Instant::now();
    let full_assignment = calculate_rln_witness(inputs, graph_data);

    #[cfg(test)]
    println!("witness generation took: {:.2?}", now.elapsed());

    // Random Values
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    // If in debug mode, we measure and later print time take to compute proof
    #[cfg(test)]
    let now = Instant::now();
    let proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
        &proving_key.0,
        r,
        s,
        &proving_key.1,
        proving_key.1.num_instance_variables,
        proving_key.1.num_constraints,
        full_assignment.as_slice(),
    )?;

    #[cfg(test)]
    println!("proof generation took: {:.2?}", now.elapsed());

    Ok(proof)
}

/// Verifies a zk-proof from a given RLN proof.
///
/// As inputs it takes a verifying key, a zk-proof and a proof values.
/// The proof values are used to generate a full assignment.
/// The full assignment is used to verify the zk-proof.
///
/// The proof is verified using the Groth16 proof system.
///
/// # Errors
/// - [`ProofError::SynthesisError`] if verifying the proof fails.
pub fn verify_proof(
    verifying_key: &VerifyingKey<Curve>,
    proof: &ArkProof<Curve>,
    proof_values: &RLNProofValues,
) -> Result<bool, ProofError> {
    // We re-arrange proof-values according to the circuit specification
    let inputs = vec![
        proof_values.y,
        proof_values.root,
        proof_values.nullifier,
        proof_values.x,
        proof_values.external_nullifier,
    ];

    // Check that the proof is valid
    let pvk = prepare_verifying_key(verifying_key);
    //let pr: ArkProof<Curve> = (*proof).into();

    // If in debug mode, we measure and later print time take to verify proof
    #[cfg(test)]
    let now = Instant::now();

    let verified = Groth16::<_, CircomReduction>::verify_proof(&pvk, proof, &inputs)?;

    #[cfg(test)]
    println!("verify took: {:.2?}", now.elapsed());

    Ok(verified)
}

/// Auxiliary function for serialization Fr to json using ark serialize
fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = vec![];
    a.serialize_compressed(&mut bytes)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

/// Auxiliary function for deserialization Fr to json using ark serialize
fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_compressed_unchecked(s.as_slice());
    a.map_err(serde::de::Error::custom)
}

/// Converts a JSON value into [`RLNWitnessInput`] object.
///
/// # Errors
/// - [`ProtocolError::InvalidMessageId`] if `rln_witness.message_id` is not within `rln_witness.user_message_limit`.
/// - [`ProtocolError::JsonError`] if deserializing the JSON value fails.
pub fn rln_witness_from_json(
    input_json: serde_json::Value,
) -> Result<RLNWitnessInput, ProtocolError> {
    let rln_witness: RLNWitnessInput = serde_json::from_value(input_json)?;
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    Ok(rln_witness)
}

/// Converts a [`RLNWitnessInput`] object to the corresponding JSON serialization.
///
/// # Errors
/// - [`ProtocolError::InvalidMessageId`] if `rln_witness.message_id` is not within `rln_witness.user_message_limit`.
/// - [`ProtocolError::JsonError`] if serializing the JSON value fails.
pub fn rln_witness_to_json(
    rln_witness: &RLNWitnessInput,
) -> Result<serde_json::Value, ProtocolError> {
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    let rln_witness_json = serde_json::to_value(rln_witness)?;
    Ok(rln_witness_json)
}

/// Converts a [`RLNWitnessInput`] object to the corresponding bigint JSON serialization.
/// Before serialization the data should be translated into big int for further calculation in the witness calculator.
///
/// # Errors
/// - [`ProtocolError::InvalidMessageId`] if `rln_witness.message_id` is not within `rln_witness.user_message_limit`.
pub fn rln_witness_to_bigint_json(
    rln_witness: &RLNWitnessInput,
) -> Result<serde_json::Value, ProtocolError> {
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    let mut path_elements = Vec::new();

    for v in rln_witness.path_elements.iter() {
        path_elements.push(to_bigint(v).to_str_radix(10));
    }

    let mut identity_path_index = Vec::new();
    rln_witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(BigInt::from(*v).to_str_radix(10)));

    let inputs = serde_json::json!({
        "identitySecret": to_bigint(&rln_witness.identity_secret).to_str_radix(10),
        "userMessageLimit": to_bigint(&rln_witness.user_message_limit).to_str_radix(10),
        "messageId": to_bigint(&rln_witness.message_id).to_str_radix(10),
        "pathElements": path_elements,
        "identityPathIndex": identity_path_index,
        "x": to_bigint(&rln_witness.x).to_str_radix(10),
        "externalNullifier":  to_bigint(&rln_witness.external_nullifier).to_str_radix(10),
    });

    Ok(inputs)
}

/// Checks if the message id is within the user message limit.
///
/// # Errors
/// - [`ProtocolError::InvalidMessageId`] if `message_id` is not within `user_message_limit`.
pub fn message_id_range_check(
    message_id: &Fr,
    user_message_limit: &Fr,
) -> Result<(), ProtocolError> {
    if message_id > user_message_limit {
        return Err(ProtocolError::InvalidMessageId(
            *message_id,
            *user_message_limit,
        ));
    }
    Ok(())
}

/// Checks if the actual reading length is equal to the expected length to read.
///
/// # Errors
/// - [`ProtocolError::InvalidReadLen`] if `actual` is not equal to `expected`.
pub fn invalid_read_len_check(actual: usize, expected: usize) -> Result<(), ProtocolError> {
    if actual != expected {
        return Err(ProtocolError::InvalidReadLen(actual, expected));
    }
    Ok(())
}

//////////////////////////////////////
// Function for testing purposes
//////////////////////////////////////

/// Creates [`RLNWitnessInput`] from it's fields.
///
/// # Errors
/// - [`ProtocolError::InvalidMessageId`] if `message_id` is not within `user_message_limit`.
pub fn rln_witness_from_values(
    identity_secret: IdSecret,
    path_elements: Vec<Fp<MontBackend<FrConfig, 4>, 4>>,
    identity_path_index: Vec<u8>,
    x: Fr,
    external_nullifier: Fr,
    user_message_limit: Fr,
    message_id: Fr,
) -> Result<RLNWitnessInput, ProtocolError> {
    message_id_range_check(&message_id, &user_message_limit)?;

    Ok(RLNWitnessInput {
        identity_secret,
        path_elements,
        identity_path_index,
        x,
        external_nullifier,
        user_message_limit,
        message_id,
    })
}

/// Generates a random RLN witness for testing purposes.
pub fn random_rln_witness(tree_height: usize) -> RLNWitnessInput {
    type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;
    let default_leaf = Fr::from(0);
    let mut tree: OptimalMerkleTree<PoseidonHash> = OptimalMerkleTree::new(
        tree_height,
        default_leaf,
        ConfigOf::<OptimalMerkleTree<PoseidonHash>>::default(),
    )
    .unwrap();

    // We generate a new identity pair
    let (identity_secret_hash, id_commitment) = keygen();

    let identity_index = tree.leaves_set();
    let user_message_limit = Fr::from(100);
    let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]);
    tree.update_next(rate_commitment).unwrap();

    // We generate a random epoch
    let epoch = hash_to_field_le(b"test-epoch");
    let rln_identifier = hash_to_field_le(b"test-rln-identifier");
    let external_nullifier = poseidon_hash(&[epoch, rln_identifier]);

    // We generate two proofs using same epoch but different signals.
    // We generate a random signal
    let mut rng = thread_rng();
    let signal: [u8; 32] = rng.gen();
    let x = hash_to_field_le(&signal);

    let merkle_proof = tree.proof(identity_index).expect("proof should exist");
    RLNWitnessInput {
        identity_secret: identity_secret_hash,
        path_elements: merkle_proof.get_path_elements(),
        identity_path_index: merkle_proof.get_path_index(),
        x,
        external_nullifier,
        user_message_limit,
        message_id: Fr::from(1),
    }
}

/// Generates a random RLN witness for testing purposes in big endian format.
pub fn random_rln_witness_be(tree_height: usize) -> RLNWitnessInput {
    type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;
    let default_leaf = Fr::from(0);
    let mut tree: OptimalMerkleTree<PoseidonHash> = OptimalMerkleTree::new(
        tree_height,
        default_leaf,
        ConfigOf::<OptimalMerkleTree<PoseidonHash>>::default(),
    )
    .unwrap();

    // We generate a new identity pair
    let (identity_secret_hash, id_commitment) = keygen();

    let identity_index = tree.leaves_set();
    let user_message_limit = Fr::from(100);
    let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]);
    tree.update_next(rate_commitment).unwrap();

    // We generate a random epoch
    let epoch = hash_to_field_be(b"test-epoch");
    let rln_identifier = hash_to_field_be(b"test-rln-identifier");
    let external_nullifier = poseidon_hash(&[epoch, rln_identifier]);

    // We generate two proofs using same epoch but different signals.
    // We generate a random signal
    let mut rng = thread_rng();
    let signal: [u8; 32] = rng.gen();
    let x = hash_to_field_be(&signal);

    let merkle_proof = tree.proof(identity_index).expect("proof should exist");
    RLNWitnessInput {
        identity_secret: identity_secret_hash,
        path_elements: merkle_proof.get_path_elements(),
        identity_path_index: merkle_proof.get_path_index(),
        x,
        external_nullifier,
        user_message_limit,
        message_id: Fr::from(1),
    }
}

/// Prepares the input data for the proof generation.
///
/// The input data is prepared as follows:
/// - identity_secret: 32 bytes
/// - id_index: 8 bytes
/// - user_message_limit: 32 bytes
/// - message_id: 32 bytes
/// - external_nullifier: 32 bytes
/// - signal_len: 8 bytes
/// - signal: `signal_len` length of bytes
///
/// Don't return any errors as this function is used for testing purposes.
pub fn prepare_prove_input_le(
    identity_secret: IdSecret,
    id_index: usize,
    user_message_limit: Fr,
    message_id: Fr,
    external_nullifier: Fr,
    signal: &[u8],
) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - 4 field elements: identity_secret, user_message_limit, message_id, external_nullifier
    // - 16 bytes for two normalized usize values (id_index<8> + signal_len<8>)
    // - variable length signal data
    let mut serialized = Vec::with_capacity(fr_byte_size() * 4 + 16 + signal.len()); // length of 4 fr elements + 16 bytes (id_index + len) + signal length

    serialized.extend_from_slice(&identity_secret.to_bytes_le());
    serialized.extend_from_slice(&normalize_usize_le(id_index));
    serialized.extend_from_slice(&fr_to_bytes_le(&user_message_limit));
    serialized.extend_from_slice(&fr_to_bytes_le(&message_id));
    serialized.extend_from_slice(&fr_to_bytes_le(&external_nullifier));
    serialized.extend_from_slice(&normalize_usize_le(signal.len()));
    serialized.extend_from_slice(signal);

    serialized
}

/// Prepares the input data for the proof verification.
///
/// The input data is prepared as follows:
/// - proof_data: 128 bytes + 32 bytes + 32 bytes + 32 bytes + 32 bytes + 32 bytes
/// - signal_len: 8 bytes
/// - signal: `signal_len` length of bytes
pub fn prepare_verify_input_le(proof_data: Vec<u8>, signal: &[u8]) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - proof_data contains the proof and proof values (proof<128> + root<32> + external_nullifier<32> + x<32> + y<32> + nullifier<32>)
    // - 8 bytes for normalized signal length value (signal_len<8>)
    // - variable length signal data
    let mut serialized = Vec::with_capacity(proof_data.len() + 8 + signal.len());

    serialized.extend(proof_data);
    serialized.extend_from_slice(&normalize_usize_le(signal.len()));
    serialized.extend_from_slice(signal);

    serialized
}

/// Prepares the input data for the proof verification.
///
/// The input data is prepared as follows:
/// - proof_data: 128 bytes + 32 bytes + 32 bytes + 32 bytes + 32 bytes + 32 bytes
/// - signal_len: 8 bytes
/// - signal: `signal_len` length of bytes
pub fn prepare_verify_input_be(proof_data: Vec<u8>, signal: &[u8]) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - proof_data contains the proof and proof values (proof<128> + root<32> + external_nullifier<32> + x<32> + y<32> + nullifier<32>)
    // - 8 bytes for normalized signal length value (signal_len<8>)
    // - variable length signal data
    let mut serialized = Vec::with_capacity(proof_data.len() + 8 + signal.len());

    serialized.extend(proof_data);
    serialized.extend_from_slice(&normalize_usize_be(signal.len()));
    serialized.extend_from_slice(signal);

    serialized
}
