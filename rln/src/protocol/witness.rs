use std::{
    collections::HashSet,
    io::{Read, Write},
};

use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use num_bigint::BigInt;
use zeroize::Zeroize;

use super::{
    mode::{MessageMode, VERSION_BYTE_SIZE},
    proof::RLNProofValues,
    serialize::{CanonicalDeserializeBE, CanonicalSerializeBE},
    ENUM_TAG_MULTI, ENUM_TAG_SINGLE, ENUM_TAG_SIZE,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::FrOrSecret;
use crate::{
    circuit::Fr,
    error::ProtocolError,
    hashers::poseidon_hash,
    utils::{
        bytes_be_to_fr, bytes_be_to_vec_bool, bytes_be_to_vec_fr, bytes_be_to_vec_u8,
        bytes_le_to_fr, bytes_le_to_vec_bool, bytes_le_to_vec_fr, bytes_le_to_vec_u8,
        fr_to_bytes_be, fr_to_bytes_le, to_bigint, vec_bool_to_bytes_be, vec_bool_to_bytes_le,
        vec_fr_to_bytes_be, vec_fr_to_bytes_le, vec_u8_to_bytes_be, vec_u8_to_bytes_le, IdSecret,
        FR_BYTE_SIZE, VEC_LEN_BYTE_SIZE,
    },
};

/// Variant-specific message inputs for RLN witness.
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RLNMessageInputs {
    SingleV1 {
        message_id: Fr,
    },
    MultiV1 {
        message_ids: Vec<Fr>,
        selector_used: Vec<bool>,
    },
}

/// Witness input for RLN proof generation.
///
/// Contains the identity credentials, merkle proof, rate-limiting parameters,
/// and signal binding data required to generate a Groth16 proof for the RLN protocol.
///
/// The serialization format for this type is defined in the `protocol::mode` module.
#[derive(Debug, PartialEq, Clone)]
pub struct RLNWitnessInput {
    identity_secret: IdSecret,
    user_message_limit: Fr,
    path_elements: Vec<Fr>,
    identity_path_index: Vec<u8>,
    x: Fr,
    external_nullifier: Fr,
    pub(crate) message_inputs: RLNMessageInputs,
}

/// Partial witness input for RLN proof precalculation.
///
/// Contains the non-changing inputs used to precompute a partial proof
/// before the signal, external nullifier, and message ID are known.
///
/// The serialization format for this type is defined in the `protocol::mode` module.
#[derive(Debug, PartialEq, Clone)]
pub struct RLNPartialWitnessInput {
    identity_secret: IdSecret,
    user_message_limit: Fr,
    path_elements: Vec<Fr>,
    identity_path_index: Vec<u8>,
}

impl RLNWitnessInput {
    /// Creates a new single message-id witness.
    pub fn new_single(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        message_id: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: Fr,
        external_nullifier: Fr,
    ) -> Result<Self, ProtocolError> {
        if user_message_limit == Fr::from(0) {
            return Err(ProtocolError::ZeroUserMessageLimit);
        }
        let path_elements_len = path_elements.len();
        let identity_path_index_len = identity_path_index.len();
        if path_elements_len != identity_path_index_len {
            return Err(ProtocolError::InvalidMerkleProofLength(
                path_elements_len,
                identity_path_index_len,
            ));
        }
        if message_id >= user_message_limit {
            return Err(ProtocolError::InvalidMessageId(
                message_id,
                user_message_limit,
            ));
        }
        Ok(Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_inputs: RLNMessageInputs::SingleV1 { message_id },
        })
    }

    /// Creates a new multi message-id witness.
    #[allow(clippy::too_many_arguments)]
    pub fn new_multi(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        message_ids: Vec<Fr>,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: Fr,
        external_nullifier: Fr,
        selector_used: Vec<bool>,
    ) -> Result<Self, ProtocolError> {
        if user_message_limit == Fr::from(0) {
            return Err(ProtocolError::ZeroUserMessageLimit);
        }
        let path_elements_len = path_elements.len();
        let identity_path_index_len = identity_path_index.len();
        if path_elements_len != identity_path_index_len {
            return Err(ProtocolError::InvalidMerkleProofLength(
                path_elements_len,
                identity_path_index_len,
            ));
        }
        if message_ids.is_empty() {
            return Err(ProtocolError::EmptyMessageIds);
        }
        if selector_used.len() != message_ids.len() {
            return Err(ProtocolError::FieldLengthMismatch(
                "message_ids",
                message_ids.len(),
                "selector_used",
                selector_used.len(),
            ));
        }
        if !selector_used.iter().any(|&s| s) {
            return Err(ProtocolError::NoActiveSelectorUsed);
        }
        {
            let mut seen = HashSet::with_capacity(message_ids.len());
            for (id, &used) in message_ids.iter().zip(&selector_used) {
                if used && !seen.insert(*id) {
                    return Err(ProtocolError::DuplicateMessageIds);
                }
            }
        }
        for (message_id, used) in message_ids.iter().zip(&selector_used) {
            if *used && *message_id >= user_message_limit {
                return Err(ProtocolError::InvalidMessageId(
                    *message_id,
                    user_message_limit,
                ));
            }
        }
        Ok(Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_inputs: RLNMessageInputs::MultiV1 {
                message_ids,
                selector_used,
            },
        })
    }

    /// Returns the version byte corresponding to the witness variant.
    pub fn version_byte(&self) -> u8 {
        match &self.message_inputs {
            RLNMessageInputs::SingleV1 { .. } => MessageMode::SingleV1.version_byte(),
            RLNMessageInputs::MultiV1 { .. } => MessageMode::MultiV1 { max_out: 0 }.version_byte(),
        }
    }

    /// Returns the identity secret.
    pub fn identity_secret(&self) -> &IdSecret {
        &self.identity_secret
    }

    /// Returns the user message limit.
    pub fn user_message_limit(&self) -> &Fr {
        &self.user_message_limit
    }

    /// Returns the message ID (only valid for SingleV1 witnesses).
    pub fn message_id(&self) -> &Fr {
        match &self.message_inputs {
            RLNMessageInputs::SingleV1 { message_id } => message_id,
            RLNMessageInputs::MultiV1 { .. } => {
                panic!("message_id() is not available for MultiV1 witness; use message_ids()")
            }
        }
    }

    /// Returns the multi message IDs (only valid for MultiV1 witnesses).
    pub fn message_ids(&self) -> &[Fr] {
        match &self.message_inputs {
            RLNMessageInputs::MultiV1 { message_ids, .. } => message_ids,
            RLNMessageInputs::SingleV1 { .. } => {
                panic!("message_ids() is not available for SingleV1 witness; use message_id()")
            }
        }
    }

    /// Returns the Merkle path elements.
    pub fn path_elements(&self) -> &[Fr] {
        &self.path_elements
    }

    /// Returns the Merkle path indices.
    pub fn identity_path_index(&self) -> &[u8] {
        &self.identity_path_index
    }

    /// Returns the signal hash.
    pub fn x(&self) -> &Fr {
        &self.x
    }

    /// Returns the external nullifier.
    pub fn external_nullifier(&self) -> &Fr {
        &self.external_nullifier
    }

    /// Returns the selector flags (only valid for MultiV1 witnesses).
    pub fn selector_used(&self) -> &[bool] {
        match &self.message_inputs {
            RLNMessageInputs::MultiV1 { selector_used, .. } => selector_used,
            RLNMessageInputs::SingleV1 { .. } => {
                panic!("selector_used() is not available for SingleV1 witness")
            }
        }
    }
}

impl RLNPartialWitnessInput {
    /// Creates a new RLNPartialWitnessInput instance.
    pub fn new(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        // User message limit check
        if user_message_limit == Fr::from(0) {
            return Err(ProtocolError::ZeroUserMessageLimit);
        }

        // Merkle proof length check
        let path_elements_len = path_elements.len();
        let identity_path_index_len = identity_path_index.len();
        if path_elements_len != identity_path_index_len {
            return Err(ProtocolError::InvalidMerkleProofLength(
                path_elements_len,
                identity_path_index_len,
            ));
        }

        Ok(Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
        })
    }

    /// Returns the identity secret.
    pub fn identity_secret(&self) -> &IdSecret {
        &self.identity_secret
    }

    /// Returns the user message limit.
    pub fn user_message_limit(&self) -> &Fr {
        &self.user_message_limit
    }

    /// Returns the Merkle path elements.
    pub fn path_elements(&self) -> &[Fr] {
        &self.path_elements
    }

    /// Returns the Merkle path indices.
    pub fn identity_path_index(&self) -> &[u8] {
        &self.identity_path_index
    }

    /// Returns the version byte for this partial witness's serialization format.
    pub fn version_byte(&self) -> u8 {
        // TODO: new enum for partial witness instead of reusing SingleV1 version byte, which is technically not correct
        // TODO: current master branch return SingleV1 or MultiV1 version byte based compile-time feature flag
        MessageMode::SingleV1.version_byte()
    }
}

impl From<&RLNWitnessInput> for RLNPartialWitnessInput {
    fn from(witness: &RLNWitnessInput) -> Self {
        Self {
            identity_secret: witness.identity_secret.clone(),
            user_message_limit: witness.user_message_limit,
            path_elements: witness.path_elements.clone(),
            identity_path_index: witness.identity_path_index.clone(),
        }
    }
}

/// Converts the witness to JSON with BigInt string representation for the witness calculator.
pub fn rln_witness_to_bigint_json(
    witness: &RLNWitnessInput,
) -> Result<serde_json::Value, ProtocolError> {
    let path_elements_str: Vec<String> = witness
        .path_elements
        .iter()
        .map(|v| to_bigint(v).to_str_radix(10))
        .collect();
    let identity_path_index_str: Vec<String> = witness
        .identity_path_index
        .iter()
        .map(|v| BigInt::from(*v).to_str_radix(10))
        .collect();

    match &witness.message_inputs {
        RLNMessageInputs::SingleV1 { message_id } => Ok(serde_json::json!({
            "identitySecret": to_bigint(&witness.identity_secret).to_str_radix(10),
            "userMessageLimit": to_bigint(&witness.user_message_limit).to_str_radix(10),
            "messageId": to_bigint(message_id).to_str_radix(10),
            "pathElements": path_elements_str,
            "identityPathIndex": identity_path_index_str,
            "x": to_bigint(&witness.x).to_str_radix(10),
            "externalNullifier": to_bigint(&witness.external_nullifier).to_str_radix(10),
        })),
        RLNMessageInputs::MultiV1 {
            message_ids,
            selector_used,
        } => {
            let message_ids_str: Vec<String> = message_ids
                .iter()
                .map(|id| to_bigint(id).to_str_radix(10))
                .collect();
            let selector_used_str: Vec<String> = selector_used
                .iter()
                .map(|&v| BigInt::from(v).to_str_radix(10))
                .collect();

            Ok(serde_json::json!({
                "identitySecret": to_bigint(&witness.identity_secret).to_str_radix(10),
                "userMessageLimit": to_bigint(&witness.user_message_limit).to_str_radix(10),
                "messageId": message_ids_str,
                "selectorUsed": selector_used_str,
                "pathElements": path_elements_str,
                "identityPathIndex": identity_path_index_str,
                "x": to_bigint(&witness.x).to_str_radix(10),
                "externalNullifier": to_bigint(&witness.external_nullifier).to_str_radix(10),
            }))
        }
    }
}

/// Serializes an RLN witness to little-endian bytes.
pub fn rln_witness_to_bytes_le(witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    let capacity = match &witness.message_inputs {
        RLNMessageInputs::SingleV1 { .. } => {
            VERSION_BYTE_SIZE
                + FR_BYTE_SIZE * (5 + witness.path_elements.len())
                + witness.identity_path_index.len()
                + VEC_LEN_BYTE_SIZE * 2
        }
        RLNMessageInputs::MultiV1 {
            message_ids,
            selector_used,
        } => {
            VERSION_BYTE_SIZE
                + FR_BYTE_SIZE * (4 + witness.path_elements.len() + message_ids.len())
                + witness.identity_path_index.len()
                + selector_used.len()
                + VEC_LEN_BYTE_SIZE * 4
        }
    };

    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(witness.version_byte());
    bytes.extend_from_slice(&witness.identity_secret.to_bytes_le());
    bytes.extend_from_slice(&fr_to_bytes_le(&witness.user_message_limit));

    match &witness.message_inputs {
        RLNMessageInputs::SingleV1 { message_id } => {
            bytes.extend_from_slice(&fr_to_bytes_le(message_id));
            bytes.extend_from_slice(&vec_fr_to_bytes_le(&witness.path_elements));
            bytes.extend_from_slice(&vec_u8_to_bytes_le(&witness.identity_path_index));
            bytes.extend_from_slice(&fr_to_bytes_le(&witness.x));
            bytes.extend_from_slice(&fr_to_bytes_le(&witness.external_nullifier));
        }
        RLNMessageInputs::MultiV1 {
            message_ids,
            selector_used,
        } => {
            bytes.extend_from_slice(&vec_fr_to_bytes_le(&witness.path_elements));
            bytes.extend_from_slice(&vec_u8_to_bytes_le(&witness.identity_path_index));
            bytes.extend_from_slice(&fr_to_bytes_le(&witness.x));
            bytes.extend_from_slice(&fr_to_bytes_le(&witness.external_nullifier));
            bytes.extend_from_slice(&vec_fr_to_bytes_le(message_ids));
            bytes.extend_from_slice(&vec_bool_to_bytes_le(selector_used));
        }
    }
    Ok(bytes)
}

/// Serializes an RLN witness to big-endian bytes.
pub fn rln_witness_to_bytes_be(witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    let capacity = match &witness.message_inputs {
        RLNMessageInputs::SingleV1 { .. } => {
            VERSION_BYTE_SIZE
                + FR_BYTE_SIZE * (5 + witness.path_elements.len())
                + witness.identity_path_index.len()
                + VEC_LEN_BYTE_SIZE * 2
        }
        RLNMessageInputs::MultiV1 {
            message_ids,
            selector_used,
        } => {
            VERSION_BYTE_SIZE
                + FR_BYTE_SIZE * (4 + witness.path_elements.len() + message_ids.len())
                + witness.identity_path_index.len()
                + selector_used.len()
                + VEC_LEN_BYTE_SIZE * 4
        }
    };

    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(witness.version_byte());
    bytes.extend_from_slice(&witness.identity_secret.to_bytes_be());
    bytes.extend_from_slice(&fr_to_bytes_be(&witness.user_message_limit));

    match &witness.message_inputs {
        RLNMessageInputs::SingleV1 { message_id } => {
            bytes.extend_from_slice(&fr_to_bytes_be(message_id));
            bytes.extend_from_slice(&vec_fr_to_bytes_be(&witness.path_elements));
            bytes.extend_from_slice(&vec_u8_to_bytes_be(&witness.identity_path_index));
            bytes.extend_from_slice(&fr_to_bytes_be(&witness.x));
            bytes.extend_from_slice(&fr_to_bytes_be(&witness.external_nullifier));
        }
        RLNMessageInputs::MultiV1 {
            message_ids,
            selector_used,
        } => {
            bytes.extend_from_slice(&vec_fr_to_bytes_be(&witness.path_elements));
            bytes.extend_from_slice(&vec_u8_to_bytes_be(&witness.identity_path_index));
            bytes.extend_from_slice(&fr_to_bytes_be(&witness.x));
            bytes.extend_from_slice(&fr_to_bytes_be(&witness.external_nullifier));
            bytes.extend_from_slice(&vec_fr_to_bytes_be(message_ids));
            bytes.extend_from_slice(&vec_bool_to_bytes_be(selector_used));
        }
    }
    Ok(bytes)
}

/// Deserializes an RLN witness from little-endian bytes.
///
/// Returns the deserialized witness and the number of bytes read.
pub fn bytes_le_to_rln_witness(bytes: &[u8]) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::InvalidReadLen(1, 0));
    }
    let version = MessageMode::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    let (identity_secret, el_size) = IdSecret::from_bytes_le(&bytes[read..])?;
    read += el_size;
    let (user_message_limit, el_size) = bytes_le_to_fr(&bytes[read..])?;
    read += el_size;

    match version {
        MessageMode::SingleV1 => {
            let (message_id, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
            let (path_elements, el_size) = bytes_le_to_vec_fr(&bytes[read..])?;
            read += el_size;
            let (identity_path_index, el_size) = bytes_le_to_vec_u8(&bytes[read..])?;
            read += el_size;
            let (x, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
            let (external_nullifier, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
            if read != bytes.len() {
                return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
            }
            let witness = RLNWitnessInput::new_single(
                identity_secret,
                user_message_limit,
                message_id,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
            )?;
            Ok((witness, read))
        }
        MessageMode::MultiV1 { .. } => {
            let (path_elements, el_size) = bytes_le_to_vec_fr(&bytes[read..])?;
            read += el_size;
            let (identity_path_index, el_size) = bytes_le_to_vec_u8(&bytes[read..])?;
            read += el_size;
            let (x, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
            let (external_nullifier, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
            let (message_ids, el_size) = bytes_le_to_vec_fr(&bytes[read..])?;
            read += el_size;
            let (selector_used, el_size) = bytes_le_to_vec_bool(&bytes[read..])?;
            read += el_size;
            if selector_used.len() != message_ids.len() {
                return Err(ProtocolError::FieldLengthMismatch(
                    "message_ids",
                    message_ids.len(),
                    "selector_used",
                    selector_used.len(),
                ));
            }
            if read != bytes.len() {
                return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
            }
            Ok((
                RLNWitnessInput::new_multi(
                    identity_secret,
                    user_message_limit,
                    message_ids,
                    path_elements,
                    identity_path_index,
                    x,
                    external_nullifier,
                    selector_used,
                )?,
                read,
            ))
        }
    }
}

/// Deserializes an RLN witness from big-endian bytes.
///
/// Returns the deserialized witness and the number of bytes read.
pub fn bytes_be_to_rln_witness(bytes: &[u8]) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::InvalidReadLen(1, 0));
    }
    let version = MessageMode::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    let (identity_secret, el_size) = IdSecret::from_bytes_be(&bytes[read..])?;
    read += el_size;
    let (user_message_limit, el_size) = bytes_be_to_fr(&bytes[read..])?;
    read += el_size;

    match version {
        MessageMode::SingleV1 => {
            let (message_id, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
            let (path_elements, el_size) = bytes_be_to_vec_fr(&bytes[read..])?;
            read += el_size;
            let (identity_path_index, el_size) = bytes_be_to_vec_u8(&bytes[read..])?;
            read += el_size;
            let (x, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
            let (external_nullifier, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
            if read != bytes.len() {
                return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
            }
            let witness = RLNWitnessInput::new_single(
                identity_secret,
                user_message_limit,
                message_id,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
            )?;
            Ok((witness, read))
        }
        MessageMode::MultiV1 { .. } => {
            let (path_elements, el_size) = bytes_be_to_vec_fr(&bytes[read..])?;
            read += el_size;
            let (identity_path_index, el_size) = bytes_be_to_vec_u8(&bytes[read..])?;
            read += el_size;
            let (x, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
            let (external_nullifier, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
            let (message_ids, el_size) = bytes_be_to_vec_fr(&bytes[read..])?;
            read += el_size;
            let (selector_used, el_size) = bytes_be_to_vec_bool(&bytes[read..])?;
            read += el_size;
            if selector_used.len() != message_ids.len() {
                return Err(ProtocolError::FieldLengthMismatch(
                    "message_ids",
                    message_ids.len(),
                    "selector_used",
                    selector_used.len(),
                ));
            }
            if read != bytes.len() {
                return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
            }
            Ok((
                RLNWitnessInput::new_multi(
                    identity_secret,
                    user_message_limit,
                    message_ids,
                    path_elements,
                    identity_path_index,
                    x,
                    external_nullifier,
                    selector_used,
                )?,
                read,
            ))
        }
    }
}

/// Serializes an RLN partial witness to little-endian bytes.
pub fn rln_partial_witness_to_bytes_le(
    partial_witness: &RLNPartialWitnessInput,
) -> Result<Vec<u8>, ProtocolError> {
    // Calculate capacity for Vec:
    // - VERSION_BYTE_SIZE byte for version tag
    // - 2 field elements: identity_secret, user_message_limit
    // - variable size of path_elements, identity_path_index
    // - VEC_LEN_BYTE_SIZE bytes length prefix per vector (path_elements, identity_path_index)
    let capacity = VERSION_BYTE_SIZE
        + FR_BYTE_SIZE * (2 + partial_witness.path_elements.len())
        + partial_witness.identity_path_index.len()
        + VEC_LEN_BYTE_SIZE * 2;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(partial_witness.version_byte());
    bytes.extend_from_slice(&partial_witness.identity_secret.to_bytes_le());
    bytes.extend_from_slice(&fr_to_bytes_le(&partial_witness.user_message_limit));
    bytes.extend_from_slice(&vec_fr_to_bytes_le(&partial_witness.path_elements));
    bytes.extend_from_slice(&vec_u8_to_bytes_le(&partial_witness.identity_path_index));

    Ok(bytes)
}

/// Serializes an RLN partial witness to big-endian bytes.
pub fn rln_partial_witness_to_bytes_be(
    partial_witness: &RLNPartialWitnessInput,
) -> Result<Vec<u8>, ProtocolError> {
    // Calculate capacity for Vec:
    // - VERSION_BYTE_SIZE byte for version tag
    // - 2 field elements: identity_secret, user_message_limit
    // - variable size of path_elements, identity_path_index
    // - VEC_LEN_BYTE_SIZE bytes length prefix per vector (path_elements, identity_path_index)
    let capacity = VERSION_BYTE_SIZE
        + FR_BYTE_SIZE * (2 + partial_witness.path_elements.len())
        + partial_witness.identity_path_index.len()
        + VEC_LEN_BYTE_SIZE * 2;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(partial_witness.version_byte());
    bytes.extend_from_slice(&partial_witness.identity_secret.to_bytes_be());
    bytes.extend_from_slice(&fr_to_bytes_be(&partial_witness.user_message_limit));
    bytes.extend_from_slice(&vec_fr_to_bytes_be(&partial_witness.path_elements));
    bytes.extend_from_slice(&vec_u8_to_bytes_be(&partial_witness.identity_path_index));

    Ok(bytes)
}

/// Deserializes an RLN partial witness from little-endian bytes.
///
/// Returns the deserialized partial witness and the number of bytes read.
pub fn bytes_le_to_rln_partial_witness(
    bytes: &[u8],
) -> Result<(RLNPartialWitnessInput, usize), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::InvalidReadLen(1, 0));
    }

    let _version = MessageMode::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    let (identity_secret, el_size) = IdSecret::from_bytes_le(&bytes[read..])?;
    read += el_size;

    let (user_message_limit, el_size) = bytes_le_to_fr(&bytes[read..])?;
    read += el_size;

    let (path_elements, el_size) = bytes_le_to_vec_fr(&bytes[read..])?;
    read += el_size;

    let (identity_path_index, el_size) = bytes_le_to_vec_u8(&bytes[read..])?;
    read += el_size;

    if read != bytes.len() {
        return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
    }

    Ok((
        RLNPartialWitnessInput::new(
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
        )?,
        read,
    ))
}

/// Deserializes an RLN partial witness from big-endian bytes.
///
/// Returns the deserialized partial witness and the number of bytes read.
pub fn bytes_be_to_rln_partial_witness(
    bytes: &[u8],
) -> Result<(RLNPartialWitnessInput, usize), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::InvalidReadLen(1, 0));
    }

    let _version = MessageMode::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    let (identity_secret, el_size) = IdSecret::from_bytes_be(&bytes[read..])?;
    read += el_size;

    let (user_message_limit, el_size) = bytes_be_to_fr(&bytes[read..])?;
    read += el_size;

    let (path_elements, el_size) = bytes_be_to_vec_fr(&bytes[read..])?;
    read += el_size;

    let (identity_path_index, el_size) = bytes_be_to_vec_u8(&bytes[read..])?;
    read += el_size;

    if read != bytes.len() {
        return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
    }

    Ok((
        RLNPartialWitnessInput::new(
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
        )?,
        read,
    ))
}

/// Computes RLN proof values from witness input.
///
/// Calculates the public outputs (y, nullifier, root) that will be part of the proof.
pub fn proof_values_from_witness(witness: &RLNWitnessInput) -> RLNProofValues {
    let root = compute_tree_root(
        &witness.identity_secret,
        &witness.user_message_limit,
        &witness.path_elements,
        &witness.identity_path_index,
    );

    let a_0 = &witness.identity_secret;

    match &witness.message_inputs {
        RLNMessageInputs::SingleV1 { message_id } => {
            let mut to_hash = [**a_0, witness.external_nullifier, *message_id];
            let a_1 = poseidon_hash(&to_hash);
            let y = *(a_0.clone()) + witness.x * a_1;
            let nullifier = poseidon_hash(&[a_1]);
            to_hash[0].zeroize();
            RLNProofValues::new_single(root, witness.x, witness.external_nullifier, y, nullifier)
        }
        RLNMessageInputs::MultiV1 {
            message_ids,
            selector_used,
        } => {
            let mut ys = Vec::with_capacity(message_ids.len());
            let mut nullifiers = Vec::with_capacity(message_ids.len());
            for (i, message_id) in message_ids.iter().enumerate() {
                let mut to_hash = [**a_0, witness.external_nullifier, *message_id];
                let a_1 = poseidon_hash(&to_hash);
                let selector = Fr::from(selector_used[i]);
                let y = (*(a_0.clone()) + witness.x * a_1) * selector;
                let nullifier = poseidon_hash(&[a_1]) * selector;
                ys.push(y);
                nullifiers.push(nullifier);
                to_hash[0].zeroize();
            }
            RLNProofValues::new_multi(
                root,
                witness.x,
                witness.external_nullifier,
                ys,
                nullifiers,
                selector_used.clone(),
            )
        }
    }
}

/// Computes the Merkle tree root from identity credentials and Merkle membership proof.
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

/// Prepares inputs for witness calculation from RLN witness input.
#[cfg(not(target_arch = "wasm32"))]
pub(super) fn inputs_for_witness_calculation(
    witness: &RLNWitnessInput,
) -> Vec<(&str, Vec<FrOrSecret>)> {
    let identity_path_index_fr: Vec<FrOrSecret> = witness
        .identity_path_index
        .iter()
        .map(|v| Fr::from(*v).into())
        .collect();

    let mut inputs = vec![
        (
            "identitySecret",
            vec![witness.identity_secret.clone().into()],
        ),
        ("userMessageLimit", vec![witness.user_message_limit.into()]),
    ];

    match &witness.message_inputs {
        RLNMessageInputs::SingleV1 { message_id } => {
            inputs.push(("messageId", vec![(*message_id).into()]));
        }
        RLNMessageInputs::MultiV1 {
            message_ids,
            selector_used,
        } => {
            inputs.push((
                "messageId",
                message_ids.iter().cloned().map(Into::into).collect(),
            ));
            let selector_used_fr: Vec<FrOrSecret> =
                selector_used.iter().map(|&v| Fr::from(v).into()).collect();
            inputs.push(("selectorUsed", selector_used_fr));
        }
    }

    inputs.push((
        "pathElements",
        witness
            .path_elements
            .iter()
            .cloned()
            .map(Into::into)
            .collect(),
    ));
    inputs.push(("identityPathIndex", identity_path_index_fr));
    inputs.push(("x", vec![witness.x.into()]));
    inputs.push(("externalNullifier", vec![witness.external_nullifier.into()]));

    inputs
}

/// Prepares inputs for partial witness calculation from an RLN partial witness input.
///
/// Unknown inputs (signal, external nullifier, message ID) are represented as `None`.
#[allow(clippy::type_complexity)]
#[cfg(not(target_arch = "wasm32"))]
pub(super) fn inputs_for_partial_witness_calculation(
    witness: &RLNPartialWitnessInput,
    max_out: usize,
) -> Vec<(&'static str, Vec<Option<FrOrSecret>>)> {
    let mut identity_path_index = Vec::with_capacity(witness.identity_path_index.len());
    witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(Fr::from(*v)));

    let mut inputs: Vec<(&'static str, Vec<Option<FrOrSecret>>)> = vec![
        (
            "identitySecret",
            vec![Some(witness.identity_secret.clone().into())],
        ),
        (
            "userMessageLimit",
            vec![Some(witness.user_message_limit.into())],
        ),
    ];

    if max_out == 1 {
        inputs.push(("messageId", vec![None]));
    } else {
        inputs.push(("messageId", vec![None; max_out]));
        inputs.push(("selectorUsed", vec![None; max_out]));
    }

    inputs.push((
        "pathElements",
        witness
            .path_elements
            .iter()
            .cloned()
            .map(Into::into)
            .map(Some)
            .collect(),
    ));
    inputs.push((
        "identityPathIndex",
        identity_path_index
            .into_iter()
            .map(Into::into)
            .map(Some)
            .collect(),
    ));
    inputs.push(("x", vec![None]));
    inputs.push(("externalNullifier", vec![None]));

    inputs
}

#[derive(Debug, PartialEq, Clone)]
pub enum RLNWitnessInputV3 {
    Single(RLNWitnessInputSingle),
    Multi(RLNWitnessInputMulti),
}

impl Valid for RLNWitnessInputV3 {
    fn check(&self) -> Result<(), SerializationError> {
        match self {
            RLNWitnessInputV3::Single(inner) => inner.check(),
            RLNWitnessInputV3::Multi(inner) => inner.check(),
        }
    }
}

impl CanonicalSerialize for RLNWitnessInputV3 {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match self {
            RLNWitnessInputV3::Single(inner) => {
                ENUM_TAG_SINGLE.serialize_with_mode(&mut writer, compress)?;
                inner.serialize_with_mode(&mut writer, compress)
            }
            RLNWitnessInputV3::Multi(inner) => {
                ENUM_TAG_MULTI.serialize_with_mode(&mut writer, compress)?;
                inner.serialize_with_mode(&mut writer, compress)
            }
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        ENUM_TAG_SIZE
            + match self {
                RLNWitnessInputV3::Single(inner) => {
                    CanonicalSerialize::serialized_size(inner, compress)
                }
                RLNWitnessInputV3::Multi(inner) => {
                    CanonicalSerialize::serialized_size(inner, compress)
                }
            }
    }
}

impl CanonicalDeserialize for RLNWitnessInputV3 {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match tag {
            ENUM_TAG_SINGLE => Ok(RLNWitnessInputV3::Single(
                RLNWitnessInputSingle::deserialize_with_mode(reader, compress, validate)?,
            )),
            ENUM_TAG_MULTI => Ok(RLNWitnessInputV3::Multi(
                RLNWitnessInputMulti::deserialize_with_mode(reader, compress, validate)?,
            )),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl CanonicalSerializeBE for RLNWitnessInputV3 {
    type Error = ProtocolError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        match self {
            RLNWitnessInputV3::Single(inner) => {
                writer.write_all(&[ENUM_TAG_SINGLE])?;
                inner.serialize(&mut writer)
            }
            RLNWitnessInputV3::Multi(inner) => {
                writer.write_all(&[ENUM_TAG_MULTI])?;
                inner.serialize(&mut writer)
            }
        }
    }

    fn serialized_size(&self) -> usize {
        ENUM_TAG_SIZE
            + match self {
                RLNWitnessInputV3::Single(inner) => CanonicalSerializeBE::serialized_size(inner),
                RLNWitnessInputV3::Multi(inner) => CanonicalSerializeBE::serialized_size(inner),
            }
    }
}

impl CanonicalDeserializeBE for RLNWitnessInputV3 {
    type Error = ProtocolError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut tag = [0u8; ENUM_TAG_SIZE];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            ENUM_TAG_SINGLE => Ok(RLNWitnessInputV3::Single(
                RLNWitnessInputSingle::deserialize(reader)?,
            )),
            ENUM_TAG_MULTI => Ok(RLNWitnessInputV3::Multi(RLNWitnessInputMulti::deserialize(
                reader,
            )?)),
            _ => Err(ProtocolError::SerializationError(
                SerializationError::InvalidData,
            )),
        }
    }
}

#[derive(Debug, PartialEq, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNWitnessInputSingle {
    pub(crate) identity_secret: IdSecret,
    pub(crate) user_message_limit: Fr,
    pub(crate) path_elements: Vec<Fr>,
    pub(crate) identity_path_index: Vec<u8>,
    pub(crate) x: Fr,
    pub(crate) external_nullifier: Fr,
    pub(crate) message_id: Fr,
}

impl CanonicalSerializeBE for RLNWitnessInputSingle {
    type Error = ProtocolError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        writer.write_all(&self.identity_secret.to_bytes_be())?;
        writer.write_all(&fr_to_bytes_be(&self.user_message_limit))?;
        writer.write_all(&vec_fr_to_bytes_be(&self.path_elements))?;
        writer.write_all(&vec_u8_to_bytes_be(&self.identity_path_index))?;
        writer.write_all(&fr_to_bytes_be(&self.x))?;
        writer.write_all(&fr_to_bytes_be(&self.external_nullifier))?;
        writer.write_all(&fr_to_bytes_be(&self.message_id))?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        FR_BYTE_SIZE * (5 + self.path_elements.len())
            + self.identity_path_index.len()
            + VEC_LEN_BYTE_SIZE * 2
    }
}

impl CanonicalDeserializeBE for RLNWitnessInputSingle {
    type Error = ProtocolError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        let mut read = 0;

        let (identity_secret, el_size) = IdSecret::from_bytes_be(&bytes[read..])?;
        read += el_size;
        let (user_message_limit, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;
        let (path_elements, el_size) = bytes_be_to_vec_fr(&bytes[read..])?;
        read += el_size;
        let (identity_path_index, el_size) = bytes_be_to_vec_u8(&bytes[read..])?;
        read += el_size;
        let (x, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;
        let (external_nullifier, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;
        let (message_id, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;

        if read != bytes.len() {
            return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
        }
        Ok(Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_id,
        })
    }
}

impl RLNWitnessInputSingle {
    pub fn new(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: Fr,
        external_nullifier: Fr,
        message_id: Fr,
    ) -> Self {
        Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_id,
        }
    }
}

#[derive(Debug, PartialEq, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNWitnessInputMulti {
    pub(crate) identity_secret: IdSecret,
    pub(crate) user_message_limit: Fr,
    pub(crate) path_elements: Vec<Fr>,
    pub(crate) identity_path_index: Vec<u8>,
    pub(crate) x: Fr,
    pub(crate) external_nullifier: Fr,
    pub(crate) message_ids: Vec<Fr>,
    pub(crate) selector_used: Vec<bool>,
}

impl CanonicalSerializeBE for RLNWitnessInputMulti {
    type Error = ProtocolError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        writer.write_all(&self.identity_secret.to_bytes_be())?;
        writer.write_all(&fr_to_bytes_be(&self.user_message_limit))?;
        writer.write_all(&vec_fr_to_bytes_be(&self.path_elements))?;
        writer.write_all(&vec_u8_to_bytes_be(&self.identity_path_index))?;
        writer.write_all(&fr_to_bytes_be(&self.x))?;
        writer.write_all(&fr_to_bytes_be(&self.external_nullifier))?;
        writer.write_all(&vec_fr_to_bytes_be(&self.message_ids))?;
        writer.write_all(&vec_bool_to_bytes_be(&self.selector_used))?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        FR_BYTE_SIZE * (4 + self.path_elements.len() + self.message_ids.len())
            + self.identity_path_index.len()
            + self.selector_used.len()
            + VEC_LEN_BYTE_SIZE * 4
    }
}

impl CanonicalDeserializeBE for RLNWitnessInputMulti {
    type Error = ProtocolError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        let mut read = 0;

        let (identity_secret, el_size) = IdSecret::from_bytes_be(&bytes[read..])?;
        read += el_size;
        let (user_message_limit, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;
        let (path_elements, el_size) = bytes_be_to_vec_fr(&bytes[read..])?;
        read += el_size;
        let (identity_path_index, el_size) = bytes_be_to_vec_u8(&bytes[read..])?;
        read += el_size;
        let (x, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;
        let (external_nullifier, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;
        let (message_ids, el_size) = bytes_be_to_vec_fr(&bytes[read..])?;
        read += el_size;
        let (selector_used, el_size) = bytes_be_to_vec_bool(&bytes[read..])?;
        read += el_size;

        if read != bytes.len() {
            return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
        }
        Ok(Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_ids,
            selector_used,
        })
    }
}

impl RLNWitnessInputMulti {
    pub fn new(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: Fr,
        external_nullifier: Fr,
        message_ids: Vec<Fr>,
        selector_used: Vec<bool>,
    ) -> Self {
        Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_ids,
            selector_used,
        }
    }
}

#[derive(Debug, PartialEq, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNPartialWitnessInputV3 {
    pub(crate) identity_secret: IdSecret,
    pub(crate) user_message_limit: Fr,
    pub(crate) path_elements: Vec<Fr>,
    pub(crate) identity_path_index: Vec<u8>,
}

impl CanonicalSerializeBE for RLNPartialWitnessInputV3 {
    type Error = ProtocolError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        writer.write_all(&self.identity_secret.to_bytes_be())?;
        writer.write_all(&fr_to_bytes_be(&self.user_message_limit))?;
        writer.write_all(&vec_fr_to_bytes_be(&self.path_elements))?;
        writer.write_all(&vec_u8_to_bytes_be(&self.identity_path_index))?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        FR_BYTE_SIZE * 2
            + VEC_LEN_BYTE_SIZE
            + FR_BYTE_SIZE * self.path_elements.len()
            + VEC_LEN_BYTE_SIZE
            + self.identity_path_index.len()
    }
}

impl CanonicalDeserializeBE for RLNPartialWitnessInputV3 {
    type Error = ProtocolError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        let mut read = 0;

        let (identity_secret, el_size) = IdSecret::from_bytes_be(&bytes[read..])?;
        read += el_size;
        let (user_message_limit, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;
        let (path_elements, el_size) = bytes_be_to_vec_fr(&bytes[read..])?;
        read += el_size;
        let (identity_path_index, el_size) = bytes_be_to_vec_u8(&bytes[read..])?;
        read += el_size;

        if read != bytes.len() {
            return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
        }
        Ok(Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
        })
    }
}

impl RLNPartialWitnessInputV3 {
    pub fn new(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
    ) -> Self {
        Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
        }
    }
}

