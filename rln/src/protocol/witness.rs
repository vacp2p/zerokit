#[cfg(feature = "multi-message-id")]
use std::collections::HashSet;

use num_bigint::BigInt;
use zeroize::Zeroize;

use super::{
    proof::RLNProofValues,
    version::{SerializationVersion, VERSION_BYTE_SIZE},
};
#[cfg(feature = "multi-message-id")]
use crate::utils::{
    bytes_be_to_vec_bool, bytes_le_to_vec_bool, vec_bool_to_bytes_be, vec_bool_to_bytes_le,
};
use crate::{
    circuit::Fr,
    error::ProtocolError,
    hashers::poseidon_hash,
    utils::{
        bytes_be_to_fr, bytes_be_to_vec_fr, bytes_be_to_vec_u8, bytes_le_to_fr, bytes_le_to_vec_fr,
        bytes_le_to_vec_u8, fr_to_bytes_be, fr_to_bytes_le, to_bigint, vec_fr_to_bytes_be,
        vec_fr_to_bytes_le, vec_u8_to_bytes_be, vec_u8_to_bytes_le, FrOrSecret, IdSecret,
        FR_BYTE_SIZE,
    },
};

/// Witness input for RLN proof generation.
///
/// Contains the identity credentials, merkle proof, rate-limiting parameters,
/// and signal binding data required to generate a Groth16 proof for the RLN protocol.
#[derive(Debug, PartialEq, Clone)]
pub enum RLNWitnessInput {
    SingleV1 {
        // Private inputs:
        identity_secret: IdSecret,
        user_message_limit: Fr,
        message_id: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        // Public inputs:
        x: Fr,
        external_nullifier: Fr,
    },
    #[cfg(feature = "multi-message-id")]
    MultiV1 {
        // Private inputs:
        identity_secret: IdSecret,
        user_message_limit: Fr,
        message_ids: Vec<Fr>,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        // Public inputs:
        x: Fr,
        external_nullifier: Fr,
        selector_used: Vec<bool>,
    },
}

impl RLNWitnessInput {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        #[cfg(not(feature = "multi-message-id"))] message_id: Fr,
        #[cfg(feature = "multi-message-id")] message_id: Option<Fr>,
        #[cfg(feature = "multi-message-id")] message_ids: Option<Vec<Fr>>,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: Fr,
        external_nullifier: Fr,
        #[cfg(feature = "multi-message-id")] selector_used: Option<Vec<bool>>,
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

        #[cfg(not(feature = "multi-message-id"))]
        {
            // Message ID range check
            if message_id >= user_message_limit {
                return Err(ProtocolError::InvalidMessageId(
                    message_id,
                    user_message_limit,
                ));
            }
            Ok(Self::SingleV1 {
                identity_secret,
                user_message_limit,
                message_id,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
            })
        }

        #[cfg(feature = "multi-message-id")]
        match (message_id, message_ids) {
            (Some(message_id), None) => {
                // Message ID range check
                if message_id >= user_message_limit {
                    return Err(ProtocolError::InvalidMessageId(
                        message_id,
                        user_message_limit,
                    ));
                }
                Ok(Self::SingleV1 {
                    identity_secret,
                    user_message_limit,
                    message_id,
                    path_elements,
                    identity_path_index,
                    x,
                    external_nullifier,
                })
            }
            (None, Some(message_ids)) => {
                // Message IDs must be non-empty
                if message_ids.is_empty() {
                    return Err(ProtocolError::NoMessageIdSet);
                }
                let selector_used = selector_used.ok_or(ProtocolError::MissingSelectorUsed)?;
                // Selector length must match message IDs
                if selector_used.len() != message_ids.len() {
                    return Err(ProtocolError::MultiOutputLengthMismatch {
                        expected: message_ids.len(),
                        actual: selector_used.len(),
                    });
                }
                // At least one selector must be active
                if !selector_used.iter().any(|&s| s) {
                    return Err(ProtocolError::NoActiveSelectorUsed);
                }
                // Active message IDs must be unique
                {
                    let mut seen = HashSet::with_capacity(message_ids.len());
                    for (id, &used) in message_ids.iter().zip(&selector_used) {
                        if used && !seen.insert(*id) {
                            return Err(ProtocolError::DuplicateMessageId);
                        }
                    }
                }
                // Active message IDs must be within range
                for (message_id, used) in message_ids.iter().zip(&selector_used) {
                    if *used && *message_id >= user_message_limit {
                        return Err(ProtocolError::InvalidMessageId(
                            *message_id,
                            user_message_limit,
                        ));
                    }
                }
                Ok(Self::MultiV1 {
                    identity_secret,
                    user_message_limit,
                    message_ids,
                    selector_used,
                    path_elements,
                    identity_path_index,
                    x,
                    external_nullifier,
                })
            }
            (Some(_), Some(_)) => Err(ProtocolError::BothMessageIdSet),
            (None, None) => Err(ProtocolError::NoMessageIdSet),
        }
    }

    /// Returns the identity secret.
    pub fn identity_secret(&self) -> &IdSecret {
        match self {
            Self::SingleV1 {
                identity_secret, ..
            } => identity_secret,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 {
                identity_secret, ..
            } => identity_secret,
        }
    }

    /// Returns the user message limit.
    pub fn user_message_limit(&self) -> &Fr {
        match self {
            Self::SingleV1 {
                user_message_limit, ..
            } => user_message_limit,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 {
                user_message_limit, ..
            } => user_message_limit,
        }
    }

    /// Returns the Merkle path elements.
    pub fn path_elements(&self) -> &[Fr] {
        match self {
            Self::SingleV1 { path_elements, .. } => path_elements,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 { path_elements, .. } => path_elements,
        }
    }

    /// Returns the Merkle path indices.
    pub fn identity_path_index(&self) -> &[u8] {
        match self {
            Self::SingleV1 {
                identity_path_index,
                ..
            } => identity_path_index,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 {
                identity_path_index,
                ..
            } => identity_path_index,
        }
    }

    /// Returns the signal hash.
    pub fn x(&self) -> &Fr {
        match self {
            Self::SingleV1 { x, .. } => x,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 { x, .. } => x,
        }
    }

    /// Returns the external nullifier.
    pub fn external_nullifier(&self) -> &Fr {
        match self {
            Self::SingleV1 {
                external_nullifier, ..
            } => external_nullifier,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 {
                external_nullifier, ..
            } => external_nullifier,
        }
    }

    /// Modifies the identity secret.
    pub fn modify_identity_secret(&mut self, new_identity_secret: IdSecret) {
        match self {
            Self::SingleV1 {
                identity_secret, ..
            } => *identity_secret = new_identity_secret,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 {
                identity_secret, ..
            } => *identity_secret = new_identity_secret,
        }
    }

    /// Modifies the user message limit.
    pub fn modify_user_message_limit(&mut self, new_user_message_limit: Fr) {
        match self {
            Self::SingleV1 {
                user_message_limit, ..
            } => *user_message_limit = new_user_message_limit,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 {
                user_message_limit, ..
            } => *user_message_limit = new_user_message_limit,
        }
    }

    /// Modifies the Merkle path elements.
    pub fn modify_path_elements(&mut self, new_path_elements: Vec<Fr>) {
        match self {
            Self::SingleV1 { path_elements, .. } => *path_elements = new_path_elements,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 { path_elements, .. } => *path_elements = new_path_elements,
        }
    }

    /// Modifies the Merkle path indices.
    pub fn modify_identity_path_index(&mut self, new_identity_path_index: Vec<u8>) {
        match self {
            Self::SingleV1 {
                identity_path_index,
                ..
            } => *identity_path_index = new_identity_path_index,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 {
                identity_path_index,
                ..
            } => *identity_path_index = new_identity_path_index,
        }
    }

    /// Modifies the signal hash.
    pub fn modify_x(&mut self, new_x: Fr) {
        match self {
            Self::SingleV1 { x, .. } => *x = new_x,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 { x, .. } => *x = new_x,
        }
    }

    /// Modifies the external nullifier.
    pub fn modify_external_nullifier(&mut self, new_external_nullifier: Fr) {
        match self {
            Self::SingleV1 {
                external_nullifier, ..
            } => *external_nullifier = new_external_nullifier,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 {
                external_nullifier, ..
            } => *external_nullifier = new_external_nullifier,
        }
    }

    /// Returns the message ID.
    #[cfg(not(feature = "multi-message-id"))]
    pub fn message_id(&self) -> &Fr {
        match self {
            Self::SingleV1 { message_id, .. } => message_id,
        }
    }

    /// Returns the message ID, or `None` for `MultiV1`.
    #[cfg(feature = "multi-message-id")]
    pub fn message_id(&self) -> Option<&Fr> {
        match self {
            Self::SingleV1 { message_id, .. } => Some(message_id),
            Self::MultiV1 { .. } => None,
        }
    }

    /// Modifies the message ID. No-op for `MultiV1`.
    pub fn modify_message_id(&mut self, new_message_id: Fr) {
        match self {
            Self::SingleV1 { message_id, .. } => *message_id = new_message_id,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 { .. } => {}
        }
    }

    /// Returns the multi message IDs, or `None` for `SingleV1`.
    #[cfg(feature = "multi-message-id")]
    pub fn message_ids(&self) -> Option<&[Fr]> {
        match self {
            Self::SingleV1 { .. } => None,
            Self::MultiV1 { message_ids, .. } => Some(message_ids),
        }
    }

    /// Modifies the multi message IDs. No-op for `SingleV1`.
    #[cfg(feature = "multi-message-id")]
    pub fn modify_message_ids(&mut self, new_message_ids: Vec<Fr>) {
        match self {
            Self::SingleV1 { .. } => {}
            Self::MultiV1 { message_ids, .. } => *message_ids = new_message_ids,
        }
    }

    /// Returns the selector flags, or `None` for `SingleV1`.
    #[cfg(feature = "multi-message-id")]
    pub fn selector_used(&self) -> Option<&[bool]> {
        match self {
            Self::SingleV1 { .. } => None,
            Self::MultiV1 { selector_used, .. } => Some(selector_used),
        }
    }

    /// Modifies the selector flags. No-op for `SingleV1`.
    #[cfg(feature = "multi-message-id")]
    pub fn modify_selector_used(&mut self, new_selector_used: Vec<bool>) {
        match self {
            Self::SingleV1 { .. } => {}
            Self::MultiV1 { selector_used, .. } => *selector_used = new_selector_used,
        }
    }
}

/// Serializes an RLN witness to little-endian bytes.
pub fn rln_witness_to_bytes_le(witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    match witness {
        RLNWitnessInput::SingleV1 {
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        } => {
            // Calculate capacity for Vec:
            // - VERSION_BYTE_SIZE byte for version tag
            // - 5 field elements: identity_secret, user_message_limit, message_id, x, external_nullifier
            // - variable size of path_elements and identity_path_index (each with 8-byte length prefix)
            let capacity = VERSION_BYTE_SIZE
                + FR_BYTE_SIZE * (5 + path_elements.len())
                + identity_path_index.len()
                + 8 * 2;
            let mut bytes = Vec::with_capacity(capacity);
            bytes.push(SerializationVersion::SingleV1.into());
            bytes.extend_from_slice(&identity_secret.to_bytes_le());
            bytes.extend_from_slice(&fr_to_bytes_le(user_message_limit));
            bytes.extend_from_slice(&fr_to_bytes_le(message_id));
            bytes.extend_from_slice(&vec_fr_to_bytes_le(path_elements));
            bytes.extend_from_slice(&vec_u8_to_bytes_le(identity_path_index));
            bytes.extend_from_slice(&fr_to_bytes_le(x));
            bytes.extend_from_slice(&fr_to_bytes_le(external_nullifier));
            Ok(bytes)
        }
        #[cfg(feature = "multi-message-id")]
        RLNWitnessInput::MultiV1 {
            identity_secret,
            user_message_limit,
            message_ids,
            selector_used,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        } => {
            // Calculate capacity for Vec:
            // - VERSION_BYTE_SIZE byte for version tag
            // - 4 field elements: identity_secret, user_message_limit, x, external_nullifier
            // - variable size of path_elements, identity_path_index, message_ids, selector_used
            // - 8-byte length prefix per vector (path_elements, identity_path_index, message_ids, selector_used)
            let capacity = VERSION_BYTE_SIZE
                + FR_BYTE_SIZE * (4 + path_elements.len() + message_ids.len())
                + identity_path_index.len()
                + selector_used.len()
                + 8 * 4;
            let mut bytes = Vec::with_capacity(capacity);
            bytes.push(SerializationVersion::MultiV1.into());
            bytes.extend_from_slice(&identity_secret.to_bytes_le());
            bytes.extend_from_slice(&fr_to_bytes_le(user_message_limit));
            bytes.extend_from_slice(&vec_fr_to_bytes_le(path_elements));
            bytes.extend_from_slice(&vec_u8_to_bytes_le(identity_path_index));
            bytes.extend_from_slice(&fr_to_bytes_le(x));
            bytes.extend_from_slice(&fr_to_bytes_le(external_nullifier));
            bytes.extend_from_slice(&vec_fr_to_bytes_le(message_ids));
            bytes.extend_from_slice(&vec_bool_to_bytes_le(selector_used));
            Ok(bytes)
        }
    }
}

/// Serializes an RLN witness to big-endian bytes.
pub fn rln_witness_to_bytes_be(witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    match witness {
        RLNWitnessInput::SingleV1 {
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        } => {
            // Calculate capacity for Vec:
            // - VERSION_BYTE_SIZE byte for version tag
            // - 5 field elements: identity_secret, user_message_limit, message_id, x, external_nullifier
            // - variable size of path_elements and identity_path_index (each with 8-byte length prefix)
            let capacity = VERSION_BYTE_SIZE
                + FR_BYTE_SIZE * (5 + path_elements.len())
                + identity_path_index.len()
                + 8 * 2;
            let mut bytes = Vec::with_capacity(capacity);
            bytes.push(SerializationVersion::SingleV1.into());
            bytes.extend_from_slice(&identity_secret.to_bytes_be());
            bytes.extend_from_slice(&fr_to_bytes_be(user_message_limit));
            bytes.extend_from_slice(&fr_to_bytes_be(message_id));
            bytes.extend_from_slice(&vec_fr_to_bytes_be(path_elements));
            bytes.extend_from_slice(&vec_u8_to_bytes_be(identity_path_index));
            bytes.extend_from_slice(&fr_to_bytes_be(x));
            bytes.extend_from_slice(&fr_to_bytes_be(external_nullifier));
            Ok(bytes)
        }
        #[cfg(feature = "multi-message-id")]
        RLNWitnessInput::MultiV1 {
            identity_secret,
            user_message_limit,
            message_ids,
            selector_used,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        } => {
            // Calculate capacity for Vec:
            // - VERSION_BYTE_SIZE byte for version tag
            // - 4 field elements: identity_secret, user_message_limit, x, external_nullifier
            // - variable size of path_elements, identity_path_index, message_ids, selector_used
            // - 8-byte length prefix per vector (path_elements, identity_path_index, message_ids, selector_used)
            let capacity = VERSION_BYTE_SIZE
                + FR_BYTE_SIZE * (4 + path_elements.len() + message_ids.len())
                + identity_path_index.len()
                + selector_used.len()
                + 8 * 4;
            let mut bytes = Vec::with_capacity(capacity);
            bytes.push(SerializationVersion::MultiV1.into());
            bytes.extend_from_slice(&identity_secret.to_bytes_be());
            bytes.extend_from_slice(&fr_to_bytes_be(user_message_limit));
            bytes.extend_from_slice(&vec_fr_to_bytes_be(path_elements));
            bytes.extend_from_slice(&vec_u8_to_bytes_be(identity_path_index));
            bytes.extend_from_slice(&fr_to_bytes_be(x));
            bytes.extend_from_slice(&fr_to_bytes_be(external_nullifier));
            bytes.extend_from_slice(&vec_fr_to_bytes_be(message_ids));
            bytes.extend_from_slice(&vec_bool_to_bytes_be(selector_used));
            Ok(bytes)
        }
    }
}

/// Deserializes an RLN witness from little-endian bytes.
///
/// Returns the deserialized witness and the number of bytes read.
pub fn bytes_le_to_rln_witness(bytes: &[u8]) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::InvalidReadLen(1, 0));
    }

    let version = SerializationVersion::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    match version {
        SerializationVersion::SingleV1 => {
            let (identity_secret, el_size) = IdSecret::from_bytes_le(&bytes[read..])?;
            read += el_size;
            let (user_message_limit, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
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

            #[cfg(not(feature = "multi-message-id"))]
            let witness = RLNWitnessInput::new(
                identity_secret,
                user_message_limit,
                message_id,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
            )?;
            #[cfg(feature = "multi-message-id")]
            let witness = RLNWitnessInput::new(
                identity_secret,
                user_message_limit,
                Some(message_id),
                None,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
                None,
            )?;
            if read != bytes.len() {
                return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
            }
            Ok((witness, read))
        }
        #[cfg(feature = "multi-message-id")]
        SerializationVersion::MultiV1 => {
            let (identity_secret, el_size) = IdSecret::from_bytes_le(&bytes[read..])?;
            read += el_size;
            let (user_message_limit, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
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
                return Err(ProtocolError::MultiOutputLengthMismatch {
                    expected: message_ids.len(),
                    actual: selector_used.len(),
                });
            }
            if read != bytes.len() {
                return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
            }

            Ok((
                RLNWitnessInput::new(
                    identity_secret,
                    user_message_limit,
                    None,
                    Some(message_ids),
                    path_elements,
                    identity_path_index,
                    x,
                    external_nullifier,
                    Some(selector_used),
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

    let version = SerializationVersion::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    match version {
        SerializationVersion::SingleV1 => {
            let (identity_secret, el_size) = IdSecret::from_bytes_be(&bytes[read..])?;
            read += el_size;
            let (user_message_limit, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
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

            #[cfg(not(feature = "multi-message-id"))]
            let witness = RLNWitnessInput::new(
                identity_secret,
                user_message_limit,
                message_id,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
            )?;
            #[cfg(feature = "multi-message-id")]
            let witness = RLNWitnessInput::new(
                identity_secret,
                user_message_limit,
                Some(message_id),
                None,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
                None,
            )?;
            if read != bytes.len() {
                return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
            }
            Ok((witness, read))
        }
        #[cfg(feature = "multi-message-id")]
        SerializationVersion::MultiV1 => {
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

            if selector_used.len() != message_ids.len() {
                return Err(ProtocolError::MultiOutputLengthMismatch {
                    expected: message_ids.len(),
                    actual: selector_used.len(),
                });
            }
            if read != bytes.len() {
                return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
            }

            Ok((
                RLNWitnessInput::new(
                    identity_secret,
                    user_message_limit,
                    None,
                    Some(message_ids),
                    path_elements,
                    identity_path_index,
                    x,
                    external_nullifier,
                    Some(selector_used),
                )?,
                read,
            ))
        }
    }
}

/// Converts RLN witness to JSON with BigInt string representation for witness calculator.
pub fn rln_witness_to_bigint_json(
    witness: &RLNWitnessInput,
) -> Result<serde_json::Value, ProtocolError> {
    match witness {
        RLNWitnessInput::SingleV1 {
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        } => {
            let path_elements_str: Vec<String> = path_elements
                .iter()
                .map(|v| to_bigint(v).to_str_radix(10))
                .collect();
            let identity_path_index_str: Vec<String> = identity_path_index
                .iter()
                .map(|v| BigInt::from(*v).to_str_radix(10))
                .collect();

            Ok(serde_json::json!({
                "identitySecret": to_bigint(identity_secret).to_str_radix(10),
                "userMessageLimit": to_bigint(user_message_limit).to_str_radix(10),
                "messageId": to_bigint(message_id).to_str_radix(10),
                "pathElements": path_elements_str,
                "identityPathIndex": identity_path_index_str,
                "x": to_bigint(x).to_str_radix(10),
                "externalNullifier": to_bigint(external_nullifier).to_str_radix(10),
            }))
        }
        #[cfg(feature = "multi-message-id")]
        RLNWitnessInput::MultiV1 {
            identity_secret,
            user_message_limit,
            message_ids,
            selector_used,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        } => {
            let path_elements_str: Vec<String> = path_elements
                .iter()
                .map(|v| to_bigint(v).to_str_radix(10))
                .collect();
            let identity_path_index_str: Vec<String> = identity_path_index
                .iter()
                .map(|v| BigInt::from(*v).to_str_radix(10))
                .collect();
            let message_ids_str: Vec<String> = message_ids
                .iter()
                .map(|id| to_bigint(id).to_str_radix(10))
                .collect();
            let selector_used_str: Vec<String> = selector_used
                .iter()
                .map(|&v| BigInt::from(v).to_str_radix(10))
                .collect();

            Ok(serde_json::json!({
                "identitySecret": to_bigint(identity_secret).to_str_radix(10),
                "userMessageLimit": to_bigint(user_message_limit).to_str_radix(10),
                "messageId": message_ids_str,
                "selectorUsed": selector_used_str,
                "pathElements": path_elements_str,
                "identityPathIndex": identity_path_index_str,
                "x": to_bigint(x).to_str_radix(10),
                "externalNullifier": to_bigint(external_nullifier).to_str_radix(10),
            }))
        }
    }
}

/// Computes RLN proof values from witness input.
///
/// Calculates the public outputs (y, nullifier, root) that will be part of the proof.
pub fn proof_values_from_witness(
    witness: &RLNWitnessInput,
) -> Result<RLNProofValues, ProtocolError> {
    match witness {
        RLNWitnessInput::SingleV1 {
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        } => {
            let root = compute_tree_root(
                identity_secret,
                user_message_limit,
                path_elements,
                identity_path_index,
            )?;

            let a_0 = identity_secret;
            let mut to_hash = [**a_0, *external_nullifier, *message_id];
            let a_1 = poseidon_hash(&to_hash)?;
            let y = *(a_0.clone()) + *x * a_1;
            let nullifier = poseidon_hash(&[a_1])?;
            to_hash[0].zeroize();

            Ok(RLNProofValues::SingleV1 {
                y,
                nullifier,
                root,
                x: *x,
                external_nullifier: *external_nullifier,
            })
        }
        #[cfg(feature = "multi-message-id")]
        RLNWitnessInput::MultiV1 {
            identity_secret,
            user_message_limit,
            message_ids,
            selector_used,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        } => {
            let root = compute_tree_root(
                identity_secret,
                user_message_limit,
                path_elements,
                identity_path_index,
            )?;

            let a_0 = identity_secret;
            let mut ys = Vec::with_capacity(message_ids.len());
            let mut nullifiers = Vec::with_capacity(message_ids.len());

            for (i, message_id) in message_ids.iter().enumerate() {
                let mut to_hash = [**a_0, *external_nullifier, *message_id];
                let a_1 = poseidon_hash(&to_hash)?;

                let selector = Fr::from(selector_used[i]);
                let y = (*(a_0.clone()) + *x * a_1) * selector;
                let nullifier = poseidon_hash(&[a_1])? * selector;

                ys.push(y);
                nullifiers.push(nullifier);
                to_hash[0].zeroize();
            }

            Ok(RLNProofValues::MultiV1 {
                ys,
                nullifiers,
                root,
                x: *x,
                external_nullifier: *external_nullifier,
                selector_used: selector_used.clone(),
            })
        }
    }
}

/// Computes the Merkle tree root from identity credentials and Merkle membership proof.
pub fn compute_tree_root(
    identity_secret: &IdSecret,
    user_message_limit: &Fr,
    path_elements: &[Fr],
    identity_path_index: &[u8],
) -> Result<Fr, ProtocolError> {
    let mut to_hash = [*identity_secret.clone()];
    let id_commitment = poseidon_hash(&to_hash)?;
    to_hash[0].zeroize();

    let mut root = poseidon_hash(&[id_commitment, *user_message_limit])?;

    for i in 0..identity_path_index.len() {
        if identity_path_index[i] == 0 {
            root = poseidon_hash(&[root, path_elements[i]])?;
        } else {
            root = poseidon_hash(&[path_elements[i], root])?;
        }
    }

    Ok(root)
}

/// Prepares inputs for witness calculation from RLN witness input.
pub(super) fn inputs_for_witness_calculation(
    witness: &RLNWitnessInput,
) -> Result<Vec<(&str, Vec<FrOrSecret>)>, ProtocolError> {
    match witness {
        RLNWitnessInput::SingleV1 {
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        } => {
            let identity_path_index_fr: Vec<FrOrSecret> = identity_path_index
                .iter()
                .map(|v| Fr::from(*v).into())
                .collect();

            Ok(vec![
                ("identitySecret", vec![identity_secret.clone().into()]),
                ("userMessageLimit", vec![(*user_message_limit).into()]),
                ("messageId", vec![(*message_id).into()]),
                (
                    "pathElements",
                    path_elements.iter().cloned().map(Into::into).collect(),
                ),
                ("identityPathIndex", identity_path_index_fr),
                ("x", vec![(*x).into()]),
                ("externalNullifier", vec![(*external_nullifier).into()]),
            ])
        }
        #[cfg(feature = "multi-message-id")]
        RLNWitnessInput::MultiV1 {
            identity_secret,
            user_message_limit,
            message_ids,
            selector_used,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        } => {
            let identity_path_index_fr: Vec<FrOrSecret> = identity_path_index
                .iter()
                .map(|v| Fr::from(*v).into())
                .collect();
            let selector_used_fr: Vec<FrOrSecret> =
                selector_used.iter().map(|&v| Fr::from(v).into()).collect();

            Ok(vec![
                ("identitySecret", vec![identity_secret.clone().into()]),
                ("userMessageLimit", vec![(*user_message_limit).into()]),
                (
                    "messageId",
                    message_ids.iter().cloned().map(Into::into).collect(),
                ),
                ("selectorUsed", selector_used_fr),
                (
                    "pathElements",
                    path_elements.iter().cloned().map(Into::into).collect(),
                ),
                ("identityPathIndex", identity_path_index_fr),
                ("x", vec![(*x).into()]),
                ("externalNullifier", vec![(*external_nullifier).into()]),
            ])
        }
    }
}
