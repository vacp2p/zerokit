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
        FR_BYTE_SIZE, VEC_LEN_BYTE_SIZE,
    },
};

/// Variant-specific message inputs for RLN witness.
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RLNMessageInputs {
    #[cfg(not(feature = "multi-message-id"))]
    SingleV1 { message_id: Fr },
    #[cfg(feature = "multi-message-id")]
    MultiV1 {
        message_ids: Vec<Fr>,
        selector_used: Vec<bool>,
    },
}

/// Witness input for RLN proof generation.
///
/// Contains the identity credentials, merkle proof, rate-limiting parameters,
/// and signal binding data required to generate a Groth16 proof for the RLN protocol.
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

impl RLNWitnessInput {
    /// Creates a new RLNWitnessInput instance.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        #[cfg(not(feature = "multi-message-id"))] message_id: Fr,
        #[cfg(feature = "multi-message-id")] message_ids: Vec<Fr>,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: Fr,
        external_nullifier: Fr,
        #[cfg(feature = "multi-message-id")] selector_used: Vec<bool>,
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
        if message_id >= user_message_limit {
            return Err(ProtocolError::InvalidMessageId(
                message_id,
                user_message_limit,
            ));
        }

        #[cfg(feature = "multi-message-id")]
        {
            // Message IDs must be non-empty
            if message_ids.is_empty() {
                return Err(ProtocolError::EmptyMessageIds);
            }
            // Selector length must match message IDs
            if selector_used.len() != message_ids.len() {
                return Err(ProtocolError::FieldLengthMismatch(
                    "message_ids".into(),
                    message_ids.len(),
                    "selector_used".into(),
                    selector_used.len(),
                ));
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
                        return Err(ProtocolError::DuplicateMessageIds);
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
        }

        #[cfg(not(feature = "multi-message-id"))]
        let message_inputs = RLNMessageInputs::SingleV1 { message_id };
        #[cfg(feature = "multi-message-id")]
        let message_inputs = RLNMessageInputs::MultiV1 {
            message_ids,
            selector_used,
        };

        Ok(Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_inputs,
        })
    }

    /// Returns the version byte corresponding to the witness variant.
    pub fn version_byte(&self) -> u8 {
        match &self.message_inputs {
            #[cfg(not(feature = "multi-message-id"))]
            RLNMessageInputs::SingleV1 { .. } => SerializationVersion::SingleV1.into(),
            #[cfg(feature = "multi-message-id")]
            RLNMessageInputs::MultiV1 { .. } => SerializationVersion::MultiV1.into(),
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

    /// Returns the message ID.
    #[cfg(not(feature = "multi-message-id"))]
    pub fn message_id(&self) -> &Fr {
        let RLNMessageInputs::SingleV1 { message_id } = &self.message_inputs;
        message_id
    }

    /// Returns the multi message IDs.
    #[cfg(feature = "multi-message-id")]
    pub fn message_ids(&self) -> &[Fr] {
        let RLNMessageInputs::MultiV1 { message_ids, .. } = &self.message_inputs;
        message_ids
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

    /// Returns the selector flags.
    #[cfg(feature = "multi-message-id")]
    pub fn selector_used(&self) -> &[bool] {
        let RLNMessageInputs::MultiV1 { selector_used, .. } = &self.message_inputs;
        selector_used
    }
}

/// Serializes an RLN witness to little-endian bytes.
pub fn rln_witness_to_bytes_le(witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    #[cfg(not(feature = "multi-message-id"))]
    let RLNMessageInputs::SingleV1 { message_id } = &witness.message_inputs;
    #[cfg(feature = "multi-message-id")]
    let RLNMessageInputs::MultiV1 {
        message_ids,
        selector_used,
    } = &witness.message_inputs;

    // Calculate capacity for Vec:
    // - VERSION_BYTE_SIZE byte for version tag
    // - 2 common field elements: identity_secret, user_message_limit
    // - variable size of path_elements, identity_path_index
    #[cfg(not(feature = "multi-message-id"))]
    // - 3 field elements: message_id, x, external_nullifier
    // - VEC_LEN_BYTE_SIZE bytes length prefix per vector (path_elements, identity_path_index)
    let capacity = VERSION_BYTE_SIZE
        + FR_BYTE_SIZE * (5 + witness.path_elements.len())
        + witness.identity_path_index.len()
        + VEC_LEN_BYTE_SIZE * 2;
    #[cfg(feature = "multi-message-id")]
    // - 2 field elements: x, external_nullifier
    // - variable size of message_ids, selector_used
    // - VEC_LEN_BYTE_SIZE bytes length prefix per vector (path_elements, identity_path_index, message_ids, selector_used)
    let capacity = VERSION_BYTE_SIZE
        + FR_BYTE_SIZE * (4 + witness.path_elements.len() + message_ids.len())
        + witness.identity_path_index.len()
        + selector_used.len()
        + VEC_LEN_BYTE_SIZE * 4;

    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(witness.version_byte());
    bytes.extend_from_slice(&witness.identity_secret.to_bytes_le());
    bytes.extend_from_slice(&fr_to_bytes_le(&witness.user_message_limit));
    #[cfg(not(feature = "multi-message-id"))]
    {
        bytes.extend_from_slice(&fr_to_bytes_le(message_id));
        bytes.extend_from_slice(&vec_fr_to_bytes_le(&witness.path_elements));
        bytes.extend_from_slice(&vec_u8_to_bytes_le(&witness.identity_path_index));
        bytes.extend_from_slice(&fr_to_bytes_le(&witness.x));
        bytes.extend_from_slice(&fr_to_bytes_le(&witness.external_nullifier));
    }
    #[cfg(feature = "multi-message-id")]
    {
        bytes.extend_from_slice(&vec_fr_to_bytes_le(&witness.path_elements));
        bytes.extend_from_slice(&vec_u8_to_bytes_le(&witness.identity_path_index));
        bytes.extend_from_slice(&fr_to_bytes_le(&witness.x));
        bytes.extend_from_slice(&fr_to_bytes_le(&witness.external_nullifier));
        bytes.extend_from_slice(&vec_fr_to_bytes_le(message_ids));
        bytes.extend_from_slice(&vec_bool_to_bytes_le(selector_used));
    }
    Ok(bytes)
}

/// Serializes an RLN witness to big-endian bytes.
pub fn rln_witness_to_bytes_be(witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    #[cfg(not(feature = "multi-message-id"))]
    let RLNMessageInputs::SingleV1 { message_id } = &witness.message_inputs;
    #[cfg(feature = "multi-message-id")]
    let RLNMessageInputs::MultiV1 {
        message_ids,
        selector_used,
    } = &witness.message_inputs;

    // Calculate capacity for Vec:
    // - VERSION_BYTE_SIZE byte for version tag
    // - 2 common field elements: identity_secret, user_message_limit
    // - variable size of path_elements, identity_path_index
    #[cfg(not(feature = "multi-message-id"))]
    // - 3 field elements: message_id, x, external_nullifier
    // - VEC_LEN_BYTE_SIZE bytes length prefix per vector (path_elements, identity_path_index)
    let capacity = VERSION_BYTE_SIZE
        + FR_BYTE_SIZE * (5 + witness.path_elements.len())
        + witness.identity_path_index.len()
        + VEC_LEN_BYTE_SIZE * 2;
    #[cfg(feature = "multi-message-id")]
    // - 2 field elements: x, external_nullifier
    // - variable size of message_ids, selector_used
    // - VEC_LEN_BYTE_SIZE bytes length prefix per vector (path_elements, identity_path_index, message_ids, selector_used)
    let capacity = VERSION_BYTE_SIZE
        + FR_BYTE_SIZE * (4 + witness.path_elements.len() + message_ids.len())
        + witness.identity_path_index.len()
        + selector_used.len()
        + VEC_LEN_BYTE_SIZE * 4;

    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(witness.version_byte());
    bytes.extend_from_slice(&witness.identity_secret.to_bytes_be());
    bytes.extend_from_slice(&fr_to_bytes_be(&witness.user_message_limit));
    #[cfg(not(feature = "multi-message-id"))]
    {
        bytes.extend_from_slice(&fr_to_bytes_be(message_id));
        bytes.extend_from_slice(&vec_fr_to_bytes_be(&witness.path_elements));
        bytes.extend_from_slice(&vec_u8_to_bytes_be(&witness.identity_path_index));
        bytes.extend_from_slice(&fr_to_bytes_be(&witness.x));
        bytes.extend_from_slice(&fr_to_bytes_be(&witness.external_nullifier));
    }
    #[cfg(feature = "multi-message-id")]
    {
        bytes.extend_from_slice(&vec_fr_to_bytes_be(&witness.path_elements));
        bytes.extend_from_slice(&vec_u8_to_bytes_be(&witness.identity_path_index));
        bytes.extend_from_slice(&fr_to_bytes_be(&witness.x));
        bytes.extend_from_slice(&fr_to_bytes_be(&witness.external_nullifier));
        bytes.extend_from_slice(&vec_fr_to_bytes_be(message_ids));
        bytes.extend_from_slice(&vec_bool_to_bytes_be(selector_used));
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

    let _version = SerializationVersion::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    let (identity_secret, el_size) = IdSecret::from_bytes_le(&bytes[read..])?;
    read += el_size;
    let (user_message_limit, el_size) = bytes_le_to_fr(&bytes[read..])?;
    read += el_size;

    #[cfg(not(feature = "multi-message-id"))]
    {
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
        let witness = RLNWitnessInput::new(
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
    #[cfg(feature = "multi-message-id")]
    {
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
                "message_ids".into(),
                message_ids.len(),
                "selector_used".into(),
                selector_used.len(),
            ));
        }
        if read != bytes.len() {
            return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
        }

        Ok((
            RLNWitnessInput::new(
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

/// Deserializes an RLN witness from big-endian bytes.
///
/// Returns the deserialized witness and the number of bytes read.
pub fn bytes_be_to_rln_witness(bytes: &[u8]) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::InvalidReadLen(1, 0));
    }

    let _version = SerializationVersion::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    let (identity_secret, el_size) = IdSecret::from_bytes_be(&bytes[read..])?;
    read += el_size;
    let (user_message_limit, el_size) = bytes_be_to_fr(&bytes[read..])?;
    read += el_size;

    #[cfg(not(feature = "multi-message-id"))]
    {
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
        let witness = RLNWitnessInput::new(
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
    #[cfg(feature = "multi-message-id")]
    {
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
                "message_ids".into(),
                message_ids.len(),
                "selector_used".into(),
                selector_used.len(),
            ));
        }
        if read != bytes.len() {
            return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
        }

        Ok((
            RLNWitnessInput::new(
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

/// Converts RLN witness to JSON with BigInt string representation for witness calculator.
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

    #[cfg(not(feature = "multi-message-id"))]
    {
        let RLNMessageInputs::SingleV1 { message_id } = &witness.message_inputs;
        Ok(serde_json::json!({
            "identitySecret": to_bigint(&witness.identity_secret).to_str_radix(10),
            "userMessageLimit": to_bigint(&witness.user_message_limit).to_str_radix(10),
            "messageId": to_bigint(message_id).to_str_radix(10),
            "pathElements": path_elements_str,
            "identityPathIndex": identity_path_index_str,
            "x": to_bigint(&witness.x).to_str_radix(10),
            "externalNullifier": to_bigint(&witness.external_nullifier).to_str_radix(10),
        }))
    }
    #[cfg(feature = "multi-message-id")]
    {
        let RLNMessageInputs::MultiV1 {
            message_ids,
            selector_used,
        } = &witness.message_inputs;
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

/// Computes RLN proof values from witness input.
///
/// Calculates the public outputs (y, nullifier, root) that will be part of the proof.
pub fn proof_values_from_witness(
    witness: &RLNWitnessInput,
) -> Result<RLNProofValues, ProtocolError> {
    let root = compute_tree_root(
        &witness.identity_secret,
        &witness.user_message_limit,
        &witness.path_elements,
        &witness.identity_path_index,
    )?;

    let a_0 = &witness.identity_secret;

    #[cfg(not(feature = "multi-message-id"))]
    {
        let RLNMessageInputs::SingleV1 { message_id } = &witness.message_inputs;
        let mut to_hash = [**a_0, witness.external_nullifier, *message_id];
        let a_1 = poseidon_hash(&to_hash)?;
        let y = *(a_0.clone()) + witness.x * a_1;
        let nullifier = poseidon_hash(&[a_1])?;
        to_hash[0].zeroize();

        Ok(RLNProofValues::new(
            root,
            witness.x,
            witness.external_nullifier,
            y,
            nullifier,
        ))
    }
    #[cfg(feature = "multi-message-id")]
    {
        let RLNMessageInputs::MultiV1 {
            message_ids,
            selector_used,
        } = &witness.message_inputs;
        let mut ys = Vec::with_capacity(message_ids.len());
        let mut nullifiers = Vec::with_capacity(message_ids.len());

        for (i, message_id) in message_ids.iter().enumerate() {
            let mut to_hash = [**a_0, witness.external_nullifier, *message_id];
            let a_1 = poseidon_hash(&to_hash)?;

            let selector = Fr::from(selector_used[i]);
            let y = (*(a_0.clone()) + witness.x * a_1) * selector;
            let nullifier = poseidon_hash(&[a_1])? * selector;

            ys.push(y);
            nullifiers.push(nullifier);
            to_hash[0].zeroize();
        }

        Ok(RLNProofValues::new(
            root,
            witness.x,
            witness.external_nullifier,
            ys,
            nullifiers,
            selector_used.clone(),
        ))
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

    #[cfg(not(feature = "multi-message-id"))]
    {
        let RLNMessageInputs::SingleV1 { message_id } = &witness.message_inputs;
        inputs.push(("messageId", vec![(*message_id).into()]));
    }
    #[cfg(feature = "multi-message-id")]
    {
        let RLNMessageInputs::MultiV1 {
            message_ids,
            selector_used,
        } = &witness.message_inputs;
        inputs.push((
            "messageId",
            message_ids.iter().cloned().map(Into::into).collect(),
        ));
        let selector_used_fr: Vec<FrOrSecret> =
            selector_used.iter().map(|&v| Fr::from(v).into()).collect();
        inputs.push(("selectorUsed", selector_used_fr));
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

    Ok(inputs)
}
