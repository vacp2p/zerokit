use num_bigint::BigInt;
use zeroize::Zeroize;

use super::proof::RLNProofValues;
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
pub struct RLNWitnessInput {
    // Private inputs
    identity_secret: IdSecret,
    user_message_limit: Fr,
    #[cfg(not(feature = "multi-message-id"))]
    message_id: Fr,
    #[cfg(feature = "multi-message-id")]
    message_id: Option<Fr>,
    #[cfg(feature = "multi-message-id")]
    message_ids: Option<Vec<Fr>>,
    path_elements: Vec<Fr>,
    identity_path_index: Vec<u8>,
    // Public inputs
    x: Fr,
    external_nullifier: Fr,
    #[cfg(feature = "multi-message-id")]
    selector_used: Option<Vec<bool>>,
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

        // Message ID range check
        #[cfg(not(feature = "multi-message-id"))]
        if message_id >= user_message_limit {
            return Err(ProtocolError::InvalidMessageId(
                message_id,
                user_message_limit,
            ));
        }

        #[cfg(feature = "multi-message-id")]
        let (message_id, message_ids) = match (message_id, message_ids) {
            (Some(_), Some(_)) => {
                return Err(ProtocolError::BothMessageIdSet);
            }
            (None, None) => {
                return Err(ProtocolError::NoMessageIdSet);
            }
            (Some(message_id), None) => {
                if message_id >= user_message_limit {
                    return Err(ProtocolError::InvalidMessageId(
                        message_id,
                        user_message_limit,
                    ));
                }
                (Some(message_id), None)
            }
            (None, Some(message_ids)) => {
                if message_ids.is_empty() {
                    return Err(ProtocolError::NoMessageIdSet);
                }

                if let Some(selector_used) = &selector_used {
                    if selector_used.len() != message_ids.len() {
                        return Err(ProtocolError::InvalidSelectorUsed);
                    }

                    for (message_id, used) in message_ids.iter().zip(selector_used) {
                        if *used && *message_id >= user_message_limit {
                            return Err(ProtocolError::InvalidMessageId(
                                *message_id,
                                user_message_limit,
                            ));
                        }
                    }
                    (None, Some(message_ids))
                } else {
                    return Err(ProtocolError::InvalidSelectorUsed);
                }
            }
        };

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
            message_id,
            #[cfg(feature = "multi-message-id")]
            message_ids,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            #[cfg(feature = "multi-message-id")]
            selector_used,
        })
    }

    pub fn identity_secret(&self) -> &IdSecret {
        &self.identity_secret
    }

    pub fn user_message_limit(&self) -> &Fr {
        &self.user_message_limit
    }

    #[cfg(not(feature = "multi-message-id"))]
    pub fn message_id(&self) -> &Fr {
        &self.message_id
    }

    #[cfg(feature = "multi-message-id")]
    pub fn message_id(&self) -> Option<&Fr> {
        self.message_id.as_ref()
    }

    #[cfg(feature = "multi-message-id")]
    pub fn message_ids(&self) -> Option<&Vec<Fr>> {
        self.message_ids.as_ref()
    }

    pub fn path_elements(&self) -> &[Fr] {
        &self.path_elements
    }

    pub fn identity_path_index(&self) -> &[u8] {
        &self.identity_path_index
    }

    pub fn x(&self) -> &Fr {
        &self.x
    }

    pub fn external_nullifier(&self) -> &Fr {
        &self.external_nullifier
    }

    #[cfg(feature = "multi-message-id")]
    pub fn selector_used(&self) -> Option<&Vec<bool>> {
        self.selector_used.as_ref()
    }
}

/// Serializes an RLN witness to little-endian bytes.
pub fn rln_witness_to_bytes_le(witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    // Calculate capacity for Vec:
    // - 5 field elements: identity_secret, user_message_limit, message_id, x, external_nullifier
    // - variable size of path elements
    // - variable size of identity_path_index
    // - optional variable size of message_ids
    // - optional variable size of selector_used

    #[cfg(not(feature = "multi-message-id"))]
    let capacity =
        FR_BYTE_SIZE * (5 + witness.path_elements.len()) + witness.identity_path_index.len();
    #[cfg(feature = "multi-message-id")]
    let capacity = FR_BYTE_SIZE
        * (5 + witness.path_elements.len() + witness.message_ids.as_ref().map_or(0, |v| v.len()))
        + witness.identity_path_index.len()
        + witness.selector_used.as_ref().map_or(0, |v| v.len());

    let mut bytes: Vec<u8> = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&witness.identity_secret.to_bytes_le());
    bytes.extend_from_slice(&fr_to_bytes_le(&witness.user_message_limit));
    // Always serialize message_id field for backward compatibility
    #[cfg(not(feature = "multi-message-id"))]
    bytes.extend_from_slice(&fr_to_bytes_le(&witness.message_id));
    #[cfg(feature = "multi-message-id")]
    bytes.extend_from_slice(&fr_to_bytes_le(&witness.message_id.unwrap_or(Fr::from(0))));
    bytes.extend_from_slice(&vec_fr_to_bytes_le(&witness.path_elements));
    bytes.extend_from_slice(&vec_u8_to_bytes_le(&witness.identity_path_index));
    bytes.extend_from_slice(&fr_to_bytes_le(&witness.x));
    bytes.extend_from_slice(&fr_to_bytes_le(&witness.external_nullifier));
    #[cfg(feature = "multi-message-id")]
    {
        if let Some(message_ids) = &witness.message_ids {
            bytes.extend_from_slice(&vec_fr_to_bytes_le(message_ids));
        }
        if let Some(selector_used) = &witness.selector_used {
            bytes.extend_from_slice(&vec_bool_to_bytes_le(selector_used));
        }
    }

    Ok(bytes)
}

/// Serializes an RLN witness to big-endian bytes.
pub fn rln_witness_to_bytes_be(witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    // Calculate capacity for Vec:
    // - 5 field elements: identity_secret, user_message_limit, message_id, x, external_nullifier
    // - variable size of path elements
    // - variable size of identity_path_index
    // - optional variable size of message_ids
    // - optional variable size of selector_used

    #[cfg(not(feature = "multi-message-id"))]
    let capacity =
        FR_BYTE_SIZE * (5 + witness.path_elements.len()) + witness.identity_path_index.len();
    #[cfg(feature = "multi-message-id")]
    let capacity = FR_BYTE_SIZE
        * (5 + witness.path_elements.len() + witness.message_ids.as_ref().map_or(0, |v| v.len()))
        + witness.identity_path_index.len()
        + witness.selector_used.as_ref().map_or(0, |v| v.len());

    let mut bytes: Vec<u8> = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&witness.identity_secret.to_bytes_be());
    bytes.extend_from_slice(&fr_to_bytes_be(&witness.user_message_limit));
    // Always serialize message_id field for backward compatibility
    #[cfg(not(feature = "multi-message-id"))]
    bytes.extend_from_slice(&fr_to_bytes_be(&witness.message_id));
    #[cfg(feature = "multi-message-id")]
    bytes.extend_from_slice(&fr_to_bytes_be(&witness.message_id.unwrap_or(Fr::from(0))));
    bytes.extend_from_slice(&vec_fr_to_bytes_be(&witness.path_elements));
    bytes.extend_from_slice(&vec_u8_to_bytes_be(&witness.identity_path_index));
    bytes.extend_from_slice(&fr_to_bytes_be(&witness.x));
    bytes.extend_from_slice(&fr_to_bytes_be(&witness.external_nullifier));
    #[cfg(feature = "multi-message-id")]
    {
        if let Some(message_ids) = &witness.message_ids {
            bytes.extend_from_slice(&vec_fr_to_bytes_be(message_ids));
        }
        if let Some(selector_used) = &witness.selector_used {
            bytes.extend_from_slice(&vec_bool_to_bytes_be(selector_used));
        }
    }

    Ok(bytes)
}

/// Deserializes an RLN witness from little-endian bytes.
///
/// Format: `[ identity_secret<32> | user_message_limit<32> | message_id<32> | path_elements<var> | identity_path_index<var> | x<32> | external_nullifier<32> | message_ids<var>? | selector_used<var>? ]`
///
/// Returns the deserialized witness and the number of bytes read.
pub fn bytes_le_to_rln_witness(bytes: &[u8]) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    let mut read: usize = 0;

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

    #[cfg(feature = "multi-message-id")]
    let (message_id, message_ids, selector_used) = if read < bytes.len() {
        match bytes_le_to_vec_fr(&bytes[read..]) {
            Ok((message_ids, el_size)) => {
                read += el_size;
                if message_ids.is_empty() {
                    (Some(message_id), None, None)
                } else {
                    let selector_used = if read < bytes.len() {
                        let (selector_used, el_size) = bytes_le_to_vec_bool(&bytes[read..])?;
                        read += el_size;
                        selector_used
                    } else {
                        return Err(ProtocolError::InvalidSelectorUsed);
                    };
                    if selector_used.len() != message_ids.len() {
                        return Err(ProtocolError::InvalidSelectorUsed);
                    }
                    (None, Some(message_ids), Some(selector_used))
                }
            }
            Err(_) => {
                return Err(ProtocolError::InvalidReadLen(bytes.len(), read));
            }
        }
    } else {
        (Some(message_id), None, None)
    };

    if bytes.len() != read {
        return Err(ProtocolError::InvalidReadLen(bytes.len(), read));
    }

    Ok((
        RLNWitnessInput::new(
            identity_secret,
            user_message_limit,
            message_id,
            #[cfg(feature = "multi-message-id")]
            message_ids,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            #[cfg(feature = "multi-message-id")]
            selector_used,
        )?,
        read,
    ))
}

/// Deserializes an RLN witness from big-endian bytes.
///
/// Format: `[ identity_secret<32> | user_message_limit<32> | message_id<32> | path_elements<var> | identity_path_index<var> | x<32> | external_nullifier<32> | message_ids<var>? | selector_used<var>? ]`
///
/// Returns the deserialized witness and the number of bytes read.
pub fn bytes_be_to_rln_witness(bytes: &[u8]) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    let mut read: usize = 0;

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

    #[cfg(feature = "multi-message-id")]
    let (message_id, message_ids, selector_used) = if read < bytes.len() {
        match bytes_be_to_vec_fr(&bytes[read..]) {
            Ok((message_ids, el_size)) => {
                read += el_size;
                if message_ids.is_empty() {
                    (Some(message_id), None, None)
                } else {
                    let selector_used = if read < bytes.len() {
                        let (selector_used, el_size) = bytes_be_to_vec_bool(&bytes[read..])?;
                        read += el_size;
                        selector_used
                    } else {
                        return Err(ProtocolError::InvalidSelectorUsed);
                    };
                    if selector_used.len() != message_ids.len() {
                        return Err(ProtocolError::InvalidSelectorUsed);
                    }
                    (None, Some(message_ids), Some(selector_used))
                }
            }
            Err(_) => {
                return Err(ProtocolError::InvalidReadLen(bytes.len(), read));
            }
        }
    } else {
        (Some(message_id), None, None)
    };

    if bytes.len() != read {
        return Err(ProtocolError::InvalidReadLen(bytes.len(), read));
    }

    Ok((
        RLNWitnessInput::new(
            identity_secret,
            user_message_limit,
            message_id,
            #[cfg(feature = "multi-message-id")]
            message_ids,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            #[cfg(feature = "multi-message-id")]
            selector_used,
        )?,
        read,
    ))
}

/// Converts RLN witness to JSON with BigInt string representation for witness calculator.
pub fn rln_witness_to_bigint_json(
    witness: &RLNWitnessInput,
) -> Result<serde_json::Value, ProtocolError> {
    let mut path_elements = Vec::new();
    for v in witness.path_elements.iter() {
        path_elements.push(to_bigint(v).to_str_radix(10));
    }

    let mut identity_path_index = Vec::new();
    witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(BigInt::from(*v).to_str_radix(10)));

    #[cfg(not(feature = "multi-message-id"))]
    {
        Ok(serde_json::json!({
            "identitySecret": to_bigint(&witness.identity_secret).to_str_radix(10),
            "userMessageLimit": to_bigint(&witness.user_message_limit).to_str_radix(10),
            "messageId": to_bigint(&witness.message_id).to_str_radix(10),
            "pathElements": path_elements,
            "identityPathIndex": identity_path_index,
            "x": to_bigint(&witness.x).to_str_radix(10),
            "externalNullifier": to_bigint(&witness.external_nullifier).to_str_radix(10),
        }))
    }

    #[cfg(feature = "multi-message-id")]
    {
        let mut json = serde_json::json!({
            "identitySecret": to_bigint(&witness.identity_secret).to_str_radix(10),
            "userMessageLimit": to_bigint(&witness.user_message_limit).to_str_radix(10),
            "pathElements": path_elements,
            "identityPathIndex": identity_path_index,
            "x": to_bigint(&witness.x).to_str_radix(10),
            "externalNullifier": to_bigint(&witness.external_nullifier).to_str_radix(10),
        });

        match (&witness.message_id, &witness.message_ids) {
            (Some(message_id), None) => {
                json["messageId"] = serde_json::json!(to_bigint(message_id).to_str_radix(10));
            }
            (None, Some(message_ids)) => {
                let message_ids_str: Vec<String> = message_ids
                    .iter()
                    .map(|id| to_bigint(id).to_str_radix(10))
                    .collect();

                let selector_used_strs: Vec<String> = witness
                    .selector_used
                    .as_ref()
                    .ok_or(ProtocolError::InvalidSelectorUsed)?
                    .iter()
                    .map(|&v| BigInt::from(v).to_str_radix(10))
                    .collect();

                json["messageId"] = serde_json::json!(message_ids_str);
                json["selectorUsed"] = serde_json::json!(selector_used_strs);
            }
            _ => return Err(ProtocolError::NoMessageIdSet),
        }

        Ok(json)
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

    #[cfg(not(feature = "multi-message-id"))]
    {
        let a_0 = &witness.identity_secret;
        let mut to_hash = [**a_0, witness.external_nullifier, witness.message_id];
        let a_1 = poseidon_hash(&to_hash)?;
        let y = *(a_0.clone()) + witness.x * a_1;

        let nullifier = poseidon_hash(&[a_1])?;
        to_hash[0].zeroize();

        Ok(RLNProofValues {
            y,
            nullifier,
            root,
            x: witness.x,
            external_nullifier: witness.external_nullifier,
        })
    }

    #[cfg(feature = "multi-message-id")]
    {
        let a_0 = &witness.identity_secret;

        match (&witness.message_id, &witness.message_ids) {
            (Some(message_id), None) => {
                let mut to_hash = [**a_0, witness.external_nullifier, *message_id];
                let a_1 = poseidon_hash(&to_hash)?;
                let y = *(a_0.clone()) + witness.x * a_1;
                let nullifier = poseidon_hash(&[a_1])?;
                to_hash[0].zeroize();

                Ok(RLNProofValues {
                    y: Some(y),
                    ys: None,
                    nullifier: Some(nullifier),
                    nullifiers: None,
                    root,
                    x: witness.x,
                    external_nullifier: witness.external_nullifier,
                    selector_used: None,
                })
            }
            (None, Some(message_ids)) => {
                let selector_used = witness
                    .selector_used
                    .as_ref()
                    .ok_or(ProtocolError::InvalidSelectorUsed)?;

                let mut ys = Vec::with_capacity(message_ids.len());
                let mut nullifiers = Vec::with_capacity(message_ids.len());

                for (i, message_id) in message_ids.iter().enumerate() {
                    let mut to_hash = [**a_0, witness.external_nullifier, *message_id];
                    let a_1 = poseidon_hash(&to_hash)?;

                    let y_unmasked = *(a_0.clone()) + witness.x * a_1;
                    let nullifier_unmasked = poseidon_hash(&[a_1])?;

                    let selector = Fr::from(selector_used[i]);
                    let y = y_unmasked * selector;
                    let nullifier = nullifier_unmasked * selector;

                    ys.push(y);
                    nullifiers.push(nullifier);

                    to_hash[0].zeroize();
                }

                Ok(RLNProofValues {
                    y: None,
                    ys: Some(ys),
                    nullifier: None,
                    nullifiers: Some(nullifiers),
                    root,
                    x: witness.x,
                    external_nullifier: witness.external_nullifier,
                    selector_used: Some(selector_used.clone()),
                })
            }
            _ => Err(ProtocolError::NoMessageIdSet),
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
    let mut identity_path_index = Vec::with_capacity(witness.identity_path_index.len());
    witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(Fr::from(*v)));

    let mut inputs = vec![
        (
            "identitySecret",
            vec![witness.identity_secret.clone().into()],
        ),
        ("userMessageLimit", vec![witness.user_message_limit.into()]),
        (
            "pathElements",
            witness
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
        ("x", vec![witness.x.into()]),
        ("externalNullifier", vec![witness.external_nullifier.into()]),
    ];

    #[cfg(not(feature = "multi-message-id"))]
    {
        inputs.push(("messageId", vec![witness.message_id.into()]));
    }

    #[cfg(feature = "multi-message-id")]
    {
        match (&witness.message_id, &witness.message_ids) {
            (Some(message_id), None) => {
                inputs.push(("messageId", vec![(*message_id).into()]));
            }
            (None, Some(message_ids)) => {
                inputs.push((
                    "messageId",
                    message_ids.iter().cloned().map(Into::into).collect(),
                ));

                let mut selector_used = Vec::with_capacity(message_ids.len());
                witness
                    .selector_used
                    .as_ref()
                    .ok_or(ProtocolError::InvalidSelectorUsed)?
                    .iter()
                    .for_each(|&v| selector_used.push(Fr::from(v)));

                inputs.push((
                    "selectorUsed",
                    selector_used.into_iter().map(Into::into).collect(),
                ));
            }
            _ => return Err(ProtocolError::NoMessageIdSet),
        }
    }

    Ok(inputs)
}
