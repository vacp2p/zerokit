use zeroize::Zeroize;

use super::proof::RLNProofValues;
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
    identity_secret: IdSecret,
    user_message_limit: Fr,
    message_id: Fr,
    path_elements: Vec<Fr>,
    identity_path_index: Vec<u8>,
    x: Fr,
    external_nullifier: Fr,
}

/// Partial witness input for RLN proof precalculation.
/// Contains the non-changing inputs used to precompute a partial proof:
#[derive(Debug, PartialEq, Clone)]
pub struct RLNPartialWitnessInput {
    identity_secret: IdSecret,
    user_message_limit: Fr,
    path_elements: Vec<Fr>,
    identity_path_index: Vec<u8>,
}

impl RLNWitnessInput {
    pub fn new(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        message_id: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: Fr,
        external_nullifier: Fr,
    ) -> Result<Self, ProtocolError> {
        // User message limit check
        if user_message_limit == Fr::from(0) {
            return Err(ProtocolError::ZeroUserMessageLimit);
        }

        // Message ID range check
        if message_id >= user_message_limit {
            return Err(ProtocolError::InvalidMessageId(
                message_id,
                user_message_limit,
            ));
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
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        })
    }

    pub fn identity_secret(&self) -> &IdSecret {
        &self.identity_secret
    }

    pub fn user_message_limit(&self) -> &Fr {
        &self.user_message_limit
    }

    pub fn message_id(&self) -> &Fr {
        &self.message_id
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
}

impl RLNPartialWitnessInput {
    pub fn new(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
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

    pub fn identity_secret(&self) -> &IdSecret {
        &self.identity_secret
    }

    pub fn user_message_limit(&self) -> &Fr {
        &self.user_message_limit
    }

    pub fn path_elements(&self) -> &[Fr] {
        &self.path_elements
    }

    pub fn identity_path_index(&self) -> &[u8] {
        &self.identity_path_index
    }
}

/// Serializes an RLN witness to little-endian bytes.
pub fn rln_witness_to_bytes_le(witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    // Calculate capacity for Vec:
    // - 5 fixed field elements: identity_secret, user_message_limit, message_id, x, external_nullifier
    // - variable number of path elements
    // - identity_path_index (variable size)
    let mut bytes: Vec<u8> = Vec::with_capacity(
        FR_BYTE_SIZE * (5 + witness.path_elements.len()) + witness.identity_path_index.len(),
    );
    bytes.extend_from_slice(&witness.identity_secret.to_bytes_le());
    bytes.extend_from_slice(&fr_to_bytes_le(&witness.user_message_limit));
    bytes.extend_from_slice(&fr_to_bytes_le(&witness.message_id));
    bytes.extend_from_slice(&vec_fr_to_bytes_le(&witness.path_elements));
    bytes.extend_from_slice(&vec_u8_to_bytes_le(&witness.identity_path_index));
    bytes.extend_from_slice(&fr_to_bytes_le(&witness.x));
    bytes.extend_from_slice(&fr_to_bytes_le(&witness.external_nullifier));

    Ok(bytes)
}

/// Serializes an RLN witness to big-endian bytes.
pub fn rln_witness_to_bytes_be(witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    // Calculate capacity for Vec:
    // - 5 fixed field elements: identity_secret, user_message_limit, message_id, x, external_nullifier
    // - variable number of path elements
    // - identity_path_index (variable size)
    let mut bytes: Vec<u8> = Vec::with_capacity(
        FR_BYTE_SIZE * (5 + witness.path_elements.len()) + witness.identity_path_index.len(),
    );
    bytes.extend_from_slice(&witness.identity_secret.to_bytes_be());
    bytes.extend_from_slice(&fr_to_bytes_be(&witness.user_message_limit));
    bytes.extend_from_slice(&fr_to_bytes_be(&witness.message_id));
    bytes.extend_from_slice(&vec_fr_to_bytes_be(&witness.path_elements));
    bytes.extend_from_slice(&vec_u8_to_bytes_be(&witness.identity_path_index));
    bytes.extend_from_slice(&fr_to_bytes_be(&witness.x));
    bytes.extend_from_slice(&fr_to_bytes_be(&witness.external_nullifier));

    Ok(bytes)
}

/// Deserializes an RLN witness from little-endian bytes.
///
/// Format: `[ identity_secret<32> | user_message_limit<32> | message_id<32> | path_elements<var> | identity_path_index<var> | x<32> | external_nullifier<32> ]`
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

    if bytes.len() != read {
        return Err(ProtocolError::InvalidReadLen(bytes.len(), read));
    }

    Ok((
        RLNWitnessInput::new(
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        )?,
        read,
    ))
}

/// Deserializes an RLN witness from big-endian bytes.
///
/// Format: `[ identity_secret<32> | user_message_limit<32> | message_id<32> | path_elements<var> | identity_path_index<var> | x<32> | external_nullifier<32> ]`
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

    if bytes.len() != read {
        return Err(ProtocolError::InvalidReadLen(bytes.len(), read));
    }

    Ok((
        RLNWitnessInput::new(
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        )?,
        read,
    ))
}

/// Converts RLN witness to JSON with BigInt string representation for witness calculator.
pub fn rln_witness_to_bigint_json(
    witness: &RLNWitnessInput,
) -> Result<serde_json::Value, ProtocolError> {
    use num_bigint::BigInt;

    let mut path_elements = Vec::new();

    for v in witness.path_elements.iter() {
        path_elements.push(to_bigint(v).to_str_radix(10));
    }

    let mut identity_path_index = Vec::new();
    witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(BigInt::from(*v).to_str_radix(10)));

    let inputs = serde_json::json!({
        "identitySecret": to_bigint(&witness.identity_secret).to_str_radix(10),
        "userMessageLimit": to_bigint(&witness.user_message_limit).to_str_radix(10),
        "messageId": to_bigint(&witness.message_id).to_str_radix(10),
        "pathElements": path_elements,
        "identityPathIndex": identity_path_index,
        "x": to_bigint(&witness.x).to_str_radix(10),
        "externalNullifier":  to_bigint(&witness.external_nullifier).to_str_radix(10),
    });

    Ok(inputs)
}

/// Computes RLN proof values from witness input.
///
/// Calculates the public outputs (y, nullifier, root) that will be part of the proof.
pub fn proof_values_from_witness(
    witness: &RLNWitnessInput,
) -> Result<RLNProofValues, ProtocolError> {
    // y share
    let a_0 = &witness.identity_secret;
    let mut to_hash = [**a_0, witness.external_nullifier, witness.message_id];
    let a_1 = poseidon_hash(&to_hash)?;
    let y = *(a_0.clone()) + witness.x * a_1;

    // Nullifier
    let nullifier = poseidon_hash(&[a_1])?;
    to_hash[0].zeroize();

    // Merkle tree root computations
    let root = compute_tree_root(
        &witness.identity_secret,
        &witness.user_message_limit,
        &witness.path_elements,
        &witness.identity_path_index,
    )?;

    Ok(RLNProofValues {
        y,
        nullifier,
        root,
        x: witness.x,
        external_nullifier: witness.external_nullifier,
    })
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
) -> Result<[(&str, Vec<FrOrSecret>); 7], ProtocolError> {
    let mut identity_path_index = Vec::with_capacity(witness.identity_path_index.len());
    witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(Fr::from(*v)));

    Ok([
        (
            "identitySecret",
            vec![witness.identity_secret.clone().into()],
        ),
        ("userMessageLimit", vec![witness.user_message_limit.into()]),
        ("messageId", vec![witness.message_id.into()]),
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
    ])
}

/// Prepares known inputs for partial witness calculation from RLN witness input.
/// unknowns are `None`
pub(super) fn inputs_for_partial_witness_calculation(
    witness: &RLNPartialWitnessInput,
) -> Result<[(&str, Vec<Option<FrOrSecret>>); 7], ProtocolError> {
    let mut identity_path_index = Vec::with_capacity(witness.identity_path_index.len());
    witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(Fr::from(*v)));

    Ok([
        (
            "identitySecret",
            vec![Some(witness.identity_secret.clone().into())],
        ),
        (
            "userMessageLimit",
            vec![Some(witness.user_message_limit.into())],
        ),
        ("messageId", vec![None]),
        (
            "pathElements",
            witness
                .path_elements
                .iter()
                .cloned()
                .map(Into::into)
                .map(Some)
                .collect(),
        ),
        (
            "identityPathIndex",
            identity_path_index
                .into_iter()
                .map(Into::into)
                .map(Some)
                .collect(),
        ),
        ("x", vec![None]),
        ("externalNullifier", vec![None]),
    ])
}
