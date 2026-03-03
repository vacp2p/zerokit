use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::thread_rng, UniformRand};
use num_bigint::BigInt;
use num_traits::Signed;

use super::{
    version::{SerializationVersion, VERSION_BYTE_SIZE},
    witness::{inputs_for_witness_calculation, RLNWitnessInput},
};
#[cfg(feature = "multi-message-id")]
use crate::utils::{
    bytes_be_to_vec_bool, bytes_be_to_vec_fr, bytes_le_to_vec_bool, bytes_le_to_vec_fr,
    vec_bool_to_bytes_be, vec_bool_to_bytes_le, vec_fr_to_bytes_be, vec_fr_to_bytes_le,
    VEC_LEN_BYTE_SIZE,
};
use crate::{
    circuit::{
        iden3calc::calc_witness, qap::CircomReduction, Curve, Fr, Graph, Proof, VerifyingKey, Zkey,
        COMPRESS_PROOF_SIZE,
    },
    error::ProtocolError,
    utils::{bytes_be_to_fr, bytes_le_to_fr, fr_to_bytes_be, fr_to_bytes_le, FR_BYTE_SIZE},
};

/// Complete RLN proof.
///
/// Combines the Groth16 proof with its public values.
#[derive(Debug, PartialEq, Clone)]
pub struct RLNProof {
    pub proof: Proof,
    pub proof_values: RLNProofValues,
}

impl RLNProof {
    /// Returns the version byte corresponding to the proof values variant.
    pub fn version_byte(&self) -> u8 {
        self.proof_values.version_byte()
    }
}

/// Public values for RLN proof verification.
///
/// Contains the circuit's public inputs and outputs. Used in proof verification
/// and identity secret recovery when rate limit violations are detected.
#[derive(Debug, PartialEq, Clone)]
pub enum RLNProofValues {
    #[cfg(not(feature = "multi-message-id"))]
    SingleV1 {
        // Public inputs:
        root: Fr,
        x: Fr,
        external_nullifier: Fr,
        // Public outputs:
        y: Fr,
        nullifier: Fr,
    },
    #[cfg(feature = "multi-message-id")]
    MultiV1 {
        // Public inputs:
        root: Fr,
        x: Fr,
        external_nullifier: Fr,
        selector_used: Vec<bool>,
        // Public outputs:
        ys: Vec<Fr>,
        nullifiers: Vec<Fr>,
    },
}

impl RLNProofValues {
    /// Returns the version byte corresponding to the proof values variant.
    pub fn version_byte(&self) -> u8 {
        match self {
            #[cfg(not(feature = "multi-message-id"))]
            Self::SingleV1 { .. } => SerializationVersion::SingleV1.into(),
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 { .. } => SerializationVersion::MultiV1.into(),
        }
    }

    /// Returns the Merkle tree root.
    pub fn root(&self) -> &Fr {
        match self {
            #[cfg(not(feature = "multi-message-id"))]
            Self::SingleV1 { root, .. } => root,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 { root, .. } => root,
        }
    }

    /// Returns the signal hash.
    pub fn x(&self) -> &Fr {
        match self {
            #[cfg(not(feature = "multi-message-id"))]
            Self::SingleV1 { x, .. } => x,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 { x, .. } => x,
        }
    }

    /// Returns the external nullifier.
    pub fn external_nullifier(&self) -> &Fr {
        match self {
            #[cfg(not(feature = "multi-message-id"))]
            Self::SingleV1 {
                external_nullifier, ..
            } => external_nullifier,
            #[cfg(feature = "multi-message-id")]
            Self::MultiV1 {
                external_nullifier, ..
            } => external_nullifier,
        }
    }

    /// Returns the output `y` value.
    #[cfg(not(feature = "multi-message-id"))]
    pub fn y(&self) -> &Fr {
        match self {
            Self::SingleV1 { y, .. } => y,
        }
    }

    /// Returns the nullifier value.
    #[cfg(not(feature = "multi-message-id"))]
    pub fn nullifier(&self) -> &Fr {
        match self {
            Self::SingleV1 { nullifier, .. } => nullifier,
        }
    }

    /// Returns the selector flags.
    #[cfg(feature = "multi-message-id")]
    pub fn selector_used(&self) -> &[bool] {
        match self {
            Self::MultiV1 { selector_used, .. } => selector_used,
        }
    }

    /// Returns the per-message-id output `y` values.
    #[cfg(feature = "multi-message-id")]
    pub fn ys(&self) -> &[Fr] {
        match self {
            Self::MultiV1 { ys, .. } => ys,
        }
    }

    /// Returns the per-message-id nullifiers.
    #[cfg(feature = "multi-message-id")]
    pub fn nullifiers(&self) -> &[Fr] {
        match self {
            Self::MultiV1 { nullifiers, .. } => nullifiers,
        }
    }
}

/// Serializes RLN proof values to little-endian bytes.
pub fn rln_proof_values_to_bytes_le(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    match rln_proof_values {
        #[cfg(not(feature = "multi-message-id"))]
        RLNProofValues::SingleV1 {
            root,
            x,
            external_nullifier,
            y,
            nullifier,
        } => {
            // Calculate capacity for Vec:
            // - VERSION_BYTE_SIZE byte for version tag
            // - 5 field elements: root, external_nullifier, x, y, nullifier
            let capacity = VERSION_BYTE_SIZE + FR_BYTE_SIZE * 5;
            let mut bytes = Vec::with_capacity(capacity);
            bytes.push(SerializationVersion::SingleV1.into());
            bytes.extend_from_slice(&fr_to_bytes_le(root));
            bytes.extend_from_slice(&fr_to_bytes_le(external_nullifier));
            bytes.extend_from_slice(&fr_to_bytes_le(x));
            bytes.extend_from_slice(&fr_to_bytes_le(y));
            bytes.extend_from_slice(&fr_to_bytes_le(nullifier));
            bytes
        }
        #[cfg(feature = "multi-message-id")]
        RLNProofValues::MultiV1 {
            root,
            x,
            external_nullifier,
            selector_used,
            ys,
            nullifiers,
        } => {
            // Calculate capacity for Vec:
            // - VERSION_BYTE_SIZE byte for version tag
            // - 3 field elements: root, external_nullifier, x
            // - variable size of ys, nullifiers, selector_used
            // - VEC_LEN_BYTE_SIZE bytes length prefix per vector (ys, nullifiers, selector_used)
            let capacity = VERSION_BYTE_SIZE
                + FR_BYTE_SIZE * 3
                + FR_BYTE_SIZE * ys.len()
                + FR_BYTE_SIZE * nullifiers.len()
                + selector_used.len()
                + VEC_LEN_BYTE_SIZE * 3;
            let mut bytes = Vec::with_capacity(capacity);
            bytes.push(SerializationVersion::MultiV1.into());
            bytes.extend_from_slice(&fr_to_bytes_le(root));
            bytes.extend_from_slice(&fr_to_bytes_le(external_nullifier));
            bytes.extend_from_slice(&fr_to_bytes_le(x));
            bytes.extend_from_slice(&vec_fr_to_bytes_le(ys));
            bytes.extend_from_slice(&vec_fr_to_bytes_le(nullifiers));
            bytes.extend_from_slice(&vec_bool_to_bytes_le(selector_used));
            bytes
        }
    }
}

/// Serializes RLN proof values to big-endian bytes.
pub fn rln_proof_values_to_bytes_be(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    match rln_proof_values {
        #[cfg(not(feature = "multi-message-id"))]
        RLNProofValues::SingleV1 {
            root,
            x,
            external_nullifier,
            y,
            nullifier,
        } => {
            // Calculate capacity for Vec:
            // - VERSION_BYTE_SIZE byte for version tag
            // - 5 field elements: root, external_nullifier, x, y, nullifier
            let capacity = VERSION_BYTE_SIZE + FR_BYTE_SIZE * 5;
            let mut bytes = Vec::with_capacity(capacity);
            bytes.push(SerializationVersion::SingleV1.into());
            bytes.extend_from_slice(&fr_to_bytes_be(root));
            bytes.extend_from_slice(&fr_to_bytes_be(external_nullifier));
            bytes.extend_from_slice(&fr_to_bytes_be(x));
            bytes.extend_from_slice(&fr_to_bytes_be(y));
            bytes.extend_from_slice(&fr_to_bytes_be(nullifier));
            bytes
        }
        #[cfg(feature = "multi-message-id")]
        RLNProofValues::MultiV1 {
            root,
            x,
            external_nullifier,
            selector_used,
            ys,
            nullifiers,
        } => {
            // Calculate capacity for Vec:
            // - VERSION_BYTE_SIZE byte for version tag
            // - 3 field elements: root, external_nullifier, x
            // - variable size of ys, nullifiers, selector_used
            // - VEC_LEN_BYTE_SIZE bytes length prefix per vector (ys, nullifiers, selector_used)
            let capacity = VERSION_BYTE_SIZE
                + FR_BYTE_SIZE * 3
                + FR_BYTE_SIZE * ys.len()
                + FR_BYTE_SIZE * nullifiers.len()
                + selector_used.len()
                + VEC_LEN_BYTE_SIZE * 3;
            let mut bytes = Vec::with_capacity(capacity);
            bytes.push(SerializationVersion::MultiV1.into());
            bytes.extend_from_slice(&fr_to_bytes_be(root));
            bytes.extend_from_slice(&fr_to_bytes_be(external_nullifier));
            bytes.extend_from_slice(&fr_to_bytes_be(x));
            bytes.extend_from_slice(&vec_fr_to_bytes_be(ys));
            bytes.extend_from_slice(&vec_fr_to_bytes_be(nullifiers));
            bytes.extend_from_slice(&vec_bool_to_bytes_be(selector_used));
            bytes
        }
    }
}

/// Deserializes RLN proof values from little-endian bytes.
///
/// Returns the deserialized proof values and the number of bytes read.
pub fn bytes_le_to_rln_proof_values(
    bytes: &[u8],
) -> Result<(RLNProofValues, usize), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::InvalidReadLen(1, 0));
    }

    let version = SerializationVersion::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    match version {
        #[cfg(not(feature = "multi-message-id"))]
        SerializationVersion::SingleV1 => {
            let (root, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
            let (external_nullifier, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
            let (x, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
            let (y, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
            let (nullifier, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;

            if read != bytes.len() {
                return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
            }
            Ok((
                RLNProofValues::SingleV1 {
                    root,
                    x,
                    external_nullifier,
                    y,
                    nullifier,
                },
                read,
            ))
        }
        #[cfg(feature = "multi-message-id")]
        SerializationVersion::MultiV1 => {
            let (root, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
            let (external_nullifier, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
            let (x, el_size) = bytes_le_to_fr(&bytes[read..])?;
            read += el_size;
            let (ys, el_size) = bytes_le_to_vec_fr(&bytes[read..])?;
            read += el_size;
            let (nullifiers, el_size) = bytes_le_to_vec_fr(&bytes[read..])?;
            read += el_size;
            let (selector_used, el_size) = bytes_le_to_vec_bool(&bytes[read..])?;
            read += el_size;

            if selector_used.len() != ys.len() {
                return Err(ProtocolError::FieldLengthMismatch(
                    "ys".into(),
                    ys.len(),
                    "selector_used".into(),
                    selector_used.len(),
                ));
            }
            if nullifiers.len() != ys.len() {
                return Err(ProtocolError::FieldLengthMismatch(
                    "ys".into(),
                    ys.len(),
                    "nullifiers".into(),
                    nullifiers.len(),
                ));
            }
            if read != bytes.len() {
                return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
            }

            Ok((
                RLNProofValues::MultiV1 {
                    root,
                    x,
                    external_nullifier,
                    selector_used,
                    ys,
                    nullifiers,
                },
                read,
            ))
        }
    }
}

/// Deserializes RLN proof values from big-endian bytes.
///
/// Returns the deserialized proof values and the number of bytes read.
pub fn bytes_be_to_rln_proof_values(
    bytes: &[u8],
) -> Result<(RLNProofValues, usize), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::InvalidReadLen(1, 0));
    }

    let version = SerializationVersion::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    match version {
        #[cfg(not(feature = "multi-message-id"))]
        SerializationVersion::SingleV1 => {
            let (root, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
            let (external_nullifier, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
            let (x, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
            let (y, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
            let (nullifier, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;

            if read != bytes.len() {
                return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
            }
            Ok((
                RLNProofValues::SingleV1 {
                    root,
                    x,
                    external_nullifier,
                    y,
                    nullifier,
                },
                read,
            ))
        }
        #[cfg(feature = "multi-message-id")]
        SerializationVersion::MultiV1 => {
            let (root, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
            let (external_nullifier, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
            let (x, el_size) = bytes_be_to_fr(&bytes[read..])?;
            read += el_size;
            let (ys, el_size) = bytes_be_to_vec_fr(&bytes[read..])?;
            read += el_size;
            let (nullifiers, el_size) = bytes_be_to_vec_fr(&bytes[read..])?;
            read += el_size;
            let (selector_used, el_size) = bytes_be_to_vec_bool(&bytes[read..])?;
            read += el_size;

            if selector_used.len() != ys.len() {
                return Err(ProtocolError::FieldLengthMismatch(
                    "ys".into(),
                    ys.len(),
                    "selector_used".into(),
                    selector_used.len(),
                ));
            }
            if nullifiers.len() != ys.len() {
                return Err(ProtocolError::FieldLengthMismatch(
                    "ys".into(),
                    ys.len(),
                    "nullifiers".into(),
                    nullifiers.len(),
                ));
            }
            if read != bytes.len() {
                return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
            }

            Ok((
                RLNProofValues::MultiV1 {
                    root,
                    x,
                    external_nullifier,
                    selector_used,
                    ys,
                    nullifiers,
                },
                read,
            ))
        }
    }
}

/// Serializes RLN proof to little-endian bytes.
///
/// The Groth16 proof is always serialized in LE format (arkworks behavior),
/// while proof_values are serialized in LE format.
pub fn rln_proof_to_bytes_le(rln_proof: &RLNProof) -> Result<Vec<u8>, ProtocolError> {
    // Calculate capacity for Vec:
    // - VERSION_BYTE_SIZE byte for version tag in rln proof
    // - variable size of proof values (includes VERSION_BYTE_SIZE)
    // - COMPRESS_PROOF_SIZE bytes for compressed Groth16 proof
    let proof_values_bytes = rln_proof_values_to_bytes_le(&rln_proof.proof_values);
    let mut bytes =
        Vec::with_capacity(VERSION_BYTE_SIZE + COMPRESS_PROOF_SIZE + proof_values_bytes.len());

    bytes.push(rln_proof.proof_values.version_byte());
    // Serialize proof (always LE format from arkworks)
    rln_proof.proof.serialize_compressed(&mut bytes)?;
    bytes.extend_from_slice(&proof_values_bytes);

    Ok(bytes)
}

/// Serializes RLN proof to big-endian bytes.
///
/// The Groth16 proof is always serialized in LE format (arkworks behavior),
/// while proof_values are serialized in BE format. This creates a mixed-endian format.
pub fn rln_proof_to_bytes_be(rln_proof: &RLNProof) -> Result<Vec<u8>, ProtocolError> {
    // Calculate capacity for Vec:
    // - VERSION_BYTE_SIZE byte for version tag in rln proof
    // - variable size of proof values (includes VERSION_BYTE_SIZE)
    // - COMPRESS_PROOF_SIZE bytes for compressed Groth16 proof
    let proof_values_bytes = rln_proof_values_to_bytes_be(&rln_proof.proof_values);
    let mut bytes =
        Vec::with_capacity(VERSION_BYTE_SIZE + COMPRESS_PROOF_SIZE + proof_values_bytes.len());

    bytes.push(rln_proof.proof_values.version_byte());
    // Serialize proof (always LE format from arkworks)
    rln_proof.proof.serialize_compressed(&mut bytes)?;
    bytes.extend_from_slice(&proof_values_bytes);

    Ok(bytes)
}

/// Deserializes RLN proof from little-endian bytes.
///
/// Returns the deserialized proof and the number of bytes read.
pub fn bytes_le_to_rln_proof(bytes: &[u8]) -> Result<(RLNProof, usize), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::InvalidReadLen(1, 0));
    }

    let _version = SerializationVersion::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    // Deserialize proof (always LE from arkworks)
    if bytes.len() < read + COMPRESS_PROOF_SIZE {
        return Err(ProtocolError::InvalidReadLen(
            read + COMPRESS_PROOF_SIZE,
            bytes.len(),
        ));
    }
    let proof = Proof::deserialize_compressed(&bytes[read..read + COMPRESS_PROOF_SIZE])?;
    read += COMPRESS_PROOF_SIZE;

    let (values, el_size) = bytes_le_to_rln_proof_values(&bytes[read..])?;
    read += el_size;

    if read != bytes.len() {
        return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
    }

    Ok((
        RLNProof {
            proof,
            proof_values: values,
        },
        read,
    ))
}

/// Deserializes RLN proof from big-endian bytes.
///
/// Mixed-endian format - proof is LE (arkworks), proof_values are BE.
///
/// Returns the deserialized proof and the number of bytes read.
pub fn bytes_be_to_rln_proof(bytes: &[u8]) -> Result<(RLNProof, usize), ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::InvalidReadLen(1, 0));
    }

    let _version = SerializationVersion::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    // Deserialize proof (always LE from arkworks)
    if bytes.len() < read + COMPRESS_PROOF_SIZE {
        return Err(ProtocolError::InvalidReadLen(
            read + COMPRESS_PROOF_SIZE,
            bytes.len(),
        ));
    }
    let proof = Proof::deserialize_compressed(&bytes[read..read + COMPRESS_PROOF_SIZE])?;
    read += COMPRESS_PROOF_SIZE;

    let (values, el_size) = bytes_be_to_rln_proof_values(&bytes[read..])?;
    read += el_size;

    if read != bytes.len() {
        return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
    }

    Ok((
        RLNProof {
            proof,
            proof_values: values,
        },
        read,
    ))
}

// zkSNARK proof generation and verification

/// Converts calculated witness (BigInt) to field elements.
fn calculated_witness_to_field_elements<E: ark_ec::pairing::Pairing>(
    calculated_witness: Vec<BigInt>,
) -> Result<Vec<E::ScalarField>, ProtocolError> {
    let modulus = <E::ScalarField as PrimeField>::MODULUS;

    // convert it to field elements
    let mut field_elements = vec![];
    for w in calculated_witness.into_iter() {
        let w = if w.sign() == num_bigint::Sign::Minus {
            // Need to negate the witness element if negative
            modulus.into()
                - w.abs()
                    .to_biguint()
                    .ok_or(ProtocolError::BigUintConversion(w))?
        } else {
            w.to_biguint().ok_or(ProtocolError::BigUintConversion(w))?
        };
        field_elements.push(E::ScalarField::from(w))
    }

    Ok(field_elements)
}

/// Generates a zkSNARK proof from pre-calculated witness values.
///
/// Use this when witness calculation is performed externally.
pub fn generate_zk_proof_with_witness(
    calculated_witness: Vec<BigInt>,
    zkey: &Zkey,
) -> Result<Proof, ProtocolError> {
    let full_assignment = calculated_witness_to_field_elements::<Curve>(calculated_witness)?;

    // Random Values
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    let proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
        &zkey.0,
        r,
        s,
        &zkey.1,
        zkey.1.num_instance_variables,
        zkey.1.num_constraints,
        full_assignment.as_slice(),
    )?;

    Ok(proof)
}

/// Generates a zkSNARK proof from witness input using the provided circuit data.
pub fn generate_zk_proof(
    zkey: &Zkey,
    witness: &RLNWitnessInput,
    graph: &Graph,
) -> Result<Proof, ProtocolError> {
    let (actual_path_len, actual_index_len) = match witness {
        #[cfg(not(feature = "multi-message-id"))]
        RLNWitnessInput::SingleV1 {
            path_elements,
            identity_path_index,
            ..
        } => (path_elements.len(), identity_path_index.len()),

        #[cfg(feature = "multi-message-id")]
        RLNWitnessInput::MultiV1 {
            path_elements,
            identity_path_index,
            ..
        } => (path_elements.len(), identity_path_index.len()),
    };

    let expected_tree_depth = graph.tree_depth;
    if actual_path_len != expected_tree_depth {
        return Err(ProtocolError::FieldLengthMismatch(
            "path_elements".into(),
            actual_path_len,
            "tree_depth".into(),
            expected_tree_depth,
        )
        .into());
    }
    if actual_index_len != expected_tree_depth {
        return Err(ProtocolError::FieldLengthMismatch(
            "identity_path_index".into(),
            actual_index_len,
            "tree_depth".into(),
            expected_tree_depth,
        )
        .into());
    }

    #[cfg(feature = "multi-message-id")]
    {
        let RLNWitnessInput::MultiV1 {
            message_ids,
            selector_used,
            ..
        } = witness;

        let expected_max_out = graph.max_out;

        let actual_message_ids_len = message_ids.len();
        if actual_message_ids_len != expected_max_out {
            return Err(ProtocolError::FieldLengthMismatch(
                "message_ids".into(),
                actual_message_ids_len,
                "max_out".into(),
                expected_max_out,
            )
            .into());
        }

        let actual_selector_used_len = selector_used.len();
        if actual_selector_used_len != expected_max_out {
            return Err(ProtocolError::FieldLengthMismatch(
                "selector_used".into(),
                actual_selector_used_len,
                "max_out".into(),
                expected_max_out,
            )
            .into());
        }
    }

    let inputs = inputs_for_witness_calculation(witness)?
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));

    let full_assignment = calc_witness(inputs, graph)?;

    // Random Values
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    let proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
        &zkey.0,
        r,
        s,
        &zkey.1,
        zkey.1.num_instance_variables,
        zkey.1.num_constraints,
        full_assignment.as_slice(),
    )?;

    Ok(proof)
}

/// Verifies a zkSNARK proof against the verifying key and public values.
///
/// Returns `true` if the proof is cryptographically valid, `false` if verification fails.
///
/// Verification failure may occur due to proof computation errors, not necessarily malicious proofs.
pub fn verify_zk_proof(
    verifying_key: &VerifyingKey,
    proof: &Proof,
    proof_values: &RLNProofValues,
) -> Result<bool, ProtocolError> {
    // We re-arrange proof-values according to the circuit specification
    let inputs = match proof_values {
        #[cfg(not(feature = "multi-message-id"))]
        RLNProofValues::SingleV1 {
            y,
            root,
            nullifier,
            x,
            external_nullifier,
        } => {
            vec![*y, *root, *nullifier, *x, *external_nullifier]
        }
        #[cfg(feature = "multi-message-id")]
        RLNProofValues::MultiV1 {
            ys,
            nullifiers,
            root,
            x,
            external_nullifier,
            selector_used,
        } => {
            let mut inputs = Vec::with_capacity(3 * ys.len() + 3);
            inputs.extend_from_slice(ys);
            inputs.push(*root);
            inputs.extend_from_slice(nullifiers);
            inputs.push(*x);
            inputs.push(*external_nullifier);
            for &used in selector_used.iter() {
                inputs.push(Fr::from(used));
            }
            inputs
        }
    };

    // Check that the proof is valid
    let pvk = prepare_verifying_key(verifying_key);

    let verified = Groth16::<_, CircomReduction>::verify_proof(&pvk, proof, &inputs)?;

    Ok(verified)
}
