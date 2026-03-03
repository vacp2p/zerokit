use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::thread_rng, UniformRand};
use num_bigint::BigInt;
use num_traits::Signed;

use super::version::{SerializationVersion, VERSION_BYTE_SIZE};
#[cfg(not(target_arch = "wasm32"))]
use super::witness::{inputs_for_witness_calculation, RLNWitnessInput};
#[cfg(not(target_arch = "wasm32"))]
use crate::circuit::{iden3calc::calc_witness, Graph};
#[cfg(feature = "multi-message-id")]
use crate::utils::{
    bytes_be_to_vec_bool, bytes_be_to_vec_fr, bytes_le_to_vec_bool, bytes_le_to_vec_fr,
    vec_bool_to_bytes_be, vec_bool_to_bytes_le, vec_fr_to_bytes_be, vec_fr_to_bytes_le,
    VEC_LEN_BYTE_SIZE,
};
use crate::{
    circuit::{qap::CircomReduction, Curve, Fr, Proof, VerifyingKey, Zkey, COMPRESS_PROOF_SIZE},
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

/// Variant-specific outputs for RLN proof verification.
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RLNOutputs {
    #[cfg(not(feature = "multi-message-id"))]
    SingleV1 { y: Fr, nullifier: Fr },
    #[cfg(feature = "multi-message-id")]
    MultiV1 {
        ys: Vec<Fr>,
        nullifiers: Vec<Fr>,
        selector_used: Vec<bool>,
    },
}

/// Public values for RLN proof verification.
///
/// Contains the circuit's public inputs and outputs. Used in proof verification
/// and identity secret recovery when rate limit violations are detected.
#[derive(Debug, PartialEq, Clone)]
pub struct RLNProofValues {
    root: Fr,
    x: Fr,
    external_nullifier: Fr,
    pub(crate) outputs: RLNOutputs,
}

impl RLNProofValues {
    /// Creates a new RLNProofValues instance.
    #[cfg(not(feature = "multi-message-id"))]
    pub fn new(root: Fr, x: Fr, external_nullifier: Fr, y: Fr, nullifier: Fr) -> Self {
        Self {
            root,
            x,
            external_nullifier,
            outputs: RLNOutputs::SingleV1 { y, nullifier },
        }
    }

    /// Creates a new RLNProofValues instance.
    #[cfg(feature = "multi-message-id")]
    pub fn new(
        root: Fr,
        x: Fr,
        external_nullifier: Fr,
        ys: Vec<Fr>,
        nullifiers: Vec<Fr>,
        selector_used: Vec<bool>,
    ) -> Self {
        Self {
            root,
            x,
            external_nullifier,
            outputs: RLNOutputs::MultiV1 {
                ys,
                nullifiers,
                selector_used,
            },
        }
    }

    /// Returns the version byte corresponding to the proof values variant.
    pub fn version_byte(&self) -> u8 {
        match &self.outputs {
            #[cfg(not(feature = "multi-message-id"))]
            RLNOutputs::SingleV1 { .. } => SerializationVersion::SingleV1.into(),
            #[cfg(feature = "multi-message-id")]
            RLNOutputs::MultiV1 { .. } => SerializationVersion::MultiV1.into(),
        }
    }

    /// Returns the Merkle tree root.
    pub fn root(&self) -> &Fr {
        &self.root
    }

    /// Returns the signal hash.
    pub fn x(&self) -> &Fr {
        &self.x
    }

    /// Returns the external nullifier.
    pub fn external_nullifier(&self) -> &Fr {
        &self.external_nullifier
    }

    /// Returns the output `y` value.
    #[cfg(not(feature = "multi-message-id"))]
    pub fn y(&self) -> &Fr {
        let RLNOutputs::SingleV1 { y, .. } = &self.outputs;
        y
    }

    /// Returns the nullifier value.
    #[cfg(not(feature = "multi-message-id"))]
    pub fn nullifier(&self) -> &Fr {
        let RLNOutputs::SingleV1 { nullifier, .. } = &self.outputs;
        nullifier
    }

    /// Returns the selector flags.
    #[cfg(feature = "multi-message-id")]
    pub fn selector_used(&self) -> &[bool] {
        let RLNOutputs::MultiV1 { selector_used, .. } = &self.outputs;
        selector_used
    }

    /// Returns the per-message-id output `y` values.
    #[cfg(feature = "multi-message-id")]
    pub fn ys(&self) -> &[Fr] {
        let RLNOutputs::MultiV1 { ys, .. } = &self.outputs;
        ys
    }

    /// Returns the per-message-id nullifiers.
    #[cfg(feature = "multi-message-id")]
    pub fn nullifiers(&self) -> &[Fr] {
        let RLNOutputs::MultiV1 { nullifiers, .. } = &self.outputs;
        nullifiers
    }
}

/// Serializes RLN proof values to little-endian bytes.
pub fn rln_proof_values_to_bytes_le(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    let RLNProofValues {
        root,
        x,
        external_nullifier,
        outputs,
    } = rln_proof_values;

    #[cfg(not(feature = "multi-message-id"))]
    let RLNOutputs::SingleV1 { y, nullifier } = outputs;
    #[cfg(feature = "multi-message-id")]
    let RLNOutputs::MultiV1 {
        ys,
        nullifiers,
        selector_used,
    } = outputs;

    // Calculate capacity for Vec:
    // - VERSION_BYTE_SIZE byte for version tag
    // - 3 common field elements: root, external_nullifier, x
    #[cfg(not(feature = "multi-message-id"))]
    // - 2 field elements: y, nullifier
    let capacity = VERSION_BYTE_SIZE + FR_BYTE_SIZE * 5;
    #[cfg(feature = "multi-message-id")]
    // - variable size of ys, nullifiers, selector_used
    // - VEC_LEN_BYTE_SIZE bytes length prefix per vector (ys, nullifiers, selector_used)
    let capacity = VERSION_BYTE_SIZE
        + FR_BYTE_SIZE * 3
        + FR_BYTE_SIZE * ys.len()
        + FR_BYTE_SIZE * nullifiers.len()
        + selector_used.len()
        + VEC_LEN_BYTE_SIZE * 3;

    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(rln_proof_values.version_byte());
    bytes.extend_from_slice(&fr_to_bytes_le(root));
    bytes.extend_from_slice(&fr_to_bytes_le(external_nullifier));
    bytes.extend_from_slice(&fr_to_bytes_le(x));
    #[cfg(not(feature = "multi-message-id"))]
    {
        bytes.extend_from_slice(&fr_to_bytes_le(y));
        bytes.extend_from_slice(&fr_to_bytes_le(nullifier));
    }
    #[cfg(feature = "multi-message-id")]
    {
        bytes.extend_from_slice(&vec_fr_to_bytes_le(ys));
        bytes.extend_from_slice(&vec_fr_to_bytes_le(nullifiers));
        bytes.extend_from_slice(&vec_bool_to_bytes_le(selector_used));
    }
    bytes
}

/// Serializes RLN proof values to big-endian bytes.
pub fn rln_proof_values_to_bytes_be(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    let RLNProofValues {
        root,
        x,
        external_nullifier,
        outputs,
    } = rln_proof_values;

    #[cfg(not(feature = "multi-message-id"))]
    let RLNOutputs::SingleV1 { y, nullifier } = outputs;
    #[cfg(feature = "multi-message-id")]
    let RLNOutputs::MultiV1 {
        ys,
        nullifiers,
        selector_used,
    } = outputs;

    // Calculate capacity for Vec:
    // - VERSION_BYTE_SIZE byte for version tag
    // - 3 common field elements: root, external_nullifier, x
    #[cfg(not(feature = "multi-message-id"))]
    // - 2 field elements: y, nullifier
    let capacity = VERSION_BYTE_SIZE + FR_BYTE_SIZE * 5;
    #[cfg(feature = "multi-message-id")]
    // - variable size of ys, nullifiers, selector_used
    // - VEC_LEN_BYTE_SIZE bytes length prefix per vector (ys, nullifiers, selector_used)
    let capacity = VERSION_BYTE_SIZE
        + FR_BYTE_SIZE * 3
        + FR_BYTE_SIZE * ys.len()
        + FR_BYTE_SIZE * nullifiers.len()
        + selector_used.len()
        + VEC_LEN_BYTE_SIZE * 3;

    let mut bytes = Vec::with_capacity(capacity);
    bytes.push(rln_proof_values.version_byte());
    bytes.extend_from_slice(&fr_to_bytes_be(root));
    bytes.extend_from_slice(&fr_to_bytes_be(external_nullifier));
    bytes.extend_from_slice(&fr_to_bytes_be(x));
    #[cfg(not(feature = "multi-message-id"))]
    {
        bytes.extend_from_slice(&fr_to_bytes_be(y));
        bytes.extend_from_slice(&fr_to_bytes_be(nullifier));
    }
    #[cfg(feature = "multi-message-id")]
    {
        bytes.extend_from_slice(&vec_fr_to_bytes_be(ys));
        bytes.extend_from_slice(&vec_fr_to_bytes_be(nullifiers));
        bytes.extend_from_slice(&vec_bool_to_bytes_be(selector_used));
    }
    bytes
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

    let _version = SerializationVersion::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    let (root, el_size) = bytes_le_to_fr(&bytes[read..])?;
    read += el_size;
    let (external_nullifier, el_size) = bytes_le_to_fr(&bytes[read..])?;
    read += el_size;
    let (x, el_size) = bytes_le_to_fr(&bytes[read..])?;
    read += el_size;

    #[cfg(not(feature = "multi-message-id"))]
    let proof_values = {
        let (y, el_size) = bytes_le_to_fr(&bytes[read..])?;
        read += el_size;
        let (nullifier, el_size) = bytes_le_to_fr(&bytes[read..])?;
        read += el_size;
        RLNProofValues::new(root, x, external_nullifier, y, nullifier)
    };
    #[cfg(feature = "multi-message-id")]
    let proof_values = {
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
        RLNProofValues::new(root, x, external_nullifier, ys, nullifiers, selector_used)
    };

    if read != bytes.len() {
        return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
    }
    Ok((proof_values, read))
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

    let _version = SerializationVersion::try_from(bytes[0])?;
    let mut read: usize = VERSION_BYTE_SIZE;

    let (root, el_size) = bytes_be_to_fr(&bytes[read..])?;
    read += el_size;
    let (external_nullifier, el_size) = bytes_be_to_fr(&bytes[read..])?;
    read += el_size;
    let (x, el_size) = bytes_be_to_fr(&bytes[read..])?;
    read += el_size;

    #[cfg(not(feature = "multi-message-id"))]
    let proof_values = {
        let (y, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;
        let (nullifier, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;
        RLNProofValues::new(root, x, external_nullifier, y, nullifier)
    };
    #[cfg(feature = "multi-message-id")]
    let proof_values = {
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
        RLNProofValues::new(root, x, external_nullifier, ys, nullifiers, selector_used)
    };

    if read != bytes.len() {
        return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
    }
    Ok((proof_values, read))
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

    // Convert it to field elements
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

/// Validates that a witness's dimensions match the graph's expected tree depth and max_out.
#[cfg(not(target_arch = "wasm32"))]
fn validate_witness_against_graph(
    witness: &RLNWitnessInput,
    graph: &Graph,
) -> Result<(), ProtocolError> {
    let expected_tree_depth = graph.tree_depth;
    if witness.path_elements().len() != expected_tree_depth {
        return Err(ProtocolError::FieldLengthMismatch(
            "path_elements".into(),
            witness.path_elements().len(),
            "tree_depth".into(),
            expected_tree_depth,
        ));
    }
    if witness.identity_path_index().len() != expected_tree_depth {
        return Err(ProtocolError::FieldLengthMismatch(
            "identity_path_index".into(),
            witness.identity_path_index().len(),
            "tree_depth".into(),
            expected_tree_depth,
        ));
    }

    #[cfg(feature = "multi-message-id")]
    {
        let expected_max_out = graph.max_out;
        if witness.message_ids().len() != expected_max_out {
            return Err(ProtocolError::FieldLengthMismatch(
                "message_ids".into(),
                witness.message_ids().len(),
                "max_out".into(),
                expected_max_out,
            ));
        }
        if witness.selector_used().len() != expected_max_out {
            return Err(ProtocolError::FieldLengthMismatch(
                "selector_used".into(),
                witness.selector_used().len(),
                "max_out".into(),
                expected_max_out,
            ));
        }
    }

    Ok(())
}

/// Generates a zkSNARK proof from pre-calculated witness values.
///
/// Use this when witness calculation is performed externally.
pub fn generate_zk_proof_with_witness(
    calculated_witness: Vec<BigInt>,
    zkey: &Zkey,
    #[cfg(not(target_arch = "wasm32"))] witness: &RLNWitnessInput,
    #[cfg(not(target_arch = "wasm32"))] graph: &Graph,
) -> Result<Proof, ProtocolError> {
    #[cfg(not(target_arch = "wasm32"))]
    validate_witness_against_graph(witness, graph)?;

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
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_zk_proof(
    zkey: &Zkey,
    witness: &RLNWitnessInput,
    graph: &Graph,
) -> Result<Proof, ProtocolError> {
    validate_witness_against_graph(witness, graph)?;

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
    #[cfg(not(feature = "multi-message-id"))]
    let inputs = {
        let RLNOutputs::SingleV1 { y, nullifier } = &proof_values.outputs;
        vec![
            *y,
            proof_values.root,
            *nullifier,
            proof_values.x,
            proof_values.external_nullifier,
        ]
    };
    #[cfg(feature = "multi-message-id")]
    let inputs = {
        let RLNOutputs::MultiV1 {
            ys,
            nullifiers,
            selector_used,
        } = &proof_values.outputs;
        let mut inputs = Vec::with_capacity(3 * ys.len() + 3);
        inputs.extend_from_slice(ys);
        inputs.push(proof_values.root);
        inputs.extend_from_slice(nullifiers);
        inputs.push(proof_values.x);
        inputs.push(proof_values.external_nullifier);
        for &used in selector_used.iter() {
            inputs.push(Fr::from(used));
        }
        inputs
    };

    // Check that the proof is valid
    let pvk = prepare_verifying_key(verifying_key);

    let verified = Groth16::<_, CircomReduction>::verify_proof(&pvk, proof, &inputs)?;

    Ok(verified)
}
