use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::thread_rng, UniformRand};
use num_bigint::BigInt;
use num_traits::Signed;

#[cfg(not(target_arch = "wasm32"))]
use super::witness::{
    inputs_for_partial_witness_calculation, inputs_for_witness_calculation, RLNPartialWitnessInput,
    RLNWitnessInput,
};
use super::{
    mode::MessageMode,
    version::{RlnSerialize, SerializationVersion, VERSION_BYTE_SIZE},
    witness::RLNMessageInputs,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::{
    circuit::{
        iden3calc::{calc_witness, calc_witness_partial},
        Graph,
    },
    partial_proof::{Groth16Partial, PartialAssignment},
};
use crate::{
    circuit::{
        qap::CircomReduction, Curve, Fr, PartialProof, Proof, VerifyingKey, Zkey,
        COMPRESS_PROOF_SIZE,
    },
    error::ProtocolError,
    utils::{
        bytes_be_to_fr, bytes_be_to_vec_bool, bytes_be_to_vec_fr, bytes_le_to_fr,
        bytes_le_to_vec_bool, bytes_le_to_vec_fr, fr_to_bytes_be, fr_to_bytes_le,
        vec_bool_to_bytes_be, vec_bool_to_bytes_le, vec_fr_to_bytes_be, vec_fr_to_bytes_le,
        FR_BYTE_SIZE, VEC_LEN_BYTE_SIZE,
    },
};

/// Complete RLN proof.
///
/// Combines the Groth16 proof with its public values.
///
/// The serialization format for this type is defined in [`crate::protocol::SerializationVersion`].
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
    SingleV1 {
        y: Fr,
        nullifier: Fr,
    },
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
///
/// The serialization format for this type is defined in [`crate::protocol::SerializationVersion`].
#[derive(Debug, PartialEq, Clone)]
pub struct RLNProofValues {
    root: Fr,
    x: Fr,
    external_nullifier: Fr,
    pub(crate) outputs: RLNOutputs,
}

impl RLNProofValues {
    /// Creates a new single message-id RLNProofValues.
    pub fn new_single(root: Fr, x: Fr, external_nullifier: Fr, y: Fr, nullifier: Fr) -> Self {
        Self {
            root,
            x,
            external_nullifier,
            outputs: RLNOutputs::SingleV1 { y, nullifier },
        }
    }

    /// Creates a new multi message-id RLNProofValues.
    pub fn new_multi(
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
            RLNOutputs::SingleV1 { .. } => SerializationVersion::SingleV1.into(),
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

    /// Returns the `y` value (only valid for SingleV1).
    pub fn y(&self) -> &Fr {
        match &self.outputs {
            RLNOutputs::SingleV1 { y, .. } => y,
            RLNOutputs::MultiV1 { .. } => {
                panic!("y() is not available for MultiV1 proof values; use ys()")
            }
        }
    }

    /// Returns the nullifier (only valid for SingleV1).
    pub fn nullifier(&self) -> &Fr {
        match &self.outputs {
            RLNOutputs::SingleV1 { nullifier, .. } => nullifier,
            RLNOutputs::MultiV1 { .. } => {
                panic!("nullifier() is not available for MultiV1 proof values; use nullifiers()")
            }
        }
    }

    /// Returns the selector flags (only valid for MultiV1).
    pub fn selector_used(&self) -> &[bool] {
        match &self.outputs {
            RLNOutputs::MultiV1 { selector_used, .. } => selector_used,
            RLNOutputs::SingleV1 { .. } => {
                panic!("selector_used() is not available for SingleV1 proof values")
            }
        }
    }

    /// Returns the per-message-id `y` values (only valid for MultiV1).
    pub fn ys(&self) -> &[Fr] {
        match &self.outputs {
            RLNOutputs::MultiV1 { ys, .. } => ys,
            RLNOutputs::SingleV1 { .. } => {
                panic!("ys() is not available for SingleV1 proof values; use y()")
            }
        }
    }

    /// Returns the per-message-id nullifiers (only valid for MultiV1).
    pub fn nullifiers(&self) -> &[Fr] {
        match &self.outputs {
            RLNOutputs::MultiV1 { nullifiers, .. } => nullifiers,
            RLNOutputs::SingleV1 { .. } => {
                panic!("nullifiers() is not available for SingleV1 proof values; use nullifier()")
            }
        }
    }
}

impl RlnSerialize for RLNProofValues {
    type Error = ProtocolError;

    /// Serializes RLN proof values to little-endian bytes.
    fn to_bytes_le(&self) -> Result<Vec<u8>, Self::Error> {
        let RLNProofValues {
            root,
            x,
            external_nullifier,
            outputs,
        } = self;

        let capacity = match outputs {
            RLNOutputs::SingleV1 { .. } => VERSION_BYTE_SIZE + FR_BYTE_SIZE * 5,
            RLNOutputs::MultiV1 {
                ys,
                nullifiers,
                selector_used,
            } => {
                VERSION_BYTE_SIZE
                    + FR_BYTE_SIZE * 3
                    + FR_BYTE_SIZE * ys.len()
                    + FR_BYTE_SIZE * nullifiers.len()
                    + selector_used.len()
                    + VEC_LEN_BYTE_SIZE * 3
            }
        };

        let mut bytes = Vec::with_capacity(capacity);
        bytes.push(self.version_byte());
        bytes.extend_from_slice(&fr_to_bytes_le(root));
        bytes.extend_from_slice(&fr_to_bytes_le(external_nullifier));
        bytes.extend_from_slice(&fr_to_bytes_le(x));

        match outputs {
            RLNOutputs::SingleV1 { y, nullifier } => {
                bytes.extend_from_slice(&fr_to_bytes_le(y));
                bytes.extend_from_slice(&fr_to_bytes_le(nullifier));
            }
            RLNOutputs::MultiV1 {
                ys,
                nullifiers,
                selector_used,
            } => {
                bytes.extend_from_slice(&vec_fr_to_bytes_le(ys));
                bytes.extend_from_slice(&vec_fr_to_bytes_le(nullifiers));
                bytes.extend_from_slice(&vec_bool_to_bytes_le(selector_used));
            }
        }
        Ok(bytes)
    }

    /// Serializes RLN proof values to big-endian bytes.
    fn to_bytes_be(&self) -> Result<Vec<u8>, Self::Error> {
        let RLNProofValues {
            root,
            x,
            external_nullifier,
            outputs,
        } = self;

        let capacity = match outputs {
            RLNOutputs::SingleV1 { .. } => VERSION_BYTE_SIZE + FR_BYTE_SIZE * 5,
            RLNOutputs::MultiV1 {
                ys,
                nullifiers,
                selector_used,
            } => {
                VERSION_BYTE_SIZE
                    + FR_BYTE_SIZE * 3
                    + FR_BYTE_SIZE * ys.len()
                    + FR_BYTE_SIZE * nullifiers.len()
                    + selector_used.len()
                    + VEC_LEN_BYTE_SIZE * 3
            }
        };

        let mut bytes = Vec::with_capacity(capacity);
        bytes.push(self.version_byte());
        bytes.extend_from_slice(&fr_to_bytes_be(root));
        bytes.extend_from_slice(&fr_to_bytes_be(external_nullifier));
        bytes.extend_from_slice(&fr_to_bytes_be(x));

        match outputs {
            RLNOutputs::SingleV1 { y, nullifier } => {
                bytes.extend_from_slice(&fr_to_bytes_be(y));
                bytes.extend_from_slice(&fr_to_bytes_be(nullifier));
            }
            RLNOutputs::MultiV1 {
                ys,
                nullifiers,
                selector_used,
            } => {
                bytes.extend_from_slice(&vec_fr_to_bytes_be(ys));
                bytes.extend_from_slice(&vec_fr_to_bytes_be(nullifiers));
                bytes.extend_from_slice(&vec_bool_to_bytes_be(selector_used));
            }
        }
        Ok(bytes)
    }

    /// Deserializes RLN proof values from little-endian bytes.
    ///
    /// Returns the deserialized proof values and the number of bytes read.
    fn from_bytes_le(bytes: &[u8]) -> Result<(Self, usize), Self::Error> {
        if bytes.is_empty() {
            return Err(ProtocolError::InvalidReadLen(1, 0));
        }

        let version = SerializationVersion::try_from(bytes[0])?;
        let mut read: usize = VERSION_BYTE_SIZE;

        let (root, el_size) = bytes_le_to_fr(&bytes[read..])?;
        read += el_size;
        let (external_nullifier, el_size) = bytes_le_to_fr(&bytes[read..])?;
        read += el_size;
        let (x, el_size) = bytes_le_to_fr(&bytes[read..])?;
        read += el_size;

        let proof_values = match version {
            SerializationVersion::SingleV1 => {
                let (y, el_size) = bytes_le_to_fr(&bytes[read..])?;
                read += el_size;
                let (nullifier, el_size) = bytes_le_to_fr(&bytes[read..])?;
                read += el_size;
                RLNProofValues::new_single(root, x, external_nullifier, y, nullifier)
            }
            SerializationVersion::MultiV1 => {
                let (ys, el_size) = bytes_le_to_vec_fr(&bytes[read..])?;
                read += el_size;
                let (nullifiers, el_size) = bytes_le_to_vec_fr(&bytes[read..])?;
                read += el_size;
                let (selector_used, el_size) = bytes_le_to_vec_bool(&bytes[read..])?;
                read += el_size;

                if selector_used.len() != ys.len() {
                    return Err(ProtocolError::FieldLengthMismatch(
                        "ys",
                        ys.len(),
                        "selector_used",
                        selector_used.len(),
                    ));
                }
                if nullifiers.len() != ys.len() {
                    return Err(ProtocolError::FieldLengthMismatch(
                        "ys",
                        ys.len(),
                        "nullifiers",
                        nullifiers.len(),
                    ));
                }
                RLNProofValues::new_multi(
                    root,
                    x,
                    external_nullifier,
                    ys,
                    nullifiers,
                    selector_used,
                )
            }
        };

        if read != bytes.len() {
            return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
        }
        Ok((proof_values, read))
    }

    /// Deserializes RLN proof values from big-endian bytes.
    ///
    /// Returns the deserialized proof values and the number of bytes read.
    fn from_bytes_be(bytes: &[u8]) -> Result<(Self, usize), Self::Error> {
        if bytes.is_empty() {
            return Err(ProtocolError::InvalidReadLen(1, 0));
        }

        let version = SerializationVersion::try_from(bytes[0])?;
        let mut read: usize = VERSION_BYTE_SIZE;

        let (root, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;
        let (external_nullifier, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;
        let (x, el_size) = bytes_be_to_fr(&bytes[read..])?;
        read += el_size;

        let proof_values = match version {
            SerializationVersion::SingleV1 => {
                let (y, el_size) = bytes_be_to_fr(&bytes[read..])?;
                read += el_size;
                let (nullifier, el_size) = bytes_be_to_fr(&bytes[read..])?;
                read += el_size;
                RLNProofValues::new_single(root, x, external_nullifier, y, nullifier)
            }
            SerializationVersion::MultiV1 => {
                let (ys, el_size) = bytes_be_to_vec_fr(&bytes[read..])?;
                read += el_size;
                let (nullifiers, el_size) = bytes_be_to_vec_fr(&bytes[read..])?;
                read += el_size;
                let (selector_used, el_size) = bytes_be_to_vec_bool(&bytes[read..])?;
                read += el_size;

                if selector_used.len() != ys.len() {
                    return Err(ProtocolError::FieldLengthMismatch(
                        "ys",
                        ys.len(),
                        "selector_used",
                        selector_used.len(),
                    ));
                }
                if nullifiers.len() != ys.len() {
                    return Err(ProtocolError::FieldLengthMismatch(
                        "ys",
                        ys.len(),
                        "nullifiers",
                        nullifiers.len(),
                    ));
                }
                RLNProofValues::new_multi(
                    root,
                    x,
                    external_nullifier,
                    ys,
                    nullifiers,
                    selector_used,
                )
            }
        };

        if read != bytes.len() {
            return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
        }
        Ok((proof_values, read))
    }
}

impl RlnSerialize for RLNProof {
    type Error = ProtocolError;

    /// Serializes RLN proof to little-endian bytes.
    ///
    /// The Groth16 proof is always serialized in LE format (arkworks behavior),
    /// while proof_values are serialized in LE format.
    fn to_bytes_le(&self) -> Result<Vec<u8>, Self::Error> {
        // Calculate capacity for Vec:
        // - VERSION_BYTE_SIZE byte for version tag in rln proof
        // - variable size of proof values (includes VERSION_BYTE_SIZE)
        // - COMPRESS_PROOF_SIZE bytes for compressed Groth16 proof
        let proof_values_bytes = self.proof_values.to_bytes_le()?;
        let mut bytes =
            Vec::with_capacity(VERSION_BYTE_SIZE + COMPRESS_PROOF_SIZE + proof_values_bytes.len());

        bytes.push(self.proof_values.version_byte());
        // Serialize proof (always LE format from arkworks)
        self.proof.serialize_compressed(&mut bytes)?;
        bytes.extend_from_slice(&proof_values_bytes);

        Ok(bytes)
    }

    /// Serializes RLN proof to big-endian bytes.
    ///
    /// The Groth16 proof is always serialized in LE format (arkworks behavior),
    /// while proof_values are serialized in BE format. This creates a mixed-endian format.
    fn to_bytes_be(&self) -> Result<Vec<u8>, Self::Error> {
        // Calculate capacity for Vec:
        // - VERSION_BYTE_SIZE byte for version tag in rln proof
        // - variable size of proof values (includes VERSION_BYTE_SIZE)
        // - COMPRESS_PROOF_SIZE bytes for compressed Groth16 proof
        let proof_values_bytes = self.proof_values.to_bytes_be()?;
        let mut bytes =
            Vec::with_capacity(VERSION_BYTE_SIZE + COMPRESS_PROOF_SIZE + proof_values_bytes.len());

        bytes.push(self.proof_values.version_byte());
        // Serialize proof (always LE format from arkworks)
        self.proof.serialize_compressed(&mut bytes)?;
        bytes.extend_from_slice(&proof_values_bytes);

        Ok(bytes)
    }

    /// Deserializes RLN proof from little-endian bytes.
    ///
    /// Returns the deserialized proof and the number of bytes read.
    fn from_bytes_le(bytes: &[u8]) -> Result<(Self, usize), Self::Error> {
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

        let (values, el_size) = RLNProofValues::from_bytes_le(&bytes[read..])?;
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
    fn from_bytes_be(bytes: &[u8]) -> Result<(Self, usize), Self::Error> {
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

        let (values, el_size) = RLNProofValues::from_bytes_be(&bytes[read..])?;
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
}

impl PartialProof {
    /// Returns the version byte corresponding to the partial proof variant.
    pub fn version_byte(&self) -> u8 {
        SerializationVersion::SingleV1.into()
    }
}

impl RlnSerialize for PartialProof {
    type Error = ProtocolError;

    /// Serializes RLN partial proof to little-endian bytes.
    ///
    /// The PartialProof is always serialized in LE format (arkworks behavior).
    fn to_bytes_le(&self) -> Result<Vec<u8>, Self::Error> {
        let version_byte: u8 = SerializationVersion::SingleV1.into();

        // The compressed PartialProof size is variable (depends on circuit size).
        let mut bytes = Vec::new();
        bytes.push(version_byte);
        self.serialize_compressed(&mut bytes)?;
        Ok(bytes)
    }

    /// Serializes RLN partial proof to big-endian bytes.
    ///
    /// The PartialProof is always serialized in LE format (arkworks behavior).
    fn to_bytes_be(&self) -> Result<Vec<u8>, Self::Error> {
        self.to_bytes_le()
    }

    /// Deserializes RLN partial proof from little-endian bytes.
    ///
    /// Returns the deserialized partial proof and the number of bytes read.
    fn from_bytes_le(bytes: &[u8]) -> Result<(Self, usize), Self::Error> {
        if bytes.is_empty() {
            return Err(ProtocolError::InvalidReadLen(1, 0));
        }

        let _version = SerializationVersion::try_from(bytes[0])?;
        let mut read: usize = VERSION_BYTE_SIZE;

        let mut bytes_ref = &bytes[read..];
        let len_before = bytes_ref.len();
        let partial_proof = PartialProof::deserialize_compressed(&mut bytes_ref)?;
        read += len_before - bytes_ref.len();

        if read != bytes.len() {
            return Err(ProtocolError::InvalidReadLen(read, bytes.len()));
        }

        Ok((partial_proof, read))
    }

    /// Deserializes RLN partial proof from big-endian bytes.
    ///
    /// The PartialProof is always serialized in LE format (arkworks behavior).
    ///
    /// Returns the deserialized partial proof and the number of bytes read.
    fn from_bytes_be(bytes: &[u8]) -> Result<(Self, usize), Self::Error> {
        Self::from_bytes_le(bytes)
    }
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

/// Validates that a partial witness's dimensions match the graph's expected tree depth.
#[cfg(not(target_arch = "wasm32"))]
fn validate_partial_witness_against_graph(
    witness: &RLNPartialWitnessInput,
    graph: &Graph,
) -> Result<(), ProtocolError> {
    let expected_tree_depth = graph.tree_depth;
    if witness.path_elements().len() != expected_tree_depth {
        return Err(ProtocolError::FieldLengthMismatch(
            "path_elements",
            witness.path_elements().len(),
            "tree_depth",
            expected_tree_depth,
        ));
    }
    if witness.identity_path_index().len() != expected_tree_depth {
        return Err(ProtocolError::FieldLengthMismatch(
            "identity_path_index",
            witness.identity_path_index().len(),
            "tree_depth",
            expected_tree_depth,
        ));
    }
    Ok(())
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
            "path_elements",
            witness.path_elements().len(),
            "tree_depth",
            expected_tree_depth,
        ));
    }
    if witness.identity_path_index().len() != expected_tree_depth {
        return Err(ProtocolError::FieldLengthMismatch(
            "identity_path_index",
            witness.identity_path_index().len(),
            "tree_depth",
            expected_tree_depth,
        ));
    }

    let witness_mode = MessageMode::from(&witness.message_inputs);
    let graph_mode = MessageMode::from(graph.max_out);
    if witness_mode != graph_mode {
        return Err(ProtocolError::MessageModeAndGraphMismatch {
            witness_mode,
            graph_mode,
        });
    }

    if let RLNMessageInputs::MultiV1 {
        message_ids,
        selector_used,
    } = &witness.message_inputs
    {
        let expected_max_out = graph.max_out;
        if message_ids.len() != expected_max_out {
            return Err(ProtocolError::FieldLengthMismatch(
                "message_ids",
                message_ids.len(),
                "max_out",
                expected_max_out,
            ));
        }
        if selector_used.len() != expected_max_out {
            return Err(ProtocolError::FieldLengthMismatch(
                "selector_used",
                selector_used.len(),
                "max_out",
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
    // Random Values
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    generate_zk_proof_with_rs(zkey, witness, graph, r, s)
}

/// Generates a zkSNARK proof from witness input using the provided circuit data.
/// Takes explicit blinding scalars `r` and `s` instead of sampling them internally.
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_zk_proof_with_rs(
    zkey: &Zkey,
    witness: &RLNWitnessInput,
    graph: &Graph,
    r: Fr,
    s: Fr,
) -> Result<Proof, ProtocolError> {
    let inputs = inputs_for_witness_calculation(witness)
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));

    let full_assignment = calc_witness(inputs, graph)?;

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

/// Generates a partial zkSNARK proof from partial (known) witness inputs.
///
/// Call [`finish_zk_proof`] with the full witness to complete the proof.
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_partial_zk_proof(
    zkey: &Zkey,
    partial_witness: &RLNPartialWitnessInput,
    graph: &Graph,
) -> Result<PartialProof, ProtocolError> {
    validate_partial_witness_against_graph(partial_witness, graph)?;
    let inputs = inputs_for_partial_witness_calculation(partial_witness, graph.max_out)
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));

    let full_assignment = calc_witness_partial(inputs, graph)?;
    let mut partial_values = Vec::with_capacity(full_assignment.len() - 1);
    partial_values.extend_from_slice(&full_assignment[1..]);

    let partial_assignment = PartialAssignment::new(partial_values);
    let partial_proof =
        Groth16Partial::<_, CircomReduction>::prove_partial(&zkey.0, &partial_assignment)?;

    Ok(partial_proof)
}

/// Finishes zkSNARK proof generation from a partial proof and full witness inputs.
#[cfg(not(target_arch = "wasm32"))]
pub fn finish_zk_proof(
    zkey: &Zkey,
    partial_proof: &PartialProof,
    witness: &RLNWitnessInput,
    graph: &Graph,
) -> Result<Proof, ProtocolError> {
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    finish_zk_proof_with_rs(zkey, partial_proof, witness, graph, r, s)
}

/// Finishes zkSNARK proof generation from a partial proof and full witness inputs.
/// Takes explicit blinding scalars `r` and `s` instead of sampling them internally.
#[cfg(not(target_arch = "wasm32"))]
pub fn finish_zk_proof_with_rs(
    zkey: &Zkey,
    partial_proof: &PartialProof,
    witness: &RLNWitnessInput,
    graph: &Graph,
    r: Fr,
    s: Fr,
) -> Result<Proof, ProtocolError> {
    validate_witness_against_graph(witness, graph)?;
    let inputs = inputs_for_witness_calculation(witness)
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));

    let full_assignment = calc_witness(inputs, graph)?;

    let proof = Groth16Partial::<_, CircomReduction>::finish_proof_with_matrices(
        &zkey.0,
        partial_proof,
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
    let inputs = match &proof_values.outputs {
        RLNOutputs::SingleV1 { y, nullifier } => vec![
            *y,
            proof_values.root,
            *nullifier,
            proof_values.x,
            proof_values.external_nullifier,
        ],
        RLNOutputs::MultiV1 {
            ys,
            nullifiers,
            selector_used,
        } => {
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
        }
    };

    // Check that the proof is valid
    let pvk = prepare_verifying_key(verifying_key);

    let verified = Groth16::<_, CircomReduction>::verify_proof(&pvk, proof, &inputs)?;

    Ok(verified)
}
