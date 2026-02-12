use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::thread_rng, UniformRand};
use num_bigint::BigInt;
use num_traits::Signed;
use ark_groth16_partial::partial_prover::{Groth16Partial, PartialAssignment};
use super::witness::{inputs_for_partial_witness_calculation, inputs_for_witness_calculation, RLNPartialWitnessInput, RLNWitnessInput};
use crate::{
    circuit::{
        iden3calc::calc_witness, qap::CircomReduction, Curve, Fr, Graph, Proof, VerifyingKey, Zkey,
        COMPRESS_PROOF_SIZE,
    },
    error::ProtocolError,
    utils::{bytes_be_to_fr, bytes_le_to_fr, fr_to_bytes_be, fr_to_bytes_le, FR_BYTE_SIZE},
};
use crate::circuit::{iden3calc::calc_witness_partial, PartialProof};

/// Complete RLN proof.
///
/// Combines the Groth16 proof with its public values.
#[derive(Debug, PartialEq, Clone)]
pub struct RLNProof {
    pub proof: Proof,
    pub proof_values: RLNProofValues,
}

/// Public values for RLN proof verification.
///
/// Contains the circuit's public inputs and outputs. Used in proof verification
/// and identity secret recovery when rate limit violations are detected.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct RLNProofValues {
    // Public outputs:
    pub y: Fr,
    pub nullifier: Fr,
    pub root: Fr,
    // Public Inputs:
    pub x: Fr,
    pub external_nullifier: Fr,
}

/// Serializes RLN proof values to little-endian bytes.
pub fn rln_proof_values_to_bytes_le(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    // Calculate capacity for Vec:
    // 5 field elements: root, external_nullifier, x, y, nullifier
    let mut bytes = Vec::with_capacity(FR_BYTE_SIZE * 5);

    bytes.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.root));
    bytes.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.external_nullifier));
    bytes.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.x));
    bytes.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.y));
    bytes.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.nullifier));

    bytes
}

/// Serializes RLN proof values to big-endian bytes.
pub fn rln_proof_values_to_bytes_be(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    // Calculate capacity for Vec:
    // 5 field elements: root, external_nullifier, x, y, nullifier
    let mut bytes = Vec::with_capacity(FR_BYTE_SIZE * 5);

    bytes.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.root));
    bytes.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.external_nullifier));
    bytes.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.x));
    bytes.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.y));
    bytes.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.nullifier));

    bytes
}

/// Deserializes RLN proof values from little-endian bytes.
///
/// Format: `[ root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]`
///
/// Returns the deserialized proof values and the number of bytes read.
pub fn bytes_le_to_rln_proof_values(
    bytes: &[u8],
) -> Result<(RLNProofValues, usize), ProtocolError> {
    let mut read: usize = 0;

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

    Ok((
        RLNProofValues {
            y,
            nullifier,
            root,
            x,
            external_nullifier,
        },
        read,
    ))
}

/// Deserializes RLN proof values from big-endian bytes.
///
/// Format: `[ root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]`
///
/// Returns the deserialized proof values and the number of bytes read.
pub fn bytes_be_to_rln_proof_values(
    bytes: &[u8],
) -> Result<(RLNProofValues, usize), ProtocolError> {
    let mut read: usize = 0;

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

    Ok((
        RLNProofValues {
            y,
            nullifier,
            root,
            x,
            external_nullifier,
        },
        read,
    ))
}

/// Serializes RLN proof to little-endian bytes.
///
/// Note: The Groth16 proof is always serialized in LE format (arkworks behavior),
/// while proof_values are serialized in LE format.
pub fn rln_proof_to_bytes_le(rln_proof: &RLNProof) -> Result<Vec<u8>, ProtocolError> {
    // Calculate capacity for Vec:
    // - 128 bytes for compressed Groth16 proof
    // - 5 field elements for proof values (root, external_nullifier, x, y, nullifier)
    let mut bytes = Vec::with_capacity(COMPRESS_PROOF_SIZE + FR_BYTE_SIZE * 5);

    // Serialize proof (always LE format from arkworks)
    rln_proof.proof.serialize_compressed(&mut bytes)?;

    // Serialize proof values in LE
    let proof_values_bytes = rln_proof_values_to_bytes_le(&rln_proof.proof_values);
    bytes.extend_from_slice(&proof_values_bytes);

    Ok(bytes)
}

/// Serializes RLN proof to big-endian bytes.
///
/// Note: The Groth16 proof is always serialized in LE format (arkworks behavior),
/// while proof_values are serialized in BE format. This creates a mixed-endian format.
pub fn rln_proof_to_bytes_be(rln_proof: &RLNProof) -> Result<Vec<u8>, ProtocolError> {
    // Calculate capacity for Vec:
    // - 128 bytes for compressed Groth16 proof
    // - 5 field elements for proof values (root, external_nullifier, x, y, nullifier)
    let mut bytes = Vec::with_capacity(COMPRESS_PROOF_SIZE + FR_BYTE_SIZE * 5);

    // Serialize proof (always LE format from arkworks)
    rln_proof.proof.serialize_compressed(&mut bytes)?;

    // Serialize proof values in BE
    let proof_values_bytes = rln_proof_values_to_bytes_be(&rln_proof.proof_values);
    bytes.extend_from_slice(&proof_values_bytes);

    Ok(bytes)
}

/// Deserializes RLN proof from little-endian bytes.
///
/// Format: `[ proof<128,LE> | root<32,LE> | external_nullifier<32,LE> | x<32,LE> | y<32,LE> | nullifier<32,LE> ]`
///
/// Returns the deserialized proof and the number of bytes read.
pub fn bytes_le_to_rln_proof(bytes: &[u8]) -> Result<(RLNProof, usize), ProtocolError> {
    let mut read: usize = 0;

    // Deserialize proof (always LE from arkworks)
    let proof = Proof::deserialize_compressed(&bytes[read..read + COMPRESS_PROOF_SIZE])?;
    read += COMPRESS_PROOF_SIZE;

    // Deserialize proof values
    let (values, el_size) = bytes_le_to_rln_proof_values(&bytes[read..])?;
    read += el_size;

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
/// Format: `[ proof<128,LE> | root<32,BE> | external_nullifier<32,BE> | x<32,BE> | y<32,BE> | nullifier<32,BE> ]`
///
/// Note: Mixed-endian format - proof is LE (arkworks), proof_values are BE.
///
/// Returns the deserialized proof and the number of bytes read.
pub fn bytes_be_to_rln_proof(bytes: &[u8]) -> Result<(RLNProof, usize), ProtocolError> {
    let mut read: usize = 0;

    // Deserialize proof (always LE from arkworks)
    let proof = Proof::deserialize_compressed(&bytes[read..read + COMPRESS_PROOF_SIZE])?;
    read += COMPRESS_PROOF_SIZE;

    // Deserialize proof values
    let (values, el_size) = bytes_be_to_rln_proof_values(&bytes[read..])?;
    read += el_size;

    Ok((
        RLNProof {
            proof,
            proof_values: values,
        },
        read,
    ))
}

// partial proof serialization

/// Serializes RLN partial proof to little-endian bytes.
/// Note: The Groth16 partial proof is serialized ONLY in LE format.
pub fn rln_partial_proof_to_bytes_le(
    partial_proof: &PartialProof,
) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = Vec::new();
    partial_proof.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

/// Deserializes RLN partial proof from little-endian bytes.
/// Returns the deserialized partial proof and the number of bytes read.
pub fn bytes_le_to_rln_partial_proof(bytes: &[u8]) -> Result<(PartialProof, usize), ProtocolError> {
    let mut bytes_ref = bytes;
    let initial_len = bytes_ref.len();
    let partial_proof = PartialProof::deserialize_compressed(&mut bytes_ref)?;
    let read = initial_len - bytes_ref.len();

    Ok((partial_proof, read))
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

    // Random Values
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    generate_zk_proof_with_rs(zkey, witness, graph, r, s)
}

/// Generates a zkSNARK proof from witness input using the provided circuit data.
/// this version takes the blinding `r` and `s`
pub fn generate_zk_proof_with_rs(
    zkey: &Zkey,
    witness: &RLNWitnessInput,
    graph: &Graph,
    r: Fr,
    s: Fr,
) -> Result<Proof, ProtocolError> {
    let inputs = inputs_for_witness_calculation(witness)?
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

/// generate partial proof
/// this includes the partial witness generation
pub fn generate_partial_zk_proof(
    zkey: &Zkey,
    partial_witness: &RLNPartialWitnessInput,
    graph: &Graph,
) -> Result<PartialProof, ProtocolError> {
    let inputs = inputs_for_partial_witness_calculation(partial_witness)?
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));

    let full_assignment = calc_witness_partial(inputs, graph)?;
    let mut partial_values = Vec::with_capacity(full_assignment.len()-1);
    partial_values.extend_from_slice(&full_assignment[1..]);

    let partial_assignment = PartialAssignment::new(partial_values);
    let partial_proof = Groth16Partial::<_, CircomReduction>::prove_partial(&zkey.0, &partial_assignment);

    Ok(partial_proof)
}

/// Finish the proof using a precomputed partial proof and full witness inputs.
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

/// Finish the proof using a precomputed partial proof and full witness inputs.
pub fn finish_zk_proof_with_rs(
    zkey: &Zkey,
    partial_proof: &PartialProof,
    witness: &RLNWitnessInput,
    graph: &Graph,
    r: Fr,
    s: Fr,
) -> Result<Proof, ProtocolError> {
    let inputs = inputs_for_witness_calculation(witness)?
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
/// Note: Verification failure may occur due to proof computation errors, not necessarily malicious proofs.
pub fn verify_zk_proof(
    verifying_key: &VerifyingKey,
    proof: &Proof,
    proof_values: &RLNProofValues,
) -> Result<bool, ProtocolError> {
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

    let verified = Groth16::<_, CircomReduction>::verify_proof(&pvk, proof, &inputs)?;

    Ok(verified)
}
