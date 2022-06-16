use crate::circuit::{VK, ZKEY};
use ark_bn254::{Bn254, Fr, Parameters};
use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction};
use ark_ec::bn::Bn;
use ark_ff::{bytes::ToBytes, Fp256, PrimeField};
use ark_groth16::{
    create_proof_with_reduction_and_matrices, create_random_proof_with_reduction,
    prepare_verifying_key, verify_proof as ark_verify_proof, Proof as ArkProof, ProvingKey,
    VerifyingKey,
};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::*;
use ark_std::{rand::thread_rng, str::FromStr, UniformRand};
use color_eyre::Result;
use ethers_core::utils::keccak256;
use num_bigint::{BigInt, BigUint, ToBigInt};
use primitive_types::U256;
use semaphore::{
    identity::Identity,
    merkle_tree::{self, Branch},
    poseidon_hash,
    poseidon_tree::PoseidonHash,
    Field,
};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::time::Instant;
use thiserror::Error;

pub use crate::utils::{
    add, bytes_be_to_field, bytes_be_to_vec_field, bytes_be_to_vec_u8, bytes_le_to_field,
    bytes_le_to_vec_field, bytes_le_to_vec_u8, field_to_bytes_be, field_to_bytes_le, mul,
    str_to_field, vec_field_to_bytes_be, vec_field_to_bytes_le, vec_to_field, vec_to_fr,
    vec_u8_to_bytes_be, vec_u8_to_bytes_le,
};

///////////////////////////////////////////////////////
// RLN Witness data structure and utility functions
///////////////////////////////////////////////////////

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct RLNWitnessInput {
    identity_secret: Field,
    path_elements: Vec<Field>,
    identity_path_index: Vec<u8>,
    x: Field,
    epoch: Field,
    rln_identifier: Field,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct RLNProofValues {
    // Public outputs:
    y: Field,
    nullifier: Field,
    root: Field,
    // Public Inputs:
    x: Field,
    epoch: Field,
    rln_identifier: Field,
}

pub fn serialize_witness(rln_witness: &RLNWitnessInput) -> Vec<u8> {
    let mut serialized: Vec<u8> = Vec::new();

    serialized.append(&mut field_to_bytes_le(&rln_witness.identity_secret));
    serialized.append(&mut vec_field_to_bytes_le(&rln_witness.path_elements));
    serialized.append(&mut vec_u8_to_bytes_le(&rln_witness.identity_path_index));
    serialized.append(&mut field_to_bytes_le(&rln_witness.x));
    serialized.append(&mut field_to_bytes_le(&rln_witness.epoch));
    serialized.append(&mut field_to_bytes_le(&rln_witness.rln_identifier));

    serialized
}

pub fn deserialize_witness(serialized: &Vec<u8>) -> RLNWitnessInput {
    let mut all_read: usize = 0;

    let (identity_secret, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (path_elements, read) = bytes_le_to_vec_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (identity_path_index, read) = bytes_le_to_vec_u8(&serialized[all_read..].to_vec());
    all_read += read;

    let (x, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (epoch, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (rln_identifier, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    assert_eq!(serialized.len(), all_read);
    RLNWitnessInput {
        identity_secret,
        path_elements,
        identity_path_index,
        x,
        epoch,
        rln_identifier,
    }
}

pub fn serialize_proof_values(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    let mut serialized: Vec<u8> = Vec::new();

    serialized.append(&mut field_to_bytes_le(&rln_proof_values.y));
    serialized.append(&mut field_to_bytes_le(&rln_proof_values.nullifier));
    serialized.append(&mut field_to_bytes_le(&rln_proof_values.root));
    serialized.append(&mut field_to_bytes_le(&rln_proof_values.x));
    serialized.append(&mut field_to_bytes_le(&rln_proof_values.epoch));
    serialized.append(&mut field_to_bytes_le(&rln_proof_values.rln_identifier));

    serialized
}

pub fn deserialize_proof_values(serialized: &Vec<u8>) -> RLNProofValues {
    let mut all_read: usize = 0;

    let (y, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (nullifier, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (root, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (x, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (epoch, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (rln_identifier, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    assert_eq!(serialized.len(), all_read);

    RLNProofValues {
        y,
        nullifier,
        root,
        x,
        epoch,
        rln_identifier,
    }
}

pub fn rln_witness_from_json(input_json_str: &str) -> RLNWitnessInput {
    let input_json: serde_json::Value =
        serde_json::from_str(input_json_str).expect("JSON was not well-formatted");

    let identity_secret = str_to_field(input_json["identity_secret"].to_string(), 10);

    let mut path_elements: Vec<Field> = vec![];
    for v in input_json["path_elements"].as_array().unwrap().iter() {
        path_elements.push(str_to_field(v.to_string(), 10));
    }

    let mut identity_path_index: Vec<u8> = vec![];
    for v in input_json["identity_path_index"].as_array().unwrap().iter() {
        identity_path_index.push(v.as_u64().unwrap() as u8);
    }

    let x = str_to_field(input_json["x"].to_string(), 10);

    let epoch = str_to_field(input_json["epoch"].to_string(), 16);

    let rln_identifier = str_to_field(input_json["rln_identifier"].to_string(), 10);

    RLNWitnessInput {
        identity_secret,
        path_elements,
        identity_path_index,
        x,
        epoch,
        rln_identifier,
    }
}

pub fn rln_witness_from_values(
    identity_secret: Field,
    merkle_proof: &merkle_tree::Proof<PoseidonHash>,
    x: Field,
    epoch: Field,
    rln_identifier: Field,
) -> RLNWitnessInput {
    let path_elements = get_path_elements(merkle_proof);
    let identity_path_index = get_identity_path_index(merkle_proof);

    RLNWitnessInput {
        identity_secret,
        path_elements,
        identity_path_index,
        x,
        epoch,
        rln_identifier,
    }
}

pub fn proof_values_from_witness(rln_witness: &RLNWitnessInput) -> RLNProofValues {
    // y share
    let a_0 = rln_witness.identity_secret;
    let a_1 = poseidon_hash(&[a_0, rln_witness.epoch]);
    let y = mul(&rln_witness.x, &a_1);
    let y = add(&y, &a_0);

    // Nullifier
    let nullifier = poseidon_hash(&[a_1, rln_witness.rln_identifier]);

    // Merkle tree root computations
    let mut root = poseidon_hash(&[rln_witness.identity_secret]);
    for i in 0..rln_witness.identity_path_index.len() {
        if rln_witness.identity_path_index[i] == 0 {
            root = poseidon_hash(&[root, rln_witness.path_elements[i]]);
        } else {
            root = poseidon_hash(&[rln_witness.path_elements[i], root]);
        }
    }

    let root = get_tree_root(
        &rln_witness.identity_secret,
        &rln_witness.path_elements,
        &rln_witness.identity_path_index,
        true,
    );

    RLNProofValues {
        y,
        nullifier,
        root,
        x: rln_witness.x,
        epoch: rln_witness.epoch,
        rln_identifier: rln_witness.rln_identifier,
    }
}

///////////////////////////////////////////////////////
// Merkle tree utility functions
///////////////////////////////////////////////////////

/// Helper to merkle proof into a bigint vector
/// TODO: we should create a From trait for this
pub fn get_path_elements(proof: &merkle_tree::Proof<PoseidonHash>) -> Vec<Field> {
    proof
        .0
        .iter()
        .map(|x| match x {
            Branch::Left(value) | Branch::Right(value) => *value,
        })
        .collect()
}

pub fn get_identity_path_index(proof: &merkle_tree::Proof<PoseidonHash>) -> Vec<u8> {
    proof
        .0
        .iter()
        .map(|branch| match branch {
            Branch::Left(_) => 0,
            Branch::Right(_) => 1,
        })
        .collect()
}

pub fn get_tree_root(
    leaf: &Field,
    path_elements: &[Field],
    identity_path_index: &[u8],
    hash_leaf: bool,
) -> Field {
    let mut root = *leaf;
    if hash_leaf {
        root = poseidon_hash(&[root]);
    }

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
// Signal/nullifier utility functions
///////////////////////////////////////////////////////

pub fn hash_to_field(signal: &[u8]) -> Field {
    let hash = keccak256(signal);
    let (el, _) = bytes_le_to_field(&hash.to_vec());
    el
}

/// Generates the nullifier hash
#[must_use]
pub fn generate_nullifier_hash(identity: &Identity, external_nullifier: Field) -> Field {
    poseidon_hash(&[external_nullifier, identity.nullifier])
}

///////////////////////////////////////////////////////
// Proof data structure and utility functions
///////////////////////////////////////////////////////

// Matches the private G1Tup type in ark-circom.
pub type G1 = (U256, U256);

// Matches the private G2Tup type in ark-circom.
pub type G2 = ([U256; 2], [U256; 2]);

/// Wrap a proof object so we have serde support
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof(G1, G2, G1);

impl From<ArkProof<Bn<Parameters>>> for Proof {
    fn from(proof: ArkProof<Bn<Parameters>>) -> Self {
        let proof = ark_circom::ethereum::Proof::from(proof);
        let (a, b, c) = proof.as_tuple();
        Self(a, b, c)
    }
}

impl From<Proof> for ArkProof<Bn<Parameters>> {
    fn from(proof: Proof) -> Self {
        let eth_proof = ark_circom::ethereum::Proof {
            a: ark_circom::ethereum::G1 {
                x: proof.0 .0,
                y: proof.0 .1,
            },
            #[rustfmt::skip] // Rustfmt inserts some confusing spaces
            b: ark_circom::ethereum::G2 {
                // The order of coefficients is flipped.
                x: [proof.1.0[1], proof.1.0[0]],
                y: [proof.1.1[1], proof.1.1[0]],
            },
            c: ark_circom::ethereum::G1 {
                x: proof.2 .0,
                y: proof.2 .1,
            },
        };
        eth_proof.into()
    }
}

///////////////////////////////////////////////////////
// zkSNARK utility functions
///////////////////////////////////////////////////////

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Error reading circuit key: {0}")]
    CircuitKeyError(#[from] std::io::Error),
    #[error("Error producing witness: {0}")]
    WitnessError(color_eyre::Report),
    #[error("Error producing proof: {0}")]
    SynthesisError(#[from] SynthesisError),
}

/// Generates a RLN proof
///
/// # Errors
///
/// Returns a [`ProofError`] if proving fails.
pub fn generate_proof(
    mut builder: CircomBuilder<Bn254>,
    proving_key: &ProvingKey<Bn254>,
    rln_witness: &RLNWitnessInput,
) -> Result<Proof, ProofError> {
    let now = Instant::now();

    builder.push_input("identity_secret", BigInt::from(rln_witness.identity_secret));

    for v in rln_witness.path_elements.iter() {
        builder.push_input("path_elements", BigInt::from(*v));
    }

    for v in rln_witness.identity_path_index.iter() {
        builder.push_input("identity_path_index", BigInt::from(*v));
    }

    builder.push_input("x", BigInt::from(rln_witness.x));

    builder.push_input("epoch", BigInt::from(rln_witness.epoch));

    builder.push_input("rln_identifier", BigInt::from(rln_witness.rln_identifier));

    let circom = builder.build().unwrap();

    // This can be checked against proof_values_from_witness
    // Get the populated instance of the circuit with the witness
    //let inputs = vec_to_field(circom.get_public_inputs().unwrap());

    println!("witness generation took: {:.2?}", now.elapsed());

    let now = Instant::now();

    // Generate a random proof
    let mut rng = thread_rng();

    let ark_proof = create_random_proof_with_reduction::<_, _, _, CircomReduction>(
        circom,
        proving_key,
        &mut rng,
    )
    .unwrap();

    let proof = ark_proof.into();

    println!("proof generation took: {:.2?}", now.elapsed());

    Ok(proof)
}

/// Verifies a given RLN proof
///
/// # Errors
///
/// Returns a [`ProofError`] if verifying fails. Verification failure does not
/// necessarily mean the proof is incorrect.
pub fn verify_proof(
    verifying_key: &VerifyingKey<Bn254>,
    proof: &Proof,
    proof_values: &RLNProofValues,
) -> Result<bool, ProofError> {
    // We re-arrange proof-values according to the circuit specification
    let inputs = vec![
        proof_values.y,
        proof_values.root,
        proof_values.nullifier,
        proof_values.x,
        proof_values.epoch,
        proof_values.rln_identifier,
    ];

    // Check that the proof is valid
    let pvk = prepare_verifying_key(verifying_key);
    let pr: ArkProof<Bn254> = (*proof).into();
    let verified = ark_verify_proof(&pvk, &pr, &vec_to_fr(&inputs))?;

    Ok(verified)
}
