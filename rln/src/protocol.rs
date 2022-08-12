// This crate collects all the underlying primitives used to implement RLN

use crate::circuit::{CIRCOM, VK, ZKEY};
use ark_bn254::{Bn254, Fr, Parameters};
use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction, WitnessCalculator};
use ark_ec::bn::Bn;
use ark_ff::{bytes::ToBytes, Fp256, PrimeField};
use ark_groth16::{
    create_proof_with_reduction_and_matrices, create_random_proof_with_reduction,
    prepare_verifying_key, verify_proof as ark_verify_proof, Proof as ArkProof, ProvingKey,
    VerifyingKey,
};
use ark_relations::r1cs::ConstraintMatrices;
use ark_relations::r1cs::SynthesisError;
use ark_serialize::*;
use ark_std::{rand::thread_rng, str::FromStr, UniformRand};
use color_eyre::Result;
use ethers::core::utils::keccak256;
use num_bigint::{BigInt, BigUint, ToBigInt};
use primitive_types::U256;
use rand::Rng;
use semaphore::{identity::Identity, poseidon_hash, Field};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::Mutex;
use std::time::Instant;
use thiserror::Error;

use crate::poseidon_tree::*;
use crate::public::{RLN, RLN_IDENTIFIER};
pub use crate::utils::*;

///////////////////////////////////////////////////////
// RLN Witness data structure and utility functions
///////////////////////////////////////////////////////

#[derive(Debug, PartialEq)]
pub struct RLNWitnessInput {
    identity_secret: Field,
    path_elements: Vec<Field>,
    identity_path_index: Vec<u8>,
    x: Field,
    epoch: Field,
    rln_identifier: Field,
}

#[derive(Debug, PartialEq)]
pub struct RLNProofValues {
    // Public outputs:
    pub y: Field,
    pub nullifier: Field,
    pub root: Field,
    // Public Inputs:
    pub x: Field,
    pub epoch: Field,
    pub rln_identifier: Field,
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

pub fn deserialize_witness(serialized: &[u8]) -> (RLNWitnessInput, usize) {
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

    // TODO: check rln_identifier against public::RLN_IDENTIFIER
    assert_eq!(serialized.len(), all_read);

    (
        RLNWitnessInput {
            identity_secret,
            path_elements,
            identity_path_index,
            x,
            epoch,
            rln_identifier,
        },
        all_read,
    )
}

// This function deserializes input for kilic's rln generate_proof public API
// https://github.com/kilic/rln/blob/7ac74183f8b69b399e3bc96c1ae8ab61c026dc43/src/public.rs#L148
// input_data is [ id_key<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
// return value is a rln witness populated according to this information
pub fn proof_inputs_to_rln_witness(
    tree: &mut PoseidonTree,
    serialized: &[u8],
) -> (RLNWitnessInput, usize) {
    let mut all_read: usize = 0;

    let (identity_secret, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let id_index = u64::from_le_bytes(serialized[all_read..all_read + 8].try_into().unwrap());
    all_read += 8;

    let (epoch, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let signal_len = u64::from_le_bytes(serialized[all_read..all_read + 8].try_into().unwrap());
    all_read += 8;

    let signal: Vec<u8> =
        serialized[all_read..all_read + usize::try_from(signal_len).unwrap()].to_vec();

    let merkle_proof = tree
        .proof(usize::try_from(id_index).unwrap())
        .expect("proof should exist");
    let path_elements = merkle_proof.get_path_elements();
    let identity_path_index = merkle_proof.get_path_index();

    let x = hash_to_field(&signal);

    let rln_identifier = hash_to_field(RLN_IDENTIFIER);

    (
        RLNWitnessInput {
            identity_secret,
            path_elements,
            identity_path_index,
            x,
            epoch,
            rln_identifier,
        },
        all_read,
    )
}

pub fn serialize_proof_values(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    let mut serialized: Vec<u8> = Vec::new();

    serialized.append(&mut field_to_bytes_le(&rln_proof_values.root));
    serialized.append(&mut field_to_bytes_le(&rln_proof_values.epoch));
    serialized.append(&mut field_to_bytes_le(&rln_proof_values.x));
    serialized.append(&mut field_to_bytes_le(&rln_proof_values.y));
    serialized.append(&mut field_to_bytes_le(&rln_proof_values.nullifier));
    serialized.append(&mut field_to_bytes_le(&rln_proof_values.rln_identifier));

    serialized
}

pub fn deserialize_proof_values(serialized: &[u8]) -> (RLNProofValues, usize) {
    let mut all_read: usize = 0;

    let (root, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (epoch, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (x, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (y, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (nullifier, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    let (rln_identifier, read) = bytes_le_to_field(&serialized[all_read..].to_vec());
    all_read += read;

    (
        RLNProofValues {
            y,
            nullifier,
            root,
            x,
            epoch,
            rln_identifier,
        },
        all_read,
    )
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

    // TODO: check rln_identifier against public::RLN_IDENTIFIER

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
    merkle_proof: &MerkleProof,
    x: Field,
    epoch: Field,
    //rln_identifier: Field,
) -> RLNWitnessInput {
    let path_elements = merkle_proof.get_path_elements();
    let identity_path_index = merkle_proof.get_path_index();
    let rln_identifier = hash_to_field(RLN_IDENTIFIER);

    RLNWitnessInput {
        identity_secret,
        path_elements,
        identity_path_index,
        x,
        epoch,
        rln_identifier,
    }
}

pub fn random_rln_witness(tree_height: usize) -> RLNWitnessInput {
    let mut rng = thread_rng();

    let identity_secret = hash_to_field(&rng.gen::<[u8; 32]>());
    let x = hash_to_field(&rng.gen::<[u8; 32]>());
    let epoch = hash_to_field(&rng.gen::<[u8; 32]>());
    let rln_identifier = hash_to_field(RLN_IDENTIFIER); //hash_to_field(&rng.gen::<[u8; 32]>());

    let mut path_elements: Vec<Field> = Vec::new();
    let mut identity_path_index: Vec<u8> = Vec::new();

    for _ in 0..tree_height {
        path_elements.push(hash_to_field(&rng.gen::<[u8; 32]>()));
        identity_path_index.push(rng.gen_range(0..2) as u8);
    }

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
    let root = compute_tree_root(
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

pub fn compute_tree_root(
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
// Generates a tupe (identity_secret, id_commitment) where
// identity_secret is random and id_commitment = PoseidonHash(identity_secret)
pub fn keygen() -> (Field, Field) {
    let mut rng = thread_rng();
    let identity_secret = to_field(&Fr::rand(&mut rng));
    let id_commitment = poseidon_hash(&[identity_secret]);
    (identity_secret, id_commitment)
}

pub fn hash_to_field(signal: &[u8]) -> Field {
    let hash = keccak256(signal);
    let (el, _) = bytes_le_to_field(hash.as_ref());
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
    witness_calculator: &Mutex<WitnessCalculator>,
    proving_key: &(ProvingKey<Bn254>, ConstraintMatrices<Fr>),
    rln_witness: &RLNWitnessInput,
) -> Result<Proof, ProofError> {
    // We confert the path indexes to field elements
    // TODO: check if necessary
    let mut path_elements: Vec<BigInt> = Vec::new();
    for v in rln_witness.path_elements.iter() {
        path_elements.push(BigInt::from(*v));
    }

    let mut identity_path_index: Vec<BigInt> = Vec::new();
    for v in rln_witness.identity_path_index.iter() {
        identity_path_index.push(BigInt::from(*v));
    }

    let inputs = [
        (
            "identity_secret",
            vec![BigInt::from(rln_witness.identity_secret)],
        ),
        ("path_elements", path_elements),
        ("identity_path_index", identity_path_index),
        ("x", vec![BigInt::from(rln_witness.x)]),
        ("epoch", vec![BigInt::from(rln_witness.epoch)]),
        (
            "rln_identifier",
            vec![BigInt::from(rln_witness.rln_identifier)],
        ),
    ];
    let inputs = inputs
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));

    let now = Instant::now();

    let full_assignment = witness_calculator
        .lock()
        .expect("witness_calculator mutex should not get poisoned")
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .map_err(ProofError::WitnessError)?;

    println!("witness generation took: {:.2?}", now.elapsed());

    // Random Values
    let mut rng = thread_rng();
    let r = ark_bn254::Fr::rand(&mut rng);
    let s = ark_bn254::Fr::rand(&mut rng);

    let now = Instant::now();
    let ark_proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
        &proving_key.0,
        r,
        s,
        &proving_key.1,
        proving_key.1.num_instance_variables,
        proving_key.1.num_constraints,
        full_assignment.as_slice(),
    )?;
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
    let now = Instant::now();
    let verified = ark_verify_proof(&pvk, &pr, &vec_to_fr(&inputs))?;
    println!("verify took: {:.2?}", now.elapsed());

    Ok(verified)
}
