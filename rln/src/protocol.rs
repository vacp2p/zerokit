// This crate collects all the underlying primitives used to implement RLN

use ark_circom::{CircomReduction, WitnessCalculator};
use ark_groth16::{
    create_proof_with_reduction_and_matrices, prepare_verifying_key,
    verify_proof as ark_verify_proof, Proof as ArkProof, ProvingKey, VerifyingKey,
};
use ark_relations::r1cs::ConstraintMatrices;
use ark_relations::r1cs::SynthesisError;
use ark_std::{rand::thread_rng, UniformRand};
use color_eyre::Result;
use num_bigint::BigInt;
use rand::Rng;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Mutex;
#[cfg(debug_assertions)]
use std::time::Instant;
use thiserror::Error;
use tiny_keccak::{Hasher as _, Keccak};

use crate::circuit::{Curve, Fr};
use crate::poseidon_hash::poseidon_hash;
use crate::poseidon_tree::*;
use crate::public::RLN_IDENTIFIER;
use crate::utils::*;
use cfg_if::cfg_if;

///////////////////////////////////////////////////////
// RLN Witness data structure and utility functions
///////////////////////////////////////////////////////

#[derive(Debug, PartialEq)]
pub struct RLNWitnessInput {
    identity_secret: Fr,
    path_elements: Vec<Fr>,
    identity_path_index: Vec<u8>,
    x: Fr,
    epoch: Fr,
    rln_identifier: Fr,
}

#[derive(Debug, PartialEq)]
pub struct RLNProofValues {
    // Public outputs:
    pub y: Fr,
    pub nullifier: Fr,
    pub root: Fr,
    // Public Inputs:
    pub x: Fr,
    pub epoch: Fr,
    pub rln_identifier: Fr,
}

pub fn serialize_witness(rln_witness: &RLNWitnessInput) -> Vec<u8> {
    let mut serialized: Vec<u8> = Vec::new();

    serialized.append(&mut fr_to_bytes_le(&rln_witness.identity_secret));
    serialized.append(&mut vec_fr_to_bytes_le(&rln_witness.path_elements));
    serialized.append(&mut vec_u8_to_bytes_le(&rln_witness.identity_path_index));
    serialized.append(&mut fr_to_bytes_le(&rln_witness.x));
    serialized.append(&mut fr_to_bytes_le(&rln_witness.epoch));
    serialized.append(&mut fr_to_bytes_le(&rln_witness.rln_identifier));

    serialized
}

pub fn deserialize_witness(serialized: &[u8]) -> (RLNWitnessInput, usize) {
    let mut all_read: usize = 0;

    let (identity_secret, read) = bytes_le_to_fr(&serialized[all_read..].to_vec());
    all_read += read;

    let (path_elements, read) = bytes_le_to_vec_fr(&serialized[all_read..].to_vec());
    all_read += read;

    let (identity_path_index, read) = bytes_le_to_vec_u8(&serialized[all_read..].to_vec());
    all_read += read;

    let (x, read) = bytes_le_to_fr(&serialized[all_read..].to_vec());
    all_read += read;

    let (epoch, read) = bytes_le_to_fr(&serialized[all_read..].to_vec());
    all_read += read;

    let (rln_identifier, read) = bytes_le_to_fr(&serialized[all_read..].to_vec());
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

    let (identity_secret, read) = bytes_le_to_fr(&serialized[all_read..].to_vec());
    all_read += read;

    let id_index = u64::from_le_bytes(serialized[all_read..all_read + 8].try_into().unwrap());
    all_read += 8;

    let (epoch, read) = bytes_le_to_fr(&serialized[all_read..].to_vec());
    all_read += read;

    let signal_len = u64::from_le_bytes(serialized[all_read..all_read + 8].try_into().unwrap());
    all_read += 8;

    let signal: Vec<u8> = serialized[all_read..all_read + (signal_len as usize)].to_vec();

    let merkle_proof = tree.proof(id_index as usize).expect("proof should exist");
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

    serialized.append(&mut fr_to_bytes_le(&rln_proof_values.root));
    serialized.append(&mut fr_to_bytes_le(&rln_proof_values.epoch));
    serialized.append(&mut fr_to_bytes_le(&rln_proof_values.x));
    serialized.append(&mut fr_to_bytes_le(&rln_proof_values.y));
    serialized.append(&mut fr_to_bytes_le(&rln_proof_values.nullifier));
    serialized.append(&mut fr_to_bytes_le(&rln_proof_values.rln_identifier));

    serialized
}

pub fn deserialize_proof_values(serialized: &[u8]) -> (RLNProofValues, usize) {
    let mut all_read: usize = 0;

    let (root, read) = bytes_le_to_fr(&serialized[all_read..].to_vec());
    all_read += read;

    let (epoch, read) = bytes_le_to_fr(&serialized[all_read..].to_vec());
    all_read += read;

    let (x, read) = bytes_le_to_fr(&serialized[all_read..].to_vec());
    all_read += read;

    let (y, read) = bytes_le_to_fr(&serialized[all_read..].to_vec());
    all_read += read;

    let (nullifier, read) = bytes_le_to_fr(&serialized[all_read..].to_vec());
    all_read += read;

    let (rln_identifier, read) = bytes_le_to_fr(&serialized[all_read..].to_vec());
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

    let identity_secret = str_to_fr(&input_json["identity_secret"].to_string(), 10);

    let path_elements = input_json["path_elements"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| str_to_fr(&v.to_string(), 10))
        .collect();

    let identity_path_index = input_json["identity_path_index"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();

    let x = str_to_fr(&input_json["x"].to_string(), 10);

    let epoch = str_to_fr(&input_json["epoch"].to_string(), 16);

    let rln_identifier = str_to_fr(&input_json["rln_identifier"].to_string(), 10);

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
    identity_secret: Fr,
    merkle_proof: &MerkleProof,
    x: Fr,
    epoch: Fr,
    //rln_identifier: Fr,
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

    let mut path_elements: Vec<Fr> = Vec::new();
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
    let y = rln_witness.x * a_1;
    let y = y + a_0;

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
    leaf: &Fr,
    path_elements: &[Fr],
    identity_path_index: &[u8],
    hash_leaf: bool,
) -> Fr {
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
pub fn keygen() -> (Fr, Fr) {
    let mut rng = thread_rng();
    let identity_secret = Fr::rand(&mut rng);
    let id_commitment = poseidon_hash(&[identity_secret]);
    (identity_secret, id_commitment)
}

// Hashes arbitrary signal to the underlying prime field
pub fn hash_to_field(signal: &[u8]) -> Fr {
    // We hash the input signal using Keccak256
    // (note that a bigger curve order might require a bigger hash blocksize)
    let mut hash = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut hash);

    // We export the hash as a field element
    let (el, _) = bytes_le_to_fr(hash.as_ref());
    el
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

fn calculate_witness_element<E: ark_ec::PairingEngine>(witness: Vec<BigInt>) -> Result<Vec<E::Fr>> {
    use ark_ff::{FpParameters, PrimeField};
    let modulus = <<E::Fr as PrimeField>::Params as FpParameters>::MODULUS;

    // convert it to field elements
    use num_traits::Signed;
    let witness = witness
        .into_iter()
        .map(|w| {
            let w = if w.sign() == num_bigint::Sign::Minus {
                // Need to negate the witness element if negative
                modulus.into() - w.abs().to_biguint().unwrap()
            } else {
                w.to_biguint().unwrap()
            };
            E::Fr::from(w)
        })
        .collect::<Vec<_>>();

    Ok(witness)
}

pub fn generate_proof_with_witness(
    witness: Vec<BigInt>,
    proving_key: &(ProvingKey<Curve>, ConstraintMatrices<Fr>),
) -> Result<ArkProof<Curve>, ProofError> {
    // If in debug mode, we measure and later print time take to compute witness
    #[cfg(debug_assertions)]
    let now = Instant::now();

    let full_assignment = calculate_witness_element::<Curve>(witness)
        .map_err(ProofError::WitnessError)
        .unwrap();

    #[cfg(debug_assertions)]
    println!("witness generation took: {:.2?}", now.elapsed());

    // Random Values
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    // If in debug mode, we measure and later print time take to compute proof
    #[cfg(debug_assertions)]
    let now = Instant::now();

    let proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
        &proving_key.0,
        r,
        s,
        &proving_key.1,
        proving_key.1.num_instance_variables,
        proving_key.1.num_constraints,
        full_assignment.as_slice(),
    )
    .unwrap();

    #[cfg(debug_assertions)]
    println!("proof generation took: {:.2?}", now.elapsed());

    Ok(proof)
}

/// Generates a RLN proof
///
/// # Errors
///
/// Returns a [`ProofError`] if proving fails.
pub fn generate_proof(
    #[cfg(not(target_arch = "wasm32"))] witness_calculator: &Mutex<WitnessCalculator>,
    #[cfg(target_arch = "wasm32")] witness_calculator: &mut WitnessCalculator,
    proving_key: &(ProvingKey<Curve>, ConstraintMatrices<Fr>),
    rln_witness: &RLNWitnessInput,
) -> Result<ArkProof<Curve>, ProofError> {
    // We confert the path indexes to field elements
    // TODO: check if necessary
    let mut path_elements = Vec::new();
    rln_witness
        .path_elements
        .iter()
        .for_each(|v| path_elements.push(to_bigint(v)));

    let mut identity_path_index = Vec::new();
    rln_witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(BigInt::from(*v)));

    let inputs = [
        (
            "identity_secret",
            vec![to_bigint(&rln_witness.identity_secret)],
        ),
        ("path_elements", path_elements),
        ("identity_path_index", identity_path_index),
        ("x", vec![to_bigint(&rln_witness.x)]),
        ("epoch", vec![to_bigint(&rln_witness.epoch)]),
        (
            "rln_identifier",
            vec![to_bigint(&rln_witness.rln_identifier)],
        ),
    ];
    let inputs = inputs
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));

    // If in debug mode, we measure and later print time take to compute witness
    #[cfg(debug_assertions)]
    let now = Instant::now();

    cfg_if! {
        if #[cfg(target_arch = "wasm32")] {
            let full_assignment = witness_calculator
            .calculate_witness_element::<Curve, _>(inputs, false)
            .map_err(ProofError::WitnessError)?;
        } else {
            let full_assignment = witness_calculator
            .lock()
            .expect("witness_calculator mutex should not get poisoned")
            .calculate_witness_element::<Curve, _>(inputs, false)
            .map_err(ProofError::WitnessError)?;
        }
    }

    #[cfg(debug_assertions)]
    println!("witness generation took: {:.2?}", now.elapsed());

    // Random Values
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    // If in debug mode, we measure and later print time take to compute proof
    #[cfg(debug_assertions)]
    let now = Instant::now();

    let proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
        &proving_key.0,
        r,
        s,
        &proving_key.1,
        proving_key.1.num_instance_variables,
        proving_key.1.num_constraints,
        full_assignment.as_slice(),
    )?;

    #[cfg(debug_assertions)]
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
    verifying_key: &VerifyingKey<Curve>,
    proof: &ArkProof<Curve>,
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
    //let pr: ArkProof<Curve> = (*proof).into();

    // If in debug mode, we measure and later print time take to verify proof
    #[cfg(debug_assertions)]
    let now = Instant::now();

    let verified = ark_verify_proof(&pvk, proof, &inputs)?;

    #[cfg(debug_assertions)]
    println!("verify took: {:.2?}", now.elapsed());

    Ok(verified)
}

/// Get CIRCOM JSON inputs
///
/// Returns a JSON object containing the inputs necessary to calculate
/// the witness with CIRCOM on javascript
pub fn get_json_inputs(rln_witness: &RLNWitnessInput) -> serde_json::Value {
    let mut path_elements = Vec::new();
    rln_witness
        .path_elements
        .iter()
        .for_each(|v| path_elements.push(to_bigint(v).to_str_radix(10)));

    let mut identity_path_index = Vec::new();
    rln_witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(BigInt::from(*v).to_str_radix(10)));

    let inputs = serde_json::json!({
        "identity_secret": to_bigint(&rln_witness.identity_secret).to_str_radix(10),
        "path_elements": path_elements,
        "identity_path_index": identity_path_index,
        "x": to_bigint(&rln_witness.x).to_str_radix(10),
        "epoch":  format!("0x{:064x}", to_bigint(&rln_witness.epoch)),
        "rln_identifier": to_bigint(&rln_witness.rln_identifier).to_str_radix(10),
    });

    inputs
}
