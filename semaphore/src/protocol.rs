// Adapted from semaphore-rs/src/protocol.rs
// For illustration purposes only as an example protocol

// Private module
use crate::circuit::{witness_calculator, zkey};

use ark_bn254::{Bn254, Parameters};
use ark_circom::CircomReduction;
use ark_ec::bn::Bn;
use ark_groth16::{
    create_proof_with_reduction_and_matrices, prepare_verifying_key, Proof as ArkProof,
};
use ark_relations::r1cs::SynthesisError;
use ark_std::UniformRand;
use color_eyre::Result;
use ethers_core::types::U256;
use rand::{thread_rng, Rng};
use semaphore::{
    identity::Identity,
    merkle_tree::{self, Branch},
    poseidon,
    poseidon_tree::PoseidonHash,
    Field,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use thiserror::Error;

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

/// Helper to merkle proof into a bigint vector
/// TODO: we should create a From trait for this
fn merkle_proof_to_vec(proof: &merkle_tree::Proof<PoseidonHash>) -> Vec<Field> {
    proof
        .0
        .iter()
        .map(|x| match x {
            Branch::Left(value) | Branch::Right(value) => *value,
        })
        .collect()
}

/// Generates the nullifier hash
#[must_use]
pub fn generate_nullifier_hash(identity: &Identity, external_nullifier: Field) -> Field {
    poseidon::hash2(external_nullifier, identity.nullifier)
}

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Error reading circuit key: {0}")]
    CircuitKeyError(#[from] std::io::Error),
    #[error("Error producing witness: {0}")]
    WitnessError(Report),
    #[error("Error producing proof: {0}")]
    SynthesisError(#[from] SynthesisError),
    #[error("Error converting public input: {0}")]
    ToFieldError(#[from] ruint::ToFieldError),
}

/// Generates a semaphore proof
///
/// # Errors
///
/// Returns a [`ProofError`] if proving fails.
pub fn generate_proof(
    identity: &Identity,
    merkle_proof: &merkle_tree::Proof<PoseidonHash>,
    external_nullifier_hash: Field,
    signal_hash: Field,
) -> Result<Proof, ProofError> {
    generate_proof_rng(
        identity,
        merkle_proof,
        external_nullifier_hash,
        signal_hash,
        &mut thread_rng(),
    )
}

/// Generates a semaphore proof from entropy
///
/// # Errors
///
/// Returns a [`ProofError`] if proving fails.
pub fn generate_proof_rng(
    identity: &Identity,
    merkle_proof: &merkle_tree::Proof<PoseidonHash>,
    external_nullifier_hash: Field,
    signal_hash: Field,
    rng: &mut impl Rng,
) -> Result<Proof, ProofError> {
    generate_proof_rs(
        identity,
        merkle_proof,
        external_nullifier_hash,
        signal_hash,
        ark_bn254::Fr::rand(rng),
        ark_bn254::Fr::rand(rng),
    )
}

fn generate_proof_rs(
    identity: &Identity,
    merkle_proof: &merkle_tree::Proof<PoseidonHash>,
    external_nullifier_hash: Field,
    signal_hash: Field,
    r: ark_bn254::Fr,
    s: ark_bn254::Fr,
) -> Result<Proof, ProofError> {
    let inputs = [
        ("identityNullifier", vec![identity.nullifier]),
        ("identityTrapdoor", vec![identity.trapdoor]),
        ("treePathIndices", merkle_proof.path_index()),
        ("treeSiblings", merkle_proof_to_vec(merkle_proof)),
        ("externalNullifier", vec![external_nullifier_hash]),
        ("signalHash", vec![signal_hash]),
    ];
    let inputs = inputs.into_iter().map(|(name, values)| {
        (
            name.to_string(),
            values.iter().copied().map(Into::into).collect::<Vec<_>>(),
        )
    });

    let now = Instant::now();

    let full_assignment = witness_calculator()
        .lock()
        .expect("witness_calculator mutex should not get poisoned")
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .map_err(ProofError::WitnessError)?;

    println!("witness generation took: {:.2?}", now.elapsed());

    let now = Instant::now();
    let zkey = zkey();
    let ark_proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
        &zkey.0,
        r,
        s,
        &zkey.1,
        zkey.1.num_instance_variables,
        zkey.1.num_constraints,
        full_assignment.as_slice(),
    )?;
    let proof = ark_proof.into();
    println!("proof generation took: {:.2?}", now.elapsed());

    Ok(proof)
}

/// Verifies a given semaphore proof
///
/// # Errors
///
/// Returns a [`ProofError`] if verifying fails. Verification failure does not
/// necessarily mean the proof is incorrect.
pub fn verify_proof(
    root: Field,
    nullifier_hash: Field,
    signal_hash: Field,
    external_nullifier_hash: Field,
    proof: &Proof,
) -> Result<bool, ProofError> {
    let zkey = zkey();
    let pvk = prepare_verifying_key(&zkey.0.vk);

    let public_inputs = [root, nullifier_hash, signal_hash, external_nullifier_hash]
        .iter()
        .map(ark_bn254::Fr::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    let ark_proof = (*proof).into();
    let result = ark_groth16::verify_proof(&pvk, &ark_proof, &public_inputs[..])?;
    Ok(result)
}
