/// Adapted from semaphore-rs
use crate::circuit::{VK, WITNESS_CALCULATOR, ZKEY};
use ark_bn254::{Bn254, Fr, Parameters};
use ark_ec::bn::Bn;
use ark_ff::{Fp256, PrimeField};
use ark_groth16::{
    create_proof_with_reduction_and_matrices, create_random_proof_with_reduction,
    prepare_verifying_key, verify_proof as ark_verify_proof, Proof as ArkProof, ProvingKey,
    VerifyingKey,
};
use ark_relations::r1cs::SynthesisError;
use ark_std::{rand::thread_rng, UniformRand};
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
use std::time::Instant;
use thiserror::Error;

use ark_circom::{read_zkey, CircomBuilder, CircomConfig, CircomReduction};

#[derive(Debug, Deserialize)]
pub struct RLNWitnessInput {
    identity_secret: String,
    path_elements: Vec<String>,
    identity_path_index: Vec<u8>,
    x: String,
    epoch: String,
    rln_identifier: String,
}

pub fn initRLNWitnessFromJSON(input_json_str: &str) -> RLNWitnessInput {
    let rlnWitness: RLNWitnessInput =
        serde_json::from_str(&input_json_str).expect("JSON was not well-formatted");
    return rlnWitness;
}

pub fn initRLNWitnessFromValues(
    identity_secret: Field,
    merkle_proof: &merkle_tree::Proof<PoseidonHash>,
    x: Field,
    epoch: Field,
    rln_identifier: Field,
) -> RLNWitnessInput {
    //println!("Merkle proof: {:#?}", merkle_proof);
    let path_elements = getPathElements(merkle_proof);
    let identity_path_index = getIdentityPathIndex(merkle_proof);

    let rlnWitness = RLNWitnessInput {
        identity_secret: BigInt::from(identity_secret).to_str_radix(10),
        path_elements: path_elements,
        identity_path_index: identity_path_index,
        x: BigInt::from(x).to_str_radix(10),
        epoch: format!("{:#066x}", BigInt::from(epoch)), //We format it as a padded 32 bytes hex with leading 0x for compatibility with zk-kit
        rln_identifier: BigInt::from(rln_identifier).to_str_radix(10),
    };

    return rlnWitness;
}

// TODO Fields need to be updated to RLN based ones

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
pub fn getPathElements(proof: &merkle_tree::Proof<PoseidonHash>) -> Vec<String> {
    proof
        .0
        .iter()
        .map(|x| match x {
            Branch::Left(value) | Branch::Right(value) => BigInt::from(*value).to_str_radix(10),
        })
        .collect()
}

pub fn getIdentityPathIndex(proof: &merkle_tree::Proof<PoseidonHash>) -> Vec<u8> {
    proof
        .0
        .iter()
        .map(|branch| match branch {
            Branch::Left(_) => 0,
            Branch::Right(_) => 1,
        })
        .collect()
}

/// Internal helper to hash the signal to make sure it's in the field
fn hash_signal(signal: &[u8]) -> Field {
    let hash = keccak256(signal);
    // Shift right one byte to make it fit in the field
    let mut bytes = [0_u8; 32];
    bytes[1..].copy_from_slice(&hash[..31]);
    Field::from_be_bytes_mod_order(&bytes)
}

/// Generates the nullifier hash
#[must_use]
pub fn generate_nullifier_hash(identity: &Identity, external_nullifier: Field) -> Field {
    poseidon_hash(&[external_nullifier, identity.nullifier])
}

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
    rln_witness: RLNWitnessInput,
) -> Result<(Proof, Vec<Fr>), ProofError> {
    let now = Instant::now();

    builder.push_input(
        "identity_secret",
        BigInt::parse_bytes(rln_witness.identity_secret.as_bytes(), 10).unwrap(),
    );

    for v in rln_witness.path_elements.iter() {
        builder.push_input(
            "path_elements",
            BigInt::parse_bytes(v.as_bytes(), 10).unwrap(),
        );
    }

    for v in rln_witness.identity_path_index.iter() {
        builder.push_input("identity_path_index", BigInt::from(*v));
    }

    builder.push_input(
        "x",
        BigInt::parse_bytes(rln_witness.x.as_bytes(), 10).unwrap(),
    );

    builder.push_input(
        "epoch",
        BigInt::parse_bytes(rln_witness.epoch.strip_prefix("0x").unwrap().as_bytes(), 16).unwrap(),
    );

    builder.push_input(
        "rln_identifier",
        BigInt::parse_bytes(rln_witness.rln_identifier.as_bytes(), 10).unwrap(),
    );

    let circom = builder.build().unwrap();

    // Get the populated instance of the circuit with the witness
    let inputs = circom.get_public_inputs().unwrap();

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

    Ok((proof, inputs))
}

/// Verifies a given RLN proof
///
/// # Errors
///
/// Returns a [`ProofError`] if verifying fails. Verification failure does not
/// necessarily mean the proof is incorrect.
pub fn verify_proof(
    verifyingKey: &VerifyingKey<Bn254>,
    proof: Proof,
    inputs: Vec<Fr>,
) -> Result<bool, ProofError> {
    // Check that the proof is valid
    let pvk = prepare_verifying_key(verifyingKey);
    let pr: ArkProof<Bn254> = proof.into();
    let verified = ark_verify_proof(&pvk, &pr, &inputs)?;

    Ok(verified)
}
