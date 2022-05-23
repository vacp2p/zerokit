/// Adapted from semaphore-rs
use crate::circuit::{WITNESS_CALCULATOR, ZKEY};
use ark_bn254::{Bn254, Parameters};
use ark_circom::CircomReduction;
use ark_ec::bn::Bn;
use ark_ff::{Fp256, PrimeField};
use ark_groth16::{
    create_proof_with_reduction_and_matrices, prepare_verifying_key, Proof as ArkProof,
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
fn merkle_proof_to_vec(proof: &merkle_tree::Proof<PoseidonHash>) -> Vec<Field> {
    proof
        .0
        .iter()
        .map(|x| match x {
            Branch::Left(value) | Branch::Right(value) => *value,
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

// XXX This is different from zk-kit API:
// const witness = RLN.genWitness(secretHash, merkleProof, epoch, signal, rlnIdentifier)
// const fullProof = await RLN.genProof(witness, wasmFilePath, finalZkeyPath)
//

// TODO Change API here
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
    // TODO Fix inputs
    // Semaphore genWitness corresponds to these
    // RLN different, should be:
    // identity_secret
    // path_elements (merkleProof.siblings))
    // identity_path_index (merkleProof.pathIndices)
    // x (RLN.genSignalHash(signal), assuming shouldHash is true)
    // epoch
    // rln_identifier
    let inputs = [
        // FIXME should be identity_secret, not just nullifier!
        ("identity_secret", vec![identity.nullifier]),
        //("identityTrapdoor", vec![identity.trapdoor]),
        ("path_elements", merkle_proof_to_vec(merkle_proof)),
        ("identity_path_index", merkle_proof.path_index()),
        ("externalNullifier", vec![external_nullifier_hash]),
        // XXX: Assuming signal is hashed
        ("x", vec![signal_hash]),
        // FIXME epoch just hardcoded to random value
        ("epoch", vec![signal_hash]),
        // FIXME rln_identifier just hardcoded to random value
        ("rln_identifier", vec![signal_hash]),
    ];
    let inputs = inputs.into_iter().map(|(name, values)| {
        (
            name.to_string(),
            values.iter().copied().map(Into::into).collect::<Vec<_>>(),
        )
    });

    let now = Instant::now();

    let full_assignment = WITNESS_CALCULATOR
        .clone()
        .calculate_witness_element::<Bn254, _>(inputs, false)
        .map_err(ProofError::WitnessError)?;

    println!("witness generation took: {:.2?}", now.elapsed());

    let mut rng = thread_rng();
    let rng = &mut rng;

    let r = ark_bn254::Fr::rand(rng);
    let s = ark_bn254::Fr::rand(rng);

    let now = Instant::now();

    let ark_proof = create_proof_with_reduction_and_matrices::<_, CircomReduction>(
        &ZKEY.0,
        r,
        s,
        &ZKEY.1,
        ZKEY.1.num_instance_variables,
        ZKEY.1.num_constraints,
        full_assignment.as_slice(),
    )?;
    let proof = ark_proof.into();
    println!("proof generation took: {:.2?}", now.elapsed());

    Ok(proof)
}

// TODO Update API here

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
    // XXX: Why is verification key in zkey but that's not what is used in
    // verifyProof with verification_key.json? Is there a difference?
    let pvk = prepare_verifying_key(&ZKEY.0.vk);

    // TODO Update this, should be:
    // XXX This is returned from the proof! Why is it called yShare here?
    // Isn't this publicOutput?
    // publicSignals 0..5 in specific order:
    // yShare
    // merkleRoot
    // internalNullifier
    // signalHash
    // epoch
    // rlnIdentifier
    let public_inputs = vec![
        root.into(),
        nullifier_hash.into(),
        signal_hash.into(),
        external_nullifier_hash.into(),
    ];
    let ark_proof = (*proof).into();
    let result = ark_groth16::verify_proof(&pvk, &ark_proof, &public_inputs[..])?;
    Ok(result)
}
