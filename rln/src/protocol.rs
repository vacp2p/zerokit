// This crate collects all the underlying primitives used to implement RLN

#[cfg(not(feature = "stateless"))]
use {
    crate::error::ConversionError,
    crate::poseidon_tree::PoseidonTree,
    utils::{ZerokitMerkleProof, ZerokitMerkleTree},
};

use crate::circuit::{calculate_rln_witness, qap::CircomReduction, Curve};
use crate::error::{ComputeIdSecretError, ProofError, ProtocolError};
use crate::hashers::{hash_to_field_le, poseidon_hash};
use crate::public::RLN_IDENTIFIER;
use crate::utils::{
    bytes_be_to_fr, bytes_le_to_fr, bytes_le_to_vec_fr, bytes_le_to_vec_u8, fr_byte_size,
    fr_to_bytes_le, normalize_usize_le, to_bigint, vec_fr_to_bytes_le, vec_u8_to_bytes_le,
    FrOrSecret, IdSecret,
};
use ark_bn254::{Fr, FrConfig};
use ark_ff::{AdditiveGroup, Fp, MontBackend};
use ark_groth16::{prepare_verifying_key, Groth16, Proof as ArkProof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::thread_rng, UniformRand};
use num_bigint::BigInt;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::time::Instant;
use tiny_keccak::{Hasher as _, Keccak};
use zeroize::Zeroize;
///////////////////////////////////////////////////////
// RLN Witness data structure and utility functions
///////////////////////////////////////////////////////

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct RLNWitnessInput {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    identity_secret: IdSecret,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    user_message_limit: Fr,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    message_id: Fr,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    path_elements: Vec<Fr>,
    identity_path_index: Vec<u8>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    x: Fr,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    external_nullifier: Fr,
}

#[derive(Debug, PartialEq)]
pub struct RLNProofValues {
    // Public outputs:
    pub y: Fr,
    pub nullifier: Fr,
    pub root: Fr,
    // Public Inputs:
    pub x: Fr,
    pub external_nullifier: Fr,
}

pub fn serialize_field_element(element: Fr) -> Vec<u8> {
    fr_to_bytes_le(&element)
}

pub fn deserialize_field_element(serialized: Vec<u8>) -> Fr {
    let (element, _) = bytes_le_to_fr(&serialized);

    element
}

pub fn deserialize_identity_pair_le(serialized: Vec<u8>) -> (Fr, Fr) {
    let (identity_secret_hash, read) = bytes_le_to_fr(&serialized);
    let (id_commitment, _) = bytes_le_to_fr(&serialized[read..]);

    (identity_secret_hash, id_commitment)
}

pub fn deserialize_identity_pair_be(serialized: Vec<u8>) -> (Fr, Fr) {
    let (identity_secret_hash, read) = bytes_be_to_fr(&serialized);
    let (id_commitment, _) = bytes_be_to_fr(&serialized[read..]);

    (identity_secret_hash, id_commitment)
}

pub fn deserialize_identity_tuple_le(serialized: Vec<u8>) -> (Fr, Fr, Fr, Fr) {
    let mut all_read = 0;

    let (identity_trapdoor, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (identity_nullifier, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (identity_secret_hash, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (identity_commitment, _) = bytes_le_to_fr(&serialized[all_read..]);

    (
        identity_trapdoor,
        identity_nullifier,
        identity_secret_hash,
        identity_commitment,
    )
}

pub fn deserialize_identity_tuple_be(serialized: Vec<u8>) -> (Fr, Fr, Fr, Fr) {
    let mut all_read = 0;

    let (identity_trapdoor, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (identity_nullifier, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (identity_secret_hash, read) = bytes_be_to_fr(&serialized[all_read..]);
    all_read += read;

    let (identity_commitment, _) = bytes_be_to_fr(&serialized[all_read..]);

    (
        identity_trapdoor,
        identity_nullifier,
        identity_secret_hash,
        identity_commitment,
    )
}

/// Serializes witness
///
/// # Errors
///
/// Returns an error if `rln_witness.message_id` is not within `rln_witness.user_message_limit`.
/// input data is [ identity_secret<32> | user_message_limit<32> | message_id<32> | path_elements<32> | identity_path_index<8> | x<32> | external_nullifier<32> ]
pub fn serialize_witness(rln_witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    // Check if message_id is within user_message_limit
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    // Calculate capacity for Vec:
    // - 5 fixed field elements: identity_secret, user_message_limit, message_id, x, external_nullifier
    // - variable number of path elements
    // - identity_path_index (variable size)
    let mut serialized: Vec<u8> = Vec::with_capacity(
        fr_byte_size() * (5 + rln_witness.path_elements.len())
            + rln_witness.identity_path_index.len(),
    );
    serialized.extend_from_slice(&rln_witness.identity_secret.to_bytes_le());
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_witness.user_message_limit));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_witness.message_id));
    serialized.extend_from_slice(&vec_fr_to_bytes_le(&rln_witness.path_elements));
    serialized.extend_from_slice(&vec_u8_to_bytes_le(&rln_witness.identity_path_index));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_witness.x));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_witness.external_nullifier));

    Ok(serialized)
}

/// Deserializes witness
///
/// # Errors
///
/// Returns an error if `message_id` is not within `user_message_limit`.
pub fn deserialize_witness(serialized: &[u8]) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    let mut all_read: usize = 0;

    let (identity_secret, read) = IdSecret::from_bytes_le(&serialized[all_read..]);
    all_read += read;

    let (user_message_limit, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (message_id, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    message_id_range_check(&message_id, &user_message_limit)?;

    let (path_elements, read) = bytes_le_to_vec_fr(&serialized[all_read..])?;
    all_read += read;

    let (identity_path_index, read) = bytes_le_to_vec_u8(&serialized[all_read..])?;
    all_read += read;

    let (x, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (external_nullifier, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    if serialized.len() != all_read {
        return Err(ProtocolError::InvalidReadLen(serialized.len(), all_read));
    }

    Ok((
        RLNWitnessInput {
            identity_secret,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            user_message_limit,
            message_id,
        },
        all_read,
    ))
}

// This function deserializes input for kilic's rln generate_proof public API
// https://github.com/kilic/rln/blob/7ac74183f8b69b399e3bc96c1ae8ab61c026dc43/src/public.rs#L148
// input_data is [ identity_secret<32> | id_index<8> | user_message_limit<32> | message_id<32> | external_nullifier<32> | signal_len<8> | signal<var> ]
// return value is a rln witness populated according to this information
#[cfg(not(feature = "stateless"))]
pub fn proof_inputs_to_rln_witness(
    tree: &mut PoseidonTree,
    serialized: &[u8],
) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    let mut all_read: usize = 0;

    let (identity_secret, read) = IdSecret::from_bytes_le(&serialized[all_read..]);
    all_read += read;

    let id_index = usize::try_from(u64::from_le_bytes(
        serialized[all_read..all_read + 8]
            .try_into()
            .map_err(ConversionError::FromSlice)?,
    ))
    .map_err(ConversionError::ToUsize)?;
    all_read += 8;

    let (user_message_limit, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (message_id, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (external_nullifier, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let signal_len = usize::try_from(u64::from_le_bytes(
        serialized[all_read..all_read + 8]
            .try_into()
            .map_err(ConversionError::FromSlice)?,
    ))
    .map_err(ConversionError::ToUsize)?;
    all_read += 8;

    let signal: Vec<u8> = serialized[all_read..all_read + signal_len].to_vec();

    let merkle_proof = tree.proof(id_index).expect("proof should exist");
    let path_elements = merkle_proof.get_path_elements();
    let identity_path_index = merkle_proof.get_path_index();

    let x = hash_to_field_le(&signal);

    Ok((
        RLNWitnessInput {
            identity_secret,
            path_elements,
            identity_path_index,
            user_message_limit,
            message_id,
            x,
            external_nullifier,
        },
        all_read,
    ))
}

/// Creates [`RLNWitnessInput`] from it's fields.
///
/// # Errors
///
/// Returns an error if `message_id` is not within `user_message_limit`.
pub fn rln_witness_from_values(
    identity_secret: IdSecret,
    path_elements: Vec<Fp<MontBackend<FrConfig, 4>, 4>>,
    identity_path_index: Vec<u8>,
    x: Fr,
    external_nullifier: Fr,
    user_message_limit: Fr,
    message_id: Fr,
) -> Result<RLNWitnessInput, ProtocolError> {
    message_id_range_check(&message_id, &user_message_limit)?;

    Ok(RLNWitnessInput {
        identity_secret,
        path_elements,
        identity_path_index,
        x,
        external_nullifier,
        user_message_limit,
        message_id,
    })
}

pub fn random_rln_witness(tree_height: usize) -> RLNWitnessInput {
    let mut rng = thread_rng();

    let identity_secret = IdSecret::rand(&mut rng);
    let x = hash_to_field_le(&rng.gen::<[u8; 32]>());
    let epoch = hash_to_field_le(&rng.gen::<[u8; 32]>());
    let rln_identifier = hash_to_field_le(RLN_IDENTIFIER); //hash_to_field(&rng.gen::<[u8; 32]>());

    let mut path_elements: Vec<Fr> = Vec::new();
    let mut identity_path_index: Vec<u8> = Vec::new();

    for _ in 0..tree_height {
        path_elements.push(hash_to_field_le(&rng.gen::<[u8; 32]>()));
        identity_path_index.push(rng.gen_range(0..2) as u8);
    }

    let user_message_limit = Fr::from(100);
    let message_id = Fr::from(1);

    RLNWitnessInput {
        identity_secret,
        path_elements,
        identity_path_index,
        x,
        external_nullifier: poseidon_hash(&[epoch, rln_identifier]),
        user_message_limit,
        message_id,
    }
}

pub fn proof_values_from_witness(
    rln_witness: &RLNWitnessInput,
) -> Result<RLNProofValues, ProtocolError> {
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    // y share
    let a_0 = &rln_witness.identity_secret;
    let mut to_hash = [
        *(a_0.clone()),
        rln_witness.external_nullifier,
        rln_witness.message_id,
    ];
    let a_1 = poseidon_hash(&to_hash);
    let y = *(a_0.clone()) + rln_witness.x * a_1;

    // Nullifier
    let nullifier = poseidon_hash(&[a_1]);
    to_hash[0].zeroize();

    // Merkle tree root computations
    let root = compute_tree_root(
        &rln_witness.identity_secret,
        &rln_witness.user_message_limit,
        &rln_witness.path_elements,
        &rln_witness.identity_path_index,
    );

    Ok(RLNProofValues {
        y,
        nullifier,
        root,
        x: rln_witness.x,
        external_nullifier: rln_witness.external_nullifier,
    })
}

/// input_data is [ root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
pub fn serialize_proof_values(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    // Calculate capacity for Vec:
    // 5 field elements: root, external_nullifier, x, y, nullifier
    let mut serialized = Vec::with_capacity(fr_byte_size() * 5);

    serialized.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.root));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.external_nullifier));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.x));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.y));
    serialized.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.nullifier));

    serialized
}

// Note: don't forget to skip the 128 bytes ZK proof, if serialized contains it.
// This proc deserialzies only proof _values_, i.e. circuit outputs, not the zk proof.
pub fn deserialize_proof_values(serialized: &[u8]) -> (RLNProofValues, usize) {
    let mut all_read: usize = 0;

    let (root, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (external_nullifier, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (x, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (y, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    let (nullifier, read) = bytes_le_to_fr(&serialized[all_read..]);
    all_read += read;

    (
        RLNProofValues {
            y,
            nullifier,
            root,
            x,
            external_nullifier,
        },
        all_read,
    )
}

// input_data is [ identity_secret<32> | id_index<8> | user_message_limit<32> | message_id<32> | external_nullifier<32> | signal_len<8> | signal<var> ]
pub fn prepare_prove_input(
    identity_secret: IdSecret,
    id_index: usize,
    user_message_limit: Fr,
    message_id: Fr,
    external_nullifier: Fr,
    signal: &[u8],
) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - 4 field elements: identity_secret, user_message_limit, message_id, external_nullifier
    // - 16 bytes for two normalized usize values (id_index<8> + signal_len<8>)
    // - variable length signal data
    let mut serialized = Vec::with_capacity(fr_byte_size() * 4 + 16 + signal.len()); // length of 4 fr elements + 16 bytes (id_index + len) + signal length

    serialized.extend_from_slice(&identity_secret.to_bytes_le());
    serialized.extend_from_slice(&normalize_usize_le(id_index));
    serialized.extend_from_slice(&fr_to_bytes_le(&user_message_limit));
    serialized.extend_from_slice(&fr_to_bytes_le(&message_id));
    serialized.extend_from_slice(&fr_to_bytes_le(&external_nullifier));
    serialized.extend_from_slice(&normalize_usize_le(signal.len()));
    serialized.extend_from_slice(signal);

    serialized
}

// input_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var> ]
pub fn prepare_verify_input(proof_data: Vec<u8>, signal: &[u8]) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - proof_data contains the proof and proof values (proof<128> + root<32> + external_nullifier<32> + x<32> + y<32> + nullifier<32>)
    // - 8 bytes for normalized signal length value (signal_len<8>)
    // - variable length signal data
    let mut serialized = Vec::with_capacity(proof_data.len() + 8 + signal.len());

    serialized.extend(proof_data);
    serialized.extend_from_slice(&normalize_usize_le(signal.len()));
    serialized.extend_from_slice(signal);

    serialized
}

///////////////////////////////////////////////////////
// Merkle tree utility functions
///////////////////////////////////////////////////////

pub fn compute_tree_root(
    identity_secret: &IdSecret,
    user_message_limit: &Fr,
    path_elements: &[Fr],
    identity_path_index: &[u8],
) -> Fr {
    let mut to_hash = [*identity_secret.clone()];
    let id_commitment = poseidon_hash(&to_hash);
    to_hash[0].zeroize();

    let mut root = poseidon_hash(&[id_commitment, *user_message_limit]);

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
// Protocol utility functions
///////////////////////////////////////////////////////

// Generates a tuple (identity_secret_hash, id_commitment) where
// identity_secret_hash is random and id_commitment = PoseidonHash(identity_secret_hash)
// RNG is instantiated using thread_rng()
pub fn keygen() -> (IdSecret, Fr) {
    let mut rng = thread_rng();
    let identity_secret_hash = IdSecret::rand(&mut rng);
    let mut to_hash = [*identity_secret_hash.clone()];
    let id_commitment = poseidon_hash(&to_hash);
    to_hash[0].zeroize();
    (identity_secret_hash, id_commitment)
}

// Generates a tuple (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) where
// identity_trapdoor and identity_nullifier are random,
// identity_secret_hash = PoseidonHash(identity_trapdoor, identity_nullifier),
// id_commitment = PoseidonHash(identity_secret_hash),
// RNG is instantiated using thread_rng()
// Generated credentials are compatible with Semaphore credentials
pub fn extended_keygen() -> (Fr, Fr, Fr, Fr) {
    let mut rng = thread_rng();
    let identity_trapdoor = Fr::rand(&mut rng);
    let identity_nullifier = Fr::rand(&mut rng);
    let identity_secret_hash = poseidon_hash(&[identity_trapdoor, identity_nullifier]);
    let id_commitment = poseidon_hash(&[identity_secret_hash]);
    (
        identity_trapdoor,
        identity_nullifier,
        identity_secret_hash,
        id_commitment,
    )
}

// Generates a tuple (identity_secret_hash, id_commitment) where
// identity_secret_hash is random and id_commitment = PoseidonHash(identity_secret_hash)
// RNG is instantiated using 20 rounds of ChaCha seeded with the hash of the input
pub fn seeded_keygen(signal: &[u8]) -> (Fr, Fr) {
    // ChaCha20 requires a seed of exactly 32 bytes.
    // We first hash the input seed signal to a 32 bytes array and pass this as seed to ChaCha20
    let mut seed = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut seed);

    let mut rng = ChaCha20Rng::from_seed(seed);
    let identity_secret_hash = Fr::rand(&mut rng);
    let id_commitment = poseidon_hash(&[identity_secret_hash]);
    (identity_secret_hash, id_commitment)
}

// Generates a tuple (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) where
// identity_trapdoor and identity_nullifier are random,
// identity_secret_hash = PoseidonHash(identity_trapdoor, identity_nullifier),
// id_commitment = PoseidonHash(identity_secret_hash),
// RNG is instantiated using 20 rounds of ChaCha seeded with the hash of the input
// Generated credentials are compatible with Semaphore credentials
pub fn extended_seeded_keygen(signal: &[u8]) -> (Fr, Fr, Fr, Fr) {
    // ChaCha20 requires a seed of exactly 32 bytes.
    // We first hash the input seed signal to a 32 bytes array and pass this as seed to ChaCha20
    let mut seed = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut seed);

    let mut rng = ChaCha20Rng::from_seed(seed);
    let identity_trapdoor = Fr::rand(&mut rng);
    let identity_nullifier = Fr::rand(&mut rng);
    let identity_secret_hash = poseidon_hash(&[identity_trapdoor, identity_nullifier]);
    let id_commitment = poseidon_hash(&[identity_secret_hash]);
    (
        identity_trapdoor,
        identity_nullifier,
        identity_secret_hash,
        id_commitment,
    )
}

pub fn compute_id_secret(
    share1: (Fr, Fr),
    share2: (Fr, Fr),
) -> Result<IdSecret, ComputeIdSecretError> {
    // Assuming a0 is the identity secret and a1 = poseidonHash([a0, external_nullifier]),
    // a (x,y) share satisfies the following relation
    // y = a_0 + x * a_1
    let (x1, y1) = share1;
    let (x2, y2) = share2;

    // If the two input shares were computed for the same external_nullifier and identity secret, we can recover the latter
    // y1 = a_0 + x1 * a_1
    // y2 = a_0 + x2 * a_1

    if (x1 - x2) != Fr::ZERO {
        let a_1 = (y1 - y2) / (x1 - x2);
        let mut a_0 = y1 - x1 * a_1;

        // If shares come from the same polynomial, a0 is correctly recovered and a1 = poseidonHash([a0, external_nullifier])
        let id_secret = IdSecret::from(&mut a_0);
        Ok(id_secret)
    } else {
        Err(ComputeIdSecretError::DivisionByZero)
    }
}

///////////////////////////////////////////////////////
// zkSNARK utility functions
///////////////////////////////////////////////////////

fn calculate_witness_element<E: ark_ec::pairing::Pairing>(
    witness: Vec<BigInt>,
) -> Result<Vec<E::ScalarField>, ProtocolError> {
    use ark_ff::PrimeField;
    let modulus = <E::ScalarField as PrimeField>::MODULUS;

    // convert it to field elements
    use num_traits::Signed;
    let mut witness_vec = vec![];
    for w in witness.into_iter() {
        let w = if w.sign() == num_bigint::Sign::Minus {
            // Need to negate the witness element if negative
            modulus.into()
                - w.abs()
                    .to_biguint()
                    .ok_or(ProtocolError::BigUintConversion(w))?
        } else {
            w.to_biguint().ok_or(ProtocolError::BigUintConversion(w))?
        };
        witness_vec.push(E::ScalarField::from(w))
    }

    Ok(witness_vec)
}

pub fn generate_proof_with_witness(
    witness: Vec<BigInt>,
    proving_key: &(ProvingKey<Curve>, ConstraintMatrices<Fr>),
) -> Result<ArkProof<Curve>, ProofError> {
    // If in debug mode, we measure and later print time take to compute witness
    #[cfg(test)]
    let now = Instant::now();

    let full_assignment = calculate_witness_element::<Curve>(witness)?;

    #[cfg(test)]
    println!("witness generation took: {:.2?}", now.elapsed());

    // Random Values
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    // If in debug mode, we measure and later print time take to compute proof
    #[cfg(test)]
    let now = Instant::now();

    let proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
        &proving_key.0,
        r,
        s,
        &proving_key.1,
        proving_key.1.num_instance_variables,
        proving_key.1.num_constraints,
        full_assignment.as_slice(),
    )?;

    #[cfg(test)]
    println!("proof generation took: {:.2?}", now.elapsed());

    Ok(proof)
}

/// Formats inputs for witness calculation
///
/// # Errors
///
/// Returns an error if `rln_witness.message_id` is not within `rln_witness.user_message_limit`.
pub fn inputs_for_witness_calculation(
    rln_witness: &RLNWitnessInput,
) -> Result<[(&str, Vec<FrOrSecret>); 7], ProtocolError> {
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    let mut identity_path_index = Vec::with_capacity(rln_witness.identity_path_index.len());
    rln_witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(Fr::from(*v)));

    Ok([
        (
            "identitySecret",
            vec![rln_witness.identity_secret.clone().into()],
        ),
        (
            "userMessageLimit",
            vec![rln_witness.user_message_limit.into()],
        ),
        ("messageId", vec![rln_witness.message_id.into()]),
        (
            "pathElements",
            rln_witness
                .path_elements
                .iter()
                .cloned()
                .map(Into::into)
                .collect(),
        ),
        (
            "identityPathIndex",
            identity_path_index.into_iter().map(Into::into).collect(),
        ),
        ("x", vec![rln_witness.x.into()]),
        (
            "externalNullifier",
            vec![rln_witness.external_nullifier.into()],
        ),
    ])
}

/// Generates a RLN proof
///
/// # Errors
///
/// Returns a [`ProofError`] if proving fails.
pub fn generate_proof(
    proving_key: &(ProvingKey<Curve>, ConstraintMatrices<Fr>),
    rln_witness: &RLNWitnessInput,
    graph_data: &[u8],
) -> Result<ArkProof<Curve>, ProofError> {
    let inputs = inputs_for_witness_calculation(rln_witness)?
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));

    // If in debug mode, we measure and later print time take to compute witness
    #[cfg(test)]
    let now = Instant::now();
    let full_assignment = calculate_rln_witness(inputs, graph_data);

    #[cfg(test)]
    println!("witness generation took: {:.2?}", now.elapsed());

    // Random Values
    let mut rng = thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);

    // If in debug mode, we measure and later print time take to compute proof
    #[cfg(test)]
    let now = Instant::now();
    let proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
        &proving_key.0,
        r,
        s,
        &proving_key.1,
        proving_key.1.num_instance_variables,
        proving_key.1.num_constraints,
        full_assignment.as_slice(),
    )?;

    #[cfg(test)]
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
        proof_values.external_nullifier,
    ];

    // Check that the proof is valid
    let pvk = prepare_verifying_key(verifying_key);
    //let pr: ArkProof<Curve> = (*proof).into();

    // If in debug mode, we measure and later print time take to verify proof
    #[cfg(test)]
    let now = Instant::now();

    let verified = Groth16::<_, CircomReduction>::verify_proof(&pvk, proof, &inputs)?;

    #[cfg(test)]
    println!("verify took: {:.2?}", now.elapsed());

    Ok(verified)
}

// auxiliary function for serialisation Fr to json using ark serilize
fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = vec![];
    a.serialize_compressed(&mut bytes)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

// auxiliary function for deserialisation Fr to json using ark serilize
fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_compressed_unchecked(s.as_slice());
    a.map_err(serde::de::Error::custom)
}

/// Converts a JSON value into [`RLNWitnessInput`] object.
///
/// # Errors
///
/// Returns an error if `rln_witness.message_id` is not within `rln_witness.user_message_limit`.
pub fn rln_witness_from_json(
    input_json: serde_json::Value,
) -> Result<RLNWitnessInput, ProtocolError> {
    let rln_witness: RLNWitnessInput = serde_json::from_value(input_json).unwrap();
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    Ok(rln_witness)
}

/// Converts a [`RLNWitnessInput`] object to the corresponding JSON serialization.
///
/// # Errors
///
/// Returns an error if `message_id` is not within `user_message_limit`.
pub fn rln_witness_to_json(
    rln_witness: &RLNWitnessInput,
) -> Result<serde_json::Value, ProtocolError> {
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    let rln_witness_json = serde_json::to_value(rln_witness)?;
    Ok(rln_witness_json)
}

/// Converts a [`RLNWitnessInput`] object to the corresponding JSON serialization.
/// Before serialisation the data should be translated into big int for further calculation in the witness calculator.
///
/// # Errors
///
/// Returns an error if `message_id` is not within `user_message_limit`.
pub fn rln_witness_to_bigint_json(
    rln_witness: &RLNWitnessInput,
) -> Result<serde_json::Value, ProtocolError> {
    message_id_range_check(&rln_witness.message_id, &rln_witness.user_message_limit)?;

    let mut path_elements = Vec::new();

    for v in rln_witness.path_elements.iter() {
        path_elements.push(to_bigint(v).to_str_radix(10));
    }

    let mut identity_path_index = Vec::new();
    rln_witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(BigInt::from(*v).to_str_radix(10)));

    let inputs = serde_json::json!({
        "identitySecret": to_bigint(&rln_witness.identity_secret).to_str_radix(10),
        "userMessageLimit": to_bigint(&rln_witness.user_message_limit).to_str_radix(10),
        "messageId": to_bigint(&rln_witness.message_id).to_str_radix(10),
        "pathElements": path_elements,
        "identityPathIndex": identity_path_index,
        "x": to_bigint(&rln_witness.x).to_str_radix(10),
        "externalNullifier":  to_bigint(&rln_witness.external_nullifier).to_str_radix(10),
    });

    Ok(inputs)
}

pub fn message_id_range_check(
    message_id: &Fr,
    user_message_limit: &Fr,
) -> Result<(), ProtocolError> {
    if message_id > user_message_limit {
        return Err(ProtocolError::InvalidMessageId(
            *message_id,
            *user_message_limit,
        ));
    }
    Ok(())
}
