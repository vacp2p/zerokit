// This crate collects all the underlying primitives used to implement RLN

#[cfg(not(feature = "stateless"))]
use {
    crate::error::ConversionError,
    crate::poseidon_tree::PoseidonTree,
    utils::{ZerokitMerkleProof, ZerokitMerkleTree},
};

use crate::circuit::COMPRESS_PROOF_SIZE;
use crate::circuit::{
    iden3calc::calc_witness, qap::CircomReduction, Curve, Fr, Proof, VerifyingKey, Zkey,
};
use crate::error::{ComputeIdSecretError, ProofError, ProtocolError};
use crate::hashers::poseidon_hash;
use crate::utils::{
    bytes_be_to_fr, bytes_le_to_fr, bytes_le_to_vec_fr, bytes_le_to_vec_u8, fr_byte_size,
    fr_to_bytes_be, fr_to_bytes_le, normalize_usize_le, to_bigint, vec_fr_to_bytes_le,
    vec_u8_to_bytes_le, FrOrSecret, IdSecret,
};
use ark_ff::AdditiveGroup;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::thread_rng, UniformRand};
use num_bigint::BigInt;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
#[cfg(test)]
use std::time::Instant;
use tiny_keccak::{Hasher as _, Keccak};
use zeroize::Zeroize;

pub struct RLN {
    pub zkey: Zkey,
    #[cfg(not(target_arch = "wasm32"))]
    pub graph_data: Vec<u8>,
    #[cfg(not(feature = "stateless"))]
    pub tree: PoseidonTree,
}

///////////////////////////////////////////////////////
// RLN Witness data structure and utility functions
///////////////////////////////////////////////////////

#[derive(Debug, PartialEq)]
pub struct RLNWitnessInput {
    identity_secret: IdSecret,
    user_message_limit: Fr,
    message_id: Fr,
    path_elements: Vec<Fr>,
    identity_path_index: Vec<u8>,
    x: Fr,
    external_nullifier: Fr,
}

impl RLNWitnessInput {
    pub fn new(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        message_id: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: Fr,
        external_nullifier: Fr,
    ) -> Result<Self, ProtocolError> {
        // Message ID range check
        if message_id > user_message_limit {
            return Err(ProtocolError::InvalidMessageId(
                message_id,
                user_message_limit,
            ));
        }

        // Merkle proof length check
        let path_elements_len = path_elements.len();
        let identity_path_index_len = identity_path_index.len();
        if path_elements_len != identity_path_index_len {
            return Err(ProtocolError::InvalidMerkleProofLength(
                path_elements_len,
                identity_path_index_len,
            ));
        }

        Ok(Self {
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        })
    }
}

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

#[derive(Debug, PartialEq, Clone)]
pub struct RLNProof {
    pub proof: Proof,
    pub proof_values: RLNProofValues,
}

pub fn serialize_field_element(element: Fr) -> Vec<u8> {
    fr_to_bytes_le(&element)
}

pub fn deserialize_field_element(serialized: Vec<u8>) -> Fr {
    let (element, _) = bytes_le_to_fr(&serialized);

    element
}

pub fn deserialize_identity_pair_le(serialized: Vec<u8>) -> (Fr, Fr) {
    let (identity_secret_hash, el_size) = bytes_le_to_fr(&serialized);
    let (id_commitment, _) = bytes_le_to_fr(&serialized[el_size..]);

    (identity_secret_hash, id_commitment)
}

pub fn deserialize_identity_pair_be(serialized: Vec<u8>) -> (Fr, Fr) {
    let (identity_secret_hash, el_size) = bytes_be_to_fr(&serialized);
    let (id_commitment, _) = bytes_be_to_fr(&serialized[el_size..]);

    (identity_secret_hash, id_commitment)
}

pub fn deserialize_identity_tuple_le(serialized: Vec<u8>) -> (Fr, Fr, Fr, Fr) {
    let mut read = 0;

    let (identity_trapdoor, el_size) = bytes_le_to_fr(&serialized[read..]);
    read += el_size;

    let (identity_nullifier, el_size) = bytes_le_to_fr(&serialized[read..]);
    read += el_size;

    let (identity_secret_hash, el_size) = bytes_le_to_fr(&serialized[read..]);
    read += el_size;

    let (identity_commitment, _) = bytes_le_to_fr(&serialized[read..]);

    (
        identity_trapdoor,
        identity_nullifier,
        identity_secret_hash,
        identity_commitment,
    )
}

pub fn deserialize_identity_tuple_be(serialized: Vec<u8>) -> (Fr, Fr, Fr, Fr) {
    let mut read = 0;

    let (identity_trapdoor, el_size) = bytes_be_to_fr(&serialized[read..]);
    read += el_size;

    let (identity_nullifier, el_size) = bytes_be_to_fr(&serialized[read..]);
    read += el_size;

    let (identity_secret_hash, el_size) = bytes_be_to_fr(&serialized[read..]);
    read += el_size;

    let (identity_commitment, _) = bytes_be_to_fr(&serialized[read..]);

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
/// Returns an error if `witness.message_id` is not within `witness.user_message_limit`.
/// input data is [ identity_secret<32> | user_message_limit<32> | message_id<32> | path_elements<32> | identity_path_index<8> | x<32> | external_nullifier<32> ]
pub fn serialize_witness(witness: &RLNWitnessInput) -> Result<Vec<u8>, ProtocolError> {
    // Calculate capacity for Vec:
    // - 5 fixed field elements: identity_secret, user_message_limit, message_id, x, external_nullifier
    // - variable number of path elements
    // - identity_path_index (variable size)
    let mut serialized: Vec<u8> = Vec::with_capacity(
        fr_byte_size() * (5 + witness.path_elements.len()) + witness.identity_path_index.len(),
    );
    serialized.extend_from_slice(&witness.identity_secret.to_bytes_le());
    serialized.extend_from_slice(&fr_to_bytes_le(&witness.user_message_limit));
    serialized.extend_from_slice(&fr_to_bytes_le(&witness.message_id));
    serialized.extend_from_slice(&vec_fr_to_bytes_le(&witness.path_elements));
    serialized.extend_from_slice(&vec_u8_to_bytes_le(&witness.identity_path_index));
    serialized.extend_from_slice(&fr_to_bytes_le(&witness.x));
    serialized.extend_from_slice(&fr_to_bytes_le(&witness.external_nullifier));

    Ok(serialized)
}

/// Deserializes witness
///
/// # Errors
///
/// Returns an error if `message_id` is not within `user_message_limit`.
pub fn deserialize_witness(serialized: &[u8]) -> Result<(RLNWitnessInput, usize), ProtocolError> {
    let mut read: usize = 0;

    let (identity_secret, el_size) = IdSecret::from_bytes_le(&serialized[read..]);
    read += el_size;

    let (user_message_limit, el_size) = bytes_le_to_fr(&serialized[read..]);
    read += el_size;

    let (message_id, el_size) = bytes_le_to_fr(&serialized[read..]);
    read += el_size;

    let (path_elements, el_size) = bytes_le_to_vec_fr(&serialized[read..])?;
    read += el_size;

    let (identity_path_index, el_size) = bytes_le_to_vec_u8(&serialized[read..])?;
    read += el_size;

    let (x, el_size) = bytes_le_to_fr(&serialized[read..]);
    read += el_size;

    let (external_nullifier, el_size) = bytes_le_to_fr(&serialized[read..]);
    read += el_size;

    if serialized.len() != read {
        return Err(ProtocolError::InvalidReadLen(serialized.len(), read));
    }

    Ok((
        RLNWitnessInput::new(
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        )?,
        read,
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
    use crate::hashers::hash_to_field_le;

    let mut read: usize = 0;

    let (identity_secret, el_size) = IdSecret::from_bytes_le(&serialized[read..]);
    read += el_size;

    let id_index = usize::try_from(u64::from_le_bytes(
        serialized[read..read + 8]
            .try_into()
            .map_err(ConversionError::FromSlice)?,
    ))
    .map_err(ConversionError::ToUsize)?;
    read += 8;

    let (user_message_limit, el_size) = bytes_le_to_fr(&serialized[read..]);
    read += el_size;

    let (message_id, el_size) = bytes_le_to_fr(&serialized[read..]);
    read += el_size;

    let (external_nullifier, el_size) = bytes_le_to_fr(&serialized[read..]);
    read += el_size;

    let signal_len = usize::try_from(u64::from_le_bytes(
        serialized[read..read + 8]
            .try_into()
            .map_err(ConversionError::FromSlice)?,
    ))
    .map_err(ConversionError::ToUsize)?;
    read += 8;

    let signal: Vec<u8> = serialized[read..read + signal_len].to_vec();

    let merkle_proof = tree.proof(id_index).expect("proof should exist");
    let path_elements = merkle_proof.get_path_elements();
    let identity_path_index = merkle_proof.get_path_index();

    let x = hash_to_field_le(&signal);

    Ok((
        RLNWitnessInput::new(
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        )?,
        read,
    ))
}

pub fn proof_values_from_witness(
    witness: &RLNWitnessInput,
) -> Result<RLNProofValues, ProtocolError> {
    // y share
    let a_0 = &witness.identity_secret;
    let mut to_hash = [
        *(a_0.clone()),
        witness.external_nullifier,
        witness.message_id,
    ];
    let a_1 = poseidon_hash(&to_hash);
    let y = *(a_0.clone()) + witness.x * a_1;

    // Nullifier
    let nullifier = poseidon_hash(&[a_1]);
    to_hash[0].zeroize();

    // Merkle tree root computations
    let root = compute_tree_root(
        &witness.identity_secret,
        &witness.user_message_limit,
        &witness.path_elements,
        &witness.identity_path_index,
    );

    Ok(RLNProofValues {
        y,
        nullifier,
        root,
        x: witness.x,
        external_nullifier: witness.external_nullifier,
    })
}

pub fn rln_proof_values_to_bytes_le(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    // Calculate capacity for Vec:
    // 5 field elements: root, external_nullifier, x, y, nullifier
    let mut bytes = Vec::with_capacity(fr_byte_size() * 5);

    bytes.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.root));
    bytes.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.external_nullifier));
    bytes.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.x));
    bytes.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.y));
    bytes.extend_from_slice(&fr_to_bytes_le(&rln_proof_values.nullifier));

    bytes
}

pub fn rln_proof_values_to_bytes_be(rln_proof_values: &RLNProofValues) -> Vec<u8> {
    // Calculate capacity for Vec:
    // 5 field elements: root, external_nullifier, x, y, nullifier
    let mut bytes = Vec::with_capacity(fr_byte_size() * 5);

    bytes.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.root));
    bytes.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.external_nullifier));
    bytes.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.x));
    bytes.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.y));
    bytes.extend_from_slice(&fr_to_bytes_be(&rln_proof_values.nullifier));

    bytes
}

// input_data is [ root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
pub fn bytes_le_to_rln_proof_values(bytes: &[u8]) -> (RLNProofValues, usize) {
    let mut read: usize = 0;

    let (root, el_size) = bytes_le_to_fr(&bytes[read..]);
    read += el_size;

    let (external_nullifier, el_size) = bytes_le_to_fr(&bytes[read..]);
    read += el_size;

    let (x, el_size) = bytes_le_to_fr(&bytes[read..]);
    read += el_size;

    let (y, el_size) = bytes_le_to_fr(&bytes[read..]);
    read += el_size;

    let (nullifier, el_size) = bytes_le_to_fr(&bytes[read..]);
    read += el_size;

    (
        RLNProofValues {
            y,
            nullifier,
            root,
            x,
            external_nullifier,
        },
        read,
    )
}

// input_data is [ root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
pub fn bytes_be_to_rln_proof_values(bytes: &[u8]) -> (RLNProofValues, usize) {
    let mut read: usize = 0;

    let (root, el_size) = bytes_be_to_fr(&bytes[read..]);
    read += el_size;

    let (external_nullifier, el_size) = bytes_be_to_fr(&bytes[read..]);
    read += el_size;

    let (x, el_size) = bytes_be_to_fr(&bytes[read..]);
    read += el_size;

    let (y, el_size) = bytes_be_to_fr(&bytes[read..]);
    read += el_size;

    let (nullifier, el_size) = bytes_be_to_fr(&bytes[read..]);
    read += el_size;

    (
        RLNProofValues {
            y,
            nullifier,
            root,
            x,
            external_nullifier,
        },
        read,
    )
}

pub fn rln_proof_to_bytes_le(rln_proof: &RLNProof) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - 128 bytes for compressed Groth16 proof
    // - 5 field elements for proof values (root, external_nullifier, x, y, nullifier)
    let mut bytes = Vec::with_capacity(COMPRESS_PROOF_SIZE + fr_byte_size() * 5);

    // Serialize proof (LE format from arkworks)
    rln_proof
        .proof
        .serialize_compressed(&mut bytes)
        .expect("serialization should not fail");

    // Serialize proof values
    let proof_values_bytes = rln_proof_values_to_bytes_le(&rln_proof.proof_values);
    bytes.extend_from_slice(&proof_values_bytes);

    bytes
}

pub fn rln_proof_to_bytes_be(rln_proof: &RLNProof) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - 128 bytes for compressed Groth16 proof
    // - 5 field elements for proof values (root, external_nullifier, x, y, nullifier)
    let mut bytes = Vec::with_capacity(COMPRESS_PROOF_SIZE + fr_byte_size() * 5);

    // Serialize proof (LE format from arkworks)
    rln_proof
        .proof
        .serialize_compressed(&mut bytes)
        .expect("serialization should not fail");

    // Serialize proof values
    let proof_values_bytes = rln_proof_values_to_bytes_be(&rln_proof.proof_values);
    bytes.extend_from_slice(&proof_values_bytes);

    bytes
}

// input_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
pub fn bytes_le_to_rln_proof(bytes: &[u8]) -> Result<(RLNProof, usize), ProtocolError> {
    let mut read: usize = 0;

    // Deserialize proof
    let proof = Proof::deserialize_compressed(&bytes[read..read + COMPRESS_PROOF_SIZE])
        .map_err(|_| ProtocolError::InvalidReadLen(bytes.len(), read + COMPRESS_PROOF_SIZE))?;
    read += COMPRESS_PROOF_SIZE;

    // Deserialize proof values
    let (values, el_size) = bytes_le_to_rln_proof_values(&bytes[read..]);
    read += el_size;

    Ok((
        RLNProof {
            proof,
            proof_values: values,
        },
        read,
    ))
}

// input_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
pub fn bytes_be_to_rln_proof(bytes: &[u8]) -> Result<(RLNProof, usize), ProtocolError> {
    let mut read: usize = 0;

    // Deserialize proof
    let proof = Proof::deserialize_compressed(&bytes[read..read + COMPRESS_PROOF_SIZE])
        .map_err(|_| ProtocolError::InvalidReadLen(bytes.len(), read + COMPRESS_PROOF_SIZE))?;
    read += COMPRESS_PROOF_SIZE;

    // Deserialize proof values
    let (values, el_size) = bytes_be_to_rln_proof_values(&bytes[read..]);
    read += el_size;

    Ok((
        RLNProof {
            proof,
            proof_values: values,
        },
        read,
    ))
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

fn calculated_witness_to_field_elements<E: ark_ec::pairing::Pairing>(
    calculated_witness: Vec<BigInt>,
) -> Result<Vec<E::ScalarField>, ProtocolError> {
    use ark_ff::PrimeField;
    let modulus = <E::ScalarField as PrimeField>::MODULUS;

    // convert it to field elements
    use num_traits::Signed;
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

pub fn generate_proof_with_witness(
    calculated_witness: Vec<BigInt>,
    zkey: &Zkey,
) -> Result<Proof, ProofError> {
    // If in debug mode, we measure and later print time take to compute witness
    #[cfg(test)]
    let now = Instant::now();

    let full_assignment = calculated_witness_to_field_elements::<Curve>(calculated_witness)?;

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
        &zkey.0,
        r,
        s,
        &zkey.1,
        zkey.1.num_instance_variables,
        zkey.1.num_constraints,
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
/// Returns an error if `witness.message_id` is not within `witness.user_message_limit`.
fn inputs_for_witness_calculation(
    witness: &RLNWitnessInput,
) -> Result<[(&str, Vec<FrOrSecret>); 7], ProtocolError> {
    let mut identity_path_index = Vec::with_capacity(witness.identity_path_index.len());
    witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(Fr::from(*v)));

    Ok([
        (
            "identitySecret",
            vec![witness.identity_secret.clone().into()],
        ),
        ("userMessageLimit", vec![witness.user_message_limit.into()]),
        ("messageId", vec![witness.message_id.into()]),
        (
            "pathElements",
            witness
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
        ("x", vec![witness.x.into()]),
        ("externalNullifier", vec![witness.external_nullifier.into()]),
    ])
}

/// Generates a RLN proof
///
/// # Errors
///
/// Returns a [`ProofError`] if proving fails.
pub fn generate_proof(
    zkey: &Zkey,
    witness: &RLNWitnessInput,
    graph_data: &[u8],
) -> Result<Proof, ProofError> {
    let inputs = inputs_for_witness_calculation(witness)?
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));

    // If in debug mode, we measure and later print time take to compute witness
    #[cfg(test)]
    let now = Instant::now();
    let full_assignment = calc_witness(inputs, graph_data);

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
        &zkey.0,
        r,
        s,
        &zkey.1,
        zkey.1.num_instance_variables,
        zkey.1.num_constraints,
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
    verifying_key: &VerifyingKey,
    proof: &Proof,
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

    // If in debug mode, we measure and later print time take to verify proof
    #[cfg(test)]
    let now = Instant::now();

    let verified = Groth16::<_, CircomReduction>::verify_proof(&pvk, proof, &inputs)?;

    #[cfg(test)]
    println!("verify took: {:.2?}", now.elapsed());

    Ok(verified)
}

/// Converts a [`RLNWitnessInput`] object to the corresponding JSON serialization.
/// Before serialisation the data should be translated into big int for further calculation in the witness calculator.
///
/// # Errors
///
/// Returns an error if `message_id` is not within `user_message_limit`.
pub fn rln_witness_to_bigint_json(
    witness: &RLNWitnessInput,
) -> Result<serde_json::Value, ProtocolError> {
    let mut path_elements = Vec::new();

    for v in witness.path_elements.iter() {
        path_elements.push(to_bigint(v).to_str_radix(10));
    }

    let mut identity_path_index = Vec::new();
    witness
        .identity_path_index
        .iter()
        .for_each(|v| identity_path_index.push(BigInt::from(*v).to_str_radix(10)));

    let inputs = serde_json::json!({
        "identitySecret": to_bigint(&witness.identity_secret).to_str_radix(10),
        "userMessageLimit": to_bigint(&witness.user_message_limit).to_str_radix(10),
        "messageId": to_bigint(&witness.message_id).to_str_radix(10),
        "pathElements": path_elements,
        "identityPathIndex": identity_path_index,
        "x": to_bigint(&witness.x).to_str_radix(10),
        "externalNullifier":  to_bigint(&witness.external_nullifier).to_str_radix(10),
    });

    Ok(inputs)
}
