use ark_std::{rand::thread_rng, UniformRand};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tiny_keccak::{Hasher as _, Keccak};
use utils::error::ZerokitMerkleTreeError;

use crate::{circuit::Fr, hashers::poseidon_hash, utils::IdSecret};

/// Generates a random RLN identity using a cryptographically secure RNG.
///
/// Returns `(identity_secret, id_commitment)` where the commitment is `PoseidonHash(identity_secret)`.
pub fn keygen() -> Result<(IdSecret, Fr), ZerokitMerkleTreeError> {
    let mut rng = thread_rng();
    let identity_secret = IdSecret::rand(&mut rng);
    let id_commitment = poseidon_hash(&[*identity_secret.clone()])?;
    Ok((identity_secret, id_commitment))
}

/// Generates an extended RLN identity compatible with Semaphore.
///
/// Returns `(identity_trapdoor, identity_nullifier, identity_secret, id_commitment)` where:
/// - `identity_secret = PoseidonHash(identity_trapdoor, identity_nullifier)`
/// - `id_commitment = PoseidonHash(identity_secret)`
pub fn extended_keygen() -> Result<(Fr, Fr, Fr, Fr), ZerokitMerkleTreeError> {
    let mut rng = thread_rng();
    let identity_trapdoor = Fr::rand(&mut rng);
    let identity_nullifier = Fr::rand(&mut rng);
    let identity_secret = poseidon_hash(&[identity_trapdoor, identity_nullifier])
        .expect("Poseidon hash with pair input cannot fail");
    let id_commitment = poseidon_hash(&[identity_secret])?;
    Ok((
        identity_trapdoor,
        identity_nullifier,
        identity_secret,
        id_commitment,
    ))
}

/// Generates a deterministic RLN identity from a seed.
///
/// Uses ChaCha20 RNG seeded with Keccak-256 hash of the input.
/// Returns `(identity_secret, id_commitment)`. Same input always produces the same identity.
pub fn seeded_keygen(signal: &[u8]) -> Result<(Fr, Fr), ZerokitMerkleTreeError> {
    // ChaCha20 requires a seed of exactly 32 bytes.
    // We first hash the input seed signal to a 32 bytes array and pass this as seed to ChaCha20
    let mut seed = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut seed);

    let mut rng = ChaCha20Rng::from_seed(seed);
    let identity_secret = Fr::rand(&mut rng);
    let id_commitment = poseidon_hash(&[identity_secret])?;
    Ok((identity_secret, id_commitment))
}

/// Generates a deterministic extended RLN identity from a seed, compatible with Semaphore.
///
/// Uses ChaCha20 RNG seeded with Keccak-256 hash of the input.
/// Returns `(identity_trapdoor, identity_nullifier, identity_secret, id_commitment)`.
/// Same input always produces the same identity.
pub fn extended_seeded_keygen(signal: &[u8]) -> Result<(Fr, Fr, Fr, Fr), ZerokitMerkleTreeError> {
    // ChaCha20 requires a seed of exactly 32 bytes.
    // We first hash the input seed signal to a 32 bytes array and pass this as seed to ChaCha20
    let mut seed = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut seed);

    let mut rng = ChaCha20Rng::from_seed(seed);
    let identity_trapdoor = Fr::rand(&mut rng);
    let identity_nullifier = Fr::rand(&mut rng);
    let identity_secret = poseidon_hash(&[identity_trapdoor, identity_nullifier])
        .expect("Poseidon hash with pair input cannot fail");
    let id_commitment = poseidon_hash(&[identity_secret])?;
    Ok((
        identity_trapdoor,
        identity_nullifier,
        identity_secret,
        id_commitment,
    ))
}
