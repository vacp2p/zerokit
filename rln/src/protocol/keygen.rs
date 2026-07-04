use ark_std::rand::thread_rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tiny_keccak::{Hasher as _, Keccak};

use crate::{
    circuit::{Fr, SecretFr},
    hashers::{poseidon_hash_id_secret, poseidon_hash_secret_pair},
};

// TODO(rln-generic-hash): id_commitment (and the other keygen fns) hardcode `poseidon_hash`. To make
// RLN's hash swappable for another ZK hash, see the plan in `protocol/proof.rs` (circuit-gated).

/// Generates a random RLN identity using a cryptographically secure RNG.
///
/// Returns `(identity_secret, id_commitment)` where the commitment is `PoseidonHash(identity_secret)`.
pub fn keygen() -> (SecretFr, Fr) {
    let mut rng = thread_rng();
    let identity_secret = SecretFr::rand(&mut rng);
    let id_commitment = poseidon_hash_id_secret(&identity_secret);
    (identity_secret, id_commitment)
}

/// Generates an extended RLN identity compatible with Semaphore.
///
/// Returns `(identity_trapdoor, identity_nullifier, identity_secret, id_commitment)` where:
/// - `identity_secret = PoseidonHash(identity_trapdoor, identity_nullifier)`
/// - `id_commitment = PoseidonHash(identity_secret)`
pub fn extended_keygen() -> (SecretFr, SecretFr, SecretFr, Fr) {
    let mut rng = thread_rng();
    let identity_trapdoor = SecretFr::rand(&mut rng);
    let identity_nullifier = SecretFr::rand(&mut rng);
    let identity_secret = poseidon_hash_secret_pair(&identity_trapdoor, &identity_nullifier);
    let id_commitment = poseidon_hash_id_secret(&identity_secret);
    (
        identity_trapdoor,
        identity_nullifier,
        identity_secret,
        id_commitment,
    )
}

/// Generates a deterministic RLN identity from a seed.
///
/// Uses ChaCha20 RNG seeded with Keccak-256 hash of the input.
/// Returns `(identity_secret, id_commitment)`. Same input always produces the same identity.
pub fn seeded_keygen(signal: &[u8]) -> (SecretFr, Fr) {
    // ChaCha20 requires a seed of exactly 32 bytes.
    // We first hash the input seed signal to a 32 bytes array and pass this as seed to ChaCha20
    let mut seed = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut seed);

    let mut rng = ChaCha20Rng::from_seed(seed);
    let identity_secret = SecretFr::rand(&mut rng);
    let id_commitment = poseidon_hash_id_secret(&identity_secret);
    (identity_secret, id_commitment)
}

/// Generates a deterministic extended RLN identity from a seed, compatible with Semaphore.
///
/// Uses ChaCha20 RNG seeded with Keccak-256 hash of the input.
/// Returns `(identity_trapdoor, identity_nullifier, identity_secret, id_commitment)`.
/// Same input always produces the same identity.
pub fn extended_seeded_keygen(signal: &[u8]) -> (SecretFr, SecretFr, SecretFr, Fr) {
    // ChaCha20 requires a seed of exactly 32 bytes.
    // We first hash the input seed signal to a 32 bytes array and pass this as seed to ChaCha20
    let mut seed = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut seed);

    let mut rng = ChaCha20Rng::from_seed(seed);
    let identity_trapdoor = SecretFr::rand(&mut rng);
    let identity_nullifier = SecretFr::rand(&mut rng);
    let identity_secret = poseidon_hash_secret_pair(&identity_trapdoor, &identity_nullifier);
    let id_commitment = poseidon_hash_id_secret(&identity_secret);
    (
        identity_trapdoor,
        identity_nullifier,
        identity_secret,
        id_commitment,
    )
}
