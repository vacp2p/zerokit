use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::thread_rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tiny_keccak::{Hasher as _, Keccak};
use zerokit_utils::hasher::ZerokitHasher;

use crate::{
    circuit::{Fr, SecretFr},
    hashers::Hasher,
};

/// Derives a 32-byte ChaCha20 seed from an arbitrary-length signal using Keccak-256.
fn chacha_seed(signal: &[u8]) -> [u8; 32] {
    // ChaCha20 requires a seed of exactly 32 bytes.
    // We first hash the input seed signal to a 32 bytes array and pass this as seed to ChaCha20
    let mut seed = [0; 32];
    let mut hasher = Keccak::v256();
    hasher.update(signal);
    hasher.finalize(&mut seed);
    seed
}

/// An RLN identity: the identity secret and its commitment `H(identity_secret)`.
///
/// The secret is held as [`SecretFr`], so it is zeroized on drop.
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct IdentityKeys {
    pub(crate) identity_secret: SecretFr,
    pub(crate) id_commitment: Fr,
}

impl IdentityKeys {
    /// Generates a random RLN identity using a cryptographically secure RNG and the
    /// protocol hash `H`.
    pub fn generate<H: ZerokitHasher<Fr = Fr>>() -> Self {
        let mut rng = thread_rng();
        let identity_secret = SecretFr::rand(&mut rng);
        let id_commitment = Hasher::<H>::compute_id_commitment(&identity_secret);
        Self {
            identity_secret,
            id_commitment,
        }
    }

    /// Generates a deterministic RLN identity from a seed using the protocol hash `H`.
    ///
    /// Uses ChaCha20 RNG seeded with the Keccak-256 hash of the input.
    /// The same input always produces the same identity.
    pub fn generate_seeded<H: ZerokitHasher<Fr = Fr>>(seed: &[u8]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(chacha_seed(seed));
        let identity_secret = SecretFr::rand(&mut rng);
        let id_commitment = Hasher::<H>::compute_id_commitment(&identity_secret);
        Self {
            identity_secret,
            id_commitment,
        }
    }

    /// Returns the identity secret.
    pub fn identity_secret(&self) -> SecretFr {
        self.identity_secret.clone()
    }

    /// Returns the identity commitment `H(identity_secret)`.
    pub fn id_commitment(&self) -> Fr {
        self.id_commitment
    }
}

/// An extended RLN identity compatible with Semaphore.
///
/// Holds `(identity_trapdoor, identity_nullifier, identity_secret, id_commitment)` where:
/// - `identity_secret = H(identity_trapdoor, identity_nullifier)`
/// - `id_commitment = H(identity_secret)`
///
/// All three secrets are held as [`SecretFr`], so they are zeroized on drop.
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ExtendedIdentityKeys {
    pub(crate) identity_trapdoor: SecretFr,
    pub(crate) identity_nullifier: SecretFr,
    pub(crate) identity_secret: SecretFr,
    pub(crate) id_commitment: Fr,
}

impl ExtendedIdentityKeys {
    /// Generates a random extended RLN identity using a cryptographically secure RNG and the
    /// protocol hash `H`.
    pub fn generate<H: ZerokitHasher<Fr = Fr>>() -> Self {
        let mut rng = thread_rng();
        let identity_trapdoor = SecretFr::rand(&mut rng);
        let identity_nullifier = SecretFr::rand(&mut rng);
        Self::from_secrets::<H>(identity_trapdoor, identity_nullifier)
    }

    /// Generates a deterministic extended RLN identity from a seed using the protocol hash `H`.
    ///
    /// Uses ChaCha20 RNG seeded with the Keccak-256 hash of the input.
    /// The same input always produces the same identity.
    pub fn generate_seeded<H: ZerokitHasher<Fr = Fr>>(seed: &[u8]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(chacha_seed(seed));
        let identity_trapdoor = SecretFr::rand(&mut rng);
        let identity_nullifier = SecretFr::rand(&mut rng);
        Self::from_secrets::<H>(identity_trapdoor, identity_nullifier)
    }

    /// Builds the extended identity from its two source secrets using the protocol hash `H`.
    fn from_secrets<H: ZerokitHasher<Fr = Fr>>(
        identity_trapdoor: SecretFr,
        identity_nullifier: SecretFr,
    ) -> Self {
        let identity_secret =
            Hasher::<H>::compute_identity_secret(&identity_trapdoor, &identity_nullifier);
        let id_commitment = Hasher::<H>::compute_id_commitment(&identity_secret);
        Self {
            identity_trapdoor,
            identity_nullifier,
            identity_secret,
            id_commitment,
        }
    }

    /// Returns the identity trapdoor.
    pub fn identity_trapdoor(&self) -> SecretFr {
        self.identity_trapdoor.clone()
    }

    /// Returns the identity nullifier.
    pub fn identity_nullifier(&self) -> SecretFr {
        self.identity_nullifier.clone()
    }

    /// Returns the identity secret `H(identity_trapdoor, identity_nullifier)`.
    pub fn identity_secret(&self) -> SecretFr {
        self.identity_secret.clone()
    }

    /// Returns the identity commitment `H(identity_secret)`.
    pub fn id_commitment(&self) -> Fr {
        self.id_commitment
    }
}
