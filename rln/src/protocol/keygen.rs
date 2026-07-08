use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, Rng, SeedableRng};
use tiny_keccak::{Hasher as _, Keccak};
use zerokit_utils::hasher::ZerokitHasher;

use super::secret::{compute_id_commitment, compute_identity_secret};
use crate::circuit::{Fr, SecretFr};

/// An RLN identity: the identity secret and its commitment `H(identity_secret)`.
///
/// The secret is held as [`SecretFr`], so it is zeroized on drop.
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct IdentityKeys {
    pub(crate) identity_secret: SecretFr,
    pub(crate) id_commitment: Fr,
}

impl IdentityKeys {
    /// Generates a random RLN identity using the protocol hash `H` and the provided RNG `rng`.
    pub fn generate<H: ZerokitHasher<Scalar = Fr>, R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let identity_secret = SecretFr::rand(rng);
        let id_commitment = compute_id_commitment::<H>(&identity_secret);

        Self {
            identity_secret,
            id_commitment,
        }
    }

    /// Generates a deterministic RLN identity from a seed using the protocol hash `H` and the
    /// provided RNG `R`.
    pub fn generate_seeded<H: ZerokitHasher<Scalar = Fr>, R: Rng + CryptoRng + SeedableRng>(
        signal: &[u8],
    ) -> Self {
        let mut seed = R::Seed::default();
        let mut hasher = Keccak::v256();
        hasher.update(signal);
        hasher.finalize(seed.as_mut());

        Self::generate::<H, R>(&mut R::from_seed(seed))
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
    /// Generates a random extended RLN identity using the protocol hash `H` and the provided
    /// RNG `rng`.
    pub fn generate<H: ZerokitHasher<Scalar = Fr>, R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let identity_trapdoor = SecretFr::rand(rng);
        let identity_nullifier = SecretFr::rand(rng);
        let identity_secret = compute_identity_secret::<H>(&identity_trapdoor, &identity_nullifier);
        let id_commitment = compute_id_commitment::<H>(&identity_secret);

        Self {
            identity_trapdoor,
            identity_nullifier,
            identity_secret,
            id_commitment,
        }
    }

    /// Generates a deterministic extended RLN identity from a seed using the protocol hash `H`
    /// and the provided RNG `R`.
    pub fn generate_seeded<H: ZerokitHasher<Scalar = Fr>, R: Rng + CryptoRng + SeedableRng>(
        signal: &[u8],
    ) -> Self {
        let mut seed = R::Seed::default();
        let mut hasher = Keccak::v256();
        hasher.update(signal);
        hasher.finalize(seed.as_mut());

        Self::generate::<H, R>(&mut R::from_seed(seed))
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
