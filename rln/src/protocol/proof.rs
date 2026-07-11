use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use zerokit_utils::{hasher::ZerokitHasher, merkle_tree::compute_tree_root};

use super::{
    secret::{compute_id_commitment, compute_share_slope},
    slashing::compute_id_secret,
    witness::{RLNWitnessInput, RLNWitnessInputMulti, RLNWitnessInputSingle},
    zk::RecoverSecret,
};
use crate::{
    circuit::{Fr, Proof, SecretFr},
    error::RecoverSecretError,
    hashers::Hasher,
};

/// The public values of an RLN proof, in either Single or Multi message-id mode.
#[derive(Debug, Clone, PartialEq)]
pub enum RLNProofValues {
    Single(RLNProofValuesSingle),
    Multi(RLNProofValuesMulti),
}

impl RLNProofValues {
    /// Returns the share `y` in Single message-id mode, or `None` in Multi mode.
    pub fn y(&self) -> Option<Fr> {
        match self {
            RLNProofValues::Single(v) => Some(v.y),
            RLNProofValues::Multi(_) => None,
        }
    }

    /// Returns the per-slot shares `ys` in Multi message-id mode, or `None` in Single mode.
    pub fn ys(&self) -> Option<&[Fr]> {
        match self {
            RLNProofValues::Multi(v) => Some(&v.ys),
            RLNProofValues::Single(_) => None,
        }
    }

    /// Returns the Merkle root the proof was generated against.
    pub fn root(&self) -> Fr {
        match self {
            RLNProofValues::Single(v) => v.root,
            RLNProofValues::Multi(v) => v.root,
        }
    }

    /// Returns the nullifier in Single message-id mode, or `None` in Multi mode.
    pub fn nullifier(&self) -> Option<Fr> {
        match self {
            RLNProofValues::Single(v) => Some(v.nullifier),
            RLNProofValues::Multi(_) => None,
        }
    }

    /// Returns the per-slot nullifiers in Multi message-id mode, or `None` in Single mode.
    pub fn nullifiers(&self) -> Option<&[Fr]> {
        match self {
            RLNProofValues::Multi(v) => Some(&v.nullifiers),
            RLNProofValues::Single(_) => None,
        }
    }

    /// Returns the signal `x` bound in the proof.
    pub fn x(&self) -> Fr {
        match self {
            RLNProofValues::Single(v) => v.x,
            RLNProofValues::Multi(v) => v.x,
        }
    }

    /// Returns the external nullifier bound in the proof.
    pub fn external_nullifier(&self) -> Fr {
        match self {
            RLNProofValues::Single(v) => v.external_nullifier,
            RLNProofValues::Multi(v) => v.external_nullifier,
        }
    }

    /// Returns the per-slot selector flags in Multi message-id mode, or `None` in Single mode.
    pub fn selector_used(&self) -> Option<&[bool]> {
        match self {
            RLNProofValues::Multi(v) => Some(&v.selector_used),
            RLNProofValues::Single(_) => None,
        }
    }
}

impl RLNProofValues {
    /// Computes the proof values from a `witness` using the protocol hash `H`.
    pub fn from_witness<H: ZerokitHasher<Scalar = Fr>>(witness: &RLNWitnessInput) -> Self {
        match witness {
            RLNWitnessInput::Single(w) => {
                RLNProofValues::Single(RLNProofValuesSingle::from_witness::<H>(w))
            }
            RLNWitnessInput::Multi(w) => {
                RLNProofValues::Multi(RLNProofValuesMulti::from_witness::<H>(w))
            }
        }
    }
}

impl RecoverSecret for RLNProofValues {
    type Error = RecoverSecretError;

    fn recover_secret(&self, other: &Self) -> Result<SecretFr, Self::Error> {
        match (self, other) {
            (RLNProofValues::Single(s), RLNProofValues::Single(o)) => s.recover_secret(o),
            (RLNProofValues::Multi(s), RLNProofValues::Multi(o)) => s.recover_secret(o),
            (RLNProofValues::Single(s), RLNProofValues::Multi(o))
            | (RLNProofValues::Multi(o), RLNProofValues::Single(s)) => s.recover_secret(o),
        }
    }
}

/// Public proof values for Single message-id mode.
#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNProofValuesSingle {
    /// The share `y = a_0 + x * a_1`.
    pub y: Fr,
    /// The Merkle root the proof was generated against.
    pub root: Fr,
    /// The nullifier `H(a_1)`.
    pub nullifier: Fr,
    /// The signal `x`.
    pub x: Fr,
    /// The external nullifier.
    pub external_nullifier: Fr,
}

impl RLNProofValuesSingle {
    /// Computes the proof values from a Single message-id `witness` using the protocol hash `H`.
    pub fn from_witness<H: ZerokitHasher<Scalar = Fr>>(w: &RLNWitnessInputSingle) -> Self {
        let id_commitment = compute_id_commitment::<H>(&w.identity_secret);
        let leaf = Hasher::<H>::hash_pair(id_commitment, w.user_message_limit);
        let root = compute_tree_root::<H>(leaf, &w.path_elements, &w.identity_path_index);

        let a_0 = &w.identity_secret;
        let a_1 = compute_share_slope::<H>(a_0, w.external_nullifier, w.message_id);
        let y = **a_0 + w.x * a_1;
        let nullifier = Hasher::<H>::hash_single(a_1);
        RLNProofValuesSingle {
            y,
            root,
            nullifier,
            x: w.x,
            external_nullifier: w.external_nullifier,
        }
    }
}

impl RecoverSecret for RLNProofValuesSingle {
    type Error = RecoverSecretError;

    fn recover_secret(&self, other: &Self) -> Result<SecretFr, Self::Error> {
        if self.external_nullifier != other.external_nullifier {
            return Err(RecoverSecretError::ExternalNullifierMismatch(
                self.external_nullifier,
                other.external_nullifier,
            ));
        }
        if self.nullifier != other.nullifier {
            return Err(RecoverSecretError::NoMatchingNullifier);
        }
        compute_id_secret((self.x, self.y), (other.x, other.y))
    }
}

impl RecoverSecret<RLNProofValuesMulti> for RLNProofValuesSingle {
    type Error = RecoverSecretError;

    fn recover_secret(&self, other: &RLNProofValuesMulti) -> Result<SecretFr, Self::Error> {
        other.recover_secret(self)
    }
}

/// Public proof values for Multi message-id mode.
#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNProofValuesMulti {
    /// The per-slot shares `ys`.
    pub ys: Vec<Fr>,
    /// The Merkle root the proof was generated against.
    pub root: Fr,
    /// The per-slot nullifiers.
    pub nullifiers: Vec<Fr>,
    /// The signal `x`.
    pub x: Fr,
    /// The external nullifier.
    pub external_nullifier: Fr,
    /// The per-slot selector flags.
    pub selector_used: Vec<bool>,
}

impl RLNProofValuesMulti {
    /// Computes the proof values from a Multi message-id `witness` using the protocol hash `H`.
    pub fn from_witness<H: ZerokitHasher<Scalar = Fr>>(w: &RLNWitnessInputMulti) -> Self {
        let id_commitment = compute_id_commitment::<H>(&w.identity_secret);
        let leaf = Hasher::<H>::hash_pair(id_commitment, w.user_message_limit);
        let root = compute_tree_root::<H>(leaf, &w.path_elements, &w.identity_path_index);

        let mut ys = Vec::with_capacity(w.message_ids.len());
        let mut nullifiers = Vec::with_capacity(w.message_ids.len());
        for (message_id, &selected) in w.message_ids.iter().zip(w.selector_used.iter()) {
            let a_1 =
                compute_share_slope::<H>(&w.identity_secret, w.external_nullifier, *message_id);
            let selector = Fr::from(selected);
            let y = (*w.identity_secret + w.x * a_1) * selector;
            let nullifier = Hasher::<H>::hash_single(a_1) * selector;
            ys.push(y);
            nullifiers.push(nullifier);
        }
        RLNProofValuesMulti {
            ys,
            root,
            nullifiers,
            x: w.x,
            external_nullifier: w.external_nullifier,
            selector_used: w.selector_used.clone(),
        }
    }
}

impl RecoverSecret for RLNProofValuesMulti {
    type Error = RecoverSecretError;

    fn recover_secret(&self, other: &Self) -> Result<SecretFr, Self::Error> {
        if self.external_nullifier != other.external_nullifier {
            return Err(RecoverSecretError::ExternalNullifierMismatch(
                self.external_nullifier,
                other.external_nullifier,
            ));
        }
        for (i, (nullifier_i, &used_i)) in self
            .nullifiers
            .iter()
            .zip(self.selector_used.iter())
            .enumerate()
        {
            if !used_i {
                continue;
            }
            for (j, (nullifier_j, &used_j)) in other
                .nullifiers
                .iter()
                .zip(other.selector_used.iter())
                .enumerate()
            {
                if !used_j {
                    continue;
                }
                if nullifier_i == nullifier_j {
                    return compute_id_secret((self.x, self.ys[i]), (other.x, other.ys[j]));
                }
            }
        }
        Err(RecoverSecretError::NoMatchingNullifier)
    }
}

impl RecoverSecret<RLNProofValuesSingle> for RLNProofValuesMulti {
    type Error = RecoverSecretError;

    fn recover_secret(&self, other: &RLNProofValuesSingle) -> Result<SecretFr, Self::Error> {
        if self.external_nullifier != other.external_nullifier {
            return Err(RecoverSecretError::ExternalNullifierMismatch(
                self.external_nullifier,
                other.external_nullifier,
            ));
        }
        for (i, (nullifier_i, &used_i)) in self
            .nullifiers
            .iter()
            .zip(self.selector_used.iter())
            .enumerate()
        {
            if !used_i {
                continue;
            }
            if nullifier_i == &other.nullifier {
                return compute_id_secret((self.x, self.ys[i]), (other.x, other.y));
            }
        }
        Err(RecoverSecretError::NoMatchingNullifier)
    }
}

/// An RLN proof bundled with its public proof values.
#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNProof {
    /// The zkSNARK proof.
    pub proof: Proof,
    /// The public proof values.
    pub values: RLNProofValues,
}

impl RLNProof {
    /// Creates a new [`RLNProof`] from a `proof` and its `values`.
    pub fn new(proof: Proof, values: RLNProofValues) -> Self {
        Self { proof, values }
    }
}
