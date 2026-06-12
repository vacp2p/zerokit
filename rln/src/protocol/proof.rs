use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use zeroize::Zeroize;

use super::{
    slashing::compute_id_secret,
    witness::{RLNWitnessInput, RLNWitnessInputMulti, RLNWitnessInputSingle},
    zk::RecoverSecret,
};
use crate::{
    circuit::{Fr, IdSecret, Proof},
    error::RecoverSecretError,
    hashers::poseidon_hash,
};

/// Computes the Merkle tree root from identity credentials and Merkle membership proof.
fn compute_tree_root(
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

#[derive(Debug, PartialEq, Clone)]
pub enum RLNProofValues {
    Single(RLNProofValuesSingle),
    Multi(RLNProofValuesMulti),
}

impl RLNProofValues {
    pub fn y(&self) -> Option<Fr> {
        match self {
            RLNProofValues::Single(v) => Some(v.y),
            RLNProofValues::Multi(_) => None,
        }
    }

    pub fn ys(&self) -> Option<&[Fr]> {
        match self {
            RLNProofValues::Multi(v) => Some(&v.ys),
            RLNProofValues::Single(_) => None,
        }
    }

    pub fn root(&self) -> Fr {
        match self {
            RLNProofValues::Single(v) => v.root,
            RLNProofValues::Multi(v) => v.root,
        }
    }

    pub fn nullifier(&self) -> Option<Fr> {
        match self {
            RLNProofValues::Single(v) => Some(v.nullifier),
            RLNProofValues::Multi(_) => None,
        }
    }

    pub fn nullifiers(&self) -> Option<&[Fr]> {
        match self {
            RLNProofValues::Multi(v) => Some(&v.nullifiers),
            RLNProofValues::Single(_) => None,
        }
    }

    pub fn x(&self) -> Fr {
        match self {
            RLNProofValues::Single(v) => v.x,
            RLNProofValues::Multi(v) => v.x,
        }
    }

    pub fn external_nullifier(&self) -> Fr {
        match self {
            RLNProofValues::Single(v) => v.external_nullifier,
            RLNProofValues::Multi(v) => v.external_nullifier,
        }
    }

    pub fn selector_used(&self) -> Option<&[bool]> {
        match self {
            RLNProofValues::Multi(v) => Some(&v.selector_used),
            RLNProofValues::Single(_) => None,
        }
    }
}

impl From<&RLNWitnessInput> for RLNProofValues {
    fn from(witness: &RLNWitnessInput) -> Self {
        match witness {
            RLNWitnessInput::Single(w) => RLNProofValues::Single(w.into()),
            RLNWitnessInput::Multi(w) => RLNProofValues::Multi(w.into()),
        }
    }
}

impl RecoverSecret for RLNProofValues {
    type Error = RecoverSecretError;

    fn recover_secret(&self, other: &Self) -> Result<IdSecret, Self::Error> {
        match (self, other) {
            (RLNProofValues::Single(s), RLNProofValues::Single(o)) => s.recover_secret(o),
            (RLNProofValues::Multi(s), RLNProofValues::Multi(o)) => s.recover_secret(o),
            (RLNProofValues::Single(s), RLNProofValues::Multi(o))
            | (RLNProofValues::Multi(o), RLNProofValues::Single(s)) => s.recover_secret(o),
        }
    }
}

#[derive(Debug, PartialEq, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNProofValuesSingle {
    pub y: Fr,
    pub root: Fr,
    pub nullifier: Fr,
    pub x: Fr,
    pub external_nullifier: Fr,
}

impl From<&RLNWitnessInputSingle> for RLNProofValuesSingle {
    fn from(w: &RLNWitnessInputSingle) -> Self {
        let root = compute_tree_root(
            &w.identity_secret,
            &w.user_message_limit,
            &w.path_elements,
            &w.identity_path_index,
        );
        let a_0 = &w.identity_secret;
        let mut to_hash = [**a_0, w.external_nullifier, w.message_id];
        let a_1 = poseidon_hash(&to_hash);
        let y = *(a_0.clone()) + w.x * a_1;
        let nullifier = poseidon_hash(&[a_1]);
        to_hash[0].zeroize();
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

    fn recover_secret(&self, other: &Self) -> Result<IdSecret, Self::Error> {
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

    fn recover_secret(&self, other: &RLNProofValuesMulti) -> Result<IdSecret, Self::Error> {
        other.recover_secret(self)
    }
}

#[derive(Debug, PartialEq, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNProofValuesMulti {
    pub ys: Vec<Fr>,
    pub root: Fr,
    pub nullifiers: Vec<Fr>,
    pub x: Fr,
    pub external_nullifier: Fr,
    pub selector_used: Vec<bool>,
}

impl From<&RLNWitnessInputMulti> for RLNProofValuesMulti {
    fn from(w: &RLNWitnessInputMulti) -> Self {
        let root = compute_tree_root(
            &w.identity_secret,
            &w.user_message_limit,
            &w.path_elements,
            &w.identity_path_index,
        );
        let mut ys = Vec::with_capacity(w.message_ids.len());
        let mut nullifiers = Vec::with_capacity(w.message_ids.len());
        for (message_id, &selected) in w.message_ids.iter().zip(w.selector_used.iter()) {
            let mut to_hash = [*w.identity_secret, w.external_nullifier, *message_id];
            let a_1 = poseidon_hash(&to_hash);
            let selector = Fr::from(selected);
            let y = (*w.identity_secret + w.x * a_1) * selector;
            let nullifier = poseidon_hash(&[a_1]) * selector;
            to_hash[0].zeroize();
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

    fn recover_secret(&self, other: &Self) -> Result<IdSecret, Self::Error> {
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

    fn recover_secret(&self, other: &RLNProofValuesSingle) -> Result<IdSecret, Self::Error> {
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

#[derive(Debug, PartialEq, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNProof {
    pub proof: Proof,
    pub values: RLNProofValues,
}

impl RLNProof {
    pub fn new(proof: Proof, values: RLNProofValues) -> Self {
        Self { proof, values }
    }
}
