use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bon::bon;
use zerokit_utils::{hasher::ZerokitHasher, merkle_tree::compute_tree_root};

use super::{
    secret::{compute_id_commitment, compute_share_slope},
    slashing::compute_id_secret,
    witness::{RLNWitnessInput, RLNWitnessInputMulti, RLNWitnessInputSingle},
    zk::RecoverSecret,
};
use crate::{
    circuit::{Fr, Proof, SecretFr},
    error::{ProofValuesMultiError, RecoverSecretError},
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

#[bon]
impl RLNProofValues {
    /// Starts building Single message-id proof values; call `build` to construct them.
    #[builder(finish_fn = build)]
    pub fn new_single(y: Fr, root: Fr, nullifier: Fr, x: Fr, external_nullifier: Fr) -> Self {
        Self::Single(RLNProofValuesSingle {
            y,
            root,
            nullifier,
            x,
            external_nullifier,
        })
    }

    /// Starts building Multi message-id proof values; call `build` to check the structural
    /// invariants and construct them.
    #[builder(finish_fn = build)]
    pub fn new_multi(
        ys: Vec<Fr>,
        root: Fr,
        nullifiers: Vec<Fr>,
        x: Fr,
        external_nullifier: Fr,
        selector_used: Vec<bool>,
    ) -> Result<Self, ProofValuesMultiError> {
        let inner = RLNProofValuesMulti {
            ys,
            root,
            nullifiers,
            x,
            external_nullifier,
            selector_used,
        };
        inner.validate()?;
        Ok(Self::Multi(inner))
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
    pub(crate) y: Fr,
    /// The Merkle root the proof was generated against.
    pub(crate) root: Fr,
    /// The nullifier `H(a_1)`.
    pub(crate) nullifier: Fr,
    /// The signal `x`.
    pub(crate) x: Fr,
    /// The external nullifier.
    pub(crate) external_nullifier: Fr,
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
///
/// `CanonicalDeserialize` is hand-written (see `serialize.rs`) so deserialization runs the
/// crate-internal `RLNProofValuesMulti::validate`.
#[derive(Debug, Clone, PartialEq, CanonicalSerialize)]
pub struct RLNProofValuesMulti {
    /// The per-slot shares `ys`.
    pub(crate) ys: Vec<Fr>,
    /// The Merkle root the proof was generated against.
    pub(crate) root: Fr,
    /// The per-slot nullifiers.
    pub(crate) nullifiers: Vec<Fr>,
    /// The signal `x`.
    pub(crate) x: Fr,
    /// The external nullifier.
    pub(crate) external_nullifier: Fr,
    /// The per-slot selector flags.
    pub(crate) selector_used: Vec<bool>,
}

impl RLNProofValuesMulti {
    /// Computes the proof values from a Multi message-id `witness` using the protocol hash `H`.
    ///
    /// Assumes `w` is a validated witness; the output's validity only mirrors the input's
    /// (the builder and deserialize paths guarantee this; a `Validate::No` witness does not).
    pub fn from_witness<H: ZerokitHasher<Scalar = Fr>>(w: &RLNWitnessInputMulti) -> Self {
        let id_commitment = compute_id_commitment::<H>(&w.identity_secret);
        let leaf = Hasher::<H>::hash_pair(id_commitment, w.user_message_limit);
        let root = compute_tree_root::<H>(leaf, &w.path_elements, &w.identity_path_index);

        // `selector_used` is collected from the same zip as `ys` and `nullifiers` rather than
        // cloned, so the three stay equal in length even if the witness is malformed.
        let mut ys = Vec::with_capacity(w.message_ids.len());
        let mut nullifiers = Vec::with_capacity(w.message_ids.len());
        let mut selector_used = Vec::with_capacity(w.message_ids.len());
        for (message_id, &selected) in w.message_ids.iter().zip(w.selector_used.iter()) {
            let a_1 =
                compute_share_slope::<H>(&w.identity_secret, w.external_nullifier, *message_id);
            let selector = Fr::from(selected);
            let y = (*w.identity_secret + w.x * a_1) * selector;
            let nullifier = Hasher::<H>::hash_single(a_1) * selector;
            ys.push(y);
            nullifiers.push(nullifier);
            selector_used.push(selected);
        }
        RLNProofValuesMulti {
            ys,
            root,
            nullifiers,
            x: w.x,
            external_nullifier: w.external_nullifier,
            selector_used,
        }
    }

    /// Checks that `ys`, `nullifiers`, and `selector_used` are non-empty and all have the same
    /// length.
    pub(crate) fn validate(&self) -> Result<(), ProofValuesMultiError> {
        if self.ys.len() != self.nullifiers.len() || self.ys.len() != self.selector_used.len() {
            return Err(ProofValuesMultiError::LengthMismatch(
                self.ys.len(),
                self.nullifiers.len(),
                self.selector_used.len(),
            ));
        }
        if self.ys.is_empty() {
            return Err(ProofValuesMultiError::EmptyProofValues);
        }
        Ok(())
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
        self.validate()?;
        other.validate()?;
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
        self.validate()?;
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

#[cfg(test)]
mod test {
    // Multi proof-values invariant validation. Crate-internal because the inner fields are
    // `pub(crate)`, so proof values with mismatched lengths can only be built here.

    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use rand::thread_rng;

    use super::*;
    use crate::{
        hashers::PoseidonHash,
        prelude::{CanonicalDeserializeBE, CanonicalSerializeBE},
    };

    /// A multi with mismatched per-slot vector lengths (`ys` empty, others length 1).
    fn inconsistent_multi() -> RLNProofValues {
        RLNProofValues::Multi(RLNProofValuesMulti {
            root: Fr::from(10u64),
            x: Fr::from(20u64),
            external_nullifier: Fr::from(30u64),
            ys: vec![],
            nullifiers: vec![Fr::from(60u64)],
            selector_used: vec![true],
        })
    }

    /// `zip` stops at the shorter of `message_ids`/`selector_used`, so cloning `selector_used`
    /// wholesale would emit values that fail their own invariant.
    #[test]
    fn test_from_witness_stays_consistent_for_a_malformed_witness() {
        let w = RLNWitnessInputMulti {
            identity_secret: SecretFr::rand(&mut thread_rng()),
            user_message_limit: Fr::from(5u64),
            path_elements: vec![Fr::from(1u64)],
            identity_path_index: vec![0u8],
            x: Fr::from(7u64),
            external_nullifier: Fr::from(9u64),
            message_ids: vec![Fr::from(1u64), Fr::from(2u64)],
            selector_used: vec![true, true, true],
        };
        let values = RLNProofValuesMulti::from_witness::<PoseidonHash>(&w);
        assert!(
            values.validate().is_ok(),
            "from_witness must not emit values that fail validate: ys={} nullifiers={} selector_used={}",
            values.ys.len(),
            values.nullifiers.len(),
            values.selector_used.len()
        );
    }

    #[test]
    fn test_validate_rejects_mismatched_lengths() {
        let RLNProofValues::Multi(inner) = inconsistent_multi() else {
            panic!("expected multi proof values");
        };
        assert!(matches!(
            inner.validate(),
            Err(ProofValuesMultiError::LengthMismatch(..))
        ));
    }

    /// Consistent-but-empty vectors carry no message slot.
    #[test]
    fn test_validate_rejects_empty_slots() {
        let empty = RLNProofValuesMulti {
            root: Fr::from(1u64),
            x: Fr::from(2u64),
            external_nullifier: Fr::from(3u64),
            ys: vec![],
            nullifiers: vec![],
            selector_used: vec![],
        };
        assert!(matches!(
            empty.validate(),
            Err(ProofValuesMultiError::EmptyProofValues)
        ));

        let mut le = Vec::new();
        RLNProofValues::Multi(empty)
            .serialize_compressed(&mut le)
            .unwrap();
        assert!(
            RLNProofValues::deserialize_compressed(&le[..]).is_err(),
            "deserialize must reject empty multi proof values"
        );
    }

    #[test]
    fn test_deserialize_rejects_mismatched_lengths() {
        let values = inconsistent_multi();

        let mut le = Vec::new();
        values.serialize_compressed(&mut le).unwrap();
        assert!(
            RLNProofValues::deserialize_compressed(&le[..]).is_err(),
            "compressed deserialize must reject the mismatched lengths"
        );

        let mut be = Vec::new();
        CanonicalSerializeBE::serialize(&values, &mut be).unwrap();
        assert!(
            <RLNProofValues as CanonicalDeserializeBE>::deserialize(&be[..]).is_err(),
            "big-endian deserialize must reject the mismatched lengths"
        );

        let RLNProofValues::Multi(inner) = values else {
            unreachable!("inconsistent_multi builds a Multi variant");
        };
        let mut inner_le = Vec::new();
        inner.serialize_compressed(&mut inner_le).unwrap();
        assert!(
            RLNProofValuesMulti::deserialize_compressed(&inner_le[..]).is_err(),
            "inner compressed deserialize must reject the mismatched lengths"
        );
    }

    #[test]
    fn test_rln_proof_deserialize_rejects_mismatched_lengths() {
        let rln_proof = RLNProof {
            proof: Proof::default(),
            values: inconsistent_multi(),
        };
        let mut le = Vec::new();
        rln_proof.serialize_compressed(&mut le).unwrap();
        assert!(RLNProof::deserialize_compressed(&le[..]).is_err());
    }

    #[test]
    fn test_recover_secret_errors_instead_of_panicking() {
        // The nullifiers match, so without `validate` this would index `ys[0]` and
        // panic.
        let malformed = RLNProofValues::Multi(RLNProofValuesMulti {
            root: Fr::from(1u64),
            x: Fr::from(7u64),
            external_nullifier: Fr::from(9u64),
            ys: vec![],
            nullifiers: vec![Fr::from(42u64)],
            selector_used: vec![true],
        });
        let other = RLNProofValues::new_single()
            .y(Fr::from(3u64))
            .root(Fr::from(1u64))
            .nullifier(Fr::from(42u64))
            .x(Fr::from(5u64))
            .external_nullifier(Fr::from(9u64))
            .build();

        let err = malformed.recover_secret(&other).unwrap_err();
        assert!(
            matches!(
                err,
                RecoverSecretError::InvalidProofValues(ProofValuesMultiError::LengthMismatch(..))
            ),
            "expected LengthMismatch, got: {err:?}"
        );
    }
}
