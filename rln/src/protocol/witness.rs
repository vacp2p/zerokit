use std::collections::HashSet;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bon::bon;
use zerokit_utils::{hasher::ZerokitHasher, merkle_tree::ZerokitMerkleProof};

use crate::{
    circuit::{
        error::WitnessCalcError,
        iden3calc::{calc_witness, calc_witness_partial},
        Fr, FrOrSecret, Graph, SecretFr,
    },
    error::{
        GenerateProofError, PartialWitnessInputError, WitnessInputMultiError,
        WitnessInputSingleError,
    },
};

/// A data type representing a Merkle proof, used by the [`RLNWitnessInput`] builder functions.
///
/// It is intended for stateless contexts (e.g. WASM) and the FFI boundary. In a stateful context
/// (a tree managed by the `RLN` struct), the [`ZerokitMerkleProof`] proof types
/// (`FullMerkleProof`, `OptimalMerkleProof`, `PmTreeProof`) are typically used directly, as they
/// convert into it via the [`From`] impl below.
#[derive(Debug, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNMerkleProof {
    pub(crate) path_elements: Vec<Fr>,
    pub(crate) identity_path_index: Vec<u8>,
}

impl RLNMerkleProof {
    /// Creates a new Merkle proof from the given path elements and path index.
    pub fn new(path_elements: Vec<Fr>, identity_path_index: Vec<u8>) -> Self {
        Self {
            path_elements,
            identity_path_index,
        }
    }

    /// Returns the path elements.
    pub fn path_elements(&self) -> &[Fr] {
        &self.path_elements
    }

    /// Returns the path index.
    pub fn identity_path_index(&self) -> &[u8] {
        &self.identity_path_index
    }
}

/// Converts any tree proof into [`RLNMerkleProof`] by extracting its path data.
///
/// Covers every [`ZerokitMerkleProof`] implementor: `FullMerkleProof`, `OptimalMerkleProof`,
/// `PmTreeProof`, and any future backend's proof type.
impl<P> From<&P> for RLNMerkleProof
where
    P: ZerokitMerkleProof<Index = u8>,
    P::Hasher: ZerokitHasher<Scalar = Fr>,
{
    fn from(proof: &P) -> Self {
        Self {
            path_elements: proof.get_path_elements(),
            identity_path_index: proof.get_path_index(),
        }
    }
}

/// The witness inputs for an RLN proof, in either Single or Multi message-id mode.
#[derive(Debug, Clone, PartialEq)]
pub enum RLNWitnessInput {
    Single(RLNWitnessInputSingle),
    Multi(RLNWitnessInputMulti),
}

impl RLNWitnessInput {
    /// Returns a clone of the identity secret.
    pub fn identity_secret(&self) -> SecretFr {
        match self {
            Self::Single(w) => w.identity_secret.clone(),
            Self::Multi(w) => w.identity_secret.clone(),
        }
    }

    /// Returns the user message limit.
    pub fn user_message_limit(&self) -> Fr {
        match self {
            Self::Single(w) => w.user_message_limit,
            Self::Multi(w) => w.user_message_limit,
        }
    }

    /// Returns the Merkle path elements.
    pub fn path_elements(&self) -> &[Fr] {
        match self {
            Self::Single(w) => &w.path_elements,
            Self::Multi(w) => &w.path_elements,
        }
    }

    /// Returns the Merkle path index bits.
    pub fn identity_path_index(&self) -> &[u8] {
        match self {
            Self::Single(w) => &w.identity_path_index,
            Self::Multi(w) => &w.identity_path_index,
        }
    }

    /// Returns the Merkle proof as an `RLNMerkleProof`.
    pub fn merkle_proof(&self) -> RLNMerkleProof {
        RLNMerkleProof {
            path_elements: self.path_elements().to_vec(),
            identity_path_index: self.identity_path_index().to_vec(),
        }
    }

    /// Returns the signal `x`.
    pub fn x(&self) -> Fr {
        match self {
            Self::Single(w) => w.x,
            Self::Multi(w) => w.x,
        }
    }

    /// Returns the external nullifier.
    pub fn external_nullifier(&self) -> Fr {
        match self {
            Self::Single(w) => w.external_nullifier,
            Self::Multi(w) => w.external_nullifier,
        }
    }

    /// Returns the message id in Single message-id mode, or `None` in Multi mode.
    pub fn message_id(&self) -> Option<Fr> {
        match self {
            Self::Single(w) => Some(w.message_id),
            Self::Multi(_) => None,
        }
    }

    /// Returns the message ids in Multi message-id mode, or `None` in Single mode.
    pub fn message_ids(&self) -> Option<&[Fr]> {
        match self {
            Self::Multi(w) => Some(&w.message_ids),
            Self::Single(_) => None,
        }
    }

    /// Returns the per-slot selector flags in Multi message-id mode, or `None` in Single mode.
    pub fn selector_used(&self) -> Option<&[bool]> {
        match self {
            Self::Multi(w) => Some(&w.selector_used),
            Self::Single(_) => None,
        }
    }
}

#[bon]
impl RLNWitnessInput {
    /// Starts building a Single message-id witness; call `build` to check the structural
    /// invariants and construct it.
    #[builder(finish_fn = build)]
    pub fn new_single(
        identity_secret: SecretFr,
        user_message_limit: Fr,
        #[builder(into)] merkle_proof: RLNMerkleProof,
        x: Fr,
        external_nullifier: Fr,
        message_id: Fr,
    ) -> Result<Self, WitnessInputSingleError> {
        let RLNMerkleProof {
            path_elements,
            identity_path_index,
        } = merkle_proof;
        let inner = RLNWitnessInputSingle {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_id,
        };
        inner.validate()?;
        Ok(Self::Single(inner))
    }

    /// Starts building a Multi message-id witness; call `build` to check the structural
    /// invariants and construct it.
    #[builder(finish_fn = build)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_multi(
        identity_secret: SecretFr,
        user_message_limit: Fr,
        #[builder(into)] merkle_proof: RLNMerkleProof,
        x: Fr,
        external_nullifier: Fr,
        message_ids: Vec<Fr>,
        selector_used: Vec<bool>,
    ) -> Result<Self, WitnessInputMultiError> {
        let RLNMerkleProof {
            path_elements,
            identity_path_index,
        } = merkle_proof;
        let inner = RLNWitnessInputMulti {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_ids,
            selector_used,
        };
        inner.validate()?;
        Ok(Self::Multi(inner))
    }
}

impl RLNWitnessInput {
    /// Checks that the witness dimensions match the `graph` circuit: path lengths against the
    /// tree depth, and message-id slot counts against `max_out`.
    pub(crate) fn validate_against_graph(&self, graph: &Graph) -> Result<(), GenerateProofError> {
        let (path_len, index_len) = match self {
            Self::Single(w) => (w.path_elements.len(), w.identity_path_index.len()),
            Self::Multi(w) => (w.path_elements.len(), w.identity_path_index.len()),
        };
        if path_len != graph.tree_depth {
            return Err(GenerateProofError::PathElementsLengthMismatch(
                graph.tree_depth,
                path_len,
            ));
        }
        if index_len != graph.tree_depth {
            return Err(GenerateProofError::IdentityPathIndexLengthMismatch(
                graph.tree_depth,
                index_len,
            ));
        }
        if let Self::Single(_) = self {
            if graph.max_out != 1 {
                return Err(GenerateProofError::MessageIdsLengthMismatch(
                    graph.max_out,
                    1,
                ));
            }
        }
        if let Self::Multi(w) = self {
            if w.message_ids.len() != graph.max_out {
                return Err(GenerateProofError::MessageIdsLengthMismatch(
                    graph.max_out,
                    w.message_ids.len(),
                ));
            }
            if w.selector_used.len() != graph.max_out {
                return Err(GenerateProofError::SelectorUsedLengthMismatch(
                    graph.max_out,
                    w.selector_used.len(),
                ));
            }
        }
        Ok(())
    }
}

impl From<RLNWitnessInputSingle> for RLNWitnessInput {
    fn from(w: RLNWitnessInputSingle) -> Self {
        Self::Single(w)
    }
}

impl From<RLNWitnessInputMulti> for RLNWitnessInput {
    fn from(w: RLNWitnessInputMulti) -> Self {
        Self::Multi(w)
    }
}

impl RLNWitnessInput {
    /// Calculates the full circuit witness assignment directly from the input fields.
    pub(crate) fn calc_witness(&self, graph: &Graph) -> Result<Vec<Fr>, WitnessCalcError> {
        let inputs: Vec<(String, Vec<FrOrSecret>)> = match self {
            Self::Single(w) => vec![
                (
                    "identitySecret".to_string(),
                    vec![w.identity_secret.clone().into()],
                ),
                (
                    "userMessageLimit".to_string(),
                    vec![w.user_message_limit.into()],
                ),
                ("messageId".to_string(), vec![w.message_id.into()]),
                (
                    "pathElements".to_string(),
                    w.path_elements.iter().cloned().map(Into::into).collect(),
                ),
                (
                    "identityPathIndex".to_string(),
                    w.identity_path_index
                        .iter()
                        .map(|v| Fr::from(*v).into())
                        .collect(),
                ),
                ("x".to_string(), vec![w.x.into()]),
                (
                    "externalNullifier".to_string(),
                    vec![w.external_nullifier.into()],
                ),
            ],
            Self::Multi(w) => vec![
                (
                    "identitySecret".to_string(),
                    vec![w.identity_secret.clone().into()],
                ),
                (
                    "userMessageLimit".to_string(),
                    vec![w.user_message_limit.into()],
                ),
                (
                    "messageId".to_string(),
                    w.message_ids.iter().cloned().map(Into::into).collect(),
                ),
                (
                    "selectorUsed".to_string(),
                    w.selector_used
                        .iter()
                        .map(|&v| Fr::from(v).into())
                        .collect(),
                ),
                (
                    "pathElements".to_string(),
                    w.path_elements.iter().cloned().map(Into::into).collect(),
                ),
                (
                    "identityPathIndex".to_string(),
                    w.identity_path_index
                        .iter()
                        .map(|v| Fr::from(*v).into())
                        .collect(),
                ),
                ("x".to_string(), vec![w.x.into()]),
                (
                    "externalNullifier".to_string(),
                    vec![w.external_nullifier.into()],
                ),
            ],
        };
        calc_witness(inputs, graph)
    }
}

impl RLNPartialWitnessInput {
    /// Calculates the partial circuit witness assignment; unknown dynamic inputs become `None`.
    pub(crate) fn calc_witness_partial(
        &self,
        graph: &Graph,
    ) -> Result<Vec<Option<Fr>>, WitnessCalcError> {
        let identity_path_index_fr: Vec<Option<FrOrSecret>> = self
            .identity_path_index
            .iter()
            .map(|v| Some(Fr::from(*v).into()))
            .collect();

        let mut inputs: Vec<(String, Vec<Option<FrOrSecret>>)> = vec![
            (
                "identitySecret".to_string(),
                vec![Some(self.identity_secret.clone().into())],
            ),
            (
                "userMessageLimit".to_string(),
                vec![Some(self.user_message_limit.into())],
            ),
        ];

        if graph.max_out == 1 {
            inputs.push(("messageId".to_string(), vec![None]));
        } else {
            inputs.push(("messageId".to_string(), vec![None; graph.max_out]));
            inputs.push(("selectorUsed".to_string(), vec![None; graph.max_out]));
        }

        inputs.push((
            "pathElements".to_string(),
            self.path_elements
                .iter()
                .cloned()
                .map(Into::into)
                .map(Some)
                .collect(),
        ));
        inputs.push(("identityPathIndex".to_string(), identity_path_index_fr));
        inputs.push(("x".to_string(), vec![None]));
        inputs.push(("externalNullifier".to_string(), vec![None]));

        calc_witness_partial(inputs, graph)
    }
}

/// Witness inputs for Single message-id mode.
///
/// `CanonicalDeserialize` is hand-written (see `serialize.rs`) so deserialization runs the
/// crate-internal `RLNWitnessInputSingle::validate`.
#[derive(Debug, Clone, PartialEq, CanonicalSerialize)]
pub struct RLNWitnessInputSingle {
    pub(crate) identity_secret: SecretFr,
    pub(crate) user_message_limit: Fr,
    pub(crate) path_elements: Vec<Fr>,
    pub(crate) identity_path_index: Vec<u8>,
    pub(crate) x: Fr,
    pub(crate) external_nullifier: Fr,
    pub(crate) message_id: Fr,
}

impl RLNWitnessInputSingle {
    /// Checks the Single-mode invariants: non-zero limit, matching path lengths,
    /// in-range `message_id`.
    pub(crate) fn validate(&self) -> Result<(), WitnessInputSingleError> {
        if self.user_message_limit == Fr::from(0) {
            return Err(WitnessInputSingleError::ZeroUserMessageLimit);
        }
        if self.path_elements.len() != self.identity_path_index.len() {
            return Err(WitnessInputSingleError::PathLengthMismatch(
                self.path_elements.len(),
                self.identity_path_index.len(),
            ));
        }
        if self.message_id >= self.user_message_limit {
            return Err(WitnessInputSingleError::InvalidMessageId(
                self.message_id,
                self.user_message_limit,
            ));
        }
        Ok(())
    }
}

/// Witness inputs for Multi message-id mode.
///
/// `CanonicalDeserialize` is hand-written (see `serialize.rs`) so deserialization runs the
/// crate-internal `RLNWitnessInputMulti::validate`.
#[derive(Debug, Clone, PartialEq, CanonicalSerialize)]
pub struct RLNWitnessInputMulti {
    pub(crate) identity_secret: SecretFr,
    pub(crate) user_message_limit: Fr,
    pub(crate) path_elements: Vec<Fr>,
    pub(crate) identity_path_index: Vec<u8>,
    pub(crate) x: Fr,
    pub(crate) external_nullifier: Fr,
    pub(crate) message_ids: Vec<Fr>,
    pub(crate) selector_used: Vec<bool>,
}

impl RLNWitnessInputMulti {
    /// Checks the Multi-mode invariants: non-zero limit, matching lengths, and unique
    /// in-range active `message_id`s.
    pub(crate) fn validate(&self) -> Result<(), WitnessInputMultiError> {
        if self.user_message_limit == Fr::from(0) {
            return Err(WitnessInputMultiError::ZeroUserMessageLimit);
        }
        if self.path_elements.len() != self.identity_path_index.len() {
            return Err(WitnessInputMultiError::PathLengthMismatch(
                self.path_elements.len(),
                self.identity_path_index.len(),
            ));
        }
        if self.message_ids.is_empty() {
            return Err(WitnessInputMultiError::EmptyMessageIds);
        }
        if self.selector_used.len() != self.message_ids.len() {
            return Err(WitnessInputMultiError::SelectorLengthMismatch(
                self.message_ids.len(),
                self.selector_used.len(),
            ));
        }
        if !self.selector_used.iter().any(|&s| s) {
            return Err(WitnessInputMultiError::NoActiveSelectorUsed);
        }
        {
            let mut seen = HashSet::with_capacity(self.message_ids.len());
            for (id, &used) in self.message_ids.iter().zip(&self.selector_used) {
                if used && !seen.insert(*id) {
                    return Err(WitnessInputMultiError::DuplicateMessageIds);
                }
            }
        }
        for (message_id, used) in self.message_ids.iter().zip(&self.selector_used) {
            if *used && *message_id >= self.user_message_limit {
                return Err(WitnessInputMultiError::InvalidMessageId(
                    *message_id,
                    self.user_message_limit,
                ));
            }
        }
        Ok(())
    }
}

/// The partial witness inputs known before the message-specific values.
///
/// `CanonicalDeserialize` is hand-written (see `serialize.rs`) so deserialization runs the
/// crate-internal `RLNPartialWitnessInput::validate`.
#[derive(Debug, Clone, PartialEq, CanonicalSerialize)]
pub struct RLNPartialWitnessInput {
    pub(crate) identity_secret: SecretFr,
    pub(crate) user_message_limit: Fr,
    pub(crate) path_elements: Vec<Fr>,
    pub(crate) identity_path_index: Vec<u8>,
}

impl RLNPartialWitnessInput {
    /// Checks the partial witness invariants: non-zero limit, matching path lengths.
    pub(crate) fn validate(&self) -> Result<(), PartialWitnessInputError> {
        if self.user_message_limit == Fr::from(0) {
            return Err(PartialWitnessInputError::ZeroUserMessageLimit);
        }
        if self.path_elements.len() != self.identity_path_index.len() {
            return Err(PartialWitnessInputError::PathLengthMismatch(
                self.path_elements.len(),
                self.identity_path_index.len(),
            ));
        }
        Ok(())
    }
}

#[bon]
impl RLNPartialWitnessInput {
    /// Starts building a partial witness; call `build` to check the structural invariants and
    /// construct it.
    #[allow(clippy::new_ret_no_self)]
    #[builder(start_fn = new, finish_fn = build)]
    pub fn create(
        identity_secret: SecretFr,
        user_message_limit: Fr,
        #[builder(into)] merkle_proof: RLNMerkleProof,
    ) -> Result<Self, PartialWitnessInputError> {
        let RLNMerkleProof {
            path_elements,
            identity_path_index,
        } = merkle_proof;
        let partial = Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
        };
        partial.validate()?;
        Ok(partial)
    }

    /// Checks that the partial witness path lengths match the `graph` circuit tree depth.
    pub(crate) fn validate_against_graph(&self, graph: &Graph) -> Result<(), GenerateProofError> {
        if self.path_elements.len() != graph.tree_depth {
            return Err(GenerateProofError::PathElementsLengthMismatch(
                graph.tree_depth,
                self.path_elements.len(),
            ));
        }
        if self.identity_path_index.len() != graph.tree_depth {
            return Err(GenerateProofError::IdentityPathIndexLengthMismatch(
                graph.tree_depth,
                self.identity_path_index.len(),
            ));
        }
        Ok(())
    }
}

impl From<&RLNWitnessInput> for RLNPartialWitnessInput {
    fn from(witness: &RLNWitnessInput) -> Self {
        match witness {
            RLNWitnessInput::Single(w) => RLNPartialWitnessInput::from(w),
            RLNWitnessInput::Multi(w) => RLNPartialWitnessInput::from(w),
        }
    }
}

impl From<RLNWitnessInput> for RLNPartialWitnessInput {
    fn from(witness: RLNWitnessInput) -> Self {
        match witness {
            RLNWitnessInput::Single(w) => RLNPartialWitnessInput::from(w),
            RLNWitnessInput::Multi(w) => RLNPartialWitnessInput::from(w),
        }
    }
}

impl From<&RLNWitnessInputSingle> for RLNPartialWitnessInput {
    fn from(witness: &RLNWitnessInputSingle) -> Self {
        Self {
            identity_secret: witness.identity_secret.clone(),
            user_message_limit: witness.user_message_limit,
            path_elements: witness.path_elements.clone(),
            identity_path_index: witness.identity_path_index.clone(),
        }
    }
}

impl From<RLNWitnessInputSingle> for RLNPartialWitnessInput {
    fn from(witness: RLNWitnessInputSingle) -> Self {
        Self {
            identity_secret: witness.identity_secret,
            user_message_limit: witness.user_message_limit,
            path_elements: witness.path_elements,
            identity_path_index: witness.identity_path_index,
        }
    }
}

impl From<&RLNWitnessInputMulti> for RLNPartialWitnessInput {
    fn from(witness: &RLNWitnessInputMulti) -> Self {
        Self {
            identity_secret: witness.identity_secret.clone(),
            user_message_limit: witness.user_message_limit,
            path_elements: witness.path_elements.clone(),
            identity_path_index: witness.identity_path_index.clone(),
        }
    }
}

impl From<RLNWitnessInputMulti> for RLNPartialWitnessInput {
    fn from(witness: RLNWitnessInputMulti) -> Self {
        Self {
            identity_secret: witness.identity_secret,
            user_message_limit: witness.user_message_limit,
            path_elements: witness.path_elements,
            identity_path_index: witness.identity_path_index,
        }
    }
}

#[cfg(test)]
mod test {
    // Witness invariant validation. Crate-internal because the inner fields are
    // `pub(crate)`, so a malformed witness can only be built here.

    use ark_serialize::CanonicalDeserialize;
    use rand::thread_rng;

    use super::*;
    use crate::prelude::{CanonicalDeserializeBE, CanonicalSerializeBE};

    fn valid_single() -> RLNWitnessInputSingle {
        RLNWitnessInputSingle {
            identity_secret: SecretFr::rand(&mut thread_rng()),
            user_message_limit: Fr::from(5u64),
            path_elements: vec![Fr::from(1u64), Fr::from(2u64)],
            identity_path_index: vec![0u8, 1u8],
            x: Fr::from(7u64),
            external_nullifier: Fr::from(9u64),
            message_id: Fr::from(2u64),
        }
    }

    fn valid_multi() -> RLNWitnessInputMulti {
        RLNWitnessInputMulti {
            identity_secret: SecretFr::rand(&mut thread_rng()),
            user_message_limit: Fr::from(5u64),
            path_elements: vec![Fr::from(1u64), Fr::from(2u64)],
            identity_path_index: vec![0u8, 1u8],
            x: Fr::from(7u64),
            external_nullifier: Fr::from(9u64),
            message_ids: vec![Fr::from(1u64), Fr::from(2u64)],
            selector_used: vec![true, true],
        }
    }

    /// Deserialization rejects `witness` on the enum's compressed and big-endian paths, and on
    /// the inner struct's own compressed path (reachable without going through the enum).
    fn assert_deserialize_rejects(witness: &RLNWitnessInput) {
        let mut le = Vec::new();
        witness.serialize_compressed(&mut le).unwrap();
        assert!(
            RLNWitnessInput::deserialize_compressed(&le[..]).is_err(),
            "compressed deserialize must reject the invalid witness"
        );

        let mut be = Vec::new();
        CanonicalSerializeBE::serialize(witness, &mut be).unwrap();
        assert!(
            <RLNWitnessInput as CanonicalDeserializeBE>::deserialize(&be[..]).is_err(),
            "big-endian deserialize must reject the invalid witness"
        );

        let mut inner = Vec::new();
        match witness {
            RLNWitnessInput::Single(w) => {
                w.serialize_compressed(&mut inner).unwrap();
                assert!(
                    RLNWitnessInputSingle::deserialize_compressed(&inner[..]).is_err(),
                    "inner compressed deserialize must reject the invalid witness"
                );
            }
            RLNWitnessInput::Multi(w) => {
                w.serialize_compressed(&mut inner).unwrap();
                assert!(
                    RLNWitnessInputMulti::deserialize_compressed(&inner[..]).is_err(),
                    "inner compressed deserialize must reject the invalid witness"
                );
            }
        }
    }

    #[test]
    fn test_single_validate_rejects_each_invariant() {
        let mut zero = valid_single();
        zero.user_message_limit = Fr::from(0u64);
        assert!(matches!(
            zero.validate(),
            Err(WitnessInputSingleError::ZeroUserMessageLimit)
        ));

        let mut bad_id = valid_single();
        bad_id.message_id = bad_id.user_message_limit; // message_id == limit is out of range
        assert!(matches!(
            bad_id.validate(),
            Err(WitnessInputSingleError::InvalidMessageId(..))
        ));

        let mut bad_path = valid_single();
        bad_path.identity_path_index = vec![0u8];
        assert!(matches!(
            bad_path.validate(),
            Err(WitnessInputSingleError::PathLengthMismatch(..))
        ));

        assert!(valid_single().validate().is_ok());
    }

    #[test]
    fn test_multi_validate_rejects_each_invariant() {
        let mut zero = valid_multi();
        zero.user_message_limit = Fr::from(0u64);
        assert!(matches!(
            zero.validate(),
            Err(WitnessInputMultiError::ZeroUserMessageLimit)
        ));

        let mut selector_len = valid_multi();
        selector_len.selector_used = vec![true];
        assert!(matches!(
            selector_len.validate(),
            Err(WitnessInputMultiError::SelectorLengthMismatch(..))
        ));

        let mut no_active = valid_multi();
        no_active.selector_used = vec![false, false];
        assert!(matches!(
            no_active.validate(),
            Err(WitnessInputMultiError::NoActiveSelectorUsed)
        ));

        let mut dup = valid_multi();
        dup.message_ids = vec![Fr::from(1u64), Fr::from(1u64)];
        assert!(matches!(
            dup.validate(),
            Err(WitnessInputMultiError::DuplicateMessageIds)
        ));

        let mut bad_id = valid_multi();
        bad_id.message_ids = vec![Fr::from(1u64), Fr::from(100u64)];
        assert!(matches!(
            bad_id.validate(),
            Err(WitnessInputMultiError::InvalidMessageId(..))
        ));

        let mut empty = valid_multi();
        empty.message_ids = vec![];
        empty.selector_used = vec![];
        assert!(matches!(
            empty.validate(),
            Err(WitnessInputMultiError::EmptyMessageIds)
        ));

        assert!(valid_multi().validate().is_ok());
    }

    #[test]
    fn test_single_deserialize_rejects_out_of_range_message_id() {
        let mut w = valid_single();
        w.message_id = Fr::from(100u64); // >= limit (5)
        assert_deserialize_rejects(&RLNWitnessInput::Single(w));
    }

    #[test]
    fn test_multi_deserialize_rejects_duplicate_message_ids() {
        let mut w = valid_multi();
        w.message_ids = vec![Fr::from(1u64), Fr::from(1u64)];
        assert_deserialize_rejects(&RLNWitnessInput::Multi(w));
    }

    #[test]
    fn test_deserialize_rejects_zero_user_message_limit() {
        let mut single = valid_single();
        single.user_message_limit = Fr::from(0u64);
        assert_deserialize_rejects(&RLNWitnessInput::Single(single));

        let mut multi = valid_multi();
        multi.user_message_limit = Fr::from(0u64);
        assert_deserialize_rejects(&RLNWitnessInput::Multi(multi));
    }

    #[test]
    fn test_valid_witnesses_still_round_trip() {
        for witness in [
            RLNWitnessInput::Single(valid_single()),
            RLNWitnessInput::Multi(valid_multi()),
        ] {
            let mut le = Vec::new();
            witness.serialize_compressed(&mut le).unwrap();
            assert_eq!(
                RLNWitnessInput::deserialize_compressed(&le[..]).unwrap(),
                witness
            );

            let mut be = Vec::new();
            CanonicalSerializeBE::serialize(&witness, &mut be).unwrap();
            assert_eq!(
                <RLNWitnessInput as CanonicalDeserializeBE>::deserialize(&be[..]).unwrap(),
                witness
            );
        }
    }

    fn valid_partial() -> RLNPartialWitnessInput {
        RLNPartialWitnessInput {
            identity_secret: SecretFr::rand(&mut thread_rng()),
            user_message_limit: Fr::from(5u64),
            path_elements: vec![Fr::from(1u64), Fr::from(2u64)],
            identity_path_index: vec![0u8, 1u8],
        }
    }

    #[test]
    fn test_partial_validate_rejects_each_invariant() {
        let mut zero = valid_partial();
        zero.user_message_limit = Fr::from(0u64);
        assert!(matches!(
            zero.validate(),
            Err(PartialWitnessInputError::ZeroUserMessageLimit)
        ));

        let mut bad_path = valid_partial();
        bad_path.identity_path_index = vec![0u8];
        assert!(matches!(
            bad_path.validate(),
            Err(PartialWitnessInputError::PathLengthMismatch(..))
        ));

        assert!(valid_partial().validate().is_ok());
    }

    #[test]
    fn test_partial_deserialize_rejects_zero_limit_and_round_trips() {
        let mut bad = valid_partial();
        bad.user_message_limit = Fr::from(0u64);

        let mut le = Vec::new();
        bad.serialize_compressed(&mut le).unwrap();
        assert!(RLNPartialWitnessInput::deserialize_compressed(&le[..]).is_err());

        let mut be = Vec::new();
        CanonicalSerializeBE::serialize(&bad, &mut be).unwrap();
        assert!(<RLNPartialWitnessInput as CanonicalDeserializeBE>::deserialize(&be[..]).is_err());

        let good = valid_partial();
        let mut le_ok = Vec::new();
        good.serialize_compressed(&mut le_ok).unwrap();
        assert_eq!(
            RLNPartialWitnessInput::deserialize_compressed(&le_ok[..]).unwrap(),
            good
        );
        let mut be_ok = Vec::new();
        CanonicalSerializeBE::serialize(&good, &mut be_ok).unwrap();
        assert_eq!(
            <RLNPartialWitnessInput as CanonicalDeserializeBE>::deserialize(&be_ok[..]).unwrap(),
            good
        );
    }
}
