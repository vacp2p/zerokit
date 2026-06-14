use std::collections::HashSet;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bon::bon;

use crate::{
    circuit::{
        error::WitnessCalcError,
        iden3calc::{calc_witness, calc_witness_partial},
        CalcWitness, CalcWitnessPartial, Fr, FrOrSecret, Graph, IdSecret,
    },
    error::{
        GenerateProofError, RLNPartialWitnessInputError, RLNWitnessInputMultiError,
        RLNWitnessInputSingleError,
    },
};

#[derive(Debug, PartialEq, Clone)]
pub enum RLNWitnessInput {
    Single(RLNWitnessInputSingle),
    Multi(RLNWitnessInputMulti),
}

impl RLNWitnessInput {
    pub fn identity_secret(&self) -> &IdSecret {
        match self {
            Self::Single(w) => &w.identity_secret,
            Self::Multi(w) => &w.identity_secret,
        }
    }

    pub fn user_message_limit(&self) -> Fr {
        match self {
            Self::Single(w) => w.user_message_limit,
            Self::Multi(w) => w.user_message_limit,
        }
    }

    pub fn path_elements(&self) -> &[Fr] {
        match self {
            Self::Single(w) => &w.path_elements,
            Self::Multi(w) => &w.path_elements,
        }
    }

    pub fn identity_path_index(&self) -> &[u8] {
        match self {
            Self::Single(w) => &w.identity_path_index,
            Self::Multi(w) => &w.identity_path_index,
        }
    }

    pub fn x(&self) -> Fr {
        match self {
            Self::Single(w) => w.x,
            Self::Multi(w) => w.x,
        }
    }

    pub fn external_nullifier(&self) -> Fr {
        match self {
            Self::Single(w) => w.external_nullifier,
            Self::Multi(w) => w.external_nullifier,
        }
    }

    pub fn message_id(&self) -> Option<Fr> {
        match self {
            Self::Single(w) => Some(w.message_id),
            Self::Multi(_) => None,
        }
    }

    pub fn message_ids(&self) -> Option<&[Fr]> {
        match self {
            Self::Multi(w) => Some(&w.message_ids),
            Self::Single(_) => None,
        }
    }

    pub fn selector_used(&self) -> Option<&[bool]> {
        match self {
            Self::Multi(w) => Some(&w.selector_used),
            Self::Single(_) => None,
        }
    }
}

// TODO(PR11): add a `merkle_proof` setter accepting `impl ZerokitMerkleProof` as an
// alternative to the `path_elements` + `identity_path_index` pair (keep both ways).
// TODO(PR11): consider moving `validate_against_graph` from `generate_proof` into the
// witness builder, validating against the graph at `build()` time.
#[bon]
impl RLNWitnessInput {
    #[builder(finish_fn = build)]
    pub fn new_single(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: Fr,
        external_nullifier: Fr,
        message_id: Fr,
    ) -> Result<Self, RLNWitnessInputSingleError> {
        if user_message_limit == Fr::from(0) {
            return Err(RLNWitnessInputSingleError::ZeroUserMessageLimit);
        }
        let path_len = path_elements.len();
        let index_len = identity_path_index.len();
        if path_len != index_len {
            return Err(RLNWitnessInputSingleError::PathLengthMismatch(
                path_len, index_len,
            ));
        }
        if message_id >= user_message_limit {
            return Err(RLNWitnessInputSingleError::InvalidMessageId(
                message_id,
                user_message_limit,
            ));
        }

        Ok(Self::Single(RLNWitnessInputSingle {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_id,
        }))
    }

    #[builder(finish_fn = build)]
    #[allow(clippy::too_many_arguments)]
    pub fn new_multi(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: Fr,
        external_nullifier: Fr,
        message_ids: Vec<Fr>,
        selector_used: Vec<bool>,
    ) -> Result<Self, RLNWitnessInputMultiError> {
        if user_message_limit == Fr::from(0) {
            return Err(RLNWitnessInputMultiError::ZeroUserMessageLimit);
        }
        let path_len = path_elements.len();
        let index_len = identity_path_index.len();
        if path_len != index_len {
            return Err(RLNWitnessInputMultiError::PathLengthMismatch(
                path_len, index_len,
            ));
        }
        if message_ids.is_empty() {
            return Err(RLNWitnessInputMultiError::EmptyMessageIds);
        }
        if selector_used.len() != message_ids.len() {
            return Err(RLNWitnessInputMultiError::SelectorLengthMismatch(
                message_ids.len(),
                selector_used.len(),
            ));
        }
        if !selector_used.iter().any(|&s| s) {
            return Err(RLNWitnessInputMultiError::NoActiveSelectorUsed);
        }
        {
            let mut seen = HashSet::with_capacity(message_ids.len());
            for (id, &used) in message_ids.iter().zip(&selector_used) {
                if used && !seen.insert(*id) {
                    return Err(RLNWitnessInputMultiError::DuplicateMessageIds);
                }
            }
        }
        for (message_id, used) in message_ids.iter().zip(&selector_used) {
            if *used && *message_id >= user_message_limit {
                return Err(RLNWitnessInputMultiError::InvalidMessageId(
                    *message_id,
                    user_message_limit,
                ));
            }
        }
        Ok(Self::Multi(RLNWitnessInputMulti {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_ids,
            selector_used,
        }))
    }
}

impl RLNWitnessInput {
    pub(super) fn validate_against_graph(&self, graph: &Graph) -> Result<(), GenerateProofError> {
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

impl CalcWitness for RLNWitnessInput {
    fn calc_witness(&self, graph: &Graph) -> Result<Vec<Fr>, WitnessCalcError> {
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

impl CalcWitnessPartial for RLNPartialWitnessInput {
    fn calc_witness_partial(&self, graph: &Graph) -> Result<Vec<Option<Fr>>, WitnessCalcError> {
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

#[derive(Debug, PartialEq, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNWitnessInputSingle {
    pub(crate) identity_secret: IdSecret,
    pub(crate) user_message_limit: Fr,
    pub(crate) path_elements: Vec<Fr>,
    pub(crate) identity_path_index: Vec<u8>,
    pub(crate) x: Fr,
    pub(crate) external_nullifier: Fr,
    pub(crate) message_id: Fr,
}

#[derive(Debug, PartialEq, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNWitnessInputMulti {
    pub(crate) identity_secret: IdSecret,
    pub(crate) user_message_limit: Fr,
    pub(crate) path_elements: Vec<Fr>,
    pub(crate) identity_path_index: Vec<u8>,
    pub(crate) x: Fr,
    pub(crate) external_nullifier: Fr,
    pub(crate) message_ids: Vec<Fr>,
    pub(crate) selector_used: Vec<bool>,
}

#[derive(Debug, PartialEq, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct RLNPartialWitnessInput {
    pub(crate) identity_secret: IdSecret,
    pub(crate) user_message_limit: Fr,
    pub(crate) path_elements: Vec<Fr>,
    pub(crate) identity_path_index: Vec<u8>,
}

#[bon]
impl RLNPartialWitnessInput {
    #[allow(clippy::new_ret_no_self)]
    #[builder(start_fn = new, finish_fn = build)]
    pub fn create(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
    ) -> Result<Self, RLNPartialWitnessInputError> {
        if user_message_limit == Fr::from(0) {
            return Err(RLNPartialWitnessInputError::ZeroUserMessageLimit);
        }
        let path_len = path_elements.len();
        let index_len = identity_path_index.len();
        if path_len != index_len {
            return Err(RLNPartialWitnessInputError::PathLengthMismatch(
                path_len, index_len,
            ));
        }
        Ok(Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
        })
    }

    pub(super) fn validate_against_graph(&self, graph: &Graph) -> Result<(), GenerateProofError> {
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
