#![allow(non_camel_case_types)]

use std::{fs::File, io::Read, str::FromStr};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use safer_ffi::{
    boxed::Box_,
    derive_ReprC, ffi_export,
    prelude::{char_p, repr_c},
};
use zerokit_utils::merkle_tree::{FullMerkleTree, OptimalMerkleTree, ZerokitMerkleTree};

use super::ffi_utils::{FFI_BoolResult, FFI_Fr, FFI_Result, FFI_SecretFr, FFI_UsizeResult};
use crate::prelude::*;

const MAX_CONFIG_SIZE: u64 = 1024 * 1024;
const NO_STATELESS_TREE_ERR: &str = "tree op unsupported on stateless RLN";

pub(crate) enum FFI_RLN_Inner {
    Stateless(RLN<Stateless, ArkGroth16Backend<PoseidonHash>>),
    StatefulFullMerkleTree(
        RLN<Stateful<FullMerkleTree<PoseidonHash>>, ArkGroth16Backend<PoseidonHash>>,
    ),
    StatefulOptimalMerkleTree(
        RLN<Stateful<OptimalMerkleTree<PoseidonHash>>, ArkGroth16Backend<PoseidonHash>>,
    ),
    StatefulPmTree(RLN<Stateful<PmTree<SledDB, PoseidonHash>>, ArkGroth16Backend<PoseidonHash>>),
}

impl FFI_RLN_Inner {
    fn generate_proof(&self, witness: &RLNWitnessInput) -> Result<(Proof, RLNProofValues), String> {
        match self {
            Self::Stateless(r) => r.generate_proof(witness).map_err(|err| err.to_string()),
            Self::StatefulFullMerkleTree(r) => {
                r.generate_proof(witness).map_err(|err| err.to_string())
            }
            Self::StatefulOptimalMerkleTree(r) => {
                r.generate_proof(witness).map_err(|err| err.to_string())
            }
            Self::StatefulPmTree(r) => r.generate_proof(witness).map_err(|err| err.to_string()),
        }
    }

    fn verify(&self, proof: &Proof, values: &RLNProofValues) -> Result<bool, String> {
        match self {
            Self::Stateless(r) => r.verify(proof, values).map_err(|err| err.to_string()),
            Self::StatefulFullMerkleTree(r) => {
                r.verify(proof, values).map_err(|err| err.to_string())
            }
            Self::StatefulOptimalMerkleTree(r) => {
                r.verify(proof, values).map_err(|err| err.to_string())
            }
            Self::StatefulPmTree(r) => r.verify(proof, values).map_err(|err| err.to_string()),
        }
    }

    fn verify_with_signal(
        &self,
        proof: &Proof,
        values: &RLNProofValues,
        x: &Fr,
    ) -> Result<bool, String> {
        match self {
            Self::Stateless(r) => r
                .verify_with_signal(proof, values, x)
                .map_err(|err| err.to_string()),
            Self::StatefulFullMerkleTree(r) => r
                .verify_with_signal(proof, values, x)
                .map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r
                .verify_with_signal(proof, values, x)
                .map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r
                .verify_with_signal(proof, values, x)
                .map_err(|err| err.to_string()),
        }
    }

    fn verify_with_roots(
        &self,
        proof: &Proof,
        values: &RLNProofValues,
        x: &Fr,
        roots: &[Fr],
    ) -> Result<bool, String> {
        match self {
            Self::Stateless(r) => r
                .verify_with_roots(proof, values, x, roots)
                .map_err(|err| err.to_string()),
            Self::StatefulFullMerkleTree(r) => r
                .verify_with_roots(proof, values, x, roots)
                .map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r
                .verify_with_roots(proof, values, x, roots)
                .map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r
                .verify_with_roots(proof, values, x, roots)
                .map_err(|err| err.to_string()),
        }
    }

    fn generate_partial_proof(
        &self,
        partial_witness: &RLNPartialWitnessInput,
    ) -> Result<PartialProof, String> {
        match self {
            Self::Stateless(r) => r
                .generate_partial_proof(partial_witness)
                .map_err(|err| err.to_string()),
            Self::StatefulFullMerkleTree(r) => r
                .generate_partial_proof(partial_witness)
                .map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r
                .generate_partial_proof(partial_witness)
                .map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r
                .generate_partial_proof(partial_witness)
                .map_err(|err| err.to_string()),
        }
    }

    fn finish_proof(
        &self,
        partial_proof: &PartialProof,
        witness: &RLNWitnessInput,
    ) -> Result<(Proof, RLNProofValues), String> {
        match self {
            Self::Stateless(r) => r
                .finish_proof(partial_proof, witness)
                .map_err(|err| err.to_string()),
            Self::StatefulFullMerkleTree(r) => r
                .finish_proof(partial_proof, witness)
                .map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r
                .finish_proof(partial_proof, witness)
                .map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r
                .finish_proof(partial_proof, witness)
                .map_err(|err| err.to_string()),
        }
    }

    fn tree_depth(&self) -> Result<usize, String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => Ok(r.tree_depth()),
            Self::StatefulOptimalMerkleTree(r) => Ok(r.tree_depth()),
            Self::StatefulPmTree(r) => Ok(r.tree_depth()),
        }
    }

    fn leaves_set(&self) -> Result<usize, String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => Ok(r.leaves_set()),
            Self::StatefulOptimalMerkleTree(r) => Ok(r.leaves_set()),
            Self::StatefulPmTree(r) => Ok(r.leaves_set()),
        }
    }

    fn get_root(&self) -> Result<Fr, String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => Ok(r.get_root()),
            Self::StatefulOptimalMerkleTree(r) => Ok(r.get_root()),
            Self::StatefulPmTree(r) => Ok(r.get_root()),
        }
    }

    fn get_subtree_root(&self, level: usize, index: usize) -> Result<Fr, String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => r
                .get_subtree_root(level, index)
                .map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r
                .get_subtree_root(level, index)
                .map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r
                .get_subtree_root(level, index)
                .map_err(|err| err.to_string()),
        }
    }

    fn set_leaf(&mut self, index: usize, leaf: Fr) -> Result<(), String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => {
                r.set_leaf(index, leaf).map_err(|err| err.to_string())
            }
            Self::StatefulOptimalMerkleTree(r) => {
                r.set_leaf(index, leaf).map_err(|err| err.to_string())
            }
            Self::StatefulPmTree(r) => r.set_leaf(index, leaf).map_err(|err| err.to_string()),
        }
    }

    fn set_leaves_from(&mut self, index: usize, leaves: Vec<Fr>) -> Result<(), String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => r
                .set_leaves_from(index, leaves)
                .map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r
                .set_leaves_from(index, leaves)
                .map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r
                .set_leaves_from(index, leaves)
                .map_err(|err| err.to_string()),
        }
    }

    fn init_tree_with_leaves(&mut self, leaves: Vec<Fr>) -> Result<(), String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => r
                .init_tree_with_leaves(leaves)
                .map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r
                .init_tree_with_leaves(leaves)
                .map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r
                .init_tree_with_leaves(leaves)
                .map_err(|err| err.to_string()),
        }
    }

    fn get_leaf(&self, index: usize) -> Result<Fr, String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => r.get_leaf(index).map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r.get_leaf(index).map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r.get_leaf(index).map_err(|err| err.to_string()),
        }
    }

    fn get_empty_leaves_indices(&self) -> Result<Vec<usize>, String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => Ok(r.get_empty_leaves_indices()),
            Self::StatefulOptimalMerkleTree(r) => Ok(r.get_empty_leaves_indices()),
            Self::StatefulPmTree(r) => Ok(r.get_empty_leaves_indices()),
        }
    }

    fn atomic_operation(
        &mut self,
        index: usize,
        leaves: Vec<Fr>,
        indices: Vec<usize>,
    ) -> Result<(), String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => r
                .atomic_operation(index, leaves, indices)
                .map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r
                .atomic_operation(index, leaves, indices)
                .map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r
                .atomic_operation(index, leaves, indices)
                .map_err(|err| err.to_string()),
        }
    }

    fn set_next_leaf(&mut self, leaf: Fr) -> Result<(), String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => r.set_next_leaf(leaf).map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => {
                r.set_next_leaf(leaf).map_err(|err| err.to_string())
            }
            Self::StatefulPmTree(r) => r.set_next_leaf(leaf).map_err(|err| err.to_string()),
        }
    }

    fn delete_leaf(&mut self, index: usize) -> Result<(), String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => r.delete_leaf(index).map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => {
                r.delete_leaf(index).map_err(|err| err.to_string())
            }
            Self::StatefulPmTree(r) => r.delete_leaf(index).map_err(|err| err.to_string()),
        }
    }

    fn get_merkle_proof(&self, index: usize) -> Result<RLNMerkleProof, String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => {
                let p = r.get_merkle_proof(index).map_err(|err| err.to_string())?;
                Ok(RLNMerkleProof::from(&p))
            }
            Self::StatefulOptimalMerkleTree(r) => {
                let p = r.get_merkle_proof(index).map_err(|err| err.to_string())?;
                Ok(RLNMerkleProof::from(&p))
            }
            Self::StatefulPmTree(r) => {
                let p = r.get_merkle_proof(index).map_err(|err| err.to_string())?;
                Ok(RLNMerkleProof::from(&p))
            }
        }
    }

    fn set_metadata(&mut self, metadata: &[u8]) -> Result<(), String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => {
                r.set_metadata(metadata).map_err(|err| err.to_string())
            }
            Self::StatefulOptimalMerkleTree(r) => {
                r.set_metadata(metadata).map_err(|err| err.to_string())
            }
            Self::StatefulPmTree(r) => r.set_metadata(metadata).map_err(|err| err.to_string()),
        }
    }

    fn get_metadata(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => r.get_metadata().map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r.get_metadata().map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r.get_metadata().map_err(|err| err.to_string()),
        }
    }

    fn close(&mut self) -> Result<(), String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => r.close().map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r.close().map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r.close().map_err(|err| err.to_string()),
        }
    }
}

impl From<RLN<Stateless, ArkGroth16Backend<PoseidonHash>>> for FFI_RLN_Inner {
    fn from(r: RLN<Stateless, ArkGroth16Backend<PoseidonHash>>) -> Self {
        Self::Stateless(r)
    }
}

impl From<RLN<Stateful<FullMerkleTree<PoseidonHash>>, ArkGroth16Backend<PoseidonHash>>>
    for FFI_RLN_Inner
{
    fn from(
        r: RLN<Stateful<FullMerkleTree<PoseidonHash>>, ArkGroth16Backend<PoseidonHash>>,
    ) -> Self {
        Self::StatefulFullMerkleTree(r)
    }
}

impl From<RLN<Stateful<OptimalMerkleTree<PoseidonHash>>, ArkGroth16Backend<PoseidonHash>>>
    for FFI_RLN_Inner
{
    fn from(
        r: RLN<Stateful<OptimalMerkleTree<PoseidonHash>>, ArkGroth16Backend<PoseidonHash>>,
    ) -> Self {
        Self::StatefulOptimalMerkleTree(r)
    }
}

impl From<RLN<Stateful<PmTree<SledDB, PoseidonHash>>, ArkGroth16Backend<PoseidonHash>>>
    for FFI_RLN_Inner
{
    fn from(
        r: RLN<Stateful<PmTree<SledDB, PoseidonHash>>, ArkGroth16Backend<PoseidonHash>>,
    ) -> Self {
        Self::StatefulPmTree(r)
    }
}

// FFI_RLN

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLN(pub(crate) FFI_RLN_Inner);

fn parse_zkey_and_graph(
    zkey_data: &repr_c::Vec<u8>,
    graph_data: &repr_c::Vec<u8>,
) -> Result<(Zkey, Graph), String> {
    let zkey = zkey_from_raw(zkey_data).map_err(|err| err.to_string())?;
    let graph = graph_from_raw(graph_data, None, None).map_err(|err| err.to_string())?;
    Ok((zkey, graph))
}

#[ffi_export]
pub fn ffi_rln_new_stateless_default() -> repr_c::Box<FFI_RLN> {
    let rln = RLNBuilder::stateless().build();
    Box_::new(FFI_RLN(rln.into()))
}

#[ffi_export]
pub fn ffi_rln_new_stateless(
    zkey_data: &repr_c::Vec<u8>,
    graph_data: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLN>, repr_c::String> {
    match parse_zkey_and_graph(zkey_data, graph_data) {
        Ok((zkey, graph)) => {
            let rln = RLNBuilder::stateless().graph(graph).zkey(zkey).build();
            FFI_Result {
                ok: Some(Box_::new(FFI_RLN(rln.into()))),
                err: None,
            }
        }
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_new_with_full_merkle_tree_default(
) -> FFI_Result<repr_c::Box<FFI_RLN>, repr_c::String> {
    match FullMerkleTree::<PoseidonHash>::default(DEFAULT_TREE_DEPTH) {
        Ok(full_merkle_tree) => {
            let rln = RLNBuilder::stateful().tree(full_merkle_tree).build();
            FFI_Result {
                ok: Some(Box_::new(FFI_RLN(rln.into()))),
                err: None,
            }
        }
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_new_with_full_merkle_tree(
    tree_depth: usize,
    zkey_data: &repr_c::Vec<u8>,
    graph_data: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLN>, repr_c::String> {
    let (zkey, graph) = match parse_zkey_and_graph(zkey_data, graph_data) {
        Ok(parsed) => parsed,
        Err(err) => {
            return FFI_Result {
                ok: None,
                err: Some(err.into()),
            }
        }
    };
    match FullMerkleTree::<PoseidonHash>::default(tree_depth) {
        Ok(full_merkle_tree) => {
            let rln = RLNBuilder::stateful()
                .tree(full_merkle_tree)
                .graph(graph)
                .zkey(zkey)
                .build();
            FFI_Result {
                ok: Some(Box_::new(FFI_RLN(rln.into()))),
                err: None,
            }
        }
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_new_with_optimal_merkle_tree_default(
) -> FFI_Result<repr_c::Box<FFI_RLN>, repr_c::String> {
    match OptimalMerkleTree::<PoseidonHash>::default(DEFAULT_TREE_DEPTH) {
        Ok(optimal_merkle_tree) => {
            let rln = RLNBuilder::stateful().tree(optimal_merkle_tree).build();
            FFI_Result {
                ok: Some(Box_::new(FFI_RLN(rln.into()))),
                err: None,
            }
        }
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_new_with_optimal_merkle_tree(
    tree_depth: usize,
    zkey_data: &repr_c::Vec<u8>,
    graph_data: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLN>, repr_c::String> {
    let (zkey, graph) = match parse_zkey_and_graph(zkey_data, graph_data) {
        Ok(parsed) => parsed,
        Err(err) => {
            return FFI_Result {
                ok: None,
                err: Some(err.into()),
            }
        }
    };
    match OptimalMerkleTree::<PoseidonHash>::default(tree_depth) {
        Ok(optimal_merkle_tree) => {
            let rln = RLNBuilder::stateful()
                .tree(optimal_merkle_tree)
                .graph(graph)
                .zkey(zkey)
                .build();
            FFI_Result {
                ok: Some(Box_::new(FFI_RLN(rln.into()))),
                err: None,
            }
        }
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_new_with_pm_tree_default() -> FFI_Result<repr_c::Box<FFI_RLN>, repr_c::String> {
    match PmTree::default(DEFAULT_TREE_DEPTH) {
        Ok(pm_tree) => {
            let rln = RLNBuilder::stateful().tree(pm_tree).build();
            FFI_Result {
                ok: Some(Box_::new(FFI_RLN(rln.into()))),
                err: None,
            }
        }
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_new_with_pm_tree(
    tree_depth: usize,
    zkey_data: &repr_c::Vec<u8>,
    graph_data: &repr_c::Vec<u8>,
    config_path: char_p::Ref<'_>,
) -> FFI_Result<repr_c::Box<FFI_RLN>, repr_c::String> {
    let (zkey, graph) = match parse_zkey_and_graph(zkey_data, graph_data) {
        Ok(parsed) => parsed,
        Err(err) => {
            return FFI_Result {
                ok: None,
                err: Some(err.into()),
            }
        }
    };
    let config_str = if config_path.to_str().is_empty() {
        String::new()
    } else {
        let read_result = File::open(config_path.to_str()).and_then(|mut file| {
            let metadata = file.metadata()?;
            if metadata.len() > MAX_CONFIG_SIZE {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Config file too large: {} bytes (max {} bytes)",
                        metadata.len(),
                        MAX_CONFIG_SIZE
                    ),
                ));
            }
            let mut s = String::new();
            file.read_to_string(&mut s)?;
            Ok(s)
        });
        match read_result {
            Ok(s) => s,
            Err(err) => {
                return FFI_Result {
                    ok: None,
                    err: Some(err.to_string().into()),
                }
            }
        }
    };
    let pm_tree = if config_str.is_empty() {
        PmTree::default(tree_depth)
    } else {
        let config = match PmTreeSledConfig::from_str(&config_str) {
            Ok(config) => config,
            Err(err) => {
                return FFI_Result {
                    ok: None,
                    err: Some(err.to_string().into()),
                }
            }
        };
        PmTree::new(tree_depth, Fr::default(), config)
    };
    match pm_tree {
        Ok(pm_tree) => {
            let rln = RLNBuilder::stateful()
                .tree(pm_tree)
                .graph(graph)
                .zkey(zkey)
                .build();
            FFI_Result {
                ok: Some(Box_::new(FFI_RLN(rln.into()))),
                err: None,
            }
        }
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_generate_proof(
    rln: &FFI_RLN,
    witness: &FFI_RLNWitnessInput,
) -> FFI_Result<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    match rln.0.generate_proof(&witness.0) {
        Ok((proof, values)) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNProof(RLNProof::new(proof, values)))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_verify(rln: &FFI_RLN, rln_proof: &FFI_RLNProof) -> FFI_BoolResult {
    match rln.0.verify(&rln_proof.0.proof, &rln_proof.0.values) {
        Ok(verified) => FFI_BoolResult {
            ok: verified,
            err: None,
        },
        Err(err) => FFI_BoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_verify_with_signal(
    rln: &FFI_RLN,
    rln_proof: &FFI_RLNProof,
    x: &FFI_Fr,
) -> FFI_BoolResult {
    match rln
        .0
        .verify_with_signal(&rln_proof.0.proof, &rln_proof.0.values, &x.0)
    {
        Ok(verified) => FFI_BoolResult {
            ok: verified,
            err: None,
        },
        Err(err) => FFI_BoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_verify_with_roots(
    rln: &FFI_RLN,
    rln_proof: &FFI_RLNProof,
    roots: &repr_c::Vec<FFI_Fr>,
    x: &FFI_Fr,
) -> FFI_BoolResult {
    let roots_fr: Vec<Fr> = roots.iter().map(|fr| fr.0).collect();
    match rln
        .0
        .verify_with_roots(&rln_proof.0.proof, &rln_proof.0.values, &x.0, &roots_fr)
    {
        Ok(verified) => FFI_BoolResult {
            ok: verified,
            err: None,
        },
        Err(err) => FFI_BoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_generate_partial_proof(
    rln: &FFI_RLN,
    partial_witness: &FFI_RLNPartialWitnessInput,
) -> FFI_Result<repr_c::Box<FFI_RLNPartialProof>, repr_c::String> {
    match rln.0.generate_partial_proof(&partial_witness.0) {
        Ok(pp) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNPartialProof(pp))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_finish_proof(
    rln: &FFI_RLN,
    partial_proof: &FFI_RLNPartialProof,
    witness: &FFI_RLNWitnessInput,
) -> FFI_Result<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    match rln.0.finish_proof(&partial_proof.0, &witness.0) {
        Ok((proof, values)) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNProof(RLNProof::new(proof, values)))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_free(rln: repr_c::Box<FFI_RLN>) {
    drop(rln);
}

// FFI_RLNMerkleProof

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLNMerkleProof(pub(crate) RLNMerkleProof);

#[ffi_export]
pub fn ffi_rln_merkle_proof_new(
    path_elements: &repr_c::Vec<FFI_Fr>,
    identity_path_index: &repr_c::Vec<u8>,
) -> repr_c::Box<FFI_RLNMerkleProof> {
    let path_elements: Vec<Fr> = path_elements.iter().map(|fr| fr.0).collect();
    let identity_path_index: Vec<u8> = identity_path_index.iter().copied().collect();
    Box_::new(FFI_RLNMerkleProof(RLNMerkleProof::new(
        path_elements,
        identity_path_index,
    )))
}

#[ffi_export]
pub fn ffi_rln_merkle_proof_get_path_elements(
    merkle_proof: &FFI_RLNMerkleProof,
) -> repr_c::Vec<FFI_Fr> {
    merkle_proof
        .0
        .path_elements()
        .iter()
        .map(|fr| FFI_Fr::from(*fr))
        .collect::<Vec<_>>()
        .into()
}

#[ffi_export]
pub fn ffi_rln_merkle_proof_get_identity_path_index(
    merkle_proof: &FFI_RLNMerkleProof,
) -> repr_c::Vec<u8> {
    merkle_proof.0.identity_path_index().to_vec().into()
}

#[ffi_export]
pub fn ffi_rln_merkle_proof_to_bytes_le(
    merkle_proof: &FFI_RLNMerkleProof,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match merkle_proof.0.serialize_compressed(&mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_merkle_proof_to_bytes_be(
    merkle_proof: &FFI_RLNMerkleProof,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeBE::serialize(&merkle_proof.0, &mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_merkle_proof_from_bytes_le(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLNMerkleProof>, repr_c::String> {
    match RLNMerkleProof::deserialize_compressed(&bytes[..]) {
        Ok(merkle_proof) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNMerkleProof(merkle_proof))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_merkle_proof_from_bytes_be(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLNMerkleProof>, repr_c::String> {
    match <RLNMerkleProof as CanonicalDeserializeBE>::deserialize(&bytes[..]) {
        Ok(merkle_proof) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNMerkleProof(merkle_proof))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_merkle_proof_free(merkle_proof: repr_c::Box<FFI_RLNMerkleProof>) {
    drop(merkle_proof);
}

// FFI_RLNWitnessInput

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLNWitnessInput(pub(crate) RLNWitnessInput);

#[ffi_export]
pub fn ffi_rln_witness_input_new_single(
    identity_secret: &FFI_SecretFr,
    user_message_limit: &FFI_Fr,
    message_id: &FFI_Fr,
    merkle_proof: &FFI_RLNMerkleProof,
    x: &FFI_Fr,
    external_nullifier: &FFI_Fr,
) -> FFI_Result<repr_c::Box<FFI_RLNWitnessInput>, repr_c::String> {
    match RLNWitnessInput::new_single()
        .identity_secret(identity_secret.0.clone())
        .user_message_limit(user_message_limit.0)
        .merkle_proof(merkle_proof.0.clone())
        .x(x.0)
        .external_nullifier(external_nullifier.0)
        .message_id(message_id.0)
        .build()
    {
        Ok(w) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNWitnessInput(w))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_new_multi(
    identity_secret: &FFI_SecretFr,
    user_message_limit: &FFI_Fr,
    message_ids: &repr_c::Vec<FFI_Fr>,
    merkle_proof: &FFI_RLNMerkleProof,
    x: &FFI_Fr,
    external_nullifier: &FFI_Fr,
    selector_used: &repr_c::Vec<bool>,
) -> FFI_Result<repr_c::Box<FFI_RLNWitnessInput>, repr_c::String> {
    let message_ids: Vec<Fr> = message_ids.iter().map(|fr| fr.0).collect();
    let selector_used: Vec<bool> = selector_used.iter().copied().collect();

    match RLNWitnessInput::new_multi()
        .identity_secret(identity_secret.0.clone())
        .user_message_limit(user_message_limit.0)
        .merkle_proof(merkle_proof.0.clone())
        .x(x.0)
        .external_nullifier(external_nullifier.0)
        .message_ids(message_ids)
        .selector_used(selector_used)
        .build()
    {
        Ok(w) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNWitnessInput(w))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_identity_secret(
    witness: &FFI_RLNWitnessInput,
) -> repr_c::Box<FFI_SecretFr> {
    Box_::new(FFI_SecretFr::from(witness.0.identity_secret().clone()))
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_user_message_limit(
    witness: &FFI_RLNWitnessInput,
) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(witness.0.user_message_limit()).into()
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_message_id(
    witness: &FFI_RLNWitnessInput,
) -> FFI_Result<repr_c::Box<FFI_Fr>, repr_c::String> {
    match witness.0.message_id() {
        Some(id) => FFI_Result {
            ok: Some(FFI_Fr::from(id).into()),
            err: None,
        },
        None => FFI_Result {
            ok: None,
            err: Some("witness is Multi; use get_message_ids".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_message_ids(
    witness: &FFI_RLNWitnessInput,
) -> FFI_Result<repr_c::Vec<FFI_Fr>, repr_c::String> {
    match witness.0.message_ids() {
        Some(ids) => FFI_Result {
            ok: Some(
                ids.iter()
                    .map(|fr| FFI_Fr::from(*fr))
                    .collect::<Vec<_>>()
                    .into(),
            ),
            err: None,
        },
        None => FFI_Result {
            ok: None,
            err: Some("witness is Single; use get_message_id".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_path_elements(
    witness: &FFI_RLNWitnessInput,
) -> repr_c::Vec<FFI_Fr> {
    witness
        .0
        .path_elements()
        .iter()
        .map(|fr| FFI_Fr::from(*fr))
        .collect::<Vec<_>>()
        .into()
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_identity_path_index(
    witness: &FFI_RLNWitnessInput,
) -> repr_c::Vec<u8> {
    witness.0.identity_path_index().to_vec().into()
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_merkle_proof(
    witness: &FFI_RLNWitnessInput,
) -> repr_c::Box<FFI_RLNMerkleProof> {
    Box_::new(FFI_RLNMerkleProof(witness.0.merkle_proof()))
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_x(witness: &FFI_RLNWitnessInput) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(witness.0.x()).into()
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_external_nullifier(
    witness: &FFI_RLNWitnessInput,
) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(witness.0.external_nullifier()).into()
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_selector_used(
    witness: &FFI_RLNWitnessInput,
) -> FFI_Result<repr_c::Vec<bool>, repr_c::String> {
    match witness.0.selector_used() {
        Some(s) => FFI_Result {
            ok: Some(s.to_vec().into()),
            err: None,
        },
        None => FFI_Result {
            ok: None,
            err: Some("witness is Single; selector_used is Multi-only".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_to_bytes_le(
    witness: &FFI_RLNWitnessInput,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match witness.0.serialize_compressed(&mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_to_bytes_be(
    witness: &FFI_RLNWitnessInput,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeBE::serialize(&witness.0, &mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_from_bytes_le(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLNWitnessInput>, repr_c::String> {
    match RLNWitnessInput::deserialize_compressed(&bytes[..]) {
        Ok(w) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNWitnessInput(w))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_from_bytes_be(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLNWitnessInput>, repr_c::String> {
    match <RLNWitnessInput as CanonicalDeserializeBE>::deserialize(&bytes[..]) {
        Ok(w) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNWitnessInput(w))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_free(witness: repr_c::Box<FFI_RLNWitnessInput>) {
    drop(witness);
}

// FFI_RLNPartialWitnessInput

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLNPartialWitnessInput(pub(crate) RLNPartialWitnessInput);

#[ffi_export]
pub fn ffi_rln_partial_witness_input_new(
    identity_secret: &FFI_SecretFr,
    user_message_limit: &FFI_Fr,
    merkle_proof: &FFI_RLNMerkleProof,
) -> FFI_Result<repr_c::Box<FFI_RLNPartialWitnessInput>, repr_c::String> {
    match RLNPartialWitnessInput::new()
        .identity_secret(identity_secret.0.clone())
        .user_message_limit(user_message_limit.0)
        .merkle_proof(merkle_proof.0.clone())
        .build()
    {
        Ok(w) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNPartialWitnessInput(w))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_get_identity_secret(
    witness: &FFI_RLNPartialWitnessInput,
) -> repr_c::Box<FFI_SecretFr> {
    Box_::new(FFI_SecretFr::from(witness.0.identity_secret.clone()))
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_get_user_message_limit(
    witness: &FFI_RLNPartialWitnessInput,
) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(witness.0.user_message_limit).into()
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_get_path_elements(
    witness: &FFI_RLNPartialWitnessInput,
) -> repr_c::Vec<FFI_Fr> {
    witness
        .0
        .path_elements
        .iter()
        .map(|fr| FFI_Fr::from(*fr))
        .collect::<Vec<_>>()
        .into()
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_get_identity_path_index(
    witness: &FFI_RLNPartialWitnessInput,
) -> repr_c::Vec<u8> {
    witness.0.identity_path_index.to_vec().into()
}

#[ffi_export]
pub fn ffi_rln_witness_input_to_partial_witness(
    witness: &FFI_RLNWitnessInput,
) -> repr_c::Box<FFI_RLNPartialWitnessInput> {
    let partial = RLNPartialWitnessInput::from(&witness.0);
    Box_::new(FFI_RLNPartialWitnessInput(partial))
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_to_bytes_le(
    witness: &FFI_RLNPartialWitnessInput,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match witness.0.serialize_compressed(&mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_to_bytes_be(
    witness: &FFI_RLNPartialWitnessInput,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeBE::serialize(&witness.0, &mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_from_bytes_le(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLNPartialWitnessInput>, repr_c::String> {
    match RLNPartialWitnessInput::deserialize_compressed(&bytes[..]) {
        Ok(w) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNPartialWitnessInput(w))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_from_bytes_be(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLNPartialWitnessInput>, repr_c::String> {
    match <RLNPartialWitnessInput as CanonicalDeserializeBE>::deserialize(&bytes[..]) {
        Ok(w) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNPartialWitnessInput(w))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_free(witness: repr_c::Box<FFI_RLNPartialWitnessInput>) {
    drop(witness);
}

// FFI_RLNProof

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLNProof(pub(crate) RLNProof);

#[ffi_export]
pub fn ffi_rln_proof_get_values(rln_proof: &FFI_RLNProof) -> repr_c::Box<FFI_RLNProofValues> {
    Box_::new(FFI_RLNProofValues(rln_proof.0.values.clone()))
}

#[ffi_export]
pub fn ffi_rln_proof_to_bytes_le(
    rln_proof: &FFI_RLNProof,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match rln_proof.0.serialize_compressed(&mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_to_bytes_mixed(
    rln_proof: &FFI_RLNProof,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeMixed::serialize(&rln_proof.0, &mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_from_bytes_le(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    match RLNProof::deserialize_compressed(&bytes[..]) {
        Ok(p) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNProof(p))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_from_bytes_mixed(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    match <RLNProof as CanonicalDeserializeMixed>::deserialize(&bytes[..]) {
        Ok(p) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNProof(p))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_free(rln_proof: repr_c::Box<FFI_RLNProof>) {
    drop(rln_proof);
}

// FFI_RLNPartialProof

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLNPartialProof(pub(crate) PartialProof);

#[ffi_export]
pub fn ffi_rln_partial_proof_to_bytes_le(
    partial_proof: &FFI_RLNPartialProof,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match partial_proof.0.serialize_compressed(&mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_partial_proof_from_bytes_le(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLNPartialProof>, repr_c::String> {
    match PartialProof::deserialize_compressed(&bytes[..]) {
        Ok(p) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNPartialProof(p))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_partial_proof_free(partial_proof: repr_c::Box<FFI_RLNPartialProof>) {
    drop(partial_proof);
}

// FFI_RLNProofValues

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLNProofValues(pub(crate) RLNProofValues);

#[ffi_export]
pub fn ffi_rln_proof_values_get_root(pv: &FFI_RLNProofValues) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(pv.0.root()).into()
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_x(pv: &FFI_RLNProofValues) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(pv.0.x()).into()
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_external_nullifier(pv: &FFI_RLNProofValues) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(pv.0.external_nullifier()).into()
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_y(
    pv: &FFI_RLNProofValues,
) -> FFI_Result<repr_c::Box<FFI_Fr>, repr_c::String> {
    match pv.0.y() {
        Some(y) => FFI_Result {
            ok: Some(FFI_Fr::from(y).into()),
            err: None,
        },
        None => FFI_Result {
            ok: None,
            err: Some("values are Multi; use get_ys".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_nullifier(
    pv: &FFI_RLNProofValues,
) -> FFI_Result<repr_c::Box<FFI_Fr>, repr_c::String> {
    match pv.0.nullifier() {
        Some(n) => FFI_Result {
            ok: Some(FFI_Fr::from(n).into()),
            err: None,
        },
        None => FFI_Result {
            ok: None,
            err: Some("values are Multi; use get_nullifiers".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_selector_used(
    pv: &FFI_RLNProofValues,
) -> FFI_Result<repr_c::Vec<bool>, repr_c::String> {
    match pv.0.selector_used() {
        Some(s) => FFI_Result {
            ok: Some(s.to_vec().into()),
            err: None,
        },
        None => FFI_Result {
            ok: None,
            err: Some("values are Single; selector_used is Multi-only".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_ys(
    pv: &FFI_RLNProofValues,
) -> FFI_Result<repr_c::Vec<FFI_Fr>, repr_c::String> {
    match pv.0.ys() {
        Some(ys) => FFI_Result {
            ok: Some(
                ys.iter()
                    .map(|fr| FFI_Fr::from(*fr))
                    .collect::<Vec<_>>()
                    .into(),
            ),
            err: None,
        },
        None => FFI_Result {
            ok: None,
            err: Some("values are Single; use get_y".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_nullifiers(
    pv: &FFI_RLNProofValues,
) -> FFI_Result<repr_c::Vec<FFI_Fr>, repr_c::String> {
    match pv.0.nullifiers() {
        Some(ns) => FFI_Result {
            ok: Some(
                ns.iter()
                    .map(|fr| FFI_Fr::from(*fr))
                    .collect::<Vec<_>>()
                    .into(),
            ),
            err: None,
        },
        None => FFI_Result {
            ok: None,
            err: Some("values are Single; use get_nullifier".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_to_bytes_le(
    pv: &FFI_RLNProofValues,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match pv.0.serialize_compressed(&mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_to_bytes_be(
    pv: &FFI_RLNProofValues,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeBE::serialize(&pv.0, &mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_from_bytes_le(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLNProofValues>, repr_c::String> {
    match RLNProofValues::deserialize_compressed(&bytes[..]) {
        Ok(pv) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNProofValues(pv))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_from_bytes_be(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_RLNProofValues>, repr_c::String> {
    match <RLNProofValues as CanonicalDeserializeBE>::deserialize(&bytes[..]) {
        Ok(pv) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNProofValues(pv))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_free(proof_values: repr_c::Box<FFI_RLNProofValues>) {
    drop(proof_values);
}

#[ffi_export]
pub fn ffi_rln_compute_id_secret(
    share1_x: &FFI_Fr,
    share1_y: &FFI_Fr,
    share2_x: &FFI_Fr,
    share2_y: &FFI_Fr,
) -> FFI_Result<repr_c::Box<FFI_SecretFr>, repr_c::String> {
    let share1 = (share1_x.0, share1_y.0);
    let share2 = (share2_x.0, share2_y.0);
    match compute_id_secret(share1, share2) {
        Ok(secret) => FFI_Result {
            ok: Some(Box_::new(FFI_SecretFr::from(secret))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_recover_id_secret(
    proof_values_1: &FFI_RLNProofValues,
    proof_values_2: &FFI_RLNProofValues,
) -> FFI_Result<repr_c::Box<FFI_SecretFr>, repr_c::String> {
    match proof_values_1.0.recover_secret(&proof_values_2.0) {
        Ok(secret) => FFI_Result {
            ok: Some(Box_::new(FFI_SecretFr::from(secret))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_tree_depth(rln: &FFI_RLN) -> FFI_UsizeResult {
    match rln.0.tree_depth() {
        Ok(depth) => FFI_UsizeResult {
            ok: depth,
            err: None,
        },
        Err(err) => FFI_UsizeResult {
            ok: 0,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_leaves_set(rln: &FFI_RLN) -> FFI_UsizeResult {
    match rln.0.leaves_set() {
        Ok(count) => FFI_UsizeResult {
            ok: count,
            err: None,
        },
        Err(err) => FFI_UsizeResult {
            ok: 0,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_get_root(rln: &FFI_RLN) -> FFI_Result<repr_c::Box<FFI_Fr>, repr_c::String> {
    match rln.0.get_root() {
        Ok(root) => FFI_Result {
            ok: Some(FFI_Fr::from(root).into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_get_subtree_root(
    rln: &FFI_RLN,
    level: usize,
    index: usize,
) -> FFI_Result<repr_c::Box<FFI_Fr>, repr_c::String> {
    match rln.0.get_subtree_root(level, index) {
        Ok(root) => FFI_Result {
            ok: Some(FFI_Fr::from(root).into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_set_leaf(rln: &mut FFI_RLN, index: usize, leaf: &FFI_Fr) -> FFI_BoolResult {
    match rln.0.set_leaf(index, leaf.0) {
        Ok(_) => FFI_BoolResult {
            ok: true,
            err: None,
        },
        Err(err) => FFI_BoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_set_leaves_from(
    rln: &mut FFI_RLN,
    index: usize,
    leaves: &repr_c::Vec<FFI_Fr>,
) -> FFI_BoolResult {
    let leaves_vec: Vec<_> = leaves.iter().map(|fr| fr.0).collect();
    match rln.0.set_leaves_from(index, leaves_vec) {
        Ok(_) => FFI_BoolResult {
            ok: true,
            err: None,
        },
        Err(err) => FFI_BoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_init_tree_with_leaves(
    rln: &mut FFI_RLN,
    leaves: &repr_c::Vec<FFI_Fr>,
) -> FFI_BoolResult {
    let leaves_vec: Vec<_> = leaves.iter().map(|fr| fr.0).collect();
    match rln.0.init_tree_with_leaves(leaves_vec) {
        Ok(_) => FFI_BoolResult {
            ok: true,
            err: None,
        },
        Err(err) => FFI_BoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_get_leaf(
    rln: &FFI_RLN,
    index: usize,
) -> FFI_Result<repr_c::Box<FFI_Fr>, repr_c::String> {
    match rln.0.get_leaf(index) {
        Ok(leaf) => FFI_Result {
            ok: Some(FFI_Fr::from(leaf).into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_get_empty_leaves_indices(
    rln: &FFI_RLN,
) -> FFI_Result<repr_c::Vec<usize>, repr_c::String> {
    match rln.0.get_empty_leaves_indices() {
        Ok(indices) => FFI_Result {
            ok: Some(indices.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_atomic_operation(
    rln: &mut FFI_RLN,
    index: usize,
    leaves: &repr_c::Vec<FFI_Fr>,
    indices: &repr_c::Vec<usize>,
) -> FFI_BoolResult {
    let leaves_vec: Vec<_> = leaves.iter().map(|fr| fr.0).collect();
    let indices_vec: Vec<_> = indices.iter().copied().collect();
    match rln.0.atomic_operation(index, leaves_vec, indices_vec) {
        Ok(_) => FFI_BoolResult {
            ok: true,
            err: None,
        },
        Err(err) => FFI_BoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_set_next_leaf(rln: &mut FFI_RLN, leaf: &FFI_Fr) -> FFI_BoolResult {
    match rln.0.set_next_leaf(leaf.0) {
        Ok(_) => FFI_BoolResult {
            ok: true,
            err: None,
        },
        Err(err) => FFI_BoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_delete_leaf(rln: &mut FFI_RLN, index: usize) -> FFI_BoolResult {
    match rln.0.delete_leaf(index) {
        Ok(_) => FFI_BoolResult {
            ok: true,
            err: None,
        },
        Err(err) => FFI_BoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_get_merkle_proof(
    rln: &FFI_RLN,
    index: usize,
) -> FFI_Result<repr_c::Box<FFI_RLNMerkleProof>, repr_c::String> {
    match rln.0.get_merkle_proof(index) {
        Ok(merkle_proof) => FFI_Result {
            ok: Some(Box_::new(FFI_RLNMerkleProof(merkle_proof))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_set_metadata(rln: &mut FFI_RLN, metadata: &repr_c::Vec<u8>) -> FFI_BoolResult {
    match rln.0.set_metadata(metadata) {
        Ok(_) => FFI_BoolResult {
            ok: true,
            err: None,
        },
        Err(err) => FFI_BoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_get_metadata(rln: &FFI_RLN) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    match rln.0.get_metadata() {
        Ok(metadata) => FFI_Result {
            ok: Some(metadata.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_close(rln: &mut FFI_RLN) -> FFI_BoolResult {
    match rln.0.close() {
        Ok(_) => FFI_BoolResult {
            ok: true,
            err: None,
        },
        Err(err) => FFI_BoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}
