#![allow(non_camel_case_types)]

use std::{fs::File, io::Read, str::FromStr};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use safer_ffi::{
    boxed::Box_,
    derive_ReprC, ffi_export,
    prelude::{char_p, repr_c},
};
use zerokit_utils::merkle_tree::{
    FullMerkleTree, Hasher, OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree,
};

use super::ffi_utils::{CBoolResult, CFr, CResult};
use crate::prelude::*;

const MAX_CONFIG_SIZE: u64 = 1024 * 1024;
const NO_STATELESS_TREE_ERR: &str = "tree op unsupported on stateless RLN";

pub(crate) enum FFI_RLN_Inner {
    Stateless(RLN<Stateless, ArkGroth16Backend>),
    StatefulFullMerkleTree(RLN<Stateful<FullMerkleTree<PoseidonHash>>, ArkGroth16Backend>),
    StatefulOptimalMerkleTree(RLN<Stateful<OptimalMerkleTree<PoseidonHash>>, ArkGroth16Backend>),
    StatefulPmTree(RLN<Stateful<PmTree>, ArkGroth16Backend>),
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

    fn get_root(&self) -> Result<Fr, String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => Ok(r.get_root()),
            Self::StatefulOptimalMerkleTree(r) => Ok(r.get_root()),
            Self::StatefulPmTree(r) => Ok(r.get_root()),
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

    fn get_leaf(&self, index: usize) -> Result<Fr, String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => r.get_leaf(index).map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r.get_leaf(index).map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r.get_leaf(index).map_err(|err| err.to_string()),
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

    fn get_merkle_proof(&self, index: usize) -> Result<(Vec<Fr>, Vec<u8>), String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => {
                let p = r.get_merkle_proof(index).map_err(|err| err.to_string())?;
                Ok((p.get_path_elements(), p.get_path_index()))
            }
            Self::StatefulOptimalMerkleTree(r) => {
                let p = r.get_merkle_proof(index).map_err(|err| err.to_string())?;
                Ok((p.get_path_elements(), p.get_path_index()))
            }
            Self::StatefulPmTree(r) => {
                let p = r.get_merkle_proof(index).map_err(|err| err.to_string())?;
                Ok((p.get_path_elements(), p.get_path_index()))
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

    fn flush(&mut self) -> Result<(), String> {
        match self {
            Self::Stateless(_) => Err(NO_STATELESS_TREE_ERR.to_string()),
            Self::StatefulFullMerkleTree(r) => r.flush().map_err(|err| err.to_string()),
            Self::StatefulOptimalMerkleTree(r) => r.flush().map_err(|err| err.to_string()),
            Self::StatefulPmTree(r) => r.flush().map_err(|err| err.to_string()),
        }
    }
}

impl From<RLN<Stateless, ArkGroth16Backend>> for FFI_RLN_Inner {
    fn from(r: RLN<Stateless, ArkGroth16Backend>) -> Self {
        Self::Stateless(r)
    }
}

impl From<RLN<Stateful<FullMerkleTree<PoseidonHash>>, ArkGroth16Backend>> for FFI_RLN_Inner {
    fn from(r: RLN<Stateful<FullMerkleTree<PoseidonHash>>, ArkGroth16Backend>) -> Self {
        Self::StatefulFullMerkleTree(r)
    }
}

impl From<RLN<Stateful<OptimalMerkleTree<PoseidonHash>>, ArkGroth16Backend>> for FFI_RLN_Inner {
    fn from(r: RLN<Stateful<OptimalMerkleTree<PoseidonHash>>, ArkGroth16Backend>) -> Self {
        Self::StatefulOptimalMerkleTree(r)
    }
}

impl From<RLN<Stateful<PmTree>, ArkGroth16Backend>> for FFI_RLN_Inner {
    fn from(r: RLN<Stateful<PmTree>, ArkGroth16Backend>) -> Self {
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
) -> CResult<repr_c::Box<FFI_RLN>, repr_c::String> {
    match parse_zkey_and_graph(zkey_data, graph_data) {
        Ok((zkey, graph)) => {
            let rln = RLNBuilder::stateless().graph(graph).zkey(zkey).build();
            CResult {
                ok: Some(Box_::new(FFI_RLN(rln.into()))),
                err: None,
            }
        }
        Err(err) => CResult {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_new_with_full_merkle_tree_default() -> repr_c::Box<FFI_RLN> {
    let full_merkle_tree = FullMerkleTree::<PoseidonHash>::default(DEFAULT_TREE_DEPTH).unwrap();
    let rln = RLNBuilder::stateful().tree(full_merkle_tree).build();
    Box_::new(FFI_RLN(rln.into()))
}

#[ffi_export]
pub fn ffi_rln_new_with_full_merkle_tree(
    tree_depth: usize,
    zkey_data: &repr_c::Vec<u8>,
    graph_data: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLN>, repr_c::String> {
    let (zkey, graph) = match parse_zkey_and_graph(zkey_data, graph_data) {
        Ok(parsed) => parsed,
        Err(err) => {
            return CResult {
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
            CResult {
                ok: Some(Box_::new(FFI_RLN(rln.into()))),
                err: None,
            }
        }
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_new_with_optimal_merkle_tree_default() -> repr_c::Box<FFI_RLN> {
    let optimal_merkle_tree =
        OptimalMerkleTree::<PoseidonHash>::default(DEFAULT_TREE_DEPTH).unwrap();
    let rln = RLNBuilder::stateful().tree(optimal_merkle_tree).build();
    Box_::new(FFI_RLN(rln.into()))
}

#[ffi_export]
pub fn ffi_rln_new_with_optimal_merkle_tree(
    tree_depth: usize,
    zkey_data: &repr_c::Vec<u8>,
    graph_data: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLN>, repr_c::String> {
    let (zkey, graph) = match parse_zkey_and_graph(zkey_data, graph_data) {
        Ok(parsed) => parsed,
        Err(err) => {
            return CResult {
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
            CResult {
                ok: Some(Box_::new(FFI_RLN(rln.into()))),
                err: None,
            }
        }
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_new_with_pm_tree_default() -> repr_c::Box<FFI_RLN> {
    let pm_tree = PmTree::default(DEFAULT_TREE_DEPTH).unwrap();
    let rln = RLNBuilder::stateful().tree(pm_tree).build();
    Box_::new(FFI_RLN(rln.into()))
}

#[ffi_export]
pub fn ffi_rln_new_with_pm_tree(
    tree_depth: usize,
    zkey_data: &repr_c::Vec<u8>,
    graph_data: &repr_c::Vec<u8>,
    config_path: char_p::Ref<'_>,
) -> CResult<repr_c::Box<FFI_RLN>, repr_c::String> {
    let (zkey, graph) = match parse_zkey_and_graph(zkey_data, graph_data) {
        Ok(parsed) => parsed,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.into()),
            }
        }
    };
    let config_str = File::open(config_path.to_str())
        .and_then(|mut file| {
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
        })
        .unwrap_or_default();
    let pm_tree = if config_str.is_empty() {
        PmTree::default(tree_depth)
    } else {
        let cfg = match PmTreeConfig::from_str(&config_str) {
            Ok(c) => c,
            Err(err) => {
                return CResult {
                    ok: None,
                    err: Some(err.to_string().into()),
                }
            }
        };
        PmTree::new(tree_depth, PoseidonHash::default_leaf(), cfg)
    };
    match pm_tree {
        Ok(pm_tree) => {
            let rln = RLNBuilder::stateful()
                .tree(pm_tree)
                .graph(graph)
                .zkey(zkey)
                .build();
            CResult {
                ok: Some(Box_::new(FFI_RLN(rln.into()))),
                err: None,
            }
        }
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_generate_proof(
    rln: &repr_c::Box<FFI_RLN>,
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> CResult<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    match rln.0.generate_proof(&witness.0) {
        Ok((proof, values)) => CResult {
            ok: Some(Box_::new(FFI_RLNProof(RLNProof::new(proof, values)))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_verify(
    rln: &repr_c::Box<FFI_RLN>,
    rln_proof: &repr_c::Box<FFI_RLNProof>,
) -> CBoolResult {
    match rln.0.verify(&rln_proof.0.proof, &rln_proof.0.values) {
        Ok(verified) => CBoolResult {
            ok: verified,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_verify_with_signal(
    rln: &repr_c::Box<FFI_RLN>,
    rln_proof: &repr_c::Box<FFI_RLNProof>,
    x: &CFr,
) -> CBoolResult {
    match rln
        .0
        .verify_with_signal(&rln_proof.0.proof, &rln_proof.0.values, &x.0)
    {
        Ok(verified) => CBoolResult {
            ok: verified,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_verify_with_roots(
    rln: &repr_c::Box<FFI_RLN>,
    rln_proof: &repr_c::Box<FFI_RLNProof>,
    roots: &repr_c::Vec<CFr>,
    x: &CFr,
) -> CBoolResult {
    let roots_fr: Vec<Fr> = roots.iter().map(|cfr| cfr.0).collect();
    match rln
        .0
        .verify_with_roots(&rln_proof.0.proof, &rln_proof.0.values, &x.0, &roots_fr)
    {
        Ok(verified) => CBoolResult {
            ok: verified,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_generate_partial_proof(
    rln: &repr_c::Box<FFI_RLN>,
    partial_witness: &repr_c::Box<FFI_RLNPartialWitnessInput>,
) -> CResult<repr_c::Box<FFI_RLNPartialProof>, repr_c::String> {
    match rln.0.generate_partial_proof(&partial_witness.0) {
        Ok(pp) => CResult {
            ok: Some(Box_::new(FFI_RLNPartialProof(pp))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_finish_proof(
    rln: &repr_c::Box<FFI_RLN>,
    partial_proof: &repr_c::Box<FFI_RLNPartialProof>,
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> CResult<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    match rln.0.finish_proof(&partial_proof.0, &witness.0) {
        Ok((proof, values)) => CResult {
            ok: Some(Box_::new(FFI_RLNProof(RLNProof::new(proof, values)))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_free(rln: repr_c::Box<FFI_RLN>) {
    drop(rln);
}

// FFI_RLNWitnessInput

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_RLNWitnessInput(pub(crate) RLNWitnessInput);

#[ffi_export]
pub fn ffi_rln_witness_input_new_single(
    identity_secret: &CFr,
    user_message_limit: &CFr,
    message_id: &CFr,
    path_elements: &repr_c::Vec<CFr>,
    identity_path_index: &repr_c::Vec<u8>,
    x: &CFr,
    external_nullifier: &CFr,
) -> CResult<repr_c::Box<FFI_RLNWitnessInput>, repr_c::String> {
    let mut identity_secret_fr = identity_secret.0;
    let path_elements: Vec<Fr> = path_elements.iter().map(|cfr| cfr.0).collect();
    let identity_path_index: Vec<u8> = identity_path_index.iter().copied().collect();

    match RLNWitnessInput::new_single()
        .identity_secret(IdSecret::from(&mut identity_secret_fr))
        .user_message_limit(user_message_limit.0)
        .path_elements(path_elements)
        .identity_path_index(identity_path_index)
        .x(x.0)
        .external_nullifier(external_nullifier.0)
        .message_id(message_id.0)
        .build()
    {
        Ok(w) => CResult {
            ok: Some(Box_::new(FFI_RLNWitnessInput(w))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_new_multi(
    identity_secret: &CFr,
    user_message_limit: &CFr,
    message_ids: &repr_c::Vec<CFr>,
    path_elements: &repr_c::Vec<CFr>,
    identity_path_index: &repr_c::Vec<u8>,
    x: &CFr,
    external_nullifier: &CFr,
    selector_used: &repr_c::Vec<bool>,
) -> CResult<repr_c::Box<FFI_RLNWitnessInput>, repr_c::String> {
    let mut identity_secret_fr = identity_secret.0;
    let path_elements: Vec<Fr> = path_elements.iter().map(|cfr| cfr.0).collect();
    let identity_path_index: Vec<u8> = identity_path_index.iter().copied().collect();
    let message_ids: Vec<Fr> = message_ids.iter().map(|cfr| cfr.0).collect();
    let selector_used: Vec<bool> = selector_used.iter().copied().collect();

    match RLNWitnessInput::new_multi()
        .identity_secret(IdSecret::from(&mut identity_secret_fr))
        .user_message_limit(user_message_limit.0)
        .path_elements(path_elements)
        .identity_path_index(identity_path_index)
        .x(x.0)
        .external_nullifier(external_nullifier.0)
        .message_ids(message_ids)
        .selector_used(selector_used)
        .build()
    {
        Ok(w) => CResult {
            ok: Some(Box_::new(FFI_RLNWitnessInput(w))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_identity_secret(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> repr_c::Box<CFr> {
    CFr::from(**witness.0.identity_secret()).into()
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_user_message_limit(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> repr_c::Box<CFr> {
    CFr::from(witness.0.user_message_limit()).into()
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_message_id(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> CResult<repr_c::Box<CFr>, repr_c::String> {
    match witness.0.message_id() {
        Some(id) => CResult {
            ok: Some(CFr::from(id).into()),
            err: None,
        },
        None => CResult {
            ok: None,
            err: Some("witness is Multi; use get_message_ids".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_message_ids(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> CResult<repr_c::Vec<CFr>, repr_c::String> {
    match witness.0.message_ids() {
        Some(ids) => CResult {
            ok: Some(
                ids.iter()
                    .map(|fr| CFr::from(*fr))
                    .collect::<Vec<_>>()
                    .into(),
            ),
            err: None,
        },
        None => CResult {
            ok: None,
            err: Some("witness is Single; use get_message_id".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_path_elements(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> repr_c::Vec<CFr> {
    witness
        .0
        .path_elements()
        .iter()
        .map(|fr| CFr::from(*fr))
        .collect::<Vec<_>>()
        .into()
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_identity_path_index(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> repr_c::Vec<u8> {
    witness.0.identity_path_index().to_vec().into()
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_x(witness: &repr_c::Box<FFI_RLNWitnessInput>) -> repr_c::Box<CFr> {
    CFr::from(witness.0.x()).into()
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_external_nullifier(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> repr_c::Box<CFr> {
    CFr::from(witness.0.external_nullifier()).into()
}

#[ffi_export]
pub fn ffi_rln_witness_input_get_selector_used(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> CResult<repr_c::Vec<bool>, repr_c::String> {
    match witness.0.selector_used() {
        Some(s) => CResult {
            ok: Some(s.to_vec().into()),
            err: None,
        },
        None => CResult {
            ok: None,
            err: Some("witness is Single; selector_used is Multi-only".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_to_bytes_le(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match witness.0.serialize_compressed(&mut bytes) {
        Ok(()) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_witness_to_bytes_be(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeBE::serialize(&witness.0, &mut bytes) {
        Ok(()) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_le_to_rln_witness(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNWitnessInput>, repr_c::String> {
    match RLNWitnessInput::deserialize_compressed(&bytes[..]) {
        Ok(w) => CResult {
            ok: Some(Box_::new(FFI_RLNWitnessInput(w))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_be_to_rln_witness(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNWitnessInput>, repr_c::String> {
    match <RLNWitnessInput as CanonicalDeserializeBE>::deserialize(&bytes[..]) {
        Ok(w) => CResult {
            ok: Some(Box_::new(FFI_RLNWitnessInput(w))),
            err: None,
        },
        Err(err) => CResult {
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
    identity_secret: &CFr,
    user_message_limit: &CFr,
    path_elements: &repr_c::Vec<CFr>,
    identity_path_index: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNPartialWitnessInput>, repr_c::String> {
    let mut identity_secret_fr = identity_secret.0;
    let path_elements: Vec<Fr> = path_elements.iter().map(|cfr| cfr.0).collect();
    let identity_path_index: Vec<u8> = identity_path_index.iter().copied().collect();
    match RLNPartialWitnessInput::new()
        .identity_secret(IdSecret::from(&mut identity_secret_fr))
        .user_message_limit(user_message_limit.0)
        .path_elements(path_elements)
        .identity_path_index(identity_path_index)
        .build()
    {
        Ok(w) => CResult {
            ok: Some(Box_::new(FFI_RLNPartialWitnessInput(w))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_get_identity_secret(
    witness: &repr_c::Box<FFI_RLNPartialWitnessInput>,
) -> repr_c::Box<CFr> {
    CFr::from(*witness.0.identity_secret).into()
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_get_user_message_limit(
    witness: &repr_c::Box<FFI_RLNPartialWitnessInput>,
) -> repr_c::Box<CFr> {
    CFr::from(witness.0.user_message_limit).into()
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_get_path_elements(
    witness: &repr_c::Box<FFI_RLNPartialWitnessInput>,
) -> repr_c::Vec<CFr> {
    witness
        .0
        .path_elements
        .iter()
        .map(|fr| CFr::from(*fr))
        .collect::<Vec<_>>()
        .into()
}

#[ffi_export]
pub fn ffi_rln_partial_witness_input_get_identity_path_index(
    witness: &repr_c::Box<FFI_RLNPartialWitnessInput>,
) -> repr_c::Vec<u8> {
    witness.0.identity_path_index.to_vec().into()
}

#[ffi_export]
pub fn ffi_rln_witness_to_partial_witness(
    witness: &repr_c::Box<FFI_RLNWitnessInput>,
) -> repr_c::Box<FFI_RLNPartialWitnessInput> {
    let partial = RLNPartialWitnessInput::from(&witness.0);
    Box_::new(FFI_RLNPartialWitnessInput(partial))
}

#[ffi_export]
pub fn ffi_rln_partial_witness_to_bytes_le(
    witness: &repr_c::Box<FFI_RLNPartialWitnessInput>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match witness.0.serialize_compressed(&mut bytes) {
        Ok(()) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_partial_witness_to_bytes_be(
    witness: &repr_c::Box<FFI_RLNPartialWitnessInput>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeBE::serialize(&witness.0, &mut bytes) {
        Ok(()) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_le_to_rln_partial_witness(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNPartialWitnessInput>, repr_c::String> {
    match RLNPartialWitnessInput::deserialize_compressed(&bytes[..]) {
        Ok(w) => CResult {
            ok: Some(Box_::new(FFI_RLNPartialWitnessInput(w))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_be_to_rln_partial_witness(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNPartialWitnessInput>, repr_c::String> {
    match <RLNPartialWitnessInput as CanonicalDeserializeBE>::deserialize(&bytes[..]) {
        Ok(w) => CResult {
            ok: Some(Box_::new(FFI_RLNPartialWitnessInput(w))),
            err: None,
        },
        Err(err) => CResult {
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
pub fn ffi_rln_proof_get_values(
    rln_proof: &repr_c::Box<FFI_RLNProof>,
) -> repr_c::Box<FFI_RLNProofValues> {
    Box_::new(FFI_RLNProofValues(rln_proof.0.values.clone()))
}

#[ffi_export]
pub fn ffi_rln_proof_to_bytes_le(
    rln_proof: &repr_c::Box<FFI_RLNProof>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match rln_proof.0.serialize_compressed(&mut bytes) {
        Ok(()) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_to_bytes_mixed(
    rln_proof: &repr_c::Box<FFI_RLNProof>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeMixed::serialize(&rln_proof.0, &mut bytes) {
        Ok(()) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_le_to_rln_proof(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    match RLNProof::deserialize_compressed(&bytes[..]) {
        Ok(p) => CResult {
            ok: Some(Box_::new(FFI_RLNProof(p))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_mixed_to_rln_proof(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNProof>, repr_c::String> {
    match <RLNProof as CanonicalDeserializeMixed>::deserialize(&bytes[..]) {
        Ok(p) => CResult {
            ok: Some(Box_::new(FFI_RLNProof(p))),
            err: None,
        },
        Err(err) => CResult {
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
    partial_proof: &repr_c::Box<FFI_RLNPartialProof>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match partial_proof.0.serialize_compressed(&mut bytes) {
        Ok(()) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_le_to_rln_partial_proof(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNPartialProof>, repr_c::String> {
    match PartialProof::deserialize_compressed(&bytes[..]) {
        Ok(p) => CResult {
            ok: Some(Box_::new(FFI_RLNPartialProof(p))),
            err: None,
        },
        Err(err) => CResult {
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
pub fn ffi_rln_proof_values_get_root(pv: &repr_c::Box<FFI_RLNProofValues>) -> repr_c::Box<CFr> {
    CFr::from(pv.0.root()).into()
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_x(pv: &repr_c::Box<FFI_RLNProofValues>) -> repr_c::Box<CFr> {
    CFr::from(pv.0.x()).into()
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_external_nullifier(
    pv: &repr_c::Box<FFI_RLNProofValues>,
) -> repr_c::Box<CFr> {
    CFr::from(pv.0.external_nullifier()).into()
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_y(
    pv: &repr_c::Box<FFI_RLNProofValues>,
) -> CResult<repr_c::Box<CFr>, repr_c::String> {
    match pv.0.y() {
        Some(y) => CResult {
            ok: Some(CFr::from(y).into()),
            err: None,
        },
        None => CResult {
            ok: None,
            err: Some("values are Multi; use get_ys".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_nullifier(
    pv: &repr_c::Box<FFI_RLNProofValues>,
) -> CResult<repr_c::Box<CFr>, repr_c::String> {
    match pv.0.nullifier() {
        Some(n) => CResult {
            ok: Some(CFr::from(n).into()),
            err: None,
        },
        None => CResult {
            ok: None,
            err: Some("values are Multi; use get_nullifiers".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_selector_used(
    pv: &repr_c::Box<FFI_RLNProofValues>,
) -> CResult<repr_c::Vec<bool>, repr_c::String> {
    match pv.0.selector_used() {
        Some(s) => CResult {
            ok: Some(s.to_vec().into()),
            err: None,
        },
        None => CResult {
            ok: None,
            err: Some("values are Single; selector_used is Multi-only".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_ys(
    pv: &repr_c::Box<FFI_RLNProofValues>,
) -> CResult<repr_c::Vec<CFr>, repr_c::String> {
    match pv.0.ys() {
        Some(ys) => CResult {
            ok: Some(
                ys.iter()
                    .map(|fr| CFr::from(*fr))
                    .collect::<Vec<_>>()
                    .into(),
            ),
            err: None,
        },
        None => CResult {
            ok: None,
            err: Some("values are Single; use get_y".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_get_nullifiers(
    pv: &repr_c::Box<FFI_RLNProofValues>,
) -> CResult<repr_c::Vec<CFr>, repr_c::String> {
    match pv.0.nullifiers() {
        Some(ns) => CResult {
            ok: Some(
                ns.iter()
                    .map(|fr| CFr::from(*fr))
                    .collect::<Vec<_>>()
                    .into(),
            ),
            err: None,
        },
        None => CResult {
            ok: None,
            err: Some("values are Single; use get_nullifier".into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_to_bytes_le(
    pv: &repr_c::Box<FFI_RLNProofValues>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match pv.0.serialize_compressed(&mut bytes) {
        Ok(()) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_proof_values_to_bytes_be(
    pv: &repr_c::Box<FFI_RLNProofValues>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeBE::serialize(&pv.0, &mut bytes) {
        Ok(()) => CResult {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_le_to_rln_proof_values(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNProofValues>, repr_c::String> {
    match RLNProofValues::deserialize_compressed(&bytes[..]) {
        Ok(pv) => CResult {
            ok: Some(Box_::new(FFI_RLNProofValues(pv))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_bytes_be_to_rln_proof_values(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<FFI_RLNProofValues>, repr_c::String> {
    match <RLNProofValues as CanonicalDeserializeBE>::deserialize(&bytes[..]) {
        Ok(pv) => CResult {
            ok: Some(Box_::new(FFI_RLNProofValues(pv))),
            err: None,
        },
        Err(err) => CResult {
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
    share1_x: &CFr,
    share1_y: &CFr,
    share2_x: &CFr,
    share2_y: &CFr,
) -> CResult<repr_c::Box<CFr>, repr_c::String> {
    let share1 = (share1_x.0, share1_y.0);
    let share2 = (share2_x.0, share2_y.0);
    match compute_id_secret(share1, share2) {
        Ok(secret) => CResult {
            ok: Some(Box_::new(CFr::from(*secret))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_recover_id_secret(
    proof_values_1: &repr_c::Box<FFI_RLNProofValues>,
    proof_values_2: &repr_c::Box<FFI_RLNProofValues>,
) -> CResult<repr_c::Box<CFr>, repr_c::String> {
    match proof_values_1.0.recover_secret(&proof_values_2.0) {
        Ok(secret) => CResult {
            ok: Some(Box_::new(CFr::from(*secret))),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

// FFI_RLNMerkleProof

#[derive_ReprC]
#[repr(C)]
pub struct FFI_RLNMerkleProof {
    pub path_elements: repr_c::Vec<CFr>,
    pub path_index: repr_c::Vec<u8>,
}

#[ffi_export]
pub fn ffi_rln_merkle_proof_free(merkle_proof: repr_c::Box<FFI_RLNMerkleProof>) {
    drop(merkle_proof);
}

#[ffi_export]
pub fn ffi_rln_delete_leaf(rln: &mut repr_c::Box<FFI_RLN>, index: usize) -> CBoolResult {
    match rln.0.delete_leaf(index) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_set_leaf(rln: &mut repr_c::Box<FFI_RLN>, index: usize, leaf: &CFr) -> CBoolResult {
    match rln.0.set_leaf(index, leaf.0) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_get_leaf(
    rln: &repr_c::Box<FFI_RLN>,
    index: usize,
) -> CResult<repr_c::Box<CFr>, repr_c::String> {
    match rln.0.get_leaf(index) {
        Ok(leaf) => CResult {
            ok: Some(CFr::from(leaf).into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_leaves_set(rln: &repr_c::Box<FFI_RLN>) -> usize {
    rln.0.leaves_set().unwrap_or(0)
}

#[ffi_export]
pub fn ffi_rln_set_next_leaf(rln: &mut repr_c::Box<FFI_RLN>, leaf: &CFr) -> CBoolResult {
    match rln.0.set_next_leaf(leaf.0) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_set_leaves_from(
    rln: &mut repr_c::Box<FFI_RLN>,
    index: usize,
    leaves: &repr_c::Vec<CFr>,
) -> CBoolResult {
    let leaves_vec: Vec<_> = leaves.iter().map(|cfr| cfr.0).collect();
    match rln.0.set_leaves_from(index, leaves_vec) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_init_tree_with_leaves(
    rln: &mut repr_c::Box<FFI_RLN>,
    leaves: &repr_c::Vec<CFr>,
) -> CBoolResult {
    let leaves_vec: Vec<_> = leaves.iter().map(|cfr| cfr.0).collect();
    match rln.0.init_tree_with_leaves(leaves_vec) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_atomic_operation(
    rln: &mut repr_c::Box<FFI_RLN>,
    index: usize,
    leaves: &repr_c::Vec<CFr>,
    indices: &repr_c::Vec<usize>,
) -> CBoolResult {
    let leaves_vec: Vec<_> = leaves.iter().map(|cfr| cfr.0).collect();
    let indices_vec: Vec<_> = indices.iter().copied().collect();
    match rln.0.atomic_operation(index, leaves_vec, indices_vec) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_get_root(rln: &repr_c::Box<FFI_RLN>) -> repr_c::Box<CFr> {
    let root = rln.0.get_root().unwrap_or_else(|_| Fr::from(0u64));
    CFr::from(root).into()
}

#[ffi_export]
pub fn ffi_rln_get_merkle_proof(
    rln: &repr_c::Box<FFI_RLN>,
    index: usize,
) -> CResult<repr_c::Box<FFI_RLNMerkleProof>, repr_c::String> {
    match rln.0.get_merkle_proof(index) {
        Ok((path_elements, path_index)) => {
            let path_elements: repr_c::Vec<CFr> = path_elements
                .iter()
                .map(|fr| CFr::from(*fr))
                .collect::<Vec<_>>()
                .into();
            let path_index: repr_c::Vec<u8> = path_index.into();
            CResult {
                ok: Some(Box_::new(FFI_RLNMerkleProof {
                    path_elements,
                    path_index,
                })),
                err: None,
            }
        }
        Err(err) => CResult {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_set_metadata(
    rln: &mut repr_c::Box<FFI_RLN>,
    metadata: &repr_c::Vec<u8>,
) -> CBoolResult {
    match rln.0.set_metadata(metadata) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_get_metadata(
    rln: &repr_c::Box<FFI_RLN>,
) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    match rln.0.get_metadata() {
        Ok(metadata) => CResult {
            ok: Some(metadata.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.into()),
        },
    }
}

#[ffi_export]
pub fn ffi_rln_flush(rln: &mut repr_c::Box<FFI_RLN>) -> CBoolResult {
    match rln.0.flush() {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.into()),
        },
    }
}
