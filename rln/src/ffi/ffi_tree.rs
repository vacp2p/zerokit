#![allow(non_camel_case_types)]
#![cfg(not(feature = "stateless"))]

use {
    super::ffi_rln::FFI_RLN,
    super::ffi_utils::{CFr, CResult},
    crate::poseidon_tree::PoseidonTree,
    safer_ffi::{boxed::Box_, derive_ReprC, ffi_export, prelude::repr_c},
    utils::{ZerokitMerkleProof, ZerokitMerkleTree},
};

// MerkleProof

#[derive_ReprC]
#[repr(C)]
pub struct FFI_MerkleProof {
    pub path_elements: repr_c::Vec<CFr>,
    pub path_index: repr_c::Vec<u8>,
}

#[ffi_export]
pub fn ffi_merkle_proof_free(merkle_proof: repr_c::Box<FFI_MerkleProof>) {
    drop(merkle_proof);
}

// Merkle tree management APIs

#[ffi_export]
pub fn ffi_set_tree(rln: &mut repr_c::Box<FFI_RLN>, tree_depth: usize) -> Option<repr_c::String> {
    // We compute a default empty tree of desired depth
    match PoseidonTree::default(tree_depth) {
        Ok(tree) => {
            rln.tree = tree;
            None
        }
        Err(err) => Some(err.to_string().into()),
    }
}

// Merkle tree leaf operations

#[ffi_export]
pub fn ffi_delete_leaf(rln: &mut repr_c::Box<FFI_RLN>, index: usize) -> Option<repr_c::String> {
    match rln.tree.delete(index) {
        Ok(_) => None,
        Err(err) => Some(err.to_string().into()),
    }
}

#[ffi_export]
pub fn ffi_set_leaf(
    rln: &mut repr_c::Box<FFI_RLN>,
    index: usize,
    value: &repr_c::Box<CFr>,
) -> Option<repr_c::String> {
    match rln.tree.set(index, value.0) {
        Ok(_) => None,
        Err(err) => Some(err.to_string().into()),
    }
}

#[ffi_export]
pub fn ffi_get_leaf(
    rln: &repr_c::Box<FFI_RLN>,
    index: usize,
) -> CResult<repr_c::Box<CFr>, repr_c::String> {
    match rln.tree.get(index) {
        Ok(leaf) => CResult {
            ok: Some(CFr::from(leaf).into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_leaves_set(rln: &repr_c::Box<FFI_RLN>) -> usize {
    rln.tree.leaves_set()
}

#[ffi_export]
pub fn ffi_set_next_leaf(
    rln: &mut repr_c::Box<FFI_RLN>,
    value: &repr_c::Box<CFr>,
) -> Option<repr_c::String> {
    match rln.tree.update_next(value.0) {
        Ok(_) => None,
        Err(err) => Some(err.to_string().into()),
    }
}

#[ffi_export]
pub fn ffi_set_leaves_from(
    rln: &mut repr_c::Box<FFI_RLN>,
    index: usize,
    leaves: &repr_c::Vec<CFr>,
) -> Option<repr_c::String> {
    match rln
        .tree
        .override_range(index, leaves.iter().map(|cfr| cfr.0), [].into_iter())
    {
        Ok(_) => None,
        Err(err) => Some(err.to_string().into()),
    }
}

#[ffi_export]
pub fn ffi_init_tree_with_leaves(
    rln: &mut repr_c::Box<FFI_RLN>,
    leaves: &repr_c::Vec<CFr>,
) -> Option<repr_c::String> {
    // Reset tree to default
    let tree_depth = rln.tree.depth();
    if let Err(err) = PoseidonTree::default(tree_depth) {
        return Some(err.to_string().into());
    };

    match rln
        .tree
        .override_range(0, leaves.iter().map(|cfr| cfr.0), [].into_iter())
    {
        Ok(_) => None,
        Err(err) => Some(err.to_string().into()),
    }
}

// Atomic operations

#[ffi_export]
pub fn ffi_atomic_operation(
    rln: &mut repr_c::Box<FFI_RLN>,
    index: usize,
    leaves: &repr_c::Vec<CFr>,
    indices: &repr_c::Vec<usize>,
) -> Option<repr_c::String> {
    match rln.tree.override_range(
        index,
        leaves.iter().map(|cfr| cfr.0),
        indices.iter().copied(),
    ) {
        Ok(_) => None,
        Err(err) => Some(err.to_string().into()),
    }
}

#[ffi_export]
pub fn ffi_seq_atomic_operation(
    rln: &mut repr_c::Box<FFI_RLN>,
    leaves: &repr_c::Vec<CFr>,
    indices: &repr_c::Vec<u8>,
) -> Option<repr_c::String> {
    let index = rln.tree.leaves_set();
    match rln.tree.override_range(
        index,
        leaves.iter().map(|cfr| cfr.0),
        indices.iter().map(|x| *x as usize),
    ) {
        Ok(_) => None,
        Err(err) => Some(err.to_string().into()),
    }
}

// Root and proof operations

#[ffi_export]
pub fn ffi_get_root(rln: &repr_c::Box<FFI_RLN>) -> repr_c::Box<CFr> {
    CFr::from(rln.tree.root()).into()
}

#[ffi_export]
pub fn ffi_get_proof(
    rln: &repr_c::Box<FFI_RLN>,
    index: usize,
) -> CResult<repr_c::Box<FFI_MerkleProof>, repr_c::String> {
    match rln.tree.proof(index) {
        Ok(proof) => {
            let path_elements: repr_c::Vec<CFr> = proof
                .get_path_elements()
                .iter()
                .map(|fr| CFr::from(*fr))
                .collect::<Vec<_>>()
                .into();

            let path_index: repr_c::Vec<u8> = proof.get_path_index().into();

            let merkle_proof = FFI_MerkleProof {
                path_elements,
                path_index,
            };

            CResult {
                ok: Some(Box_::new(merkle_proof)),
                err: None,
            }
        }
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

// Persistent metadata APIs

#[ffi_export]
pub fn ffi_set_metadata(
    rln: &mut repr_c::Box<FFI_RLN>,
    metadata: &repr_c::Vec<u8>,
) -> Option<repr_c::String> {
    match rln.tree.set_metadata(metadata) {
        Ok(_) => None,
        Err(err) => Some(err.to_string().into()),
    }
}

#[ffi_export]
pub fn ffi_get_metadata(
    rln: &repr_c::Box<FFI_RLN>,
) -> CResult<repr_c::Box<repr_c::Vec<u8>>, repr_c::String> {
    match rln.tree.metadata() {
        Ok(metadata) => CResult {
            ok: Some(Box_::new(metadata.into())),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_flush(rln: &mut repr_c::Box<FFI_RLN>) -> Option<repr_c::String> {
    match rln.tree.close_db_connection() {
        Ok(_) => None,
        Err(err) => Some(err.to_string().into()),
    }
}
