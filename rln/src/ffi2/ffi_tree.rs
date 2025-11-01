#![allow(non_camel_case_types)]

#[cfg(not(feature = "stateless"))]
use {
    super::ffi_rln::FFI2_RLN,
    super::ffi_utils::{CFr, CResult},
    crate::poseidon_tree::PoseidonTree,
    safer_ffi::{boxed::Box_, derive_ReprC, ffi_export, prelude::repr_c},
    utils::{ZerokitMerkleProof, ZerokitMerkleTree},
};

// MerkleProof

#[cfg(not(feature = "stateless"))]
#[derive_ReprC]
#[repr(C)]
pub struct FFI2_MerkleProof {
    pub path_elements: repr_c::Vec<CFr>,
    pub path_index: repr_c::Vec<u8>,
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_merkle_proof_free(proof: Option<repr_c::Box<FFI2_MerkleProof>>) {
    drop(proof);
}

// Merkle tree management APIs

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_set_tree(
    rln: &mut repr_c::Box<FFI2_RLN>,
    tree_depth: usize,
) -> CResult<repr_c::Box<bool>, repr_c::String> {
    // We compute a default empty tree of desired depth
    match PoseidonTree::default(tree_depth) {
        Ok(tree) => {
            rln.tree = tree;
            CResult {
                ok: Some(Box_::new(true)),
                err: None,
            }
        }
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

// Merkle tree leaf operations

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_delete_leaf(
    rln: &mut repr_c::Box<FFI2_RLN>,
    index: usize,
) -> CResult<repr_c::Box<bool>, repr_c::String> {
    match rln.tree.delete(index) {
        Ok(_) => CResult {
            ok: Some(Box_::new(true)),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_set_leaf(
    rln: &mut repr_c::Box<FFI2_RLN>,
    index: usize,
    value: &repr_c::Box<CFr>,
) -> CResult<repr_c::Box<bool>, repr_c::String> {
    match rln.tree.set(index, value.0) {
        Ok(_) => CResult {
            ok: Some(Box_::new(true)),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_get_leaf(
    rln: &repr_c::Box<FFI2_RLN>,
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

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_leaves_set(rln: &repr_c::Box<FFI2_RLN>) -> usize {
    rln.tree.leaves_set()
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_set_next_leaf(
    rln: &mut repr_c::Box<FFI2_RLN>,
    value: &repr_c::Box<CFr>,
) -> CResult<repr_c::Box<bool>, repr_c::String> {
    match rln.tree.update_next(value.0) {
        Ok(_) => CResult {
            ok: Some(Box_::new(true)),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_set_leaves_from(
    rln: &mut repr_c::Box<FFI2_RLN>,
    index: usize,
    leaves: &repr_c::Vec<CFr>,
) -> CResult<repr_c::Box<bool>, repr_c::String> {
    match rln
        .tree
        .override_range(index, leaves.iter().map(|cfr| cfr.0), [].into_iter())
    {
        Ok(_) => CResult {
            ok: Some(Box_::new(true)),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_init_tree_with_leaves(
    rln: &mut repr_c::Box<FFI2_RLN>,
    leaves: &repr_c::Vec<CFr>,
) -> CResult<repr_c::Box<bool>, repr_c::String> {
    // Reset tree to default
    let tree_depth = rln.tree.depth();
    match PoseidonTree::default(tree_depth) {
        Ok(tree) => {
            rln.tree = tree;
        }
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            }
        }
    }

    match rln
        .tree
        .override_range(0, leaves.iter().map(|cfr| cfr.0), [].into_iter())
    {
        Ok(_) => CResult {
            ok: Some(Box_::new(true)),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

// Atomic operations

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_atomic_operation(
    rln: &mut repr_c::Box<FFI2_RLN>,
    index: usize,
    leaves: &repr_c::Vec<CFr>,
    indices: &repr_c::Vec<usize>,
) -> CResult<repr_c::Box<bool>, repr_c::String> {
    match rln.tree.override_range(
        index,
        leaves.iter().map(|cfr| cfr.0),
        indices.iter().copied(),
    ) {
        Ok(_) => CResult {
            ok: Some(Box_::new(true)),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_seq_atomic_operation(
    rln: &mut repr_c::Box<FFI2_RLN>,
    leaves: &repr_c::Vec<CFr>,
    indices: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<bool>, repr_c::String> {
    let index = rln.tree.leaves_set();
    match rln.tree.override_range(
        index,
        leaves.iter().map(|cfr| cfr.0),
        indices.iter().map(|x| *x as usize),
    ) {
        Ok(_) => CResult {
            ok: Some(Box_::new(true)),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

// Root and proof operations

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_get_root(rln: &repr_c::Box<FFI2_RLN>) -> repr_c::Box<CFr> {
    CFr::from(rln.tree.root()).into()
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_get_proof(
    rln: &repr_c::Box<FFI2_RLN>,
    index: usize,
) -> CResult<repr_c::Box<FFI2_MerkleProof>, repr_c::String> {
    match rln.tree.proof(index) {
        Ok(proof) => {
            let path_elements: repr_c::Vec<CFr> = proof
                .get_path_elements()
                .iter()
                .map(|fr| CFr::from(*fr))
                .collect::<Vec<_>>()
                .into();

            let path_index: repr_c::Vec<u8> = proof.get_path_index().into();

            let merkle_proof = FFI2_MerkleProof {
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

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_set_metadata(
    rln: &mut repr_c::Box<FFI2_RLN>,
    metadata: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<bool>, repr_c::String> {
    match rln.tree.set_metadata(metadata) {
        Ok(_) => CResult {
            ok: Some(Box_::new(true)),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_get_metadata(rln: &repr_c::Box<FFI2_RLN>) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    match rln.tree.metadata() {
        Ok(metadata) => CResult {
            ok: Some(metadata.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_flush(rln: &mut repr_c::Box<FFI2_RLN>) -> CResult<repr_c::Box<bool>, repr_c::String> {
    match rln.tree.close_db_connection() {
        Ok(_) => CResult {
            ok: Some(Box_::new(true)),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}
