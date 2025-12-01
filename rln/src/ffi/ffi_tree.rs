#![allow(non_camel_case_types)]
#![cfg(not(feature = "stateless"))]

use safer_ffi::{boxed::Box_, derive_ReprC, ffi_export, prelude::repr_c};

use super::{
    ffi_rln::FFI_RLN,
    ffi_utils::{CBoolResult, CFr, CResult},
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
pub fn ffi_set_tree(rln: &mut repr_c::Box<FFI_RLN>, tree_depth: usize) -> CBoolResult {
    match rln.0.set_tree(tree_depth) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.to_string().into()),
        },
    }
}

// Merkle tree leaf operations

#[ffi_export]
pub fn ffi_delete_leaf(rln: &mut repr_c::Box<FFI_RLN>, index: usize) -> CBoolResult {
    match rln.0.delete_leaf(index) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_set_leaf(rln: &mut repr_c::Box<FFI_RLN>, index: usize, leaf: &CFr) -> CBoolResult {
    match rln.0.set_leaf(index, leaf.0) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_get_leaf(
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
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_leaves_set(rln: &repr_c::Box<FFI_RLN>) -> usize {
    rln.0.leaves_set()
}

#[ffi_export]
pub fn ffi_set_next_leaf(rln: &mut repr_c::Box<FFI_RLN>, leaf: &CFr) -> CBoolResult {
    match rln.0.set_next_leaf(leaf.0) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_set_leaves_from(
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
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_init_tree_with_leaves(
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
            err: Some(err.to_string().into()),
        },
    }
}

// Atomic operations

#[ffi_export]
pub fn ffi_atomic_operation(
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
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_seq_atomic_operation(
    rln: &mut repr_c::Box<FFI_RLN>,
    leaves: &repr_c::Vec<CFr>,
    indices: &repr_c::Vec<u8>,
) -> CBoolResult {
    let index = rln.0.leaves_set();
    let leaves_vec: Vec<_> = leaves.iter().map(|cfr| cfr.0).collect();
    let indices_vec: Vec<_> = indices.iter().map(|x| *x as usize).collect();
    match rln.0.atomic_operation(index, leaves_vec, indices_vec) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.to_string().into()),
        },
    }
}

// Root and proof operations

#[ffi_export]
pub fn ffi_get_root(rln: &repr_c::Box<FFI_RLN>) -> repr_c::Box<CFr> {
    CFr::from(rln.0.get_root()).into()
}

#[ffi_export]
pub fn ffi_get_proof(
    rln: &repr_c::Box<FFI_RLN>,
    index: usize,
) -> CResult<repr_c::Box<FFI_MerkleProof>, repr_c::String> {
    match rln.0.get_proof(index) {
        Ok((path_elements, path_index)) => {
            let path_elements: repr_c::Vec<CFr> = path_elements
                .iter()
                .map(|fr| CFr::from(*fr))
                .collect::<Vec<_>>()
                .into();

            let path_index: repr_c::Vec<u8> = path_index.into();

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
pub fn ffi_set_metadata(rln: &mut repr_c::Box<FFI_RLN>, metadata: &repr_c::Vec<u8>) -> CBoolResult {
    match rln.0.set_metadata(metadata) {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_get_metadata(rln: &repr_c::Box<FFI_RLN>) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    match rln.0.get_metadata() {
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

#[ffi_export]
pub fn ffi_flush(rln: &mut repr_c::Box<FFI_RLN>) -> CBoolResult {
    match rln.0.flush() {
        Ok(_) => CBoolResult {
            ok: true,
            err: None,
        },
        Err(err) => CBoolResult {
            ok: false,
            err: Some(err.to_string().into()),
        },
    }
}
