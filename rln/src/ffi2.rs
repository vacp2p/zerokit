#![allow(non_camel_case_types)]

use crate::{
    circuit::{graph_from_folder, zkey_from_folder, zkey_from_raw, Curve},
    hashers::{hash_to_field_be, hash_to_field_le, poseidon_hash},
    protocol::{
        compute_id_secret, extended_keygen, extended_seeded_keygen, generate_proof, keygen,
        proof_values_from_witness, seeded_keygen, verify_proof, RLNProofValues, RLNWitnessInput,
    },
    utils::{bytes_be_to_fr, bytes_le_to_fr, fr_to_bytes_be, fr_to_bytes_le, IdSecret},
};
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_groth16::{Proof as ArkProof, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use safer_ffi::prelude::ReprC;
use safer_ffi::{
    boxed::Box_,
    derive_ReprC, ffi_export,
    prelude::{c_slice, repr_c},
};
use std::ops::Deref;

#[cfg(not(feature = "stateless"))]
use {
    crate::poseidon_tree::PoseidonTree,
    safer_ffi::prelude::char_p,
    std::{fs::File, io::Read, str::FromStr},
    utils::{Hasher, ZerokitMerkleProof, ZerokitMerkleTree},
};

// CResult

#[derive_ReprC]
#[repr(C)]
pub struct CResult<T: ReprC, Err: ReprC> {
    pub ok: Option<T>,
    pub err: Option<Err>,
}

// CFr

#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CFr(Fr);

impl Default for CFr {
    fn default() -> Self {
        Self(Fr::ZERO)
    }
}

impl PartialEq<Fr> for CFr {
    fn eq(&self, other: &Fr) -> bool {
        self.0 == *other
    }
}

impl Deref for CFr {
    type Target = Fr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&CFr> for repr_c::Box<CFr> {
    fn from(cfr: &CFr) -> Self {
        Box_::new(CFr(cfr.0))
    }
}

impl From<Fr> for CFr {
    fn from(fr: Fr) -> Self {
        Self(fr)
    }
}

impl From<CFr> for repr_c::Box<CFr> {
    fn from(cfr: CFr) -> Self {
        Box_::new(cfr)
    }
}

#[ffi_export]
pub fn cfr_zero() -> repr_c::Box<CFr> {
    Box_::new(CFr::default())
}

#[ffi_export]
pub fn cfr_one() -> repr_c::Box<CFr> {
    Box_::new(CFr::from(Fr::ONE))
}

#[ffi_export]
pub fn cfr_to_bytes_le(cfr: &CFr) -> safer_ffi::Vec<u8> {
    fr_to_bytes_le(&cfr.0).into()
}

#[ffi_export]
pub fn cfr_to_bytes_be(cfr: &CFr) -> safer_ffi::Vec<u8> {
    fr_to_bytes_be(&cfr.0).into()
}

#[ffi_export]
pub fn cfr_from_bytes_le(bytes: safer_ffi::prelude::c_slice::Ref<'_, u8>) -> repr_c::Box<CFr> {
    let (cfr, _) = bytes_le_to_fr(bytes.as_ref());
    Box_::new(CFr(cfr))
}

#[ffi_export]
pub fn cfr_from_bytes_be(bytes: safer_ffi::prelude::c_slice::Ref<'_, u8>) -> repr_c::Box<CFr> {
    let (cfr, _) = bytes_be_to_fr(bytes.as_ref());
    Box_::new(CFr(cfr))
}

#[ffi_export]
pub fn cfr_from_uint(value: u32) -> repr_c::Box<CFr> {
    Box_::new(CFr::from(Fr::from(value)))
}

#[ffi_export]
pub fn cfr_debug(cfr: Option<&CFr>) -> repr_c::String {
    format!("{:?}", cfr.map(|c| c.to_string())).into()
}

#[ffi_export]
pub fn cfr_free(cfr: Option<repr_c::Box<CFr>>) {
    drop(cfr);
}

// Vec<CFr>

#[ffi_export]
pub fn vec_cfr_get(v: Option<&repr_c::Vec<CFr>>, i: usize) -> Option<&CFr> {
    v.and_then(|v| v.get(i))
}

#[ffi_export]
pub fn vec_cfr_free(v: repr_c::Vec<CFr>) {
    drop(v);
}

pub fn vec_cfr_to_bytes_le(vec: c_slice::Ref<'_, CFr>) -> repr_c::Vec<u8> {
    let fr_vec: Vec<Fr> = vec.iter().map(|cfr| cfr.0).collect();
    crate::utils::vec_fr_to_bytes_le(&fr_vec).into()
}

pub fn vec_cfr_to_bytes_be(vec: c_slice::Ref<'_, CFr>) -> repr_c::Vec<u8> {
    let fr_vec: Vec<Fr> = vec.iter().map(|cfr| cfr.0).collect();
    crate::utils::vec_fr_to_bytes_be(&fr_vec).into()
}

pub fn bytes_le_to_vec_cfr(
    bytes: c_slice::Ref<'_, u8>,
) -> CResult<repr_c::Vec<CFr>, repr_c::String> {
    match crate::utils::bytes_le_to_vec_fr(bytes.as_ref()) {
        Ok((fr_vec, _)) => {
            let cfr_vec: repr_c::Vec<CFr> =
                fr_vec.into_iter().map(CFr).collect::<Vec<CFr>>().into();
            CResult {
                ok: Some(cfr_vec),
                err: None,
            }
        }
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

pub fn bytes_be_to_vec_cfr(
    bytes: c_slice::Ref<'_, u8>,
) -> CResult<repr_c::Vec<CFr>, repr_c::String> {
    match crate::utils::bytes_be_to_vec_fr(bytes.as_ref()) {
        Ok((fr_vec, _)) => {
            let cfr_vec: repr_c::Vec<CFr> =
                fr_vec.into_iter().map(CFr).collect::<Vec<CFr>>().into();
            CResult {
                ok: Some(cfr_vec),
                err: None,
            }
        }
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

// Vec<u8>

#[ffi_export]
pub fn vec_u8_to_bytes_le(vec: c_slice::Ref<'_, u8>) -> repr_c::Vec<u8> {
    crate::utils::vec_u8_to_bytes_le(&vec).into()
}

#[ffi_export]
pub fn vec_u8_to_bytes_be(vec: c_slice::Ref<'_, u8>) -> repr_c::Vec<u8> {
    crate::utils::vec_u8_to_bytes_be(&vec).into()
}

#[ffi_export]
pub fn bytes_le_to_vec_u8(bytes: c_slice::Ref<'_, u8>) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    match crate::utils::bytes_le_to_vec_u8(bytes.as_ref()) {
        Ok((vec, _)) => CResult {
            ok: Some(vec.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn bytes_be_to_vec_u8(bytes: c_slice::Ref<'_, u8>) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    match crate::utils::bytes_be_to_vec_u8(bytes.as_ref()) {
        Ok((vec, _)) => CResult {
            ok: Some(vec.into()),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

// RLN

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI2_RLN {
    proving_key: (ProvingKey<Curve>, ConstraintMatrices<Fr>),
    #[cfg(not(target_arch = "wasm32"))]
    graph_data: Vec<u8>,
    #[cfg(not(feature = "stateless"))]
    tree: PoseidonTree,
}

////////////////////////////////////////////////////////
// RLN APIs
////////////////////////////////////////////////////////

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_new(
    tree_depth: usize,
    config_path: char_p::Ref<'_>,
) -> CResult<repr_c::Box<FFI2_RLN>, repr_c::String> {
    let tree_config = match File::open(config_path.to_str()).and_then(|mut file| {
        let mut config_str = String::new();
        file.read_to_string(&mut config_str)?;
        Ok(config_str)
    }) {
        Ok(config_str) if !config_str.is_empty() => {
            match <PoseidonTree as ZerokitMerkleTree>::Config::from_str(&config_str) {
                Ok(config) => config,
                Err(err) => {
                    return CResult {
                        ok: None,
                        err: Some(err.to_string().into()),
                    };
                }
            }
        }
        _ => <PoseidonTree as ZerokitMerkleTree>::Config::default(),
    };

    let proving_key = zkey_from_folder().to_owned();
    let graph_data = graph_from_folder().to_owned();

    // We compute a default empty tree
    let tree = match PoseidonTree::new(
        tree_depth,
        <PoseidonTree as ZerokitMerkleTree>::Hasher::default_leaf(),
        tree_config,
    ) {
        Ok(tree) => tree,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let rln = FFI2_RLN {
        proving_key: proving_key.to_owned(),
        graph_data: graph_data.to_vec(),
        #[cfg(not(feature = "stateless"))]
        tree,
    };

    CResult {
        ok: Some(Box_::new(rln)),
        err: None,
    }
}

#[cfg(feature = "stateless")]
#[ffi_export]
pub fn ffi2_new() -> CResult<repr_c::Box<FFI2_RLN>, repr_c::String> {
    let proving_key = zkey_from_folder().to_owned();
    let graph_data = graph_from_folder().to_owned();

    let rln = FFI2_RLN {
        proving_key: proving_key.to_owned(),
        graph_data: graph_data.to_vec(),
    };

    CResult {
        ok: Some(Box_::new(rln)),
        err: None,
    }
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_new_with_params(
    tree_depth: usize,
    zkey_buffer: c_slice::Ref<'_, u8>,
    graph_data: c_slice::Ref<'_, u8>,
    config_path: char_p::Ref<'_>,
) -> CResult<repr_c::Box<FFI2_RLN>, repr_c::String> {
    let tree_config = match File::open(config_path.to_str()).and_then(|mut file| {
        let mut config_str = String::new();
        file.read_to_string(&mut config_str)?;
        Ok(config_str)
    }) {
        Ok(config_str) if !config_str.is_empty() => {
            match <PoseidonTree as ZerokitMerkleTree>::Config::from_str(&config_str) {
                Ok(config) => config,
                Err(err) => {
                    return CResult {
                        ok: None,
                        err: Some(err.to_string().into()),
                    };
                }
            }
        }
        _ => <PoseidonTree as ZerokitMerkleTree>::Config::default(),
    };

    let proving_key = match zkey_from_raw(&zkey_buffer) {
        Ok(pk) => pk,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };
    let graph_data_vec = graph_data.to_vec();

    // We compute a default empty tree
    let tree = match PoseidonTree::new(
        tree_depth,
        <PoseidonTree as ZerokitMerkleTree>::Hasher::default_leaf(),
        tree_config,
    ) {
        Ok(tree) => tree,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let rln = FFI2_RLN {
        proving_key,
        graph_data: graph_data_vec,
        #[cfg(not(feature = "stateless"))]
        tree,
    };

    CResult {
        ok: Some(Box_::new(rln)),
        err: None,
    }
}

#[cfg(feature = "stateless")]
#[ffi_export]
pub fn ffi2_new_with_params(
    zkey_buffer: c_slice::Ref<'_, u8>,
    graph_data: c_slice::Ref<'_, u8>,
) -> CResult<repr_c::Box<FFI2_RLN>, repr_c::String> {
    let proving_key = match zkey_from_raw(&zkey_buffer) {
        Ok(pk) => pk,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };
    let graph_data_vec = graph_data.to_vec();

    let rln = FFI2_RLN {
        proving_key,
        graph_data: graph_data_vec,
    };

    CResult {
        ok: Some(Box_::new(rln)),
        err: None,
    }
}

#[ffi_export]
pub fn ffi2_rln_free(rln: Option<repr_c::Box<FFI2_RLN>>) {
    drop(rln);
}

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

#[cfg(feature = "stateless")]
#[ffi_export]
pub fn ffi2_generate_rln_proof_stateless(
    rln: &repr_c::Box<FFI2_RLN>,
    identity_secret: &CFr,
    user_message_limit: &CFr,
    message_id: &CFr,
    path_elements: &repr_c::Vec<CFr>,
    identity_path_index: &repr_c::Vec<u8>,
    x: &CFr,
    external_nullifier: &CFr,
) -> CResult<repr_c::Box<FFI2_RLNProof>, repr_c::String> {
    let mut identity_secret_fr = identity_secret.0;
    let path_elements_vec: Vec<Fr> = path_elements.iter().map(|cfr| cfr.0).collect();
    let identity_path_index_vec: Vec<u8> = identity_path_index.iter().copied().collect();
    let rln_witness = match RLNWitnessInput::new(
        IdSecret::from(&mut identity_secret_fr),
        user_message_limit.0,
        message_id.0,
        path_elements_vec,
        identity_path_index_vec,
        x.0,
        external_nullifier.0,
    ) {
        Ok(witness) => witness,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let proof_values = match proof_values_from_witness(&rln_witness) {
        Ok(pv) => pv,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let proof = match generate_proof(&rln.proving_key, &rln_witness, &rln.graph_data) {
        Ok(proof) => proof,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    CResult {
        ok: Some(Box_::new(FFI2_RLNProof {
            proof_values,
            proof,
        })),
        err: None,
    }
}

// RLNProof

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI2_RLNProof {
    proof: ArkProof<Curve>,
    proof_values: RLNProofValues,
}

#[ffi_export]
pub fn ffi2_rln_proof_free(rln: Option<repr_c::Box<FFI2_RLNProof>>) {
    drop(rln);
}

////////////////////////////////////////////////////////
// Merkle tree APIs
////////////////////////////////////////////////////////

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

////////////////////////////////////////////////////////
// zkSNARKs APIs
////////////////////////////////////////////////////////

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_generate_rln_proof(
    rln: &repr_c::Box<FFI2_RLN>,
    identity_secret: &CFr,
    user_message_limit: &CFr,
    message_id: &CFr,
    x: &CFr,
    external_nullifier: &CFr,
    leaf_index: usize,
) -> CResult<repr_c::Box<FFI2_RLNProof>, repr_c::String> {
    let proof = match rln.tree.proof(leaf_index) {
        Ok(proof) => proof,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let path_elements_vec: Vec<Fr> = proof.get_path_elements();
    let identity_path_index_vec: Vec<u8> = proof.get_path_index();

    let mut identity_secret_fr = identity_secret.0;
    let rln_witness = match RLNWitnessInput::new(
        IdSecret::from(&mut identity_secret_fr),
        user_message_limit.0,
        message_id.0,
        path_elements_vec,
        identity_path_index_vec,
        x.0,
        external_nullifier.0,
    ) {
        Ok(witness) => witness,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let proof_values = match proof_values_from_witness(&rln_witness) {
        Ok(pv) => pv,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    let proof = match generate_proof(&rln.proving_key, &rln_witness, &rln.graph_data) {
        Ok(proof) => proof,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    CResult {
        ok: Some(Box_::new(FFI2_RLNProof {
            proof_values,
            proof,
        })),
        err: None,
    }
}

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_verify_rln_proof(
    rln: &repr_c::Box<FFI2_RLN>,
    proof: &repr_c::Box<FFI2_RLNProof>,
    x: &CFr,
) -> CResult<repr_c::Box<bool>, repr_c::String> {
    // Verify the proof
    match verify_proof(&rln.proving_key.0.vk, &proof.proof, &proof.proof_values) {
        Ok(proof_verified) => {
            // Verify the root and signal
            let roots_verified = rln.tree.root() == proof.proof_values.root;
            let signal_verified = *x == proof.proof_values.x;
            CResult {
                ok: Some(Box_::new(
                    proof_verified && roots_verified && signal_verified,
                )),
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
pub fn ffi2_verify_with_roots(
    rln: &repr_c::Box<FFI2_RLN>,
    proof: &repr_c::Box<FFI2_RLNProof>,
    roots: &repr_c::Vec<CFr>,
    x: &CFr,
) -> CResult<repr_c::Box<bool>, repr_c::String> {
    // Verify the proof
    let proof_verified =
        match verify_proof(&rln.proving_key.0.vk, &proof.proof, &proof.proof_values) {
            Ok(v) => v,
            Err(err) => {
                return CResult {
                    ok: None,
                    err: Some(err.to_string().into()),
                };
            }
        };

    // If proof verification failed, return early
    if !proof_verified {
        return CResult {
            ok: Some(Box_::new(false)),
            err: None,
        };
    }

    // Verify the root
    let roots_verified: bool = if roots.is_empty() {
        // If no root is passed in roots_buffer, we skip proof's root check
        true
    } else {
        // We check if the proof's root is in roots
        roots.iter().any(|root| root.0 == proof.proof_values.root)
    };

    // Verify the signal
    let signal_verified = *x == proof.proof_values.x;

    CResult {
        ok: Some(Box_::new(
            proof_verified && roots_verified && signal_verified,
        )),
        err: None,
    }
}

////////////////////////////////////////////////////////
// Utils
////////////////////////////////////////////////////////

#[ffi_export]
pub fn ffi2_recover_id_secret(
    proof_1: &repr_c::Box<FFI2_RLNProof>,
    proof_2: &repr_c::Box<FFI2_RLNProof>,
) -> CResult<repr_c::Box<CFr>, repr_c::String> {
    let external_nullifier_1 = proof_1.proof_values.external_nullifier;
    let external_nullifier_2 = proof_2.proof_values.external_nullifier;

    // We continue only if the proof values are for the same external nullifier
    if external_nullifier_1 != external_nullifier_2 {
        return CResult {
            ok: None,
            err: Some("External nullifiers do not match".to_string().into()),
        };
    }

    // We extract the two shares
    let share1 = (proof_1.proof_values.x, proof_1.proof_values.y);
    let share2 = (proof_2.proof_values.x, proof_2.proof_values.y);

    // We recover the secret
    let recovered_identity_secret_hash = match compute_id_secret(share1, share2) {
        Ok(secret) => secret,
        Err(err) => {
            return CResult {
                ok: None,
                err: Some(err.to_string().into()),
            };
        }
    };

    CResult {
        ok: Some(CFr::from(*recovered_identity_secret_hash).into()),
        err: None,
    }
}

////////////////////////////////////////////////////////
// Persistent metadata APIs
////////////////////////////////////////////////////////

#[cfg(not(feature = "stateless"))]
#[ffi_export]
pub fn ffi2_set_metadata(
    rln: &mut repr_c::Box<FFI2_RLN>,
    metadata: c_slice::Ref<'_, u8>,
) -> CResult<repr_c::Box<bool>, repr_c::String> {
    match rln.tree.set_metadata(&metadata) {
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
pub fn ffi2_get_metadata(
    rln: &repr_c::Box<FFI2_RLN>,
) -> CResult<repr_c::Box<[u8]>, repr_c::String> {
    match rln.tree.metadata() {
        Ok(metadata) => CResult {
            ok: Some(metadata.into_boxed_slice().into()),
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

/// ////////////////////////////////////////////////////////
// Utils APIs
////////////////////////////////////////////////////////

#[ffi_export]
pub fn ffi2_hash_to_field_le(input: c_slice::Ref<'_, u8>) -> repr_c::Box<CFr> {
    let hash_result = hash_to_field_le(&input);
    CFr::from(hash_result).into()
}

#[ffi_export]
pub fn ffi2_hash_to_field_be(input: c_slice::Ref<'_, u8>) -> repr_c::Box<CFr> {
    let hash_result = hash_to_field_be(&input);
    CFr::from(hash_result).into()
}

#[ffi_export]
pub fn ffi2_poseidon_hash(inputs: &repr_c::Vec<CFr>) -> repr_c::Box<CFr> {
    let inputs_vec: Vec<Fr> = inputs.iter().map(|cfr| cfr.0).collect();
    let hash_result = poseidon_hash(&inputs_vec);
    CFr::from(hash_result).into()
}

#[ffi_export]
pub fn ffi2_key_gen() -> repr_c::Vec<CFr> {
    let (identity_secret_hash, id_commitment) = keygen();
    vec![CFr(*identity_secret_hash), CFr(id_commitment)].into()
}

#[ffi_export]
pub fn ffi2_seeded_key_gen(seed: c_slice::Ref<'_, u8>) -> repr_c::Vec<CFr> {
    let (identity_secret_hash, id_commitment) = seeded_keygen(&seed);
    vec![CFr(identity_secret_hash), CFr(id_commitment)].into()
}

#[ffi_export]
pub fn ffi2_extended_key_gen() -> repr_c::Vec<CFr> {
    let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
        extended_keygen();
    vec![
        CFr(identity_trapdoor),
        CFr(identity_nullifier),
        CFr(identity_secret_hash),
        CFr(id_commitment),
    ]
    .into()
}

#[ffi_export]
pub fn ffi2_seeded_extended_key_gen(seed: c_slice::Ref<'_, u8>) -> repr_c::Vec<CFr> {
    let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
        extended_seeded_keygen(&seed);
    vec![
        CFr(identity_trapdoor),
        CFr(identity_nullifier),
        CFr(identity_secret_hash),
        CFr(id_commitment),
    ]
    .into()
}

// The following function is only necessary for the header generation.
#[cfg(feature = "headers")] // c.f. the `Cargo.toml` section
pub fn generate_headers() -> ::std::io::Result<()> {
    ::safer_ffi::headers::builder().to_file("rln.h")?.generate()
}
