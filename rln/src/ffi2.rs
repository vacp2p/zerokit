#![allow(non_camel_case_types)]

use crate::{
    circuit::{graph_from_folder, zkey_from_folder, zkey_from_raw, Curve},
    hashers::hash_to_field_le,
    poseidon_tree::PoseidonTree,
    protocol::{
        extended_keygen, extended_seeded_keygen, generate_proof, keygen, proof_values_from_witness,
        seeded_keygen, verify_proof, RLNProofValues, RLNWitnessInput,
    },
    utils::IdSecret,
};
use ark_bn254::Fr;
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use num_traits::Zero;
use safer_ffi::prelude::ReprC;
use safer_ffi::{
    boxed::Box_,
    derive_ReprC, ffi_export,
    prelude::{c_slice, char_p, repr_c},
};
use std::ops::Deref;
use std::str::FromStr;
use utils::{Hasher, ZerokitMerkleProof, ZerokitMerkleTree};

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
#[derive(Debug, Clone)]
pub struct CFr(Fr);

impl Default for CFr {
    fn default() -> Self {
        Self(Fr::zero())
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
fn cfr_zero<'a>() -> repr_c::Box<CFr> {
    Box_::new(CFr::default())
}

#[ffi_export]
fn cfr_debug(cfr: Option<&CFr>) {
    println!("{:?}", cfr);
}

#[ffi_export]
fn cfr_free(cfr: Option<repr_c::Box<CFr>>) {
    drop(cfr);
}

// Vec<CFr>

#[ffi_export]
fn vec_cfr_get(v: Option<&repr_c::Vec<CFr>>, i: usize) -> Option<&CFr> {
    v.and_then(|v| v.get(i))
}

#[ffi_export]
fn vec_cfr_free(v: repr_c::Vec<CFr>) {
    drop(v);
}

// RLN

/// The RLN object.
///
/// It implements the methods required to update the internal Merkle Tree, generate and verify RLN ZK proofs.
#[derive_ReprC]
#[repr(opaque)]
pub struct FFI2_RLN {
    proving_key: (ProvingKey<Curve>, ConstraintMatrices<Fr>),
    pub(crate) verification_key: VerifyingKey<Curve>,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) graph_data: Vec<u8>,
    #[cfg(not(feature = "stateless"))]
    pub(crate) tree: PoseidonTree,
}

// RLN functions

#[ffi_export]
pub fn ffi2_new(
    tree_depth: usize,
    config: char_p::Ref<'_>,
) -> CResult<repr_c::Box<FFI2_RLN>, repr_c::String> {
    let proving_key = zkey_from_folder().to_owned();
    let verification_key = proving_key.0.vk.to_owned();
    let graph_data = graph_from_folder().to_owned();
    let tree_config = {
        let config_str = config.to_str();
        if config_str.is_empty() {
            <PoseidonTree as ZerokitMerkleTree>::Config::default()
        } else {
            match <PoseidonTree as ZerokitMerkleTree>::Config::from_str(config_str) {
                Ok(config) => config,
                Err(err) => {
                    return CResult {
                        ok: None,
                        err: Some(err.to_string().into()),
                    };
                }
            }
        }
    };

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
        verification_key: verification_key.to_owned(),
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
pub fn ffi2_new() {
    let proving_key = zkey_from_folder().to_owned();
    let verification_key = proving_key.0.vk.to_owned();
    let graph_data = graph_from_folder().to_owned();

    let rln = FFI2_RLN {
        proving_key: proving_key.to_owned(),
        verification_key: verification_key.to_owned(),
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
    config: char_p::Ref<'_>,
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
    let verification_key = proving_key.0.vk.to_owned();
    let graph_data_vec = graph_data.to_vec();

    let tree_config = {
        let config_str = config.to_str();
        if config_str.is_empty() {
            <PoseidonTree as ZerokitMerkleTree>::Config::default()
        } else {
            match <PoseidonTree as ZerokitMerkleTree>::Config::from_str(config_str) {
                Ok(config) => config,
                Err(err) => {
                    return CResult {
                        ok: None,
                        err: Some(err.to_string().into()),
                    };
                }
            }
        }
    };

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
        verification_key,
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
    let verification_key = proving_key.0.vk.to_owned();
    let graph_data_vec = graph_data.to_vec();

    let rln = FFI2_RLN {
        proving_key,
        verification_key,
        graph_data: graph_data_vec,
    };

    CResult {
        ok: Some(Box_::new(rln)),
        err: None,
    }
}

#[ffi_export]
fn ffi2_rln_free(rln: Option<repr_c::Box<FFI2_RLN>>) {
    drop(rln);
}

/*
#[ffi_export]
fn ffi_init_witness_input<'a>(rln: &FFI2_RLN,
                              tree_index: usize,
                              identity_secret: &CFr,
                              user_message_limit: &CFr,
                              message_id: &CFr,
                              external_nullifier: &CFr,
                              signal: c_slice::Ref<'_, u8>
) -> Option<repr_c::Box<FFI2_RLNWitnessInput>> {

    let merkle_proof = rln.tree.proof(tree_index).expect("proof should exist");
    let path_elements = merkle_proof.get_path_elements();
    let identity_path_index = merkle_proof.get_path_index();

    let x = hash_to_field_le(&signal);

    let witness = FFI2_RLNWitnessInput {
        identity_secret: Box_::new(identity_secret.clone()),
        user_message_limit: Box_::new(user_message_limit.clone()),
        message_id: Box_::new(message_id.clone()),
        // TODO / FIXME
        // path_elements: path_elements.into_iter().map(|fr| CFr(fr)).collect(),
        path_elements: repr_c::Vec::EMPTY,
        identity_path_index: identity_path_index
            .into_boxed_slice()
            .into(),
        x: Box_::new(CFr(x)),
        external_nullifier: Box_::new(external_nullifier.clone()),
    };

    Some(Box_::new(witness))
}
*/

// MerkleProof

#[derive_ReprC]
#[repr(C)]
pub struct FFI2_MerkleProof {
    pub path_elements: repr_c::Vec<CFr>,
    pub path_index: repr_c::Vec<u8>,
}

#[ffi_export]
fn ffi2_merkle_proof_free(proof: Option<repr_c::Box<FFI2_MerkleProof>>) {
    drop(proof);
}

// RLNWitnessInput

#[derive_ReprC]
#[repr(C)]
pub struct FFI2_RLNWitnessInput {
    pub identity_secret: repr_c::Box<CFr>,
    pub user_message_limit: repr_c::Box<CFr>,
    pub message_id: repr_c::Box<CFr>,
    pub external_nullifier: repr_c::Box<CFr>,
    pub tree_index: u64,
    pub signal: repr_c::Box<[u8]>,
}

// RLNProofValues

/*
#[derive_ReprC]
#[repr(C)]
#[derive(Debug)]
pub struct FFI2_RLNProofValues {
    pub y: repr_c::Box<CFr>,
    pub nullifier: repr_c::Box<CFr>,
    pub root: repr_c::Box<CFr>,
    pub x: repr_c::Box<CFr>,
    pub external_nullifier: repr_c::Box<CFr>,
}
*/

/*
impl From<RLNProofValues> for FFI2_RLNProofValues {
    fn from(value: RLNProofValues) -> Self {
        todo!()
    }
}
*/

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI2_RLNProof {
    proof_values: RLNProofValues,
    proof: Proof<Curve>,
}

#[ffi_export]
fn ffi2_rln_proof_free(rln: Option<repr_c::Box<FFI2_RLNProof>>) {
    drop(rln);
}

// Merkle tree functions

#[ffi_export]
pub fn ffi2_set_next_leaf(rln: &mut repr_c::Box<FFI2_RLN>, value: repr_c::Box<CFr>) -> bool {
    rln.tree.update_next(value.0).is_ok()
}

#[ffi_export]
pub fn ffi2_get_root(rln: &repr_c::Box<FFI2_RLN>) -> repr_c::Box<CFr> {
    CFr::from(rln.tree.root()).into()
}

#[ffi_export]
pub fn ffi2_set_tree(rln: &mut repr_c::Box<FFI2_RLN>, tree_depth: usize) -> bool {
    // We compute a default empty tree of desired depth
    match PoseidonTree::default(tree_depth) {
        Ok(tree) => {
            rln.tree = tree;
            true
        }
        Err(_) => false,
    }
}

#[ffi_export]
pub fn ffi2_delete_leaf(rln: &mut repr_c::Box<FFI2_RLN>, index: usize) -> bool {
    rln.tree.delete(index).is_ok()
}

#[ffi_export]
pub fn ffi2_set_leaf(
    rln: &mut repr_c::Box<FFI2_RLN>,
    index: usize,
    value: repr_c::Box<CFr>,
) -> bool {
    rln.tree.set(index, value.0).is_ok()
}

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

#[ffi_export]
pub fn ffi2_leaves_set(rln: &repr_c::Box<FFI2_RLN>) -> usize {
    rln.tree.leaves_set()
}

#[ffi_export]
pub fn ffi2_set_leaves_from(
    rln: &mut repr_c::Box<FFI2_RLN>,
    index: usize,
    leaves: repr_c::Vec<CFr>,
) -> bool {
    let leaves_iter = leaves.iter().map(|cfr| cfr.0);
    rln.tree
        .override_range(index, leaves_iter, [].into_iter())
        .is_ok()
}

#[ffi_export]
pub fn ffi2_init_tree_with_leaves(
    rln: &mut repr_c::Box<FFI2_RLN>,
    leaves: repr_c::Vec<CFr>,
) -> bool {
    // Reset tree to default
    let tree_depth = rln.tree.depth();
    match PoseidonTree::default(tree_depth) {
        Ok(tree) => {
            rln.tree = tree;
        }
        Err(_) => return false,
    }

    // Set all leaves from index 0
    let leaves_iter = leaves.iter().map(|cfr| cfr.0);
    rln.tree
        .override_range(0, leaves_iter, [].into_iter())
        .is_ok()
}

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

// ZK functions

#[ffi_export]
pub fn ffi2_generate_rln_proof(
    rln: &repr_c::Box<FFI2_RLN>,
    witness_input: &mut repr_c::Box<FFI2_RLNWitnessInput>,
) -> CResult<repr_c::Box<FFI2_RLNProof>, repr_c::String> {
    let witness_input_ = {
        let merkle_proof = rln
            .tree
            .proof(witness_input.tree_index as usize)
            .expect("proof should exist");
        let path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        let x = hash_to_field_le(&witness_input.signal);

        RLNWitnessInput {
            identity_secret: IdSecret::from(&mut witness_input.identity_secret.0),
            user_message_limit: witness_input.user_message_limit.0,
            message_id: witness_input.message_id.0,
            path_elements,
            identity_path_index,
            x,
            external_nullifier: witness_input.external_nullifier.0,
        }
    };

    let proof_values = proof_values_from_witness(&witness_input_).unwrap();
    let proof = match generate_proof(&rln.proving_key, &witness_input_, &rln.graph_data) {
        Ok(proof) => proof,
        Err(e) => {
            return CResult {
                ok: None,
                err: Some(e.to_string().into()),
            };
        }
    };

    //    .map_err(|err| CString::new(format!("Error: {err}")).unwrap())?;

    let res = FFI2_RLNProof {
        proof_values,
        proof,
    };

    CResult {
        ok: Some(Box_::new(res)),
        err: None,
    }
}

#[ffi_export]
pub fn ffi2_verify_rln_proof(
    rln: &repr_c::Box<FFI2_RLN>,
    proof: repr_c::Box<FFI2_RLNProof>,
    signal: c_slice::Ref<'_, u8>,
) -> bool {
    let verified = verify_proof(&rln.proving_key.0.vk, &proof.proof, &proof.proof_values).unwrap();
    let x = hash_to_field_le(&signal);
    // TODO: should this check be in verify_proof?
    // Consistency checks to counter proof tampering
    verified && (rln.tree.root() == proof.proof_values.root) && (x == proof.proof_values.x)
}

// Hash functions

// Keygen functions

/// Generate an identity which is composed of an identity secret and identity commitment.
/// The identity secret is a random field element.
/// The identity commitment is the Poseidon hash of the identity secret.
#[ffi_export]
pub fn ffi2_key_gen() -> repr_c::Vec<CFr> {
    let (identity_secret_hash, id_commitment) = keygen();
    vec![CFr(*identity_secret_hash), CFr(id_commitment)].into()
}

/// Generate an identity which is composed of an identity trapdoor, nullifier, secret and commitment.
/// The identity secret is the Poseidon hash of the identity trapdoor and identity nullifier.
/// The identity commitment is the Poseidon hash of the identity secret.
///
/// Generated credentials are compatible with
/// [Semaphore](https://semaphore.appliedzkp.org/docs/guides/identities)'s credentials.
///
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

/// Generate an identity which is composed of an identity secret and identity commitment using a seed.
/// The identity secret is a random field element,
/// where RNG is instantiated using 20 rounds of ChaCha seeded with the hash of the input.
/// The identity commitment is the Poseidon hash of the identity secret.
#[ffi_export]
pub fn ffi2_seeded_key_gen(seed: c_slice::Ref<'_, u8>) -> repr_c::Vec<CFr> {
    let (identity_secret_hash, id_commitment) = seeded_keygen(&seed);
    vec![CFr(identity_secret_hash), CFr(id_commitment)].into()
}

/// Generate an identity which is composed of an identity trapdoor, nullifier, secret and commitment using a seed.
/// The identity trapdoor and nullifier are random field elements,
///   where RNG is instantiated using 20 rounds of ChaCha seeded with the hash of the input.
/// The identity secret is the Poseidon hash of the identity trapdoor and identity nullifier.
/// The identity commitment is the Poseidon hash of the identity secret.
///
/// Generated credentials are compatible with
/// [Semaphore](https://semaphore.appliedzkp.org/docs/guides/identities)'s credentials.
///
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

// headers

// The following function is only necessary for the header generation.
#[cfg(feature = "headers")] // c.f. the `Cargo.toml` section
pub fn generate_headers() -> ::std::io::Result<()> {
    ::safer_ffi::headers::builder().to_file("rln.h")?.generate()
}
