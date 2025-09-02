use std::ops::Deref;
use ark_bn254::Fr;
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use num_traits::Zero;
use safer_ffi::{
    derive_ReprC,
    ffi_export,
    boxed::Box_,
    prelude::{
        c_slice,
        repr_c,
        // Out
    },
};
use utils::{Hasher, ZerokitMerkleProof, ZerokitMerkleTree};
use crate::circuit::{graph_from_folder, zkey_from_folder, Curve};
use crate::hashers::hash_to_field_le;
use crate::poseidon_tree::PoseidonTree;
// internal
use crate::protocol::{extended_keygen, extended_seeded_keygen, generate_proof, keygen, proof_values_from_witness, seeded_keygen, RLNProofValues, RLNWitnessInput};
use crate::utils::IdSecret;

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

// End Vec<CFr>

// RLN

/// The RLN object.
///
/// It implements the methods required to update the internal Merkle Tree, generate and verify RLN ZK proofs.
#[derive_ReprC]
#[repr(opaque)]
pub struct FFI2_RLN {
    proving_key: (ProvingKey<Curve>, ConstraintMatrices<crate::circuit::Fr>),
    // pub(crate) verification_key: VerifyingKey<Curve>,
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) graph_data: Vec<u8>,
    #[cfg(not(feature = "stateless"))]
    pub(crate) tree: PoseidonTree,
}

// RLN functions

#[ffi_export]
fn ffi2_rln_try_new(tree_depth: usize) -> Option<repr_c::Box<FFI2_RLN>> {

    // TODO: return an Option but would be nice if it can return a Result
    // TODO: tree config

    let proving_key = zkey_from_folder();
    // let verification_key = &proving_key.0.vk;
    let graph_data = graph_from_folder();

    // We compute a default empty tree
    let tree_config: <PoseidonTree as ZerokitMerkleTree>::Config =
        <PoseidonTree as ZerokitMerkleTree>::Config::default();

    let tree = match PoseidonTree::new(tree_depth, <PoseidonTree as ZerokitMerkleTree>::Hasher::default_leaf(), tree_config) {
        Ok(tree) => tree,
        Err(err) => {
            println!("Error: {err}");
            return None;
        }
    };

    let rln = FFI2_RLN {
        proving_key: proving_key.to_owned(),
        // verification_key: verification_key.to_owned(),
        graph_data: graph_data.to_vec(),
        #[cfg(not(feature = "stateless"))]
        tree,
    };

    Some(Box_::new(rln))
}

#[ffi_export]
fn ffi2_rln_free(rln: Option<repr_c::Box<FFI2_RLN>>) {
    drop(rln);
}

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

// RLNWitnessInput

#[derive_ReprC]
#[repr(C)]
pub struct FFI2_RLNWitnessInput {
    identity_secret: repr_c::Box<CFr>,
    user_message_limit: repr_c::Box<CFr>,
    message_id: repr_c::Box<CFr>,
    path_elements: repr_c::Vec<CFr>,
    identity_path_index: repr_c::Box<[u8]>,
    x: repr_c::Box<CFr>,
    external_nullifier: repr_c::Box<CFr>,
}

impl From<RLNWitnessInput> for FFI2_RLNWitnessInput {
    fn from(value: RLNWitnessInput) -> Self {
        todo!()
    }
}

impl From<&FFI2_RLNWitnessInput> for RLNWitnessInput {
    fn from(value: &FFI2_RLNWitnessInput) -> Self {
        todo!()
    }
}

// RLNProofValues
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

impl From<RLNProofValues> for FFI2_RLNProofValues {
    fn from(value: RLNProofValues) -> Self {
        todo!()
    }
}

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI2_RLNProof {
    proof_values: RLNProofValues,
    proof: Proof<Curve>
}

#[ffi_export]
fn ffi2_rln_proof_free(rln: Option<repr_c::Box<FFI2_RLNProof>>) {
    drop(rln);
}

// Merkle tree functions

// ZK functions

pub fn generate_rln_proof(rln: &FFI2_RLN, witness_input: &FFI2_RLNWitnessInput) -> Option<repr_c::Box<FFI2_RLNProof>> {

    let mut id_s = Fr::from(0);

    // TODO: Do we need to define FFI2_RLNWitnessInput? Maybe just ask for ffi_init_witness_input arguments
    let witness_input_ = RLNWitnessInput::from(witness_input);
    /*
    let witness_input_ = RLNWitnessInput {
        identity_secret: IdSecret::from(&mut id_s), // FIXME
        user_message_limit: witness_input.user_message_limit.0,
        message_id: witness_input.message_id.0,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: witness_input.x.0,
        external_nullifier: witness_input.external_nullifier.0,
    };
    */
    let proof_values = proof_values_from_witness(&witness_input_).unwrap();
    let proof = generate_proof(&rln.proving_key, &witness_input_, &rln.graph_data).unwrap();

    // TODO: Do we need to define FFI2_RLNProofValues? Use opaque type here?
    // let proof_values_: FFI2_RLNProofValues = proof_values.into();

    // TODO: return proof as well
    let res = FFI2_RLNProof {
        proof_values,
        proof,
    };
    Some(Box_::new(res))
}

// Hash functions



// Keygen functions

/// Generate an identity which is composed of an identity secret and identity commitment.
/// The identity secret is a random field element.
/// The identity commitment is the Poseidon hash of the identity secret.
#[ffi_export]
pub fn ffi2_key_gen() -> repr_c::Vec<CFr> {
    let (identity_secret_hash, id_commitment) = keygen();
    vec![CFr(identity_secret_hash.deref().clone()), CFr(id_commitment)].into()
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
        CFr(id_commitment)
    ].into()
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
        CFr(id_commitment)
    ].into()
}




