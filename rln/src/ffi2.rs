use std::ops::Deref;
use ark_bn254::Fr;
use num_traits::Zero;
use safer_ffi::{
    derive_ReprC,
    ffi_export,
    // boxed::Box_,
    prelude::{
        c_slice,
        repr_c,
        // Out
    },
};
// internal
use crate::protocol::{keygen, seeded_keygen};

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

#[ffi_export]
pub fn ffi2_key_gen() -> repr_c::Vec<CFr> {
    let (identity_secret_hash, id_commitment) = keygen();
    vec![CFr(identity_secret_hash.deref().clone()), CFr(id_commitment)].into()
}

#[ffi_export]
/// Generate an identity which is composed of an identity secret and identity commitment using a seed.
/// The identity secret is a random field element,
/// where RNG is instantiated using 20 rounds of ChaCha seeded with the hash of the input.
/// The identity commitment is the Poseidon hash of the identity secret.
pub fn ffi2_seeded_key_gen(seed: c_slice::Ref<'_, u8>) -> repr_c::Vec<CFr> {
    let (identity_secret_hash, id_commitment) = seeded_keygen(&seed);
    vec![CFr(identity_secret_hash), CFr(id_commitment)].into()
}


