#![allow(non_camel_case_types)]

use crate::{
    circuit::Fr,
    hashers::{hash_to_field_be, hash_to_field_le, poseidon_hash},
    protocol::{extended_keygen, extended_seeded_keygen, keygen, seeded_keygen},
    utils::{bytes_be_to_fr, bytes_le_to_fr, fr_to_bytes_be, fr_to_bytes_le},
};
use safer_ffi::prelude::ReprC;
use safer_ffi::{boxed::Box_, derive_ReprC, ffi_export, prelude::repr_c};
use std::ops::Deref;

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
pub struct CFr(pub(crate) Fr);

impl Deref for CFr {
    type Target = Fr;
    fn deref(&self) -> &Self::Target {
        &self.0
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

impl From<&CFr> for repr_c::Box<CFr> {
    fn from(cfr: &CFr) -> Self {
        Box_::new(CFr(cfr.0))
    }
}

impl PartialEq<Fr> for CFr {
    fn eq(&self, other: &Fr) -> bool {
        self.0 == *other
    }
}

#[ffi_export]
pub fn cfr_zero() -> repr_c::Box<CFr> {
    Box_::new(CFr::from(Fr::from(0)))
}

#[ffi_export]
pub fn cfr_one() -> repr_c::Box<CFr> {
    Box_::new(CFr::from(Fr::from(1)))
}

#[ffi_export]
pub fn cfr_to_bytes_le(cfr: &CFr) -> repr_c::Vec<u8> {
    fr_to_bytes_le(&cfr.0).into()
}

#[ffi_export]
pub fn cfr_to_bytes_be(cfr: &CFr) -> repr_c::Vec<u8> {
    fr_to_bytes_be(&cfr.0).into()
}

#[ffi_export]
pub fn bytes_le_to_cfr(bytes: &repr_c::Vec<u8>) -> repr_c::Box<CFr> {
    let (cfr, _) = bytes_le_to_fr(bytes);
    Box_::new(CFr(cfr))
}

#[ffi_export]
pub fn bytes_be_to_cfr(bytes: &repr_c::Vec<u8>) -> repr_c::Box<CFr> {
    let (cfr, _) = bytes_be_to_fr(bytes);
    Box_::new(CFr(cfr))
}

#[ffi_export]
pub fn uint_to_cfr(value: u32) -> repr_c::Box<CFr> {
    Box_::new(CFr::from(Fr::from(value)))
}

#[ffi_export]
pub fn cfr_debug(cfr: Option<&CFr>) -> repr_c::String {
    format!("{:?}", cfr.map(|c| c.0.to_string())).into()
}

#[ffi_export]
pub fn cfr_free(cfr: Option<repr_c::Box<CFr>>) {
    drop(cfr);
}

// Vec<CFr>

#[ffi_export]
pub fn vec_cfr_get(v: &repr_c::Vec<CFr>, i: usize) -> Option<&CFr> {
    v.get(i)
}

#[ffi_export]
pub fn vec_cfr_to_bytes_le(vec: &repr_c::Vec<CFr>) -> repr_c::Vec<u8> {
    let vec_fr: Vec<Fr> = vec.iter().map(|cfr| cfr.0).collect();
    crate::utils::vec_fr_to_bytes_le(&vec_fr).into()
}

#[ffi_export]
pub fn vec_cfr_to_bytes_be(vec: &repr_c::Vec<CFr>) -> repr_c::Vec<u8> {
    let vec_fr: Vec<Fr> = vec.iter().map(|cfr| cfr.0).collect();
    crate::utils::vec_fr_to_bytes_be(&vec_fr).into()
}

#[ffi_export]
pub fn bytes_le_to_vec_cfr(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<repr_c::Vec<CFr>>, repr_c::String> {
    match crate::utils::bytes_le_to_vec_fr(bytes) {
        Ok((vec_fr, _)) => {
            let vec_cfr: Vec<CFr> = vec_fr.into_iter().map(CFr).collect();
            CResult {
                ok: Some(Box_::new(vec_cfr.into())),
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
pub fn bytes_be_to_vec_cfr(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<repr_c::Vec<CFr>>, repr_c::String> {
    match crate::utils::bytes_be_to_vec_fr(bytes) {
        Ok((vec_fr, _)) => {
            let vec_cfr: Vec<CFr> = vec_fr.into_iter().map(CFr).collect();
            CResult {
                ok: Some(Box_::new(vec_cfr.into())),
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
pub fn vec_cfr_debug(v: &repr_c::Vec<CFr>) -> repr_c::String {
    format!("{:?}", v.iter().map(|cfr| cfr.0).collect::<Vec<Fr>>()).into()
}

#[ffi_export]
pub fn vec_cfr_free(v: repr_c::Vec<CFr>) {
    drop(v);
}

// Vec<u8>

#[ffi_export]
pub fn vec_u8_to_bytes_le(vec: &repr_c::Vec<u8>) -> repr_c::Vec<u8> {
    crate::utils::vec_u8_to_bytes_le(vec).into()
}

#[ffi_export]
pub fn vec_u8_to_bytes_be(vec: &repr_c::Vec<u8>) -> repr_c::Vec<u8> {
    crate::utils::vec_u8_to_bytes_be(vec).into()
}

#[ffi_export]
pub fn bytes_le_to_vec_u8(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<repr_c::Vec<u8>>, repr_c::String> {
    match crate::utils::bytes_le_to_vec_u8(bytes) {
        Ok((vec, _)) => CResult {
            ok: Some(Box_::new(vec.into())),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn bytes_be_to_vec_u8(
    bytes: &repr_c::Vec<u8>,
) -> CResult<repr_c::Box<repr_c::Vec<u8>>, repr_c::String> {
    match crate::utils::bytes_be_to_vec_u8(bytes) {
        Ok((vec, _)) => CResult {
            ok: Some(Box_::new(vec.into())),
            err: None,
        },
        Err(err) => CResult {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn vec_u8_debug(v: &repr_c::Vec<u8>) -> repr_c::String {
    format!("{:?}", v.iter().copied().collect::<Vec<u8>>()).into()
}

#[ffi_export]
pub fn vec_u8_free(v: repr_c::Vec<u8>) {
    drop(v);
}

// Utility APIs

#[ffi_export]
pub fn ffi2_hash_to_field_le(input: &repr_c::Vec<u8>) -> repr_c::Box<CFr> {
    let hash_result = hash_to_field_le(input);
    CFr::from(hash_result).into()
}

#[ffi_export]
pub fn ffi2_hash_to_field_be(input: &repr_c::Vec<u8>) -> repr_c::Box<CFr> {
    let hash_result = hash_to_field_be(input);
    CFr::from(hash_result).into()
}

#[ffi_export]
pub fn ffi2_poseidon_hash_pair(a: &CFr, b: &CFr) -> repr_c::Box<CFr> {
    let hash_result = poseidon_hash(&[a.0, b.0]);
    CFr::from(hash_result).into()
}

#[ffi_export]
pub fn ffi2_key_gen() -> repr_c::Vec<CFr> {
    let (identity_secret_hash, id_commitment) = keygen();
    vec![CFr(*identity_secret_hash), CFr(id_commitment)].into()
}

#[ffi_export]
pub fn ffi2_seeded_key_gen(seed: &repr_c::Vec<u8>) -> repr_c::Vec<CFr> {
    let (identity_secret_hash, id_commitment) = seeded_keygen(seed);
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
pub fn ffi2_seeded_extended_key_gen(seed: &repr_c::Vec<u8>) -> repr_c::Vec<CFr> {
    let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
        extended_seeded_keygen(seed);
    vec![
        CFr(identity_trapdoor),
        CFr(identity_nullifier),
        CFr(identity_secret_hash),
        CFr(id_commitment),
    ]
    .into()
}
