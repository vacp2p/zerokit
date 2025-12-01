#![allow(non_camel_case_types)]

use std::ops::Deref;

use safer_ffi::{
    boxed::Box_,
    derive_ReprC, ffi_export,
    prelude::{repr_c, ReprC},
};

use crate::{
    circuit::Fr,
    hashers::{hash_to_field_be, hash_to_field_le, poseidon_hash},
    protocol::{extended_keygen, extended_seeded_keygen, keygen, seeded_keygen},
    utils::{bytes_be_to_fr, bytes_le_to_fr, fr_to_bytes_be, fr_to_bytes_le},
};

// CResult

#[derive_ReprC]
#[repr(C)]
pub struct CResult<T: ReprC, Err: ReprC> {
    pub ok: Option<T>,
    pub err: Option<Err>,
}

// CBoolResult

#[derive_ReprC]
#[repr(C)]
pub struct CBoolResult {
    pub ok: bool,
    pub err: Option<repr_c::String>,
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
        CFr(cfr.0).into()
    }
}

impl PartialEq<Fr> for CFr {
    fn eq(&self, other: &Fr) -> bool {
        self.0 == *other
    }
}

#[ffi_export]
pub fn cfr_zero() -> repr_c::Box<CFr> {
    CFr::from(Fr::from(0)).into()
}

#[ffi_export]
pub fn cfr_one() -> repr_c::Box<CFr> {
    CFr::from(Fr::from(1)).into()
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
    CFr(cfr).into()
}

#[ffi_export]
pub fn bytes_be_to_cfr(bytes: &repr_c::Vec<u8>) -> repr_c::Box<CFr> {
    let (cfr, _) = bytes_be_to_fr(bytes);
    CFr(cfr).into()
}

#[ffi_export]
pub fn uint_to_cfr(value: u32) -> repr_c::Box<CFr> {
    CFr::from(Fr::from(value)).into()
}

#[ffi_export]
pub fn cfr_debug(cfr: Option<&CFr>) -> repr_c::String {
    match cfr {
        Some(cfr) => format!("{:?}", cfr.0).into(),
        None => "None".into(),
    }
}

#[ffi_export]
pub fn cfr_free(cfr: repr_c::Box<CFr>) {
    drop(cfr);
}

// Vec<CFr>

#[ffi_export]
pub fn vec_cfr_new(capacity: usize) -> repr_c::Vec<CFr> {
    Vec::with_capacity(capacity).into()
}

#[ffi_export]
pub fn vec_cfr_from_cfr(cfr: &CFr) -> repr_c::Vec<CFr> {
    vec![*cfr].into()
}

#[ffi_export]
pub fn vec_cfr_push(v: &mut safer_ffi::Vec<CFr>, cfr: &CFr) {
    let mut new: Vec<CFr> = std::mem::replace(v, Vec::new().into()).into();
    if new.len() == new.capacity() {
        new.reserve_exact(1);
    }
    new.push(*cfr);
    *v = new.into();
}

#[ffi_export]
pub fn vec_cfr_len(v: &repr_c::Vec<CFr>) -> usize {
    v.len()
}

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
pub fn bytes_le_to_vec_cfr(bytes: &repr_c::Vec<u8>) -> CResult<repr_c::Vec<CFr>, repr_c::String> {
    match crate::utils::bytes_le_to_vec_fr(bytes) {
        Ok((vec_fr, _)) => {
            let vec_cfr: Vec<CFr> = vec_fr.into_iter().map(CFr).collect();
            CResult {
                ok: Some(vec_cfr.into()),
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
pub fn bytes_be_to_vec_cfr(bytes: &repr_c::Vec<u8>) -> CResult<repr_c::Vec<CFr>, repr_c::String> {
    match crate::utils::bytes_be_to_vec_fr(bytes) {
        Ok((vec_fr, _)) => {
            let vec_cfr: Vec<CFr> = vec_fr.into_iter().map(CFr).collect();
            CResult {
                ok: Some(vec_cfr.into()),
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
pub fn vec_cfr_debug(v: Option<&repr_c::Vec<CFr>>) -> repr_c::String {
    match v {
        Some(v) => {
            let vec_fr: Vec<Fr> = v.iter().map(|cfr| cfr.0).collect();
            format!("{:?}", vec_fr).into()
        }
        None => "None".into(),
    }
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
pub fn bytes_le_to_vec_u8(bytes: &repr_c::Vec<u8>) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    match crate::utils::bytes_le_to_vec_u8(bytes) {
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
pub fn bytes_be_to_vec_u8(bytes: &repr_c::Vec<u8>) -> CResult<repr_c::Vec<u8>, repr_c::String> {
    match crate::utils::bytes_be_to_vec_u8(bytes) {
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
pub fn vec_u8_debug(v: Option<&repr_c::Vec<u8>>) -> repr_c::String {
    match v {
        Some(v) => format!("{:x?}", v.deref()).into(),
        None => "None".into(),
    }
}

#[ffi_export]
pub fn vec_u8_free(v: repr_c::Vec<u8>) {
    drop(v);
}

// Utility APIs

#[ffi_export]
pub fn ffi_hash_to_field_le(input: &repr_c::Vec<u8>) -> repr_c::Box<CFr> {
    let hash_result = hash_to_field_le(input);
    CFr::from(hash_result).into()
}

#[ffi_export]
pub fn ffi_hash_to_field_be(input: &repr_c::Vec<u8>) -> repr_c::Box<CFr> {
    let hash_result = hash_to_field_be(input);
    CFr::from(hash_result).into()
}

#[ffi_export]
pub fn ffi_poseidon_hash_pair(a: &CFr, b: &CFr) -> repr_c::Box<CFr> {
    let hash_result = poseidon_hash(&[a.0, b.0]);
    CFr::from(hash_result).into()
}

#[ffi_export]
pub fn ffi_key_gen() -> repr_c::Vec<CFr> {
    let (identity_secret, id_commitment) = keygen();
    vec![CFr(*identity_secret), CFr(id_commitment)].into()
}

#[ffi_export]
pub fn ffi_seeded_key_gen(seed: &repr_c::Vec<u8>) -> repr_c::Vec<CFr> {
    let (identity_secret, id_commitment) = seeded_keygen(seed);
    vec![CFr(identity_secret), CFr(id_commitment)].into()
}

#[ffi_export]
pub fn ffi_extended_key_gen() -> repr_c::Vec<CFr> {
    let (identity_trapdoor, identity_nullifier, identity_secret, id_commitment) = extended_keygen();
    vec![
        CFr(identity_trapdoor),
        CFr(identity_nullifier),
        CFr(identity_secret),
        CFr(id_commitment),
    ]
    .into()
}

#[ffi_export]
pub fn ffi_seeded_extended_key_gen(seed: &repr_c::Vec<u8>) -> repr_c::Vec<CFr> {
    let (identity_trapdoor, identity_nullifier, identity_secret, id_commitment) =
        extended_seeded_keygen(seed);
    vec![
        CFr(identity_trapdoor),
        CFr(identity_nullifier),
        CFr(identity_secret),
        CFr(id_commitment),
    ]
    .into()
}

#[ffi_export]
pub fn c_string_free(s: repr_c::String) {
    drop(s);
}
