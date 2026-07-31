#![allow(non_camel_case_types)]

use std::ops::Deref;

use rand::{rngs::ThreadRng, thread_rng};
use rand_chacha::ChaCha20Rng;
use safer_ffi::{
    boxed::Box_,
    derive_ReprC, ffi_export,
    prelude::{repr_c, ReprC},
};

use crate::prelude::*;

// FFI_Result

#[derive_ReprC]
#[repr(C)]
pub struct FFI_Result<T: ReprC, Err: ReprC> {
    pub ok: Option<T>,
    pub err: Option<Err>,
}

// FFI_BoolResult

#[derive_ReprC]
#[repr(C)]
pub struct FFI_BoolResult {
    pub ok: bool,
    pub err: Option<repr_c::String>,
}

// FFI_UsizeResult

#[derive_ReprC]
#[repr(C)]
pub struct FFI_UsizeResult {
    pub ok: usize,
    pub err: Option<repr_c::String>,
}

// FFI_Fr

#[derive_ReprC]
#[repr(opaque)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FFI_Fr(pub(crate) Fr);

impl Deref for FFI_Fr {
    type Target = Fr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Fr> for FFI_Fr {
    fn from(fr: Fr) -> Self {
        Self(fr)
    }
}

impl From<FFI_Fr> for repr_c::Box<FFI_Fr> {
    fn from(fr: FFI_Fr) -> Self {
        Box_::new(fr)
    }
}

impl From<&FFI_Fr> for repr_c::Box<FFI_Fr> {
    fn from(fr: &FFI_Fr) -> Self {
        FFI_Fr::from(fr.0).into()
    }
}

impl PartialEq<Fr> for FFI_Fr {
    fn eq(&self, other: &Fr) -> bool {
        self.0 == *other
    }
}

#[ffi_export]
pub fn ffi_fr_zero() -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(Fr::from(0)).into()
}

#[ffi_export]
pub fn ffi_fr_one() -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(Fr::from(1)).into()
}

#[ffi_export]
pub fn ffi_fr_to_bytes_le(fr: &FFI_Fr) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match fr.0.serialize_compressed(&mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_fr_to_bytes_be(fr: &FFI_Fr) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeBE::serialize(&fr.0, &mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_fr_from_bytes_le(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_Fr>, repr_c::String> {
    match Fr::deserialize_compressed(&bytes[..]) {
        Ok(fr) => FFI_Result {
            ok: Some(FFI_Fr::from(fr).into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_fr_from_bytes_be(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_Fr>, repr_c::String> {
    match <Fr as CanonicalDeserializeBE>::deserialize(&bytes[..]) {
        Ok(fr) => FFI_Result {
            ok: Some(FFI_Fr::from(fr).into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_uint_to_fr(value: u32) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(Fr::from(value)).into()
}

#[ffi_export]
pub fn ffi_fr_debug(fr: Option<&FFI_Fr>) -> repr_c::String {
    match fr {
        Some(fr) => format!("{:?}", fr.0).into(),
        None => "None".into(),
    }
}

#[ffi_export]
pub fn ffi_fr_free(fr: repr_c::Box<FFI_Fr>) {
    drop(fr);
}

// FFI_SecretFr (opaque secret field element, zeroized on drop)

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_SecretFr(pub(crate) SecretFr);

impl FFI_SecretFr {
    pub fn inner(&self) -> &SecretFr {
        &self.0
    }
}

impl From<SecretFr> for FFI_SecretFr {
    fn from(secret: SecretFr) -> Self {
        Self(secret)
    }
}

#[ffi_export]
pub fn ffi_secret_fr_eq(a: Option<&FFI_SecretFr>, b: Option<&FFI_SecretFr>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.0 == b.0,
        _ => false,
    }
}

#[ffi_export]
pub fn ffi_secret_fr_debug(secret: Option<&FFI_SecretFr>) -> repr_c::String {
    match secret {
        Some(secret) => format!("{:?}", secret.0).into(),
        None => "None".into(),
    }
}

#[ffi_export]
pub fn ffi_secret_fr_free(secret: repr_c::Box<FFI_SecretFr>) {
    drop(secret);
}

// Vec<FFI_Fr>

#[ffi_export]
pub fn ffi_vec_fr_new(capacity: usize) -> repr_c::Vec<FFI_Fr> {
    Vec::with_capacity(capacity).into()
}

#[ffi_export]
pub fn ffi_vec_fr_from_fr(fr: &FFI_Fr) -> repr_c::Vec<FFI_Fr> {
    vec![*fr].into()
}

#[ffi_export]
pub fn ffi_vec_fr_push(v: &mut safer_ffi::Vec<FFI_Fr>, fr: &FFI_Fr) {
    let mut new: Vec<FFI_Fr> = std::mem::replace(v, Vec::new().into()).into();
    if new.len() == new.capacity() {
        new.reserve_exact(1);
    }
    new.push(*fr);
    *v = new.into();
}

#[ffi_export]
pub fn ffi_vec_fr_len(v: &repr_c::Vec<FFI_Fr>) -> usize {
    v.len()
}

#[ffi_export]
pub fn ffi_vec_fr_get(v: &repr_c::Vec<FFI_Fr>, i: usize) -> Option<&FFI_Fr> {
    v.get(i)
}

#[ffi_export]
pub fn ffi_vec_fr_to_bytes_le(
    vec: &repr_c::Vec<FFI_Fr>,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let vec_fr: Vec<Fr> = vec.iter().map(|fr| fr.0).collect();
    let mut bytes = Vec::new();
    match vec_fr.serialize_compressed(&mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_vec_fr_to_bytes_be(
    vec: &repr_c::Vec<FFI_Fr>,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let vec_fr: Vec<Fr> = vec.iter().map(|fr| fr.0).collect();
    let mut bytes = Vec::new();
    match CanonicalSerializeBE::serialize(&vec_fr, &mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_vec_fr_from_bytes_le(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Vec<FFI_Fr>, repr_c::String> {
    match Vec::<Fr>::deserialize_compressed(&bytes[..]) {
        Ok(vec_fr) => {
            let vec_fr: Vec<FFI_Fr> = vec_fr.into_iter().map(FFI_Fr).collect();
            FFI_Result {
                ok: Some(vec_fr.into()),
                err: None,
            }
        }
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_vec_fr_from_bytes_be(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Vec<FFI_Fr>, repr_c::String> {
    match <Vec<Fr> as CanonicalDeserializeBE>::deserialize(&bytes[..]) {
        Ok(vec_fr) => {
            let vec_fr: Vec<FFI_Fr> = vec_fr.into_iter().map(FFI_Fr).collect();
            FFI_Result {
                ok: Some(vec_fr.into()),
                err: None,
            }
        }
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_vec_fr_debug(v: Option<&repr_c::Vec<FFI_Fr>>) -> repr_c::String {
    match v {
        Some(v) => {
            let vec_fr: Vec<Fr> = v.iter().map(|fr| fr.0).collect();
            format!("{:?}", vec_fr).into()
        }
        None => "None".into(),
    }
}

#[ffi_export]
pub fn ffi_vec_fr_free(v: repr_c::Vec<FFI_Fr>) {
    drop(v);
}

// Vec<u8>

#[ffi_export]
pub fn ffi_vec_u8_to_bytes_le(
    vec: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match vec[..].serialize_compressed(&mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_vec_u8_to_bytes_be(
    vec: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeBE::serialize(&vec[..], &mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_vec_u8_from_bytes_le(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    match Vec::<u8>::deserialize_compressed(&bytes[..]) {
        Ok(vec) => FFI_Result {
            ok: Some(vec.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_vec_u8_from_bytes_be(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    match <Vec<u8> as CanonicalDeserializeBE>::deserialize(&bytes[..]) {
        Ok(vec) => FFI_Result {
            ok: Some(vec.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_vec_u8_debug(v: Option<&repr_c::Vec<u8>>) -> repr_c::String {
    match v {
        Some(v) => format!("{:x?}", v.deref()).into(),
        None => "None".into(),
    }
}

#[ffi_export]
pub fn ffi_vec_u8_free(v: repr_c::Vec<u8>) {
    drop(v);
}

// Vec<bool>

#[ffi_export]
pub fn ffi_vec_bool_free(v: repr_c::Vec<bool>) {
    drop(v);
}

// Vec<usize>

#[ffi_export]
pub fn ffi_vec_usize_free(v: repr_c::Vec<usize>) {
    drop(v);
}

// Hashing

#[ffi_export]
pub fn ffi_hash_to_field_le(input: &repr_c::Vec<u8>) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(hash_to_field_le(input)).into()
}

#[ffi_export]
pub fn ffi_hash_to_field_be(input: &repr_c::Vec<u8>) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(hash_to_field_be(input)).into()
}

#[ffi_export]
pub fn ffi_poseidon_hash_pair(a: &FFI_Fr, b: &FFI_Fr) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(Hasher::<PoseidonHash>::hash_pair(a.0, b.0)).into()
}

// FFI_IdentityKeys

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_IdentityKeys(IdentityKeys);

#[ffi_export]
pub fn ffi_identity_keys_generate() -> repr_c::Box<FFI_IdentityKeys> {
    Box_::new(FFI_IdentityKeys(IdentityKeys::generate::<
        PoseidonHash,
        ThreadRng,
    >(&mut thread_rng())))
}

#[ffi_export]
pub fn ffi_identity_keys_generate_seeded(seed: &repr_c::Vec<u8>) -> repr_c::Box<FFI_IdentityKeys> {
    Box_::new(FFI_IdentityKeys(IdentityKeys::generate_seeded::<
        PoseidonHash,
        ChaCha20Rng,
    >(seed)))
}

#[ffi_export]
pub fn ffi_identity_keys_get_secret(identity: &FFI_IdentityKeys) -> repr_c::Box<FFI_SecretFr> {
    Box_::new(FFI_SecretFr::from(identity.0.identity_secret()))
}

#[ffi_export]
pub fn ffi_identity_keys_get_commitment(identity: &FFI_IdentityKeys) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(identity.0.id_commitment()).into()
}

#[ffi_export]
pub fn ffi_identity_keys_to_bytes_le(
    identity: &FFI_IdentityKeys,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match identity.0.serialize_compressed(&mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_identity_keys_to_bytes_be(
    identity: &FFI_IdentityKeys,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeBE::serialize(&identity.0, &mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_identity_keys_from_bytes_le(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_IdentityKeys>, repr_c::String> {
    match IdentityKeys::deserialize_compressed(&bytes[..]) {
        Ok(identity) => FFI_Result {
            ok: Some(Box_::new(FFI_IdentityKeys(identity))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_identity_keys_from_bytes_be(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_IdentityKeys>, repr_c::String> {
    match <IdentityKeys as CanonicalDeserializeBE>::deserialize(&bytes[..]) {
        Ok(identity) => FFI_Result {
            ok: Some(Box_::new(FFI_IdentityKeys(identity))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_identity_keys_free(identity: repr_c::Box<FFI_IdentityKeys>) {
    drop(identity);
}

// FFI_ExtendedIdentityKeys

#[derive_ReprC]
#[repr(opaque)]
pub struct FFI_ExtendedIdentityKeys(ExtendedIdentityKeys);

#[ffi_export]
pub fn ffi_extended_identity_keys_generate() -> repr_c::Box<FFI_ExtendedIdentityKeys> {
    Box_::new(FFI_ExtendedIdentityKeys(ExtendedIdentityKeys::generate::<
        PoseidonHash,
        ThreadRng,
    >(&mut thread_rng())))
}

#[ffi_export]
pub fn ffi_extended_identity_keys_generate_seeded(
    seed: &repr_c::Vec<u8>,
) -> repr_c::Box<FFI_ExtendedIdentityKeys> {
    Box_::new(FFI_ExtendedIdentityKeys(
        ExtendedIdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(seed),
    ))
}

#[ffi_export]
pub fn ffi_extended_identity_keys_get_trapdoor(
    identity: &FFI_ExtendedIdentityKeys,
) -> repr_c::Box<FFI_SecretFr> {
    Box_::new(FFI_SecretFr::from(identity.0.identity_trapdoor()))
}

#[ffi_export]
pub fn ffi_extended_identity_keys_get_nullifier(
    identity: &FFI_ExtendedIdentityKeys,
) -> repr_c::Box<FFI_SecretFr> {
    Box_::new(FFI_SecretFr::from(identity.0.identity_nullifier()))
}

#[ffi_export]
pub fn ffi_extended_identity_keys_get_secret(
    identity: &FFI_ExtendedIdentityKeys,
) -> repr_c::Box<FFI_SecretFr> {
    Box_::new(FFI_SecretFr::from(identity.0.identity_secret()))
}

#[ffi_export]
pub fn ffi_extended_identity_keys_get_commitment(
    identity: &FFI_ExtendedIdentityKeys,
) -> repr_c::Box<FFI_Fr> {
    FFI_Fr::from(identity.0.id_commitment()).into()
}

#[ffi_export]
pub fn ffi_extended_identity_keys_to_bytes_le(
    identity: &FFI_ExtendedIdentityKeys,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match identity.0.serialize_compressed(&mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_extended_identity_keys_to_bytes_be(
    identity: &FFI_ExtendedIdentityKeys,
) -> FFI_Result<repr_c::Vec<u8>, repr_c::String> {
    let mut bytes = Vec::new();
    match CanonicalSerializeBE::serialize(&identity.0, &mut bytes) {
        Ok(()) => FFI_Result {
            ok: Some(bytes.into()),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_extended_identity_keys_from_bytes_le(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_ExtendedIdentityKeys>, repr_c::String> {
    match ExtendedIdentityKeys::deserialize_compressed(&bytes[..]) {
        Ok(identity) => FFI_Result {
            ok: Some(Box_::new(FFI_ExtendedIdentityKeys(identity))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_extended_identity_keys_from_bytes_be(
    bytes: &repr_c::Vec<u8>,
) -> FFI_Result<repr_c::Box<FFI_ExtendedIdentityKeys>, repr_c::String> {
    match <ExtendedIdentityKeys as CanonicalDeserializeBE>::deserialize(&bytes[..]) {
        Ok(identity) => FFI_Result {
            ok: Some(Box_::new(FFI_ExtendedIdentityKeys(identity))),
            err: None,
        },
        Err(err) => FFI_Result {
            ok: None,
            err: Some(err.to_string().into()),
        },
    }
}

#[ffi_export]
pub fn ffi_extended_identity_keys_free(identity: repr_c::Box<FFI_ExtendedIdentityKeys>) {
    drop(identity);
}

// CString

#[ffi_export]
pub fn ffi_c_string_free(s: repr_c::String) {
    drop(s);
}
