#![cfg(target_arch = "wasm32")]

use std::ops::Deref;

use js_sys::Uint8Array;
use rand::{rngs::ThreadRng, thread_rng};
use rand_chacha::ChaCha20Rng;
use rln::prelude::*;
use wasm_bindgen::prelude::*;

// WasmFr

#[wasm_bindgen]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WasmFr(Fr);

impl From<Fr> for WasmFr {
    fn from(fr: Fr) -> Self {
        Self(fr)
    }
}

impl Deref for WasmFr {
    type Target = Fr;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[wasm_bindgen]
impl WasmFr {
    #[wasm_bindgen(js_name = zero)]
    pub fn zero() -> Self {
        Self(Fr::from(0u32))
    }

    #[wasm_bindgen(js_name = one)]
    pub fn one() -> Self {
        Self(Fr::from(1u32))
    }

    #[wasm_bindgen(js_name = fromUint)]
    pub fn from_uint(value: u32) -> Self {
        Self(Fr::from(value))
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<Self, String> {
        let bytes_vec = bytes.to_vec();
        let fr = Fr::deserialize_compressed(&bytes_vec[..]).map_err(|err| err.to_string())?;
        Ok(Self(fr))
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<Self, String> {
        let bytes_vec = bytes.to_vec();
        let fr = <Fr as CanonicalDeserializeBE>::deserialize(&bytes_vec[..])
            .map_err(|err| err.to_string())?;
        Ok(Self(fr))
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Uint8Array, String> {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Result<Uint8Array, String> {
        let mut bytes = Vec::new();
        CanonicalSerializeBE::serialize(&self.0, &mut bytes).map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = debug)]
    pub fn debug(&self) -> String {
        format!("{:?}", self.0)
    }
}

impl WasmFr {
    pub fn inner(&self) -> Fr {
        self.0
    }
}

// WasmSecretFr (opaque secret field element, zeroized on drop)

#[wasm_bindgen]
pub struct WasmSecretFr(SecretFr);

#[wasm_bindgen]
impl WasmSecretFr {
    #[wasm_bindgen(js_name = debug)]
    pub fn debug(&self) -> String {
        format!("{:?}", self.0)
    }
}

impl WasmSecretFr {
    pub fn inner(&self) -> &SecretFr {
        &self.0
    }
}

impl From<SecretFr> for WasmSecretFr {
    fn from(secret: SecretFr) -> Self {
        Self(secret)
    }
}

// VecWasmFr

#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VecWasmFr(Vec<Fr>);

#[wasm_bindgen]
impl VecWasmFr {
    #[wasm_bindgen(js_name = new)]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<VecWasmFr, String> {
        let bytes_vec = bytes.to_vec();
        Vec::<Fr>::deserialize_compressed(&bytes_vec[..])
            .map(VecWasmFr)
            .map_err(|err| err.to_string())
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<VecWasmFr, String> {
        let bytes_vec = bytes.to_vec();
        <Vec<Fr> as CanonicalDeserializeBE>::deserialize(&bytes_vec[..])
            .map(VecWasmFr)
            .map_err(|err| err.to_string())
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Uint8Array, String> {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Result<Uint8Array, String> {
        let mut bytes = Vec::new();
        CanonicalSerializeBE::serialize(&self.0, &mut bytes).map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = get)]
    pub fn get(&self, index: usize) -> Option<WasmFr> {
        self.0.get(index).map(|&fr| WasmFr::from(fr))
    }

    #[wasm_bindgen(js_name = length)]
    pub fn length(&self) -> usize {
        self.0.len()
    }

    #[wasm_bindgen(js_name = push)]
    pub fn push(&mut self, element: &WasmFr) {
        self.0.push(element.0);
    }

    #[wasm_bindgen(js_name = debug)]
    pub fn debug(&self) -> String {
        format!("{:?}", self.0)
    }
}

impl VecWasmFr {
    pub fn inner(&self) -> Vec<Fr> {
        self.0.clone()
    }
}

impl From<Vec<Fr>> for VecWasmFr {
    fn from(vec: Vec<Fr>) -> Self {
        Self(vec)
    }
}

// Uint8Array

#[wasm_bindgen]
pub struct WasmUint8ArrayUtils;

#[wasm_bindgen]
impl WasmUint8ArrayUtils {
    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(input: &Uint8Array) -> Result<Uint8Array, String> {
        let input_vec = input.to_vec();
        let mut bytes = Vec::new();
        input_vec
            .serialize_compressed(&mut bytes)
            .map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(input: &Uint8Array) -> Result<Uint8Array, String> {
        let input_vec = input.to_vec();
        let mut bytes = Vec::new();
        CanonicalSerializeBE::serialize(&input_vec, &mut bytes).map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<Uint8Array, String> {
        let bytes_vec = bytes.to_vec();
        Vec::<u8>::deserialize_compressed(&bytes_vec[..])
            .map(|vec_u8| Uint8Array::from(&vec_u8[..]))
            .map_err(|err| err.to_string())
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<Uint8Array, String> {
        let bytes_vec = bytes.to_vec();
        <Vec<u8> as CanonicalDeserializeBE>::deserialize(&bytes_vec[..])
            .map(|vec_u8| Uint8Array::from(&vec_u8[..]))
            .map_err(|err| err.to_string())
    }
}

// Hashing

#[wasm_bindgen(js_name = poseidonHashPair)]
pub fn wasm_poseidon_hash_pair(a: &WasmFr, b: &WasmFr) -> WasmFr {
    WasmFr::from(Hasher::<PoseidonHash>::hash_pair(a.0, b.0))
}

#[wasm_bindgen(js_name = hashToFieldLE)]
pub fn wasm_hash_to_field_le(input: &Uint8Array) -> WasmFr {
    WasmFr::from(hash_to_field_le(&input.to_vec()))
}

#[wasm_bindgen(js_name = hashToFieldBE)]
pub fn wasm_hash_to_field_be(input: &Uint8Array) -> WasmFr {
    WasmFr::from(hash_to_field_be(&input.to_vec()))
}

// WasmIdentityKeys

#[wasm_bindgen]
pub struct WasmIdentityKeys(IdentityKeys);

#[wasm_bindgen]
impl WasmIdentityKeys {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate() -> WasmIdentityKeys {
        WasmIdentityKeys(IdentityKeys::generate::<PoseidonHash, ThreadRng>(
            &mut thread_rng(),
        ))
    }

    #[wasm_bindgen(js_name = generateSeeded)]
    pub fn generate_seeded(seed: &Uint8Array) -> WasmIdentityKeys {
        let seed_vec = seed.to_vec();
        WasmIdentityKeys(IdentityKeys::generate_seeded::<PoseidonHash, ChaCha20Rng>(
            &seed_vec,
        ))
    }

    #[wasm_bindgen(js_name = getSecret)]
    pub fn get_secret(&self) -> WasmSecretFr {
        WasmSecretFr::from(self.0.identity_secret())
    }

    #[wasm_bindgen(js_name = getCommitment)]
    pub fn get_commitment(&self) -> WasmFr {
        WasmFr::from(self.0.id_commitment())
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Uint8Array, String> {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Result<Uint8Array, String> {
        let mut bytes = Vec::new();
        CanonicalSerializeBE::serialize(&self.0, &mut bytes).map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<WasmIdentityKeys, String> {
        let bytes_vec = bytes.to_vec();
        IdentityKeys::deserialize_compressed(&bytes_vec[..])
            .map(WasmIdentityKeys)
            .map_err(|err| err.to_string())
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<WasmIdentityKeys, String> {
        let bytes_vec = bytes.to_vec();
        <IdentityKeys as CanonicalDeserializeBE>::deserialize(&bytes_vec[..])
            .map(WasmIdentityKeys)
            .map_err(|err| err.to_string())
    }
}

// WasmExtendedIdentityKeys

#[wasm_bindgen]
pub struct WasmExtendedIdentityKeys(ExtendedIdentityKeys);

#[wasm_bindgen]
impl WasmExtendedIdentityKeys {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate() -> WasmExtendedIdentityKeys {
        WasmExtendedIdentityKeys(ExtendedIdentityKeys::generate::<PoseidonHash, ThreadRng>(
            &mut thread_rng(),
        ))
    }

    #[wasm_bindgen(js_name = generateSeeded)]
    pub fn generate_seeded(seed: &Uint8Array) -> WasmExtendedIdentityKeys {
        let seed_vec = seed.to_vec();
        WasmExtendedIdentityKeys(ExtendedIdentityKeys::generate_seeded::<
            PoseidonHash,
            ChaCha20Rng,
        >(&seed_vec))
    }

    #[wasm_bindgen(js_name = getTrapdoor)]
    pub fn get_trapdoor(&self) -> WasmSecretFr {
        WasmSecretFr::from(self.0.identity_trapdoor())
    }

    #[wasm_bindgen(js_name = getNullifier)]
    pub fn get_nullifier(&self) -> WasmSecretFr {
        WasmSecretFr::from(self.0.identity_nullifier())
    }

    #[wasm_bindgen(js_name = getSecret)]
    pub fn get_secret(&self) -> WasmSecretFr {
        WasmSecretFr::from(self.0.identity_secret())
    }

    #[wasm_bindgen(js_name = getCommitment)]
    pub fn get_commitment(&self) -> WasmFr {
        WasmFr::from(self.0.id_commitment())
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Uint8Array, String> {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Result<Uint8Array, String> {
        let mut bytes = Vec::new();
        CanonicalSerializeBE::serialize(&self.0, &mut bytes).map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<WasmExtendedIdentityKeys, String> {
        let bytes_vec = bytes.to_vec();
        ExtendedIdentityKeys::deserialize_compressed(&bytes_vec[..])
            .map(WasmExtendedIdentityKeys)
            .map_err(|err| err.to_string())
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<WasmExtendedIdentityKeys, String> {
        let bytes_vec = bytes.to_vec();
        <ExtendedIdentityKeys as CanonicalDeserializeBE>::deserialize(&bytes_vec[..])
            .map(WasmExtendedIdentityKeys)
            .map_err(|err| err.to_string())
    }
}
