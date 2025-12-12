#![cfg(target_arch = "wasm32")]

use std::ops::Deref;

use js_sys::Uint8Array;
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
        let (fr, _) = bytes_le_to_fr(&bytes_vec).map_err(|e| e.to_string())?;
        Ok(Self(fr))
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<Self, String> {
        let bytes_vec = bytes.to_vec();
        let (fr, _) = bytes_be_to_fr(&bytes_vec).map_err(|e| e.to_string())?;
        Ok(Self(fr))
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Uint8Array {
        let bytes = fr_to_bytes_le(&self.0);
        Uint8Array::from(&bytes[..])
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Uint8Array {
        let bytes = fr_to_bytes_be(&self.0);
        Uint8Array::from(&bytes[..])
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

// VecWasmFr

#[wasm_bindgen]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VecWasmFr(Vec<Fr>);

#[wasm_bindgen]
impl VecWasmFr {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<VecWasmFr, String> {
        let bytes_vec = bytes.to_vec();
        bytes_le_to_vec_fr(&bytes_vec)
            .map(|(vec_fr, _)| VecWasmFr(vec_fr))
            .map_err(|err| err.to_string())
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<VecWasmFr, String> {
        let bytes_vec = bytes.to_vec();
        bytes_be_to_vec_fr(&bytes_vec)
            .map(|(vec_fr, _)| VecWasmFr(vec_fr))
            .map_err(|err| err.to_string())
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Uint8Array {
        let bytes = vec_fr_to_bytes_le(&self.0);
        Uint8Array::from(&bytes[..])
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Uint8Array {
        let bytes = vec_fr_to_bytes_be(&self.0);
        Uint8Array::from(&bytes[..])
    }

    #[wasm_bindgen(js_name = get)]
    pub fn get(&self, index: usize) -> Option<WasmFr> {
        self.0.get(index).map(|&fr| WasmFr(fr))
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

// Uint8Array

#[wasm_bindgen]
pub struct Uint8ArrayUtils;

#[wasm_bindgen]
impl Uint8ArrayUtils {
    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(input: &Uint8Array) -> Uint8Array {
        let input_vec = input.to_vec();
        let bytes = vec_u8_to_bytes_le(&input_vec);
        Uint8Array::from(&bytes[..])
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(input: &Uint8Array) -> Uint8Array {
        let input_vec = input.to_vec();
        let bytes = vec_u8_to_bytes_be(&input_vec);
        Uint8Array::from(&bytes[..])
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<Uint8Array, String> {
        let bytes_vec = bytes.to_vec();
        bytes_le_to_vec_u8(&bytes_vec)
            .map(|(vec_u8, _)| Uint8Array::from(&vec_u8[..]))
            .map_err(|err| err.to_string())
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<Uint8Array, String> {
        let bytes_vec = bytes.to_vec();
        bytes_be_to_vec_u8(&bytes_vec)
            .map(|(vec_u8, _)| Uint8Array::from(&vec_u8[..]))
            .map_err(|err| err.to_string())
    }
}

// Utility APIs

#[wasm_bindgen]
pub struct Hasher;

#[wasm_bindgen]
impl Hasher {
    #[wasm_bindgen(js_name = hashToFieldLE)]
    pub fn hash_to_field_le(input: &Uint8Array) -> Result<WasmFr, String> {
        hash_to_field_le(&input.to_vec())
            .map(WasmFr)
            .map_err(|e| e.to_string())
    }

    #[wasm_bindgen(js_name = hashToFieldBE)]
    pub fn hash_to_field_be(input: &Uint8Array) -> Result<WasmFr, String> {
        hash_to_field_be(&input.to_vec())
            .map(WasmFr)
            .map_err(|e| e.to_string())
    }

    #[wasm_bindgen(js_name = poseidonHashPair)]
    pub fn poseidon_hash_pair(a: &WasmFr, b: &WasmFr) -> Result<WasmFr, String> {
        poseidon_hash(&[a.0, b.0])
            .map(WasmFr)
            .map_err(|e| e.to_string())
    }
}

#[wasm_bindgen]
pub struct Identity {
    identity_secret: Fr,
    id_commitment: Fr,
}

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate() -> Result<Identity, String> {
        let (identity_secret, id_commitment) = keygen().map_err(|e| e.to_string())?;
        Ok(Identity {
            identity_secret: *identity_secret,
            id_commitment,
        })
    }

    #[wasm_bindgen(js_name = generateSeeded)]
    pub fn generate_seeded(seed: &Uint8Array) -> Result<Identity, String> {
        let seed_vec = seed.to_vec();
        let (identity_secret, id_commitment) =
            seeded_keygen(&seed_vec).map_err(|e| e.to_string())?;
        Ok(Identity {
            identity_secret,
            id_commitment,
        })
    }

    #[wasm_bindgen(js_name = getSecretHash)]
    pub fn get_secret_hash(&self) -> WasmFr {
        WasmFr(self.identity_secret)
    }

    #[wasm_bindgen(js_name = getCommitment)]
    pub fn get_commitment(&self) -> WasmFr {
        WasmFr(self.id_commitment)
    }

    #[wasm_bindgen(js_name = toArray)]
    pub fn to_array(&self) -> VecWasmFr {
        VecWasmFr(vec![self.identity_secret, self.id_commitment])
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Uint8Array {
        let vec_fr = vec![self.identity_secret, self.id_commitment];
        let bytes = vec_fr_to_bytes_le(&vec_fr);
        Uint8Array::from(&bytes[..])
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Uint8Array {
        let vec_fr = vec![self.identity_secret, self.id_commitment];
        let bytes = vec_fr_to_bytes_be(&vec_fr);
        Uint8Array::from(&bytes[..])
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<Identity, String> {
        let bytes_vec = bytes.to_vec();
        let (vec_fr, _) = bytes_le_to_vec_fr(&bytes_vec).map_err(|e| e.to_string())?;
        if vec_fr.len() != 2 {
            return Err(format!("Expected 2 elements, got {}", vec_fr.len()));
        }
        Ok(Identity {
            identity_secret: vec_fr[0],
            id_commitment: vec_fr[1],
        })
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<Identity, String> {
        let bytes_vec = bytes.to_vec();
        let (vec_fr, _) = bytes_be_to_vec_fr(&bytes_vec).map_err(|e| e.to_string())?;
        if vec_fr.len() != 2 {
            return Err(format!("Expected 2 elements, got {}", vec_fr.len()));
        }
        Ok(Identity {
            identity_secret: vec_fr[0],
            id_commitment: vec_fr[1],
        })
    }
}

#[wasm_bindgen]
pub struct ExtendedIdentity {
    identity_trapdoor: Fr,
    identity_nullifier: Fr,
    identity_secret: Fr,
    id_commitment: Fr,
}

#[wasm_bindgen]
impl ExtendedIdentity {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate() -> Result<ExtendedIdentity, String> {
        let (identity_trapdoor, identity_nullifier, identity_secret, id_commitment) =
            extended_keygen().map_err(|e| e.to_string())?;
        Ok(ExtendedIdentity {
            identity_trapdoor,
            identity_nullifier,
            identity_secret,
            id_commitment,
        })
    }

    #[wasm_bindgen(js_name = generateSeeded)]
    pub fn generate_seeded(seed: &Uint8Array) -> Result<ExtendedIdentity, String> {
        let seed_vec = seed.to_vec();
        let (identity_trapdoor, identity_nullifier, identity_secret, id_commitment) =
            extended_seeded_keygen(&seed_vec).map_err(|e| e.to_string())?;
        Ok(ExtendedIdentity {
            identity_trapdoor,
            identity_nullifier,
            identity_secret,
            id_commitment,
        })
    }

    #[wasm_bindgen(js_name = getTrapdoor)]
    pub fn get_trapdoor(&self) -> WasmFr {
        WasmFr(self.identity_trapdoor)
    }

    #[wasm_bindgen(js_name = getNullifier)]
    pub fn get_nullifier(&self) -> WasmFr {
        WasmFr(self.identity_nullifier)
    }

    #[wasm_bindgen(js_name = getSecretHash)]
    pub fn get_secret_hash(&self) -> WasmFr {
        WasmFr(self.identity_secret)
    }

    #[wasm_bindgen(js_name = getCommitment)]
    pub fn get_commitment(&self) -> WasmFr {
        WasmFr(self.id_commitment)
    }

    #[wasm_bindgen(js_name = toArray)]
    pub fn to_array(&self) -> VecWasmFr {
        VecWasmFr(vec![
            self.identity_trapdoor,
            self.identity_nullifier,
            self.identity_secret,
            self.id_commitment,
        ])
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Uint8Array {
        let vec_fr = vec![
            self.identity_trapdoor,
            self.identity_nullifier,
            self.identity_secret,
            self.id_commitment,
        ];
        let bytes = vec_fr_to_bytes_le(&vec_fr);
        Uint8Array::from(&bytes[..])
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Uint8Array {
        let vec_fr = vec![
            self.identity_trapdoor,
            self.identity_nullifier,
            self.identity_secret,
            self.id_commitment,
        ];
        let bytes = vec_fr_to_bytes_be(&vec_fr);
        Uint8Array::from(&bytes[..])
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<ExtendedIdentity, String> {
        let bytes_vec = bytes.to_vec();
        let (vec_fr, _) = bytes_le_to_vec_fr(&bytes_vec).map_err(|e| e.to_string())?;
        if vec_fr.len() != 4 {
            return Err(format!("Expected 4 elements, got {}", vec_fr.len()));
        }
        Ok(ExtendedIdentity {
            identity_trapdoor: vec_fr[0],
            identity_nullifier: vec_fr[1],
            identity_secret: vec_fr[2],
            id_commitment: vec_fr[3],
        })
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<ExtendedIdentity, String> {
        let bytes_vec = bytes.to_vec();
        let (vec_fr, _) = bytes_be_to_vec_fr(&bytes_vec).map_err(|e| e.to_string())?;
        if vec_fr.len() != 4 {
            return Err(format!("Expected 4 elements, got {}", vec_fr.len()));
        }
        Ok(ExtendedIdentity {
            identity_trapdoor: vec_fr[0],
            identity_nullifier: vec_fr[1],
            identity_secret: vec_fr[2],
            id_commitment: vec_fr[3],
        })
    }
}
