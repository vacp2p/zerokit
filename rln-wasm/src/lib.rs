#![cfg(target_arch = "wasm32")]

use ark_bn254::Fr;
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_bigint::BigInt;
use rln::public::RLN;
use rln::utils::{bytes_be_to_fr, bytes_le_to_fr, fr_to_bytes_be, fr_to_bytes_le};
use std::vec::Vec;
use wasm_bindgen::prelude::*;

#[cfg(feature = "panic_hook")]
#[wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[cfg(feature = "parallel")]
pub use wasm_bindgen_rayon::init_thread_pool;

// WasmFr

#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct WasmFr(pub(crate) Fr);

#[wasm_bindgen]
impl WasmFr {
    #[wasm_bindgen(js_name = zero)]
    pub fn zero() -> Self {
        Self(Fr::ZERO)
    }

    #[wasm_bindgen(js_name = one)]
    pub fn one() -> Self {
        Self(Fr::ONE)
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Vec<u8>, String> {
        fr_to_bytes_le(&self.0).into()
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Result<Vec<u8>, String> {
        fr_to_bytes_be(&self.0).into()
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &[u8]) -> Result<WasmFr, String> {
        let (cfr, _) = bytes_le_to_fr(bytes);
        Ok(Self(cfr))
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &[u8]) -> Result<WasmFr, String> {
        let (cfr, _) = bytes_be_to_fr(bytes);
        Ok(Self(cfr))
    }
}

// Vec<WasmFr>

#[wasm_bindgen]
pub struct WasmVecFr {
    elements: Vec<Fr>,
}

#[wasm_bindgen]
impl WasmVecFr {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            elements: Vec::new(),
        }
    }

    #[wasm_bindgen(js_name = withCapacity)]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            elements: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.elements.len()
    }

    #[wasm_bindgen(js_name = isEmpty)]
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    #[wasm_bindgen(js_name = get)]
    pub fn get(&self, index: usize) -> Option<WasmFr> {
        self.elements.get(index).map(|fr| WasmFr::from_inner(*fr))
    }

    #[wasm_bindgen(js_name = push)]
    pub fn push(&mut self, element: &WasmFr) {
        self.elements.push(element.inner);
    }

    #[wasm_bindgen(js_name = pop)]
    pub fn pop(&mut self) -> Option<WasmFr> {
        self.elements.pop().map(WasmFr::from_inner)
    }

    #[wasm_bindgen(js_name = clear)]
    pub fn clear(&mut self) {
        self.elements.clear();
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&(self.elements.len() as u32).to_le_bytes());

        for element in &self.elements {
            element
                .serialize_compressed(&mut bytes)
                .map_err(|e| format!("Serialization error: {:?}", e))?;
        }

        Ok(bytes)
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &[u8]) -> Result<WasmVecFr, String> {
        if bytes.len() < 4 {
            return Err("Buffer too small for length prefix".to_string());
        }

        let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let mut elements = Vec::with_capacity(len);
        let mut offset = 4;

        for i in 0..len {
            if offset >= bytes.len() {
                return Err(format!("Buffer too small for element {}", i));
            }

            let element = Fr::deserialize_compressed(&bytes[offset..])
                .map_err(|e| format!("Deserialization error at index {}: {:?}", i, e))?;

            let element_size = element.compressed_size();
            elements.push(element);
            offset += element_size;
        }

        Ok(Self { elements })
    }

    pub fn debug(&self) -> String {
        format!("WasmVecFr(len={}, elements=[...])", self.elements.len())
    }
}

#[wasm_bindgen]
pub struct WasmRLNProof {
    pub(crate) proof: ArkProof<Curve>,
    pub(crate) proof_values: RLNProofValues,
}

#[wasm_bindgen]
impl WasmRLNProof {
    #[wasm_bindgen(js_name = getProof)]
    pub fn get_proof(&self) -> Vec<u8> {
        self.proof.clone()
    }

    #[wasm_bindgen(js_name = getNullifier)]
    pub fn get_nullifier(&self) -> WasmFr {
        WasmFr::from_inner(self.nullifier)
    }

    #[wasm_bindgen(js_name = getRoot)]
    pub fn get_root(&self) -> WasmFr {
        WasmFr::from_inner(self.root)
    }

    #[wasm_bindgen(js_name = getEpoch)]
    pub fn get_epoch(&self) -> WasmFr {
        WasmFr::from_inner(self.epoch)
    }

    #[wasm_bindgen(js_name = getShareX)]
    pub fn get_x(&self) -> WasmFr {
        WasmFr::from_inner(self.x)
    }

    #[wasm_bindgen(js_name = getShareY)]
    pub fn get_y(&self) -> WasmFr {
        WasmFr::from_inner(self.y)
    }

    #[wasm_bindgen(js_name = getRlnIdentifier)]
    pub fn get_rln_identifier(&self) -> WasmFr {
        WasmFr::from_inner(self.rln_identifier)
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.proof);

        for element in [
            &self.nullifier,
            &self.root,
            &self.epoch,
            &self.x,
            &self.y,
            &self.rln_identifier,
        ] {
            element
                .serialize_compressed(&mut bytes)
                .map_err(|e| format!("Serialization error: {:?}", e))?;
        }

        Ok(bytes)
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &[u8]) -> Result<WasmRLNProof, String> {
        if bytes.len() < 4 {
            return Err("Buffer too small for proof length".to_string());
        }

        let mut offset = 0;

        let proof_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        offset += 4;

        if bytes.len() < offset + proof_len {
            return Err("Buffer too small for proof data".to_string());
        }

        let proof = bytes[offset..offset + proof_len].to_vec();
        offset += proof_len;

        let deserialize_fr = |offset: &mut usize, name: &str| -> Result<Fr, String> {
            if *offset >= bytes.len() {
                return Err(format!("Buffer too small for {}", name));
            }

            let fr = Fr::deserialize_compressed(&bytes[*offset..])
                .map_err(|e| format!("Failed to deserialize {}: {:?}", name, e))?;

            *offset += fr.compressed_size();
            Ok(fr)
        };

        let nullifier = deserialize_fr(&mut offset, "nullifier")?;
        let root = deserialize_fr(&mut offset, "root")?;
        let epoch = deserialize_fr(&mut offset, "epoch")?;
        let x = deserialize_fr(&mut offset, "x")?;
        let y = deserialize_fr(&mut offset, "y")?;
        let rln_identifier = deserialize_fr(&mut offset, "rln_identifier")?;

        Ok(Self {
            proof,
            nullifier,
            root,
            epoch,
            x,
            y,
            rln_identifier,
        })
    }

    pub fn debug(&self) -> String {
        format!(
            "WasmRLNProof {{ proof_len: {}, nullifier: {:?}, root: {:?}, epoch: {:?} }}",
            self.proof.len(),
            self.nullifier,
            self.root,
            self.epoch
        )
    }
}

impl WasmRLNProof {
    pub(crate) fn new(
        proof: Vec<u8>,
        nullifier: Fr,
        root: Fr,
        epoch: Fr,
        x: Fr,
        y: Fr,
        rln_identifier: Fr,
    ) -> Self {
        Self {
            proof,
            nullifier,
            root,
            epoch,
            x,
            y,
            rln_identifier,
        }
    }

    pub(crate) fn inner_proof(&self) -> &[u8] {
        &self.proof
    }
}

#[wasm_bindgen]
pub struct WasmMerkleProof {
    path_elements: Vec<Fr>,
    path_indices: Vec<u8>,
    leaf_index: usize,
}

#[wasm_bindgen]
impl WasmMerkleProof {
    #[wasm_bindgen(js_name = getPathElements)]
    pub fn get_path_elements(&self) -> WasmVecFr {
        WasmVecFr::from_vec(self.path_elements.clone())
    }

    #[wasm_bindgen(js_name = getPathIndices)]
    pub fn get_path_indices(&self) -> Vec<u8> {
        self.path_indices.clone()
    }

    #[wasm_bindgen(js_name = getLeafIndex)]
    pub fn get_leaf_index(&self) -> usize {
        self.leaf_index
    }

    #[wasm_bindgen(js_name = getDepth)]
    pub fn get_depth(&self) -> usize {
        self.path_elements.len()
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&(self.path_elements.len() as u32).to_le_bytes());
        for element in &self.path_elements {
            element
                .serialize_compressed(&mut bytes)
                .map_err(|e| format!("Serialization error: {:?}", e))?;
        }

        bytes.extend_from_slice(&(self.path_indices.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.path_indices);

        bytes.extend_from_slice(&(self.leaf_index as u64).to_le_bytes());

        Ok(bytes)
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &[u8]) -> Result<WasmMerkleProof, String> {
        let mut offset = 0;

        if bytes.len() < offset + 4 {
            return Err("Buffer too small for path elements length".to_string());
        }

        let path_elements_len = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        let mut path_elements = Vec::with_capacity(path_elements_len);
        for i in 0..path_elements_len {
            if offset >= bytes.len() {
                return Err(format!("Buffer too small for path element {}", i));
            }

            let element = Fr::deserialize_compressed(&bytes[offset..])
                .map_err(|e| format!("Failed to deserialize path element {}: {:?}", i, e))?;

            offset += element.compressed_size();
            path_elements.push(element);
        }

        if bytes.len() < offset + 4 {
            return Err("Buffer too small for path indices length".to_string());
        }

        let path_indices_len = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        offset += 4;

        if bytes.len() < offset + path_indices_len {
            return Err("Buffer too small for path indices data".to_string());
        }

        let path_indices = bytes[offset..offset + path_indices_len].to_vec();
        offset += path_indices_len;

        if bytes.len() < offset + 8 {
            return Err("Buffer too small for leaf index".to_string());
        }

        let leaf_index = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]) as usize;

        Ok(Self {
            path_elements,
            path_indices,
            leaf_index,
        })
    }

    pub fn debug(&self) -> String {
        format!(
            "WasmMerkleProof {{ depth: {}, leaf_index: {} }}",
            self.path_elements.len(),
            self.leaf_index
        )
    }
}

impl WasmMerkleProof {
    pub(crate) fn new(path_elements: Vec<Fr>, path_indices: Vec<u8>, leaf_index: usize) -> Self {
        Self {
            path_elements,
            path_indices,
            leaf_index,
        }
    }
}

#[wasm_bindgen]
pub struct WasmRLN {
    instance: RLN,
}

#[wasm_bindgen]
impl WasmRLN {
    #[wasm_bindgen(constructor)]
    pub fn new(zkey: Vec<u8>) -> Result<WasmRLN, String> {
        let instance =
            RLN::new_with_params(zkey).map_err(|e| format!("Failed to create RLN: {:?}", e))?;
        Ok(Self { instance })
    }

    #[wasm_bindgen(js_name = leavesSet)]
    pub fn leaves_set(&self) -> usize {
        self.instance.leaves_set()
    }

    #[wasm_bindgen(js_name = setNextLeaf)]
    pub fn set_next_leaf(&mut self, leaf: &WasmFr) -> Result<(), String> {
        self.instance
            .set_next_leaf(leaf.inner())
            .map_err(|e| format!("Failed to set leaf: {:?}", e))
    }

    #[wasm_bindgen(js_name = getProof)]
    pub fn get_proof(&self, index: usize) -> Result<WasmMerkleProof, String> {
        let proof = self
            .instance
            .get_proof(index)
            .map_err(|e| format!("Failed to get proof: {:?}", e))?;

        Ok(WasmMerkleProof::new(
            proof.path_elements,
            proof.path_indices,
            index,
        ))
    }

    #[wasm_bindgen(js_name = verifyRlnProof)]
    pub fn verify_rln_proof(&self, proof: &WasmRLNProof, x: &WasmFr) -> Result<bool, String> {
        self.instance
            .verify_proof(proof.inner_proof(), x.inner())
            .map_err(|e| format!("Verification failed: {:?}", e))
    }

    #[wasm_bindgen(js_name = verifyWithRoots)]
    pub fn verify_with_roots(
        &self,
        proof: &WasmRLNProof,
        roots: &WasmVecFr,
        x: &WasmFr,
    ) -> Result<bool, String> {
        self.instance
            .verify_with_roots(proof.inner_proof(), roots.as_slice(), x.inner())
            .map_err(|e| format!("Verification with roots failed: {:?}", e))
    }
}

#[wasm_bindgen(js_name = hashToFieldLE)]
pub fn hash_to_field_le(data: &[u8]) -> Result<WasmFr, String> {
    use rln::protocol::hash_to_field;
    let fr = hash_to_field(data).map_err(|e| format!("Hash to field failed: {:?}", e))?;
    Ok(WasmFr::from_inner(fr))
}

#[wasm_bindgen(js_name = poseidonHashPair)]
pub fn poseidon_hash_pair(a: &WasmFr, b: &WasmFr) -> Result<WasmFr, String> {
    use rln::protocol::poseidon_hash;
    let result = poseidon_hash(&[*a.inner(), *b.inner()])
        .map_err(|e| format!("Poseidon hash failed: {:?}", e))?;
    Ok(WasmFr::from_inner(result))
}

#[wasm_bindgen(js_name = keyGen)]
pub fn key_gen() -> Result<WasmVecFr, String> {
    use rln::protocol::keygen;
    let (secret, commitment) = keygen();

    let mut vec = WasmVecFr::new();
    vec.push(&WasmFr::from_inner(secret));
    vec.push(&WasmFr::from_inner(commitment));
    Ok(vec)
}

#[wasm_bindgen(js_name = recoverIdSecret)]
pub fn recover_id_secret(proof1: &WasmRLNProof, proof2: &WasmRLNProof) -> Result<WasmFr, String> {
    if proof1.get_epoch().inner() != proof2.get_epoch().inner() {
        return Err("Proofs must share the same epoch".to_string());
    }

    let x1 = proof1.get_x().inner();
    let y1 = proof1.get_y().inner();
    let x2 = proof2.get_x().inner();
    let y2 = proof2.get_y().inner();

    if x1 == x2 {
        return Err("Shares have the same x coordinate (not a valid double-signal)".to_string());
    }

    let x_diff = *x1 - x2;
    let x_diff_inv = x_diff
        .inverse()
        .ok_or("Failed to compute inverse (this should never happen)")?;

    let l1 = -*x2 * x_diff_inv;
    let l2 = *x1 * x_diff_inv;

    let secret = *y1 * l1 + *y2 * l2;

    Ok(WasmFr::from_inner(secret))
}
