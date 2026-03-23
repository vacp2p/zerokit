#![cfg(target_arch = "wasm32")]
#![cfg(not(feature = "utils"))]

use js_sys::{BigInt as JsBigInt, Object, Uint8Array};
use num_bigint::BigInt;
use rln::prelude::*;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::wasm_utils::{VecWasmFr, WasmFr};

#[wasm_bindgen]
pub struct WasmRLN(RLN);

#[wasm_bindgen]
impl WasmRLN {
    #[wasm_bindgen(constructor)]
    pub fn new(zkey_data: &Uint8Array) -> Result<WasmRLN, String> {
        let rln = RLN::new_with_params(zkey_data.to_vec()).map_err(|err| err.to_string())?;
        Ok(WasmRLN(rln))
    }

    #[wasm_bindgen(js_name = generateRLNProofWithWitness)]
    pub fn generate_rln_proof_with_witness(
        &self,
        calculated_witness: Vec<JsBigInt>,
        witness: &WasmRLNWitnessInput,
    ) -> Result<WasmRLNProof, String> {
        let calculated_witness_bigint: Vec<BigInt> = calculated_witness
            .iter()
            .map(|js_bigint| {
                js_bigint
                    .to_string(10)
                    .ok()
                    .and_then(|js_str| js_str.as_string())
                    .ok_or_else(|| "Failed to convert JsBigInt to string".to_string())
                    .and_then(|str_val| {
                        str_val
                            .parse::<BigInt>()
                            .map_err(|err| format!("Failed to parse BigInt: {}", err))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let (proof, proof_values) = self
            .0
            .generate_rln_proof_with_witness(calculated_witness_bigint, &witness.0)
            .map_err(|err| err.to_string())?;

        let rln_proof = RLNProof {
            proof_values,
            proof,
        };

        Ok(WasmRLNProof(rln_proof))
    }

    #[wasm_bindgen(js_name = verifyWithRoots)]
    pub fn verify_with_roots(
        &self,
        rln_proof: &WasmRLNProof,
        roots: &VecWasmFr,
        x: &WasmFr,
    ) -> Result<bool, String> {
        let roots_fr: Vec<Fr> = (0..roots.length())
            .filter_map(|i| roots.get(i))
            .map(|root| *root)
            .collect();

        self.0
            .verify_with_roots(&rln_proof.0.proof, &rln_proof.0.proof_values, x, &roots_fr)
            .map_err(|err| err.to_string())
    }
}

#[wasm_bindgen]
pub struct WasmRLNProof(RLNProof);

#[wasm_bindgen]
impl WasmRLNProof {
    #[wasm_bindgen(js_name = getValues)]
    pub fn get_values(&self) -> WasmRLNProofValues {
        WasmRLNProofValues(self.0.proof_values.clone())
    }

    #[wasm_bindgen(js_name = getVersionByte)]
    pub fn get_version_byte(&self) -> u8 {
        self.0.version_byte()
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Uint8Array, String> {
        let bytes = self.0.to_bytes_le().map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Result<Uint8Array, String> {
        let bytes = self.0.to_bytes_be().map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<WasmRLNProof, String> {
        let bytes_vec = bytes.to_vec();
        let (proof, _) = RLNProof::from_bytes_le(&bytes_vec).map_err(|err| err.to_string())?;
        Ok(WasmRLNProof(proof))
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<WasmRLNProof, String> {
        let bytes_vec = bytes.to_vec();
        let (proof, _) = RLNProof::from_bytes_be(&bytes_vec).map_err(|err| err.to_string())?;
        Ok(WasmRLNProof(proof))
    }
}

#[wasm_bindgen]
pub struct WasmRLNProofValues(RLNProofValues);

#[wasm_bindgen]
impl WasmRLNProofValues {
    #[wasm_bindgen(getter)]
    pub fn root(&self) -> WasmFr {
        WasmFr::from(*self.0.root())
    }

    #[wasm_bindgen(getter)]
    pub fn x(&self) -> WasmFr {
        WasmFr::from(*self.0.x())
    }

    #[wasm_bindgen(getter, js_name = externalNullifier)]
    pub fn external_nullifier(&self) -> WasmFr {
        WasmFr::from(*self.0.external_nullifier())
    }

    #[cfg(not(feature = "multi-message-id"))]
    #[wasm_bindgen(getter)]
    pub fn y(&self) -> WasmFr {
        WasmFr::from(*self.0.y())
    }

    #[cfg(not(feature = "multi-message-id"))]
    #[wasm_bindgen(getter)]
    pub fn nullifier(&self) -> WasmFr {
        WasmFr::from(*self.0.nullifier())
    }

    #[cfg(feature = "multi-message-id")]
    #[wasm_bindgen(js_name = selectorUsed)]
    pub fn selector_used(&self) -> Uint8Array {
        let bytes: Vec<u8> = self
            .0
            .selector_used()
            .iter()
            .map(|&b| if b { 1u8 } else { 0u8 })
            .collect();
        Uint8Array::from(&bytes[..])
    }

    #[cfg(feature = "multi-message-id")]
    #[wasm_bindgen(js_name = ys)]
    pub fn ys(&self) -> VecWasmFr {
        VecWasmFr::from(self.0.ys().to_vec())
    }

    #[cfg(feature = "multi-message-id")]
    #[wasm_bindgen(js_name = nullifiers)]
    pub fn nullifiers(&self) -> VecWasmFr {
        VecWasmFr::from(self.0.nullifiers().to_vec())
    }

    #[wasm_bindgen(js_name = getVersionByte)]
    pub fn get_version_byte(&self) -> u8 {
        self.0.version_byte()
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Uint8Array {
        Uint8Array::from(&self.0.to_bytes_le().expect("RLNProofValues serialization is infallible")[..])
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Uint8Array {
        Uint8Array::from(&self.0.to_bytes_be().expect("RLNProofValues serialization is infallible")[..])
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<WasmRLNProofValues, String> {
        let bytes_vec = bytes.to_vec();
        let (proof_values, _) =
            RLNProofValues::from_bytes_le(&bytes_vec).map_err(|err| err.to_string())?;
        Ok(WasmRLNProofValues(proof_values))
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<WasmRLNProofValues, String> {
        let bytes_vec = bytes.to_vec();
        let (proof_values, _) =
            RLNProofValues::from_bytes_be(&bytes_vec).map_err(|err| err.to_string())?;
        Ok(WasmRLNProofValues(proof_values))
    }

    #[wasm_bindgen(js_name = computeIdSecret)]
    pub fn compute_id_secret_from_shares(
        share1_x: &WasmFr,
        share1_y: &WasmFr,
        share2_x: &WasmFr,
        share2_y: &WasmFr,
    ) -> Result<WasmFr, String> {
        let share1 = (share1_x.inner(), share1_y.inner());
        let share2 = (share2_x.inner(), share2_y.inner());
        let secret = compute_id_secret(share1, share2).map_err(|err| err.to_string())?;
        Ok(WasmFr::from(*secret))
    }

    #[wasm_bindgen(js_name = recoverIdSecret)]
    pub fn recover_id_secret(
        proof_values_1: &WasmRLNProofValues,
        proof_values_2: &WasmRLNProofValues,
    ) -> Result<WasmFr, String> {
        let recovered_identity_secret = recover_id_secret(&proof_values_1.0, &proof_values_2.0)
            .map_err(|err| err.to_string())?;

        Ok(WasmFr::from(*recovered_identity_secret))
    }
}

#[wasm_bindgen]
pub struct WasmRLNWitnessInput(RLNWitnessInput);

#[wasm_bindgen]
impl WasmRLNWitnessInput {
    #[cfg(not(feature = "multi-message-id"))]
    #[wasm_bindgen(constructor)]
    pub fn new(
        identity_secret: &WasmFr,
        user_message_limit: &WasmFr,
        message_id: &WasmFr,
        path_elements: &VecWasmFr,
        identity_path_index: &Uint8Array,
        x: &WasmFr,
        external_nullifier: &WasmFr,
    ) -> Result<WasmRLNWitnessInput, String> {
        let mut identity_secret_fr = identity_secret.inner();
        let path_elements: Vec<Fr> = path_elements.inner();
        let identity_path_index: Vec<u8> = identity_path_index.to_vec();

        let witness = RLNWitnessInput::new(
            IdSecret::from(&mut identity_secret_fr),
            user_message_limit.inner(),
            message_id.inner(),
            path_elements,
            identity_path_index,
            x.inner(),
            external_nullifier.inner(),
        )
        .map_err(|err| err.to_string())?;

        Ok(WasmRLNWitnessInput(witness))
    }

    #[cfg(feature = "multi-message-id")]
    #[wasm_bindgen(constructor)]
    pub fn new(
        identity_secret: &WasmFr,
        user_message_limit: &WasmFr,
        message_ids: VecWasmFr,
        path_elements: &VecWasmFr,
        identity_path_index: &Uint8Array,
        x: &WasmFr,
        external_nullifier: &WasmFr,
        selector_used: Uint8Array,
    ) -> Result<WasmRLNWitnessInput, String> {
        let mut identity_secret_fr = identity_secret.inner();
        let path_elements: Vec<Fr> = path_elements.inner();
        let identity_path_index: Vec<u8> = identity_path_index.to_vec();

        let message_ids: Vec<Fr> = message_ids.inner();
        let selector_used: Vec<bool> = selector_used.to_vec().iter().map(|&b| b != 0).collect();

        let witness = RLNWitnessInput::new(
            IdSecret::from(&mut identity_secret_fr),
            user_message_limit.inner(),
            message_ids,
            path_elements,
            identity_path_index,
            x.inner(),
            external_nullifier.inner(),
            selector_used,
        )
        .map_err(|err| err.to_string())?;

        Ok(WasmRLNWitnessInput(witness))
    }

    #[wasm_bindgen(js_name = getVersionByte)]
    pub fn get_version_byte(&self) -> u8 {
        self.0.version_byte()
    }

    #[wasm_bindgen(js_name = getIdentitySecret)]
    pub fn get_identity_secret(&self) -> WasmFr {
        WasmFr::from(**self.0.identity_secret())
    }

    #[wasm_bindgen(js_name = getUserMessageLimit)]
    pub fn get_user_message_limit(&self) -> WasmFr {
        WasmFr::from(*self.0.user_message_limit())
    }

    #[cfg(not(feature = "multi-message-id"))]
    #[wasm_bindgen(js_name = getMessageId)]
    pub fn get_message_id(&self) -> WasmFr {
        WasmFr::from(*self.0.message_id())
    }

    #[cfg(feature = "multi-message-id")]
    #[wasm_bindgen(js_name = getMessageIds)]
    pub fn get_message_ids(&self) -> VecWasmFr {
        VecWasmFr::from(self.0.message_ids().to_vec())
    }

    #[wasm_bindgen(js_name = getPathElements)]
    pub fn get_path_elements(&self) -> VecWasmFr {
        VecWasmFr::from(self.0.path_elements().to_vec())
    }

    #[wasm_bindgen(js_name = getIdentityPathIndex)]
    pub fn get_identity_path_index(&self) -> Uint8Array {
        Uint8Array::from(self.0.identity_path_index())
    }

    #[wasm_bindgen(js_name = getX)]
    pub fn get_x(&self) -> WasmFr {
        WasmFr::from(*self.0.x())
    }

    #[wasm_bindgen(js_name = getExternalNullifier)]
    pub fn get_external_nullifier(&self) -> WasmFr {
        WasmFr::from(*self.0.external_nullifier())
    }

    #[cfg(feature = "multi-message-id")]
    #[wasm_bindgen(js_name = getSelectorUsed)]
    pub fn get_selector_used(&self) -> Uint8Array {
        let bytes: Vec<u8> = self
            .0
            .selector_used()
            .iter()
            .map(|&b| if b { 1u8 } else { 0u8 })
            .collect();
        Uint8Array::from(&bytes[..])
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Uint8Array, String> {
        let bytes = self.0.to_bytes_le().map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Result<Uint8Array, String> {
        let bytes = self.0.to_bytes_be().map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<WasmRLNWitnessInput, String> {
        let bytes_vec = bytes.to_vec();
        let (witness, _) = RLNWitnessInput::from_bytes_le(&bytes_vec).map_err(|err| err.to_string())?;
        Ok(WasmRLNWitnessInput(witness))
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<WasmRLNWitnessInput, String> {
        let bytes_vec = bytes.to_vec();
        let (witness, _) = RLNWitnessInput::from_bytes_be(&bytes_vec).map_err(|err| err.to_string())?;
        Ok(WasmRLNWitnessInput(witness))
    }

    #[wasm_bindgen(js_name = toBigIntJson)]
    pub fn to_bigint_json(&self) -> Result<Object, String> {
        let bigint_json = self.0.to_bigint_json().map_err(|err| err.to_string())?;

        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        let js_value = bigint_json
            .serialize(&serializer)
            .map_err(|err| err.to_string())?;

        js_value
            .dyn_into::<Object>()
            .map_err(|err| format!("{:#?}", err))
    }
}
