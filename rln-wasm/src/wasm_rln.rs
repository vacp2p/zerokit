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
        WasmRLNProofValues(self.0.proof_values)
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Uint8Array, String> {
        let bytes = rln_proof_to_bytes_le(&self.0).map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Result<Uint8Array, String> {
        let bytes = rln_proof_to_bytes_be(&self.0).map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<WasmRLNProof, String> {
        let bytes_vec = bytes.to_vec();
        let (proof, _) = bytes_le_to_rln_proof(&bytes_vec).map_err(|err| err.to_string())?;
        Ok(WasmRLNProof(proof))
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<WasmRLNProof, String> {
        let bytes_vec = bytes.to_vec();
        let (proof, _) = bytes_be_to_rln_proof(&bytes_vec).map_err(|err| err.to_string())?;
        Ok(WasmRLNProof(proof))
    }
}

#[wasm_bindgen]
pub struct WasmRLNProofValues(RLNProofValues);

#[wasm_bindgen]
impl WasmRLNProofValues {
    #[wasm_bindgen(getter)]
    pub fn y(&self) -> WasmFr {
        WasmFr::from(self.0.y)
    }

    #[wasm_bindgen(getter)]
    pub fn nullifier(&self) -> WasmFr {
        WasmFr::from(self.0.nullifier)
    }

    #[wasm_bindgen(getter)]
    pub fn root(&self) -> WasmFr {
        WasmFr::from(self.0.root)
    }

    #[wasm_bindgen(getter)]
    pub fn x(&self) -> WasmFr {
        WasmFr::from(self.0.x)
    }

    #[wasm_bindgen(getter, js_name = externalNullifier)]
    pub fn external_nullifier(&self) -> WasmFr {
        WasmFr::from(self.0.external_nullifier)
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Uint8Array {
        Uint8Array::from(&rln_proof_values_to_bytes_le(&self.0)[..])
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Uint8Array {
        Uint8Array::from(&rln_proof_values_to_bytes_be(&self.0)[..])
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<WasmRLNProofValues, String> {
        let bytes_vec = bytes.to_vec();
        let (proof_values, _) =
            bytes_le_to_rln_proof_values(&bytes_vec).map_err(|err| err.to_string())?;
        Ok(WasmRLNProofValues(proof_values))
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<WasmRLNProofValues, String> {
        let bytes_vec = bytes.to_vec();
        let (proof_values, _) =
            bytes_be_to_rln_proof_values(&bytes_vec).map_err(|err| err.to_string())?;
        Ok(WasmRLNProofValues(proof_values))
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

    #[wasm_bindgen(js_name = toBigIntJson)]
    pub fn to_bigint_json(&self) -> Result<Object, String> {
        let bigint_json = rln_witness_to_bigint_json(&self.0).map_err(|err| err.to_string())?;

        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        let js_value = bigint_json
            .serialize(&serializer)
            .map_err(|err| err.to_string())?;

        js_value
            .dyn_into::<Object>()
            .map_err(|err| format!("{:#?}", err))
    }

    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Uint8Array, String> {
        let bytes = rln_witness_to_bytes_le(&self.0).map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = toBytesBE)]
    pub fn to_bytes_be(&self) -> Result<Uint8Array, String> {
        let bytes = rln_witness_to_bytes_be(&self.0).map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<WasmRLNWitnessInput, String> {
        let bytes_vec = bytes.to_vec();
        let (witness, _) = bytes_le_to_rln_witness(&bytes_vec).map_err(|err| err.to_string())?;
        Ok(WasmRLNWitnessInput(witness))
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<WasmRLNWitnessInput, String> {
        let bytes_vec = bytes.to_vec();
        let (witness, _) = bytes_be_to_rln_witness(&bytes_vec).map_err(|err| err.to_string())?;
        Ok(WasmRLNWitnessInput(witness))
    }
}
