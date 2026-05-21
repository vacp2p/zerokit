#![cfg(target_arch = "wasm32")]
#![cfg(not(feature = "utils"))]

use js_sys::{BigInt as JsBigInt, Object, Uint8Array};
use num_bigint::BigInt;
use rln::prelude::*;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::wasm_utils::{VecWasmFr, WasmFr};

#[wasm_bindgen]
pub struct WasmRLN(RLNV3<Stateless, ArkGroth16Backend>);

#[wasm_bindgen]
impl WasmRLN {
    #[wasm_bindgen(constructor)]
    pub fn new(zkey_data: &Uint8Array) -> Result<WasmRLN, String> {
        let rln = RLNV3::<Stateless, ArkGroth16Backend>::new_with_params(zkey_data.to_vec())
            .map_err(|err| err.to_string())?;
        Ok(WasmRLN(rln))
    }

    #[wasm_bindgen(js_name = generateProofFromCalculatedWitness)]
    pub fn generate_proof(
        &self,
        calculated_witness_js_bigints: Vec<JsBigInt>,
    ) -> Result<WasmRLNProof, String> {
        let calculated_witness_bigints: Vec<BigInt> = calculated_witness_js_bigints
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

        let calculated_witness =
            calculated_witness_to_field_elements::<Curve>(calculated_witness_bigints)
                .map_err(|err| err.to_string())?;

        let proof = self
            .0
            .generate_proof(&calculated_witness)
            .map_err(|err| err.to_string())?;

        Ok(WasmRLNProof(proof))
    }

    #[wasm_bindgen(js_name = verify)]
    pub fn verify(
        &self,
        proof: &WasmRLNProof,
        values: &WasmRLNProofValues,
    ) -> Result<bool, String> {
        self.0
            .verify(&proof.0, &values.0)
            .map_err(|err| err.to_string())
    }

    #[wasm_bindgen(js_name = verifyWithRoots)]
    pub fn verify_with_roots(
        &self,
        proof: &WasmRLNProof,
        values: &WasmRLNProofValues,
        roots: &VecWasmFr,
        x: &WasmFr,
    ) -> Result<bool, String> {
        let roots_fr: Vec<Fr> = (0..roots.length())
            .filter_map(|i| roots.get(i))
            .map(|root| *root)
            .collect();
        self.0
            .verify_with_roots(&proof.0, &values.0, x, &roots_fr)
            .map_err(|err| err.to_string())
    }
}

#[wasm_bindgen]
pub struct WasmRLNProof(Proof);

#[wasm_bindgen]
impl WasmRLNProof {
    #[wasm_bindgen(js_name = toBytesLE)]
    pub fn to_bytes_le(&self) -> Result<Uint8Array, String> {
        let mut bytes = Vec::new();
        self.0
            .serialize_compressed(&mut bytes)
            .map_err(|err| err.to_string())?;
        Ok(Uint8Array::from(&bytes[..]))
    }

    #[wasm_bindgen(js_name = fromBytesLE)]
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<WasmRLNProof, String> {
        let proof =
            Proof::deserialize_compressed(&bytes.to_vec()[..]).map_err(|err| err.to_string())?;
        Ok(WasmRLNProof(proof))
    }
}

#[wasm_bindgen]
pub struct WasmRLNProofValues(RLNProofValuesV3);

#[wasm_bindgen]
impl WasmRLNProofValues {
    #[wasm_bindgen(getter)]
    pub fn y(&self) -> Result<WasmFr, String> {
        self.0.y().map(WasmFr::from).map_err(|e| e.to_string())
    }

    #[wasm_bindgen(js_name = ys)]
    pub fn ys(&self) -> Result<VecWasmFr, String> {
        self.0
            .ys()
            .map(|s| VecWasmFr::from(s.to_vec()))
            .map_err(|e| e.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn root(&self) -> WasmFr {
        WasmFr::from(self.0.root())
    }

    #[wasm_bindgen(getter)]
    pub fn nullifier(&self) -> Result<WasmFr, String> {
        self.0
            .nullifier()
            .map(WasmFr::from)
            .map_err(|e| e.to_string())
    }

    #[wasm_bindgen(js_name = nullifiers)]
    pub fn nullifiers(&self) -> Result<VecWasmFr, String> {
        self.0
            .nullifiers()
            .map(|s| VecWasmFr::from(s.to_vec()))
            .map_err(|e| e.to_string())
    }

    #[wasm_bindgen(getter)]
    pub fn x(&self) -> WasmFr {
        WasmFr::from(self.0.x())
    }

    #[wasm_bindgen(getter, js_name = externalNullifier)]
    pub fn external_nullifier(&self) -> WasmFr {
        WasmFr::from(self.0.external_nullifier())
    }

    #[wasm_bindgen(js_name = selectorUsed)]
    pub fn selector_used(&self) -> Result<Uint8Array, String> {
        let bytes: Vec<u8> = self
            .0
            .selector_used()
            .map_err(|e| e.to_string())?
            .iter()
            .map(|&b| if b { 1u8 } else { 0u8 })
            .collect();
        Ok(Uint8Array::from(&bytes[..]))
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
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<WasmRLNProofValues, String> {
        let proof_values = RLNProofValuesV3::deserialize_compressed(&bytes.to_vec()[..])
            .map_err(|err| err.to_string())?;
        Ok(WasmRLNProofValues(proof_values))
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<WasmRLNProofValues, String> {
        let proof_values =
            <RLNProofValuesV3 as CanonicalDeserializeBE>::deserialize(&bytes.to_vec()[..])
                .map_err(|err| err.to_string())?;
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
        let recovered_identity_secret = proof_values_1
            .0
            .recover_secret(&proof_values_2.0)
            .map_err(|err| err.to_string())?;
        Ok(WasmFr::from(*recovered_identity_secret))
    }
}

#[wasm_bindgen]
pub struct WasmRLNWitnessInput(RLNWitnessInputV3);

#[wasm_bindgen]
impl WasmRLNWitnessInput {
    #[wasm_bindgen(js_name = newSingle)]
    pub fn new_single(
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

        let witness = RLNWitnessInputSingle::new(
            IdSecret::from(&mut identity_secret_fr),
            user_message_limit.inner(),
            path_elements,
            identity_path_index,
            x.inner(),
            external_nullifier.inner(),
            message_id.inner(),
        )
        .map_err(|err| err.to_string())?;

        Ok(WasmRLNWitnessInput(witness.into()))
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = newMulti)]
    pub fn new_multi(
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

        let witness = RLNWitnessInputMulti::new(
            IdSecret::from(&mut identity_secret_fr),
            user_message_limit.inner(),
            path_elements,
            identity_path_index,
            x.inner(),
            external_nullifier.inner(),
            message_ids,
            selector_used,
        )
        .map_err(|err| err.to_string())?;

        Ok(WasmRLNWitnessInput(witness.into()))
    }

    #[wasm_bindgen(js_name = getIdentitySecret)]
    pub fn get_identity_secret(&self) -> WasmFr {
        WasmFr::from(**self.0.identity_secret())
    }

    #[wasm_bindgen(js_name = getUserMessageLimit)]
    pub fn get_user_message_limit(&self) -> WasmFr {
        WasmFr::from(*self.0.user_message_limit())
    }

    #[wasm_bindgen(js_name = getMessageId)]
    pub fn get_message_id(&self) -> Result<WasmFr, String> {
        self.0
            .message_id()
            .map(|fr| WasmFr::from(*fr))
            .map_err(|e| e.to_string())
    }

    #[wasm_bindgen(js_name = getMessageIds)]
    pub fn get_message_ids(&self) -> Result<VecWasmFr, String> {
        self.0
            .message_ids()
            .map(|s| VecWasmFr::from(s.to_vec()))
            .map_err(|e| e.to_string())
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

    #[wasm_bindgen(js_name = getSelectorUsed)]
    pub fn get_selector_used(&self) -> Result<Uint8Array, String> {
        let bytes: Vec<u8> = self
            .0
            .selector_used()
            .map_err(|e| e.to_string())?
            .iter()
            .map(|&b| if b { 1u8 } else { 0u8 })
            .collect();
        Ok(Uint8Array::from(&bytes[..]))
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
    pub fn from_bytes_le(bytes: &Uint8Array) -> Result<WasmRLNWitnessInput, String> {
        let witness = RLNWitnessInputV3::deserialize_compressed(&bytes.to_vec()[..])
            .map_err(|err| err.to_string())?;
        Ok(WasmRLNWitnessInput(witness))
    }

    #[wasm_bindgen(js_name = fromBytesBE)]
    pub fn from_bytes_be(bytes: &Uint8Array) -> Result<WasmRLNWitnessInput, String> {
        let witness =
            <RLNWitnessInputV3 as CanonicalDeserializeBE>::deserialize(&bytes.to_vec()[..])
                .map_err(|err| err.to_string())?;
        Ok(WasmRLNWitnessInput(witness))
    }

    #[wasm_bindgen(js_name = toProofValues)]
    pub fn to_proof_values(&self) -> Result<WasmRLNProofValues, String> {
        RLNProofValuesV3::try_from(self.0.clone())
            .map(WasmRLNProofValues)
            .map_err(|e| e.to_string())
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
