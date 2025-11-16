#![cfg(target_arch = "wasm32")]

use ark_groth16::{Proof as ArkProof, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use js_sys::{BigInt as JsBigInt, Object, Uint8Array};
use num_bigint::BigInt;
use rln::{
    circuit::{zkey_from_raw, Curve, Fr},
    protocol::{
        compute_id_secret, generate_proof_with_witness, proof_values_from_witness,
        rln_witness_to_bigint_json, verify_proof, RLNProofValues, RLNWitnessInput,
    },
    utils::IdSecret,
};
use rln_wasm_utils::{VecWasmFr, WasmFr};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[cfg(feature = "panic_hook")]
#[wasm_bindgen(js_name = initPanicHook)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[cfg(feature = "parallel")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen]
pub struct WasmRLN {
    proving_key: (ProvingKey<Curve>, ConstraintMatrices<Fr>),
}

#[wasm_bindgen]
impl WasmRLN {
    #[wasm_bindgen(js_name = new)]
    pub fn new(zkey_buffer: &Uint8Array) -> Result<WasmRLN, String> {
        let zkey_vec = zkey_buffer.to_vec();
        let proving_key = zkey_from_raw(&zkey_vec).map_err(|err| err.to_string())?;

        Ok(WasmRLN { proving_key })
    }

    #[wasm_bindgen(js_name = generateProofWithWitness)]
    pub fn generate_proof_with_witness(
        &self,
        calculated_witness: Vec<JsBigInt>,
        rln_witness: &WasmRLNWitnessInput,
    ) -> Result<WasmRLNProof, String> {
        let proof_values =
            proof_values_from_witness(&rln_witness.0).map_err(|err| err.to_string())?;

        // Convert js_sys::BigInt to num_bigint::BigInt
        let calculated_witness_bigint: Vec<BigInt> = calculated_witness
            .iter()
            .map(|js_bigint| {
                let str_val = js_bigint.to_string(10).unwrap().as_string().unwrap();
                str_val.parse::<BigInt>().unwrap()
            })
            .collect();

        let proof = generate_proof_with_witness(calculated_witness_bigint, &self.proving_key)
            .map_err(|err| err.to_string())?;

        Ok(WasmRLNProof {
            proof_values,
            proof,
        })
    }

    #[wasm_bindgen(js_name = verifyWithRoots)]
    pub fn verify_with_roots(
        &self,
        proof: &WasmRLNProof,
        roots: &VecWasmFr,
        x: WasmFr,
    ) -> Result<bool, String> {
        let proof_verified =
            verify_proof(&self.proving_key.0.vk, &proof.proof, &proof.proof_values)
                .map_err(|err| err.to_string())?;

        if !proof_verified {
            return Ok(false);
        }

        let roots_verified = if roots.length() == 0 {
            true
        } else {
            (0..roots.length())
                .filter_map(|i| roots.get(i))
                .any(|root| *root == proof.proof_values.root)
        };

        let signal_verified = *x == proof.proof_values.x;

        Ok(proof_verified && roots_verified && signal_verified)
    }
}

#[wasm_bindgen]
pub struct WasmRLNProof {
    proof: ArkProof<Curve>,
    proof_values: RLNProofValues,
}

#[wasm_bindgen]
impl WasmRLNProof {
    #[wasm_bindgen(getter)]
    pub fn y(&self) -> WasmFr {
        WasmFr::from(self.proof_values.y)
    }

    #[wasm_bindgen(getter)]
    pub fn nullifier(&self) -> WasmFr {
        WasmFr::from(self.proof_values.nullifier)
    }

    #[wasm_bindgen(getter)]
    pub fn root(&self) -> WasmFr {
        WasmFr::from(self.proof_values.root)
    }

    #[wasm_bindgen(getter)]
    pub fn x(&self) -> WasmFr {
        WasmFr::from(self.proof_values.x)
    }

    #[wasm_bindgen(getter, js_name = externalNullifier)]
    pub fn external_nullifier(&self) -> WasmFr {
        WasmFr::from(self.proof_values.external_nullifier)
    }

    #[wasm_bindgen(js_name = recoverIdSecret)]
    pub fn recover_id_secret(
        proof_1: &WasmRLNProof,
        proof_2: &WasmRLNProof,
    ) -> Result<WasmFr, String> {
        let external_nullifier_1 = proof_1.proof_values.external_nullifier;
        let external_nullifier_2 = proof_2.proof_values.external_nullifier;

        if external_nullifier_1 != external_nullifier_2 {
            return Err("External nullifiers do not match".to_string());
        }

        let share1 = (proof_1.proof_values.x, proof_1.proof_values.y);
        let share2 = (proof_2.proof_values.x, proof_2.proof_values.y);

        let recovered_identity_secret_hash =
            compute_id_secret(share1, share2).map_err(|err| err.to_string())?;

        Ok(WasmFr::from(*recovered_identity_secret_hash))
    }
}

#[wasm_bindgen]
pub struct WasmRLNWitnessInput(RLNWitnessInput);

#[wasm_bindgen]
impl WasmRLNWitnessInput {
    #[wasm_bindgen(constructor)]
    pub fn new(
        identity_secret: WasmFr,
        user_message_limit: WasmFr,
        message_id: WasmFr,
        path_elements: &VecWasmFr,
        identity_path_index: &Uint8Array,
        x: WasmFr,
        external_nullifier: WasmFr,
    ) -> Result<WasmRLNWitnessInput, String> {
        let mut identity_secret_fr = identity_secret.inner();
        let path_elements: Vec<Fr> = path_elements.inner();
        let identity_path_index: Vec<u8> = identity_path_index.to_vec();

        let rln_witness = RLNWitnessInput::new(
            IdSecret::from(&mut identity_secret_fr),
            user_message_limit.inner(),
            message_id.inner(),
            path_elements,
            identity_path_index,
            x.inner(),
            external_nullifier.inner(),
        )
        .map_err(|err| err.to_string())?;

        Ok(WasmRLNWitnessInput(rln_witness))
    }

    #[wasm_bindgen(js_name = toBigIntJson)]
    pub fn to_bigint_json(&self) -> Result<Object, String> {
        let inputs = rln_witness_to_bigint_json(&self.0).map_err(|err| err.to_string())?;

        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        let js_value = inputs
            .serialize(&serializer)
            .map_err(|err| err.to_string())?;

        js_value
            .dyn_into::<Object>()
            .map_err(|err| format!("{:#?}", err))
    }
}
