#![cfg(target_arch = "wasm32")]

use ark_groth16::{Proof as ArkProof, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use js_sys::Uint8Array;
use rln::{
    circuit::{zkey_from_raw, Curve, Fr},
    protocol::{
        compute_id_secret, generate_proof, proof_values_from_witness, verify_proof, RLNProofValues,
        RLNWitnessInput,
    },
    utils::IdSecret,
};
use rln_wasm_utils::{VecWasmFr, WasmFr};
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
    pub(crate) proving_key: (ProvingKey<Curve>, ConstraintMatrices<Fr>),
    pub(crate) graph_data: Vec<u8>,
}

#[wasm_bindgen]
impl WasmRLN {
    #[wasm_bindgen(js_name = newWithParams)]
    pub fn new_with_params(
        zkey_buffer: &Uint8Array,
        graph_data: &Uint8Array,
    ) -> Result<WasmRLN, String> {
        let zkey_vec = zkey_buffer.to_vec();
        let proving_key = zkey_from_raw(&zkey_vec).map_err(|err| err.to_string())?;
        let graph_data = graph_data.to_vec();

        Ok(WasmRLN {
            proving_key,
            graph_data,
        })
    }

    #[wasm_bindgen(js_name = generateProof)]
    pub fn generate_proof(
        &self,
        identity_secret: &WasmFr,
        user_message_limit: &WasmFr,
        message_id: &WasmFr,
        path_elements: &VecWasmFr,
        identity_path_index: &Uint8Array,
        x: &WasmFr,
        external_nullifier: &WasmFr,
    ) -> Result<WasmRLNProof, String> {
        let mut identity_secret_fr = identity_secret.0;
        let path_elements_fr: Vec<Fr> = (0..path_elements.length())
            .filter_map(|i| path_elements.get(i))
            .map(|w| Fr::from(w.0))
            .collect();
        let identity_path_index_vec = identity_path_index.to_vec();

        let rln_witness = RLNWitnessInput::new(
            IdSecret::from(&mut identity_secret_fr),
            user_message_limit.0,
            message_id.0,
            path_elements_fr,
            &identity_path_index_vec,
            x.0,
            external_nullifier.0,
        )
        .map_err(|err| err.to_string())?;

        let proof_values =
            proof_values_from_witness(&rln_witness).map_err(|err| err.to_string())?;

        let proof = generate_proof(&self.proving_key, &rln_witness, &self.graph_data)
            .map_err(|err| err.to_string())?;

        Ok(WasmRLNProof {
            proof,
            proof_values,
        })
    }

    #[wasm_bindgen(js_name = verifyProof)]
    pub fn verify_proof(
        &self,
        proof: &WasmRLNProof,
        root: &WasmFr,
        x: &WasmFr,
    ) -> Result<bool, String> {
        self.verify_with_roots(proof, &VecWasmFr::from_single(*root), x)
    }

    #[wasm_bindgen(js_name = verifyWithRoots)]
    pub fn verify_with_roots(
        &self,
        proof: &WasmRLNProof,
        roots: &VecWasmFr,
        x: &WasmFr,
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
                .any(|root| root.0 == proof.proof_values.root)
        };

        let signal_verified = x.0 == proof.proof_values.x;

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
