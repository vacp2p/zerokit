#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen;
extern crate web_sys;

use js_sys::{BigInt as JsBigInt, Object, Uint8Array};
use num_bigint::BigInt;
use rln::public::RLN;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen(js_name = RLN)]
pub struct RLNWrapper {
    // The purpose of this wrapper is to hold a RLN instance with the 'static lifetime
    // because wasm_bindgen does not allow returning elements with lifetimes
    instance: RLN<'static>,
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = newRLN)]
pub fn wasm_new(tree_height: usize, zkey: Uint8Array, vk: Uint8Array) -> *mut RLNWrapper {
    let instance = RLN::new_with_params(tree_height, zkey.to_vec(), vk.to_vec());
    let wrapper = RLNWrapper { instance };
    Box::into_raw(Box::new(wrapper))
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = getSerializedRLNWitness)]
pub fn wasm_get_serialized_rln_witness(ctx: *mut RLNWrapper, input: Uint8Array) -> Uint8Array {
    let wrapper = unsafe { &mut *ctx };
    let rln_witness = wrapper
        .instance
        .get_serialized_rln_witness(&input.to_vec()[..]);

    Uint8Array::from(&rln_witness[..])
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = insertMember)]
pub fn wasm_set_next_leaf(ctx: *mut RLNWrapper, input: Uint8Array) -> Result<(), String> {
    let wrapper = unsafe { &mut *ctx };
    if wrapper.instance.set_next_leaf(&input.to_vec()[..]).is_ok() {
        Ok(())
    } else {
        Err("could not insert member into merkle tree".into())
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = RLNWitnessToJson)]
pub fn rln_witness_to_json(ctx: *mut RLNWrapper, serialized_witness: Uint8Array) -> Object {
    let wrapper = unsafe { &mut *ctx };
    let inputs = wrapper
        .instance
        .get_rln_witness_json(&serialized_witness.to_vec()[..])
        .unwrap();

    let js_value = serde_wasm_bindgen::to_value(&inputs).unwrap();
    let obj = Object::from_entries(&js_value);
    obj.unwrap()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen]
pub fn generate_rln_proof_with_witness(
    ctx: *mut RLNWrapper,
    calculated_witness: Vec<JsBigInt>,
    serialized_witness: Uint8Array,
) -> Result<Uint8Array, String> {
    let wrapper = unsafe { &mut *ctx };

    let witness_vec: Vec<BigInt> = calculated_witness
        .iter()
        .map(|v| {
            v.to_string(10)
                .unwrap()
                .as_string()
                .unwrap()
                .parse::<BigInt>()
                .unwrap()
        })
        .collect();

    let mut output_data: Vec<u8> = Vec::new();

    if wrapper
        .instance
        .generate_rln_proof_with_witness(witness_vec, serialized_witness.to_vec(), &mut output_data)
        .is_ok()
    {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    } else {
        std::mem::forget(output_data);
        Err("could not generate proof".into())
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = generateMembershipKey)]
pub fn wasm_key_gen(ctx: *const RLNWrapper) -> Result<Uint8Array, String> {
    let wrapper = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if wrapper.instance.key_gen(&mut output_data).is_ok() {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    } else {
        std::mem::forget(output_data);
        Err("could not generate membership keys".into())
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = verifyRLNProof)]
pub fn wasm_verify_rln_proof(ctx: *const RLNWrapper, proof: Uint8Array) -> Result<bool, String> {
    let wrapper = unsafe { &*ctx };
    if match wrapper.instance.verify_rln_proof(&proof.to_vec()[..]) {
        Ok(verified) => verified,
        Err(_) => return Err("error while verifying rln proof".into()),
    } {
        return Ok(true);
    }

    Ok(false)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = verifyWithRoots)]
pub fn wasm_verify_with_roots(
    ctx: *const RLNWrapper,
    proof: Uint8Array,
    roots: Uint8Array,
) -> Result<bool, String> {
    let wrapper = unsafe { &*ctx };
    if match wrapper
        .instance
        .verify_with_roots(&proof.to_vec()[..], &roots.to_vec()[..])
    {
        Ok(verified) => verified,
        Err(_) => return Err("error while verifying proof with roots".into()),
    } {
        return Ok(true);
    }

    Ok(false)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[wasm_bindgen(js_name = getRoot)]
pub fn wasm_get_root(ctx: *const RLNWrapper) -> Result<Uint8Array, String> {
    let wrapper = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if wrapper.instance.get_root(&mut output_data).is_ok() {
        let result = Uint8Array::from(&output_data[..]);
        std::mem::forget(output_data);
        Ok(result)
    } else {
        std::mem::forget(output_data);
        Err("could not obtain root".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rln::circuit::TEST_TREE_HEIGHT;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen(module = "/src/utils.js")]
    extern "C" {
        #[wasm_bindgen(catch)]
        fn read_file(path: &str) -> Result<Uint8Array, JsValue>;

        #[wasm_bindgen(catch)]
        async fn calculateWitness(circom_path: &str, input: Object) -> Result<JsValue, JsValue>;
    }

    #[wasm_bindgen_test]
    pub async fn test_basic_flow() {
        let tree_height = TEST_TREE_HEIGHT;
        let circom_path = format!("../rln/resources/tree_height_{TEST_TREE_HEIGHT}/rln.wasm");
        let zkey_path = format!("../rln/resources/tree_height_{TEST_TREE_HEIGHT}/rln_final.zkey");
        let vk_path =
            format!("../rln/resources/tree_height_{TEST_TREE_HEIGHT}/verification_key.json");
        let zkey = read_file(&zkey_path).unwrap();
        let vk = read_file(&vk_path).unwrap();

        // Creating an instance of RLN
        let rln_instance = wasm_new(tree_height, zkey, vk);

        // Creating membership key
        let mem_keys = wasm_key_gen(rln_instance).unwrap();
        let idkey = mem_keys.subarray(0, 32);
        let idcommitment = mem_keys.subarray(32, 64);

        // Insert PK
        wasm_set_next_leaf(rln_instance, idcommitment).unwrap();

        // Prepare the message
        let signal = "Hello World".as_bytes();
        let signal_len: u64 = signal.len() as u64;

        // Setting up the epoch (With 0s for the test)
        let epoch = Uint8Array::new_with_length(32);
        epoch.fill(0, 0, 32);

        let identity_index: u64 = 0;

        // Serializing the message
        let mut serialized_vec: Vec<u8> = Vec::new();
        serialized_vec.append(&mut idkey.to_vec());
        serialized_vec.append(&mut identity_index.to_le_bytes().to_vec());
        serialized_vec.append(&mut epoch.to_vec());
        serialized_vec.append(&mut signal_len.to_le_bytes().to_vec());
        serialized_vec.append(&mut signal.to_vec());
        let serialized_message = Uint8Array::from(&serialized_vec[..]);

        let serialized_rln_witness =
            wasm_get_serialized_rln_witness(rln_instance, serialized_message);

        // Obtaining inputs that should be sent to circom witness calculator
        let json_inputs = rln_witness_to_json(rln_instance, serialized_rln_witness.clone());

        // Calculating witness with JS
        // (Using a JSON since wasm_bindgen does not like Result<Vec<JsBigInt>,JsValue>)
        let calculated_witness_json = calculateWitness(&circom_path, json_inputs)
            .await
            .unwrap()
            .as_string()
            .unwrap();
        let calculated_witness_vec_str: Vec<String> =
            serde_json::from_str(&calculated_witness_json).unwrap();
        let calculated_witness: Vec<JsBigInt> = calculated_witness_vec_str
            .iter()
            .map(|x| JsBigInt::new(&x.into()).unwrap())
            .collect();

        // Generating proof
        let proof = generate_rln_proof_with_witness(
            rln_instance,
            calculated_witness.into(),
            serialized_rln_witness,
        )
        .unwrap();

        // Add signal_len | signal
        let mut proof_bytes = proof.to_vec();
        proof_bytes.append(&mut signal_len.to_le_bytes().to_vec());
        proof_bytes.append(&mut signal.to_vec());
        let proof_with_signal = Uint8Array::from(&proof_bytes[..]);

        // Validate Proof
        let is_proof_valid = wasm_verify_rln_proof(rln_instance, proof_with_signal);

        assert!(
            is_proof_valid.unwrap(),
            "validating proof generated with wasm failed"
        );

        // Validating Proof with Roots
        let root = wasm_get_root(rln_instance).unwrap();
        let roots = Uint8Array::from(&root.to_vec()[..]);
        let proof_with_signal = Uint8Array::from(&proof_bytes[..]);

        let is_proof_valid = wasm_verify_with_roots(rln_instance, proof_with_signal, roots);
        assert!(is_proof_valid.unwrap(), "verifying proof with roots failed");
    }
}
