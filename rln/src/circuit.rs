// This crate provides interfaces for the zero-knowledge circuit and keys

use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G1Affine as ArkG1Affine,
    G1Projective as ArkG1Projective, G2Affine as ArkG2Affine, G2Projective as ArkG2Projective,
};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::CanonicalDeserialize;
use cfg_if::cfg_if;
use color_eyre::{Report, Result};

cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        use ark_circom::{WitnessCalculator};
        use once_cell::sync::{Lazy};
        use std::sync::Mutex;
        use wasmer::{Module, Store};
        use std::sync::Arc;
    }
}

cfg_if! {
    if #[cfg(feature = "arkzkey")] {
        use ark_zkey::read_arkzkey_from_bytes;
        const ARKZKEY_BYTES: &[u8] = include_bytes!("tree_height_20/rln_final.arkzkey");
    } else {
        use std::io::Cursor;
        use ark_circom::read_zkey;
    }
}

pub const ZKEY_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/rln_final.zkey");
pub const VK_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/verification_key.arkvkey");
const WASM_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/rln.wasm");

#[cfg(not(target_arch = "wasm32"))]
static ZKEY: Lazy<(ProvingKey<Curve>, ConstraintMatrices<Fr>)> = Lazy::new(|| {
    cfg_if! {
        if #[cfg(feature = "arkzkey")] {
            read_arkzkey_from_bytes(ARKZKEY_BYTES).expect("Failed to read arkzkey")
        } else {
            let mut reader = Cursor::new(ZKEY_BYTES);
            read_zkey(&mut reader).expect("Failed to read zkey")
        }
    }
});

#[cfg(not(target_arch = "wasm32"))]
static VK: Lazy<VerifyingKey<Curve>> =
    Lazy::new(|| vk_from_ark_serialized(VK_BYTES).expect("Failed to read vk"));

#[cfg(not(target_arch = "wasm32"))]
static WITNESS_CALCULATOR: Lazy<Arc<Mutex<WitnessCalculator>>> = Lazy::new(|| {
    circom_from_raw(WASM_BYTES.to_vec()).expect("Failed to create witness calculator")
});

pub const TEST_TREE_HEIGHT: usize = 20;

// The following types define the pairing friendly elliptic curve, the underlying finite fields and groups default to this module
// Note that proofs are serialized assuming Fr to be 4x8 = 32 bytes in size. Hence, changing to a curve with different encoding will make proof verification to fail
pub type Curve = Bn254;
pub type Fr = ArkFr;
pub type Fq = ArkFq;
pub type Fq2 = ArkFq2;
pub type G1Affine = ArkG1Affine;
pub type G1Projective = ArkG1Projective;
pub type G2Affine = ArkG2Affine;
pub type G2Projective = ArkG2Projective;

// Loads the proving key using a bytes vector
pub fn zkey_from_raw(zkey_data: &Vec<u8>) -> Result<(ProvingKey<Curve>, ConstraintMatrices<Fr>)> {
    if !zkey_data.is_empty() {
        let proving_key_and_matrices = match () {
            #[cfg(feature = "arkzkey")]
            () => read_arkzkey_from_bytes(zkey_data.as_slice())?,
            #[cfg(not(feature = "arkzkey"))]
            () => {
                let mut c = Cursor::new(zkey_data);
                read_zkey(&mut c)?
            }
        };
        Ok(proving_key_and_matrices)
    } else {
        Err(Report::msg("No proving key found!"))
    }
}

// Loads the proving key
#[cfg(not(target_arch = "wasm32"))]
pub fn zkey_from_folder() -> &'static (ProvingKey<Curve>, ConstraintMatrices<Fr>) {
    &ZKEY
}

// Loads the verification key from a bytes vector
pub fn vk_from_raw(vk_data: &[u8], zkey_data: &Vec<u8>) -> Result<VerifyingKey<Curve>> {
    let verifying_key: VerifyingKey<Curve>;

    if !vk_data.is_empty() {
        verifying_key = vk_from_ark_serialized(vk_data)?;
        Ok(verifying_key)
    } else if !zkey_data.is_empty() {
        let (proving_key, _matrices) = zkey_from_raw(zkey_data)?;
        verifying_key = proving_key.vk;
        Ok(verifying_key)
    } else {
        Err(Report::msg("No proving/verification key found!"))
    }
}

// Loads the verification key
#[cfg(not(target_arch = "wasm32"))]
pub fn vk_from_folder() -> &'static VerifyingKey<Curve> {
    &VK
}

// Initializes the witness calculator using a bytes vector
#[cfg(not(target_arch = "wasm32"))]
pub fn circom_from_raw(wasm_buffer: Vec<u8>) -> Result<Arc<Mutex<WitnessCalculator>>> {
    let store = Store::default();
    let module = Module::new(&store, wasm_buffer)?;
    let result = WitnessCalculator::from_module(module)?;
    let wrapped = Mutex::new(result);
    Ok(Arc::new(wrapped))
}

// Initializes the witness calculator
#[cfg(not(target_arch = "wasm32"))]
pub fn circom_from_folder() -> &'static Arc<Mutex<WitnessCalculator>> {
    &WITNESS_CALCULATOR
}

// Computes the verification key from a bytes vector containing pre-processed ark-serialized verification key
// uncompressed, unchecked
pub fn vk_from_ark_serialized(data: &[u8]) -> Result<VerifyingKey<Curve>> {
    let vk = VerifyingKey::<Curve>::deserialize_uncompressed_unchecked(data)?;
    Ok(vk)
}

// Checks verification key to be correct with respect to proving key
#[cfg(not(target_arch = "wasm32"))]
pub fn check_vk_from_zkey(verifying_key: VerifyingKey<Curve>) -> Result<()> {
    let (proving_key, _matrices) = zkey_from_folder();
    if proving_key.vk == verifying_key {
        Ok(())
    } else {
        Err(Report::msg("verifying_keys are not equal"))
    }
}
