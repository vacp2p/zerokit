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
        use once_cell::sync::OnceCell;
        use std::sync::Mutex;
        use wasmer::{Module, Store};
        use include_dir::{include_dir, Dir};
        use std::path::Path;
    }
}

cfg_if! {
    if #[cfg(feature = "arkzkey")] {
        use ark_zkey::read_arkzkey_from_bytes;
        const ARKZKEY_FILENAME: &str = "tree_height_20/rln_final.arkzkey";

    } else {
        use std::io::Cursor;
        use ark_circom::read_zkey;
    }
}

const ZKEY_FILENAME: &str = "tree_height_20/rln_final.zkey";
pub const VK_FILENAME: &str = "tree_height_20/verification_key.arkvkey";
const WASM_FILENAME: &str = "tree_height_20/rln.wasm";

pub const TEST_TREE_HEIGHT: usize = 20;

#[cfg(not(target_arch = "wasm32"))]
pub static RESOURCES_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/resources");

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
pub fn zkey_from_folder() -> Result<(ProvingKey<Curve>, ConstraintMatrices<Fr>)> {
    #[cfg(feature = "arkzkey")]
    let zkey = RESOURCES_DIR.get_file(Path::new(ARKZKEY_FILENAME));
    #[cfg(not(feature = "arkzkey"))]
    let zkey = RESOURCES_DIR.get_file(Path::new(ZKEY_FILENAME));

    if let Some(zkey) = zkey {
        let proving_key_and_matrices = match () {
            #[cfg(feature = "arkzkey")]
            () => read_arkzkey_from_bytes(zkey.contents())?,
            #[cfg(not(feature = "arkzkey"))]
            () => {
                let mut c = Cursor::new(zkey.contents());
                read_zkey(&mut c)?
            }
        };
        Ok(proving_key_and_matrices)
    } else {
        Err(Report::msg("No proving key found!"))
    }
}

// Loads the verification key from a bytes vector
pub fn vk_from_raw(vk_data: &[u8], zkey_data: &Vec<u8>) -> Result<VerifyingKey<Curve>> {
    let verifying_key: VerifyingKey<Curve>;

    if !vk_data.is_empty() {
        verifying_key = vk_from_slice(vk_data)?;
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
pub fn vk_from_folder() -> Result<VerifyingKey<Curve>> {
    let vk = RESOURCES_DIR.get_file(Path::new(VK_FILENAME));
    let zkey = RESOURCES_DIR.get_file(Path::new(ZKEY_FILENAME));

    let verifying_key: VerifyingKey<Curve>;
    if let Some(vk) = vk {
        verifying_key = vk_from_slice(vk.contents())?;
        Ok(verifying_key)
    } else if let Some(_zkey) = zkey {
        let (proving_key, _matrices) = zkey_from_folder()?;
        verifying_key = proving_key.vk;
        Ok(verifying_key)
    } else {
        Err(Report::msg("No proving/verification key found!"))
    }
}

#[cfg(not(target_arch = "wasm32"))]
static WITNESS_CALCULATOR: OnceCell<Mutex<WitnessCalculator>> = OnceCell::new();

// Initializes the witness calculator using a bytes vector
#[cfg(not(target_arch = "wasm32"))]
pub fn circom_from_raw(wasm_buffer: Vec<u8>) -> Result<&'static Mutex<WitnessCalculator>> {
    WITNESS_CALCULATOR.get_or_try_init(|| {
        let store = Store::default();
        let module = Module::new(&store, wasm_buffer)?;
        let result = WitnessCalculator::from_module(module)?;
        Ok::<Mutex<WitnessCalculator>, Report>(Mutex::new(result))
    })
}

// Initializes the witness calculator
#[cfg(not(target_arch = "wasm32"))]
pub fn circom_from_folder() -> Result<&'static Mutex<WitnessCalculator>> {
    // We read the wasm file
    let wasm = RESOURCES_DIR.get_file(Path::new(WASM_FILENAME));

    if let Some(wasm) = wasm {
        let wasm_buffer = wasm.contents();
        circom_from_raw(wasm_buffer.to_vec())
    } else {
        Err(Report::msg("No wasm file found!"))
    }
}

// Computes the verification key from a bytes vector containing pre-processed ark-serialized verification key
// uncompressed, unchecked
pub fn vk_from_slice(data: &[u8]) -> Result<VerifyingKey<Curve>> {
    let vk = VerifyingKey::<Curve>::deserialize_uncompressed_unchecked(data)?;
    Ok(vk)
}

// Checks verification key to be correct with respect to proving key
#[cfg(not(target_arch = "wasm32"))]
pub fn check_vk_from_zkey(verifying_key: VerifyingKey<Curve>) -> Result<()> {
    let (proving_key, _matrices) = zkey_from_folder()?;
    if proving_key.vk == verifying_key {
        Ok(())
    } else {
        Err(Report::msg("verifying_keys are not equal"))
    }
}
