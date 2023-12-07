// This crate provides interfaces for the zero-knowledge circuit and keys

use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G1Affine as ArkG1Affine,
    G1Projective as ArkG1Projective, G2Affine as ArkG2Affine, G2Projective as ArkG2Projective,
};
use ark_circom::read_zkey;
use ark_circom::WitnessCalculator;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use color_eyre::{Report, Result};
use num_bigint::BigUint;
use serde_json::Value;
use std::io::Cursor;
use std::str::FromStr;
use wasmer::{Module, Store};

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        use once_cell::sync::OnceCell;
        use std::sync::Mutex;
    }
}

// These parameters are used for tests
const ZKEY_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/rln_final.zkey");

const VK_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/verification_key.json");

const WASM_BYTES: &[u8] = include_bytes!("../resources/tree_height_20/rln.wasm");

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
        let mut c = Cursor::new(zkey_data);
        let proving_key_and_matrices = read_zkey(&mut c)?;
        Ok(proving_key_and_matrices)
    } else {
        Err(Report::msg("No proving key found!"))
    }
}

// Loads the proving key
pub fn default_zkey() -> Result<(ProvingKey<Curve>, ConstraintMatrices<Fr>)> {
    let mut c = Cursor::new(ZKEY_BYTES);
    let proving_key_and_matrices = read_zkey(&mut c)?;
    Ok(proving_key_and_matrices)
}

// Loads the verification key from a bytes vector
pub fn vk_from_raw(vk_data: &Vec<u8>, zkey_data: &Vec<u8>) -> Result<VerifyingKey<Curve>> {
    let verifying_key: VerifyingKey<Curve>;

    if !vk_data.is_empty() {
        verifying_key = vk_from_vector(vk_data)?;
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
pub fn default_vk() -> Result<VerifyingKey<Curve>> {
    vk_from_vector(VK_BYTES)
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

#[cfg(target_arch = "wasm32")]
pub fn circom_from_raw(wasm_buffer: Vec<u8>) -> Result<WitnessCalculator> {
    let store = Store::default();
    let module = Module::new(&store, wasm_buffer)?;
    let witness_calculator = WitnessCalculator::from_module(module)?;
    Ok(witness_calculator)
}

// Initializes the witness calculator
#[cfg(not(target_arch = "wasm32"))]
pub fn default_circom() -> Result<&'static Mutex<WitnessCalculator>> {
    // We read the wasm file
    circom_from_raw(WASM_BYTES.into())
}

#[cfg(target_arch = "wasm32")]
pub fn default_circom() -> Result<WitnessCalculator> {
    // We read the wasm file
    circom_from_raw(WASM_BYTES.into())
}

// The following function implementations are taken/adapted from https://github.com/gakonst/ark-circom/blob/1732e15d6313fe176b0b1abb858ac9e095d0dbd7/src/zkey.rs

// Utilities to convert a json verification key in a groth16::VerificationKey
fn fq_from_str(s: &str) -> Result<Fq> {
    Ok(Fq::try_from(BigUint::from_str(s)?)?)
}

// Extracts the element in G1 corresponding to its JSON serialization
fn json_to_g1(json: &Value, key: &str) -> Result<G1Affine> {
    let els: Vec<String> = json
        .get(key)
        .ok_or(Report::msg("no json value"))?
        .as_array()
        .ok_or(Report::msg("value not an array"))?
        .iter()
        .map(|i| i.as_str().ok_or(Report::msg("element is not a string")))
        .map(|x| x.map(|v| v.to_owned()))
        .collect::<Result<Vec<String>>>()?;

    Ok(G1Affine::from(G1Projective::new(
        fq_from_str(&els[0])?,
        fq_from_str(&els[1])?,
        fq_from_str(&els[2])?,
    )))
}

// Extracts the vector of G1 elements corresponding to its JSON serialization
fn json_to_g1_vec(json: &Value, key: &str) -> Result<Vec<G1Affine>> {
    let els: Vec<Vec<String>> = json
        .get(key)
        .ok_or(Report::msg("no json value"))?
        .as_array()
        .ok_or(Report::msg("value not an array"))?
        .iter()
        .map(|i| {
            i.as_array()
                .ok_or(Report::msg("element is not an array"))
                .and_then(|array| {
                    array
                        .iter()
                        .map(|x| x.as_str().ok_or(Report::msg("element is not a string")))
                        .map(|x| x.map(|v| v.to_owned()))
                        .collect::<Result<Vec<String>>>()
                })
        })
        .collect::<Result<Vec<Vec<String>>>>()?;

    let mut res = vec![];
    for coords in els {
        res.push(G1Affine::from(G1Projective::new(
            fq_from_str(&coords[0])?,
            fq_from_str(&coords[1])?,
            fq_from_str(&coords[2])?,
        )))
    }

    Ok(res)
}

// Extracts the element in G2 corresponding to its JSON serialization
fn json_to_g2(json: &Value, key: &str) -> Result<G2Affine> {
    let els: Vec<Vec<String>> = json
        .get(key)
        .ok_or(Report::msg("no json value"))?
        .as_array()
        .ok_or(Report::msg("value not an array"))?
        .iter()
        .map(|i| {
            i.as_array()
                .ok_or(Report::msg("element is not an array"))
                .and_then(|array| {
                    array
                        .iter()
                        .map(|x| x.as_str().ok_or(Report::msg("element is not a string")))
                        .map(|x| x.map(|v| v.to_owned()))
                        .collect::<Result<Vec<String>>>()
                })
        })
        .collect::<Result<Vec<Vec<String>>>>()?;

    let x = Fq2::new(fq_from_str(&els[0][0])?, fq_from_str(&els[0][1])?);
    let y = Fq2::new(fq_from_str(&els[1][0])?, fq_from_str(&els[1][1])?);
    let z = Fq2::new(fq_from_str(&els[2][0])?, fq_from_str(&els[2][1])?);
    Ok(G2Affine::from(G2Projective::new(x, y, z)))
}

// Converts JSON to a VerifyingKey
fn to_verifying_key(json: serde_json::Value) -> Result<VerifyingKey<Curve>> {
    Ok(VerifyingKey {
        alpha_g1: json_to_g1(&json, "vk_alpha_1")?,
        beta_g2: json_to_g2(&json, "vk_beta_2")?,
        gamma_g2: json_to_g2(&json, "vk_gamma_2")?,
        delta_g2: json_to_g2(&json, "vk_delta_2")?,
        gamma_abc_g1: json_to_g1_vec(&json, "IC")?,
    })
}

// Computes the verification key from its JSON serialization
fn vk_from_json(vk: &str) -> Result<VerifyingKey<Curve>> {
    let json: Value = serde_json::from_str(vk)?;
    to_verifying_key(json)
}

// Computes the verification key from a bytes vector containing its JSON serialization
fn vk_from_vector(vk: &[u8]) -> Result<VerifyingKey<Curve>> {
    let json = String::from_utf8(vk.to_vec())?;
    let json: Value = serde_json::from_str(&json)?;

    to_verifying_key(json)
}

// Checks verification key to be correct with respect to proving key
pub fn check_vk_from_zkey(verifying_key: VerifyingKey<Curve>) -> Result<()> {
    let (proving_key, _matrices) = default_zkey()?;
    if proving_key.vk == verifying_key {
        Ok(())
    } else {
        Err(Report::msg("verifying_keys are not equal"))
    }
}
