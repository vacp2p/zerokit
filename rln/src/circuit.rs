// This crate provides interfaces for the zero-knowledge circuit and keys

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_circom::{read_zkey, WitnessCalculator};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use num_bigint::BigUint;
use once_cell::sync::OnceCell;
use serde_json::Value;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result};
use std::path::Path;
use std::str::FromStr;
use std::sync::Mutex;
use wasmer::{Module, Store};

const ZKEY_FILENAME: &str = "rln_final.zkey";
const VK_FILENAME: &str = "verifying_key.json";
const WASM_FILENAME: &str = "rln.wasm";

// These parameters are used for tests
// Note that the circuit and keys in TEST_RESOURCES_FOLDER are compiled for Merkle trees of height 15 and 19
// Changing these parameters to other values than these two defaults will cause zkSNARK proof verification to fail
//pub const TEST_TREE_HEIGHT: usize = 15;
//pub const TEST_RESOURCES_FOLDER: &str = "./resources/tree_height_15/";
//pub const TEST_TREE_HEIGHT: usize = 19;
//pub const TEST_RESOURCES_FOLDER: &str = "./resources/tree_height_19/";
pub const TEST_TREE_HEIGHT: usize = 20;
pub const TEST_RESOURCES_FOLDER: &str = "./resources/tree_height_20/";

#[allow(non_snake_case)]
pub fn ZKEY(resources_folder: &str) -> Result<(ProvingKey<Bn254>, ConstraintMatrices<Fr>)> {
    let zkey_path = format!("{resources_folder}{ZKEY_FILENAME}");
    if Path::new(&zkey_path).exists() {
        let mut file = File::open(&zkey_path)?;
        let proving_key_and_matrices = read_zkey(&mut file)?;
        Ok(proving_key_and_matrices)
    } else {
        Err(Error::new(ErrorKind::NotFound, "No proving key found!"))
    }
}

#[allow(non_snake_case)]
pub fn VK(resources_folder: &str) -> Result<VerifyingKey<Bn254>> {
    let vk_path = format!("{resources_folder}{VK_FILENAME}");
    let zkey_path = format!("{resources_folder}{ZKEY_FILENAME}");

    let verifying_key: VerifyingKey<Bn254>;

    if Path::new(&vk_path).exists() {
        verifying_key = vk_from_json(&vk_path);
        Ok(verifying_key)
    } else if Path::new(&zkey_path).exists() {
        let (proving_key, _matrices) = ZKEY(resources_folder)?;
        verifying_key = proving_key.vk;
        Ok(verifying_key)
    } else {
        Err(Error::new(
            ErrorKind::NotFound,
            "No proving/verification key found!",
        ))
    }
}

static WITNESS_CALCULATOR: OnceCell<Mutex<WitnessCalculator>> = OnceCell::new();

fn read_wasm(resources_folder: &str) -> Vec<u8> {
    let wasm_path = format!("{resources_folder}{WASM_FILENAME}");
    let mut wasm_file = File::open(&wasm_path).expect("no file found");
    let metadata = std::fs::metadata(&wasm_path).expect("unable to read metadata");
    let mut wasm_buffer = vec![0; metadata.len() as usize];
    wasm_file
        .read_exact(&mut wasm_buffer)
        .expect("buffer overflow");
    wasm_buffer
}

#[allow(non_snake_case)]
pub fn CIRCOM(resources_folder: &str) -> &'static Mutex<WitnessCalculator> {
    WITNESS_CALCULATOR.get_or_init(|| {
        // We read the wasm file
        let wasm_buffer = read_wasm(resources_folder);
        let store = Store::default();
        let module = Module::from_binary(&store, &wasm_buffer).expect("wasm should be valid");
        let result =
            WitnessCalculator::from_module(module).expect("Failed to create witness calculator");
        Mutex::new(result)
    })
}

// The following function implementations are taken/adapted from https://github.com/gakonst/ark-circom/blob/1732e15d6313fe176b0b1abb858ac9e095d0dbd7/src/zkey.rs

// Utilities to convert a json verification key in a groth16::VerificationKey
fn fq_from_str(s: &str) -> Fq {
    Fq::try_from(BigUint::from_str(s).unwrap()).unwrap()
}

// Extracts the element in G1 corresponding to its JSON serialization
fn json_to_g1(json: &Value, key: &str) -> G1Affine {
    let els: Vec<String> = json
        .get(key)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i.as_str().unwrap().to_string())
        .collect();
    G1Affine::from(G1Projective::new(
        fq_from_str(&els[0]),
        fq_from_str(&els[1]),
        fq_from_str(&els[2]),
    ))
}

// Extracts the vector of G1 elements corresponding to its JSON serialization
fn json_to_g1_vec(json: &Value, key: &str) -> Vec<G1Affine> {
    let els: Vec<Vec<String>> = json
        .get(key)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            i.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect::<Vec<String>>()
        })
        .collect();

    els.iter()
        .map(|coords| {
            G1Affine::from(G1Projective::new(
                fq_from_str(&coords[0]),
                fq_from_str(&coords[1]),
                fq_from_str(&coords[2]),
            ))
        })
        .collect()
}

// Extracts the element in G2 corresponding to its JSON serialization
fn json_to_g2(json: &Value, key: &str) -> G2Affine {
    let els: Vec<Vec<String>> = json
        .get(key)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            i.as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect::<Vec<String>>()
        })
        .collect();

    let x = Fq2::new(fq_from_str(&els[0][0]), fq_from_str(&els[0][1]));
    let y = Fq2::new(fq_from_str(&els[1][0]), fq_from_str(&els[1][1]));
    let z = Fq2::new(fq_from_str(&els[2][0]), fq_from_str(&els[2][1]));
    G2Affine::from(G2Projective::new(x, y, z))
}

// Computes the verification key from its JSON serialization
fn vk_from_json(vk_path: &str) -> VerifyingKey<Bn254> {
    let json = std::fs::read_to_string(vk_path).unwrap();
    let json: Value = serde_json::from_str(&json).unwrap();

    VerifyingKey {
        alpha_g1: json_to_g1(&json, "vk_alpha_1"),
        beta_g2: json_to_g2(&json, "vk_beta_2"),
        gamma_g2: json_to_g2(&json, "vk_gamma_2"),
        delta_g2: json_to_g2(&json, "vk_delta_2"),
        gamma_abc_g1: json_to_g1_vec(&json, "IC"),
    }
}

// Checks verification key to be correct with respect to proving key
pub fn check_vk_from_zkey(resources_folder: &str, verifying_key: VerifyingKey<Bn254>) {
    let (proving_key, _matrices) = ZKEY(resources_folder).unwrap();
    assert_eq!(proving_key.vk, verifying_key);
}
