use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_circom::{read_zkey, CircomBuilder, CircomConfig, WitnessCalculator};
use ark_ff::BigInteger256;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintMatrices;
use core::include_bytes;
use num_bigint::BigUint;
use serde_json::Value;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{Cursor, Error, ErrorKind, Result, Write};
use std::option::Option;
use std::path::Path;
use std::str::FromStr;

const ZKEY_FILENAME: &str = "rln_final.zkey";
const VK_FILENAME: &str = "verifying_key.json";
const R1CS_FILENAME: &str = "rln.r1cs";
const WASM_FILENAME: &str = "rln.wasm";

// These parameters are used for tests
// Note that the circuit and keys in TEST_RESOURCES_FOLDER are compiled for Merkle trees of height 16 and 20 (including leaves level)
// Changing these parameters to other value than these pairs of defaults will cause zkSNARK proof verification to fail
// All tests should pass for TEST_TREE_HEIGHT = 16
// The following tests fails for TEST_TREE_HEIGHT = 20 : ffi::test::test_merkle_proof_ffi, public::test::test_merkle_proof, test::test_merkle_proof, test::test_witness_from_json
// TODO: tests containing hardcoded values for TEST_TREE_HEIGHT = 16 need to be extended for the case TEST_TREE_HEIGHT = 20 in order to pass
pub const TEST_TREE_HEIGHT: usize = 16;
pub const TEST_RESOURCES_FOLDER: &str = "./resources/tree_height_16/";
//pub const TEST_TREE_HEIGHT: usize = 20;
//pub const TEST_RESOURCES_FOLDER: &str = "./resources/tree_height_20/";

#[allow(non_snake_case)]
pub fn ZKEY(resources_folder: &str) -> Result<ProvingKey<Bn254>> {
    let zkey_path = format!("{resources_folder}{ZKEY_FILENAME}");
    if Path::new(&zkey_path).exists() {
        let mut file = File::open(&zkey_path).unwrap();
        let (proving_key, _matrices) = read_zkey(&mut file).unwrap();
        Ok(proving_key)
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
        verifying_key = ZKEY(resources_folder).unwrap().vk;
        Ok(verifying_key)
    } else {
        Err(Error::new(
            ErrorKind::NotFound,
            "No proving/verification key found!",
        ))
    }
}

#[allow(non_snake_case)]
pub fn CIRCOM(resources_folder: &str) -> Option<CircomBuilder<Bn254>> {
    let wasm_path = format!("{resources_folder}{WASM_FILENAME}");
    let r1cs_path = format!("{resources_folder}{R1CS_FILENAME}");

    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Bn254>::new(&wasm_path, &r1cs_path).unwrap();

    // We build and return the circuit
    Some(CircomBuilder::new(cfg))
}

// TODO: all the following implementations are taken from a public github project: find reference for them

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
    let zkey = ZKEY(resources_folder);
    if zkey.is_ok() {
        assert_eq!(zkey.unwrap().vk, verifying_key);
    }
}
