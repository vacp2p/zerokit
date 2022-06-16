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
use std::path::Path;
use std::str::FromStr;

const ZKEY_PATH: &str = "./resources/rln_final.zkey";
const VK_PATH: &str = "./resources/verifying_key.json";
const R1CS_PATH: &str = "./resources/rln.r1cs";
const WASM_PATH: &str = "./resources/rln.wasm";

pub fn ZKEY() -> Result<ProvingKey<Bn254>> /*, ConstraintMatrices<Fr>)*/ {
    if Path::new(ZKEY_PATH).exists() {
        let mut file = File::open(ZKEY_PATH).unwrap();
        let (proving_key, _matrices) = read_zkey(&mut file).unwrap();
        Ok(proving_key)
    } else {
        Err(Error::new(ErrorKind::NotFound, "No proving key found!"))
    }
}

pub fn VK() -> Result<VerifyingKey<Bn254>> {
    let verifying_key: VerifyingKey<Bn254>;

    if Path::new(VK_PATH).exists() {
        verifying_key = vk_from_json(VK_PATH);
        Ok(verifying_key)
    } else if Path::new(ZKEY_PATH).exists() {
        verifying_key = ZKEY().unwrap().vk;
        Ok(verifying_key)
    } else {
        Err(Error::new(
            ErrorKind::NotFound,
            "No proving/verification key found!",
        ))
    }
}

pub fn CIRCOM() -> CircomBuilder<Bn254> {
    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<Bn254>::new(WASM_PATH, R1CS_PATH).unwrap(); // should be )?; but need to address "the trait `From<ErrReport>` is not implemented for `protocol::ProofError`"
                                                                         // We build and return the circuit
    CircomBuilder::new(cfg)
}

// Utilities to convert a json verification key in a groth16::VerificationKey
fn fq_from_str(s: &str) -> Fq {
    Fq::try_from(BigUint::from_str(s).unwrap()).unwrap() //was BigInteger256:: and .into()
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
pub fn check_vk_from_zkey(verifying_key: VerifyingKey<Bn254>) {
    let zkey = ZKEY();
    if zkey.is_ok() {
        assert_eq!(zkey.unwrap().vk, verifying_key);
    }
}
