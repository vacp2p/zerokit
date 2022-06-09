use ark_bn254::{Bn254, Fr, Parameters};
use ark_ff::{Fp256, PrimeField};
use ark_std::str::FromStr;
use ethers_core::utils::keccak256;
use num_bigint::{BigInt, BigUint, ToBigInt};
use semaphore::{identity::Identity, Field};

pub fn to_fr(el: Field) -> Fr {
    Fr::try_from(el).unwrap()
}

pub fn to_field(el: Fr) -> Field {
    el.try_into().unwrap()
}

pub fn vec_to_fr(v: Vec<Field>) -> Vec<Fr> {
    let mut result: Vec<Fr> = vec![];
    for el in v {
        result.push(to_fr(el));
    }
    result
}

pub fn vec_to_field(v: Vec<Fr>) -> Vec<Field> {
    let mut result: Vec<Field> = vec![];
    for el in v {
        result.push(to_field(el));
    }
    result
}

pub fn str_to_field(input: String, radix: i32) -> Field {
    assert!((radix == 10) || (radix == 16));

    // We remove any quote present and we trim
    let input_clean = input.replace("\"", "");
    let input_clean = input_clean.trim();

    if radix == 10 {
        Field::from_str(&format!(
            "{:01$x}",
            BigUint::from_str(input_clean).unwrap(),
            64
        ))
        .unwrap()
    } else {
        let input_clean = input_clean.replace("0x", "");
        Field::from_str(&format!("{:0>64}", &input_clean)).unwrap()
    }
}

pub fn bytes_to_fr(input: &[u8]) -> Fr {
    Fr::from(BigUint::from_bytes_le(input))
}

pub fn bytes_to_field(input: &[u8]) -> Field {
    to_field(bytes_to_fr(input))
}

// Arithmetic over Field elements (wrapped over arkworks algebra crate)

pub fn add(a: Field, b: Field) -> Field {
    to_field(to_fr(a) + to_fr(b))
}

pub fn mul(a: Field, b: Field) -> Field {
    to_field(to_fr(a) * to_fr(b))
}

pub fn div(a: Field, b: Field) -> Field {
    to_field(to_fr(a) / to_fr(b))
}

pub fn inv(a: Field) -> Field {
    to_field(Fr::from(1) / to_fr(a))
}
