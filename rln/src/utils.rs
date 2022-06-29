use ark_bn254::{Bn254, Fr, Parameters};
use ark_ff::{BigInteger, Field as ArkField, FpParameters, PrimeField};
use ark_std::str::FromStr;
use ethers_core::utils::keccak256;
use num_bigint::{BigInt, BigUint, ToBigInt};
use semaphore::{identity::Identity, Field};
use std::iter::Extend;

pub fn modulus_bit_size() -> usize {
    <Fr as PrimeField>::Params::MODULUS
        .num_bits()
        .try_into()
        .unwrap()
}

pub fn fr_byte_size() -> usize {
    let mbs = modulus_bit_size();
    (mbs + 64 - (mbs % 64)) / 8
}

pub fn to_fr(el: &Field) -> Fr {
    Fr::try_from(*el).unwrap()
}

pub fn to_field(el: &Fr) -> Field {
    (*el).try_into().unwrap()
}

pub fn vec_to_fr(v: &Vec<Field>) -> Vec<Fr> {
    let mut result: Vec<Fr> = vec![];
    for el in v {
        result.push(to_fr(el));
    }
    result
}

pub fn vec_to_field(v: &Vec<Fr>) -> Vec<Field> {
    let mut result: Vec<Field> = vec![];
    for el in v {
        result.push(to_field(el));
    }
    result
}

pub fn vec_fr_to_field(input: &Vec<Fr>) -> Vec<Field> {
    let mut res: Vec<Field> = Vec::new();
    for el in input {
        res.push(to_field(el));
    }
    res
}

pub fn vec_field_to_fr(input: &Vec<Field>) -> Vec<Fr> {
    let mut res: Vec<Fr> = Vec::new();
    for el in input {
        res.push(to_fr(el));
    }
    res
}

pub fn str_to_field(input: String, radix: i32) -> Field {
    assert!((radix == 10) || (radix == 16));

    // We remove any quote present and we trim
    let single_quote: char = '\"';
    let input_clean = input.replace(single_quote, "");
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

pub fn bytes_le_to_fr(input: &[u8]) -> (Fr, usize) {
    let el_size = fr_byte_size();
    (
        Fr::from(BigUint::from_bytes_le(&input[0..el_size])),
        el_size,
    )
}

pub fn bytes_be_to_fr(input: &[u8]) -> (Fr, usize) {
    let el_size = fr_byte_size();
    (
        Fr::from(BigUint::from_bytes_be(&input[0..el_size])),
        el_size,
    )
}

pub fn bytes_le_to_field(input: &[u8]) -> (Field, usize) {
    let (fr_el, read) = bytes_le_to_fr(input);
    (to_field(&fr_el), read)
}

pub fn bytes_be_to_field(input: &[u8]) -> (Field, usize) {
    let (fr_el, read) = bytes_be_to_fr(input);
    (to_field(&fr_el), read)
}

pub fn fr_to_bytes_le(input: &Fr) -> Vec<u8> {
    let input_biguint: BigUint = (*input).into();
    let mut res = input_biguint.to_bytes_le();
    //BigUint conversion ignores most significant zero bytes. We restore them otherwise serialization will fail (length % 8 != 0)
    while res.len() != fr_byte_size() {
        res.push(0);
    }
    res
}

pub fn fr_to_bytes_be(input: &Fr) -> Vec<u8> {
    let input_biguint: BigUint = (*input).into();
    let mut res = input_biguint.to_bytes_be();
    // BigUint conversion ignores most significant zero bytes. We restore them otherwise serialization might fail
    // Fr elements are stored using 64 bits nimbs
    while res.len() != fr_byte_size() {
        res.insert(0, 0);
    }
    res
}

pub fn field_to_bytes_le(input: &Field) -> Vec<u8> {
    fr_to_bytes_le(&to_fr(input))
}

pub fn field_to_bytes_be(input: &Field) -> Vec<u8> {
    fr_to_bytes_be(&to_fr(input))
}

pub fn vec_fr_to_bytes_le(input: &Vec<Fr>) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    //We store the vector length
    bytes.extend(input.len().to_le_bytes().to_vec());
    // We store each element
    for el in input {
        bytes.extend(fr_to_bytes_le(el));
    }
    bytes
}

pub fn vec_fr_to_bytes_be(input: &Vec<Fr>) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    //We store the vector length
    bytes.extend(input.len().to_be_bytes().to_vec());
    // We store each element
    for el in input {
        bytes.extend(fr_to_bytes_be(el));
    }
    bytes
}

pub fn vec_field_to_bytes_le(input: &Vec<Field>) -> Vec<u8> {
    vec_fr_to_bytes_le(&vec_field_to_fr(input))
}

pub fn vec_field_to_bytes_be(input: &Vec<Field>) -> Vec<u8> {
    vec_fr_to_bytes_be(&vec_field_to_fr(input))
}

pub fn vec_u8_to_bytes_le(input: &Vec<u8>) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    //We store the vector length
    bytes.extend(u64::try_from(input.len()).unwrap().to_le_bytes().to_vec());
    bytes.extend(input);
    bytes
}

pub fn vec_u8_to_bytes_be(input: Vec<u8>) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    //We store the vector length
    bytes.extend(u64::try_from(input.len()).unwrap().to_be_bytes().to_vec());
    bytes.extend(input);
    bytes
}

pub fn bytes_le_to_vec_u8(input: &[u8]) -> (Vec<u8>, usize) {
    let mut read: usize = 0;

    let len = usize::try_from(u64::from_le_bytes(input[0..8].try_into().unwrap())).unwrap();
    read += 8;

    let res = input[8..8 + len].to_vec();
    read += res.len();

    (res, read)
}

pub fn bytes_be_to_vec_u8(input: &[u8]) -> (Vec<u8>, usize) {
    let mut read: usize = 0;

    let len = usize::try_from(u64::from_be_bytes(input[0..8].try_into().unwrap())).unwrap();
    read += 8;

    let res = input[8..8 + len].to_vec();

    read += res.len();

    (res, read)
}

pub fn bytes_le_to_vec_fr(input: &[u8]) -> (Vec<Fr>, usize) {
    let mut read: usize = 0;
    let mut res: Vec<Fr> = Vec::new();

    let len = usize::try_from(u64::from_le_bytes(input[0..8].try_into().unwrap())).unwrap();
    read += 8;

    let el_size = fr_byte_size();
    for i in 0..len {
        let (curr_el, _) = bytes_le_to_fr(&input[8 + el_size * i..8 + el_size * (i + 1)].to_vec());
        res.push(curr_el);
        read += el_size;
    }

    (res, read)
}

pub fn bytes_be_to_vec_fr(input: &[u8]) -> (Vec<Fr>, usize) {
    let mut read: usize = 0;
    let mut res: Vec<Fr> = Vec::new();

    let len = usize::try_from(u64::from_be_bytes(input[0..8].try_into().unwrap())).unwrap();
    read += 8;

    let el_size = fr_byte_size();
    for i in 0..len {
        let (curr_el, _) = bytes_be_to_fr(&input[8 + el_size * i..8 + el_size * (i + 1)].to_vec());
        res.push(curr_el);
        read += el_size;
    }

    (res, read)
}

pub fn bytes_le_to_vec_field(input: &[u8]) -> (Vec<Field>, usize) {
    let (vec_fr, read) = bytes_le_to_vec_fr(input);
    (vec_fr_to_field(&vec_fr), read)
}

pub fn bytes_be_to_vec_field(input: &[u8]) -> (Vec<Field>, usize) {
    let (vec_fr, read) = bytes_be_to_vec_fr(input);
    (vec_fr_to_field(&vec_fr), read)
}

// Arithmetic over Field elements (wrapped over arkworks algebra crate)

pub fn add(a: &Field, b: &Field) -> Field {
    to_field(&(to_fr(a) + to_fr(b)))
}

pub fn mul(a: &Field, b: &Field) -> Field {
    to_field(&(to_fr(a) * to_fr(b)))
}

pub fn div(a: &Field, b: &Field) -> Field {
    to_field(&(to_fr(a) / to_fr(b)))
}

pub fn inv(a: &Field) -> Field {
    to_field(&(Fr::from(1) / to_fr(a)))
}
