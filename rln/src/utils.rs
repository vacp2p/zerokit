// This crate provides cross-module useful utilities (mainly type conversions) not necessarily specific to RLN

use crate::circuit::Fr;
use ark_ff::PrimeField;
use num_bigint::{BigInt, BigUint};
use num_traits::Num;
use std::iter::Extend;

pub fn to_bigint(el: &Fr) -> BigInt {
    let res: BigUint = (*el).try_into().unwrap();
    res.try_into().unwrap()
}

pub fn fr_byte_size() -> usize {
    let mbs = <Fr as PrimeField>::size_in_bits();
    (mbs + 64 - (mbs % 64)) / 8
}

pub fn str_to_fr(input: &str, radix: u32) -> Fr {
    assert!((radix == 10) || (radix == 16));

    // We remove any quote present and we trim
    let single_quote: char = '\"';
    let mut input_clean = input.replace(single_quote, "");
    input_clean = input_clean.trim().to_string();

    if radix == 10 {
        BigUint::from_str_radix(&input_clean, radix)
            .unwrap()
            .try_into()
            .unwrap()
    } else {
        input_clean = input_clean.replace("0x", "");
        BigUint::from_str_radix(&input_clean, radix)
            .unwrap()
            .try_into()
            .unwrap()
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

pub fn vec_fr_to_bytes_le(input: &[Fr]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    //We store the vector length
    bytes.extend(u64::try_from(input.len()).unwrap().to_le_bytes().to_vec());
    // We store each element
    input.iter().for_each(|el| bytes.extend(fr_to_bytes_le(el)));

    bytes
}

pub fn vec_fr_to_bytes_be(input: &[Fr]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    //We store the vector length
    bytes.extend(u64::try_from(input.len()).unwrap().to_be_bytes().to_vec());
    // We store each element
    input.iter().for_each(|el| bytes.extend(fr_to_bytes_be(el)));

    bytes
}

pub fn vec_u8_to_bytes_le(input: &[u8]) -> Vec<u8> {
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

    let len = u64::from_le_bytes(input[0..8].try_into().unwrap()) as usize;
    read += 8;

    let res = input[8..8 + len].to_vec();
    read += res.len();

    (res, read)
}

pub fn bytes_be_to_vec_u8(input: &[u8]) -> (Vec<u8>, usize) {
    let mut read: usize = 0;

    let len = u64::from_be_bytes(input[0..8].try_into().unwrap()) as usize;
    read += 8;

    let res = input[8..8 + len].to_vec();

    read += res.len();

    (res, read)
}

pub fn bytes_le_to_vec_fr(input: &[u8]) -> (Vec<Fr>, usize) {
    let mut read: usize = 0;
    let mut res: Vec<Fr> = Vec::new();

    let len = u64::from_le_bytes(input[0..8].try_into().unwrap()) as usize;
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

    let len = u64::from_be_bytes(input[0..8].try_into().unwrap()) as usize;
    read += 8;

    let el_size = fr_byte_size();
    for i in 0..len {
        let (curr_el, _) = bytes_be_to_fr(&input[8 + el_size * i..8 + el_size * (i + 1)].to_vec());
        res.push(curr_el);
        read += el_size;
    }

    (res, read)
}

/* Old conversion utilities between different libraries data types

// Conversion Utilities between poseidon-rs Field and arkworks Fr (in order to call directly poseidon-rs' poseidon_hash)

use ff::{PrimeField as _, PrimeFieldRepr as _};
use poseidon_rs::Fr as PosFr;

pub fn fr_to_posfr(value: Fr) -> PosFr {
    let mut bytes = [0_u8; 32];
    let byte_vec = value.into_repr().to_bytes_be();
    bytes.copy_from_slice(&byte_vec[..]);
    let mut repr = <PosFr as ff::PrimeField>::Repr::default();
    repr.read_be(&bytes[..])
        .expect("read from correctly sized slice always succeeds");
    PosFr::from_repr(repr).expect("value is always in range")
}

pub fn posfr_to_fr(value: PosFr) -> Fr {
    let mut bytes = [0u8; 32];
    value
        .into_repr()
        .write_be(&mut bytes[..])
        .expect("write to correctly sized slice always succeeds");
    Fr::from_be_bytes_mod_order(&bytes)
}


// Conversion Utilities between semaphore-rs Field and arkworks Fr

use semaphore::Field;

pub fn to_fr(el: &Field) -> Fr {
    Fr::try_from(*el).unwrap()
}

pub fn to_field(el: &Fr) -> Field {
    (*el).try_into().unwrap()
}

pub fn vec_to_fr(v: &[Field]) -> Vec<Fr> {
    v.iter().map(|el| to_fr(el)).collect()
}

pub fn vec_to_field(v: &[Fr]) -> Vec<Field> {
    v.iter().map(|el| to_field(el)).collect()
}

pub fn vec_fr_to_field(input: &[Fr]) -> Vec<Field> {
    input.iter().map(|el| to_field(el)).collect()
}

pub fn vec_field_to_fr(input: &[Field]) -> Vec<Fr> {
    input.iter().map(|el| to_fr(el)).collect()
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

pub fn bytes_le_to_field(input: &[u8]) -> (Field, usize) {
    let (fr_el, read) = bytes_le_to_fr(input);
    (to_field(&fr_el), read)
}

pub fn bytes_be_to_field(input: &[u8]) -> (Field, usize) {
    let (fr_el, read) = bytes_be_to_fr(input);
    (to_field(&fr_el), read)
}


pub fn field_to_bytes_le(input: &Field) -> Vec<u8> {
    fr_to_bytes_le(&to_fr(input))
}

pub fn field_to_bytes_be(input: &Field) -> Vec<u8> {
    fr_to_bytes_be(&to_fr(input))
}


pub fn vec_field_to_bytes_le(input: &[Field]) -> Vec<u8> {
    vec_fr_to_bytes_le(&vec_field_to_fr(input))
}

pub fn vec_field_to_bytes_be(input: &[Field]) -> Vec<u8> {
    vec_fr_to_bytes_be(&vec_field_to_fr(input))
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
*/
