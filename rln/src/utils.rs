// This crate provides cross-module useful utilities (mainly type conversions) not necessarily specific to RLN

use crate::circuit::Fr;
use ark_ff::PrimeField;
use color_eyre::{Report, Result};
use num_bigint::{BigInt, BigUint};
use num_traits::Num;
use serde_json::json;
use std::io::Cursor;
use std::iter::Extend;

pub fn to_bigint(el: &Fr) -> Result<BigInt> {
    let res: BigUint = (*el).into();
    Ok(res.into())
}

pub fn fr_byte_size() -> usize {
    let mbs = <Fr as PrimeField>::MODULUS_BIT_SIZE;
    ((mbs + 64 - (mbs % 64)) / 8) as usize
}

pub fn str_to_fr(input: &str, radix: u32) -> Result<Fr> {
    if !(radix == 10 || radix == 16) {
        return Err(Report::msg("wrong radix"));
    }

    // We remove any quote present and we trim
    let single_quote: char = '\"';
    let mut input_clean = input.replace(single_quote, "");
    input_clean = input_clean.trim().to_string();

    if radix == 10 {
        Ok(BigUint::from_str_radix(&input_clean, radix)?.into())
    } else {
        input_clean = input_clean.replace("0x", "");
        Ok(BigUint::from_str_radix(&input_clean, radix)?.into())
    }
}

pub fn bytes_le_to_fr(input: &[u8]) -> (Fr, usize) {
    let el_size = fr_byte_size();
    (
        Fr::from(BigUint::from_bytes_le(&input[0..el_size])),
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

pub fn vec_fr_to_bytes_le(input: &[Fr]) -> Result<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    //We store the vector length
    bytes.extend(u64::try_from(input.len())?.to_le_bytes().to_vec());

    // We store each element
    input.iter().for_each(|el| bytes.extend(fr_to_bytes_le(el)));

    Ok(bytes)
}

pub fn vec_u8_to_bytes_le(input: &[u8]) -> Result<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    //We store the vector length
    bytes.extend(u64::try_from(input.len())?.to_le_bytes().to_vec());

    bytes.extend(input);

    Ok(bytes)
}

pub fn bytes_le_to_vec_u8(input: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut read: usize = 0;

    let len = usize::try_from(u64::from_le_bytes(input[0..8].try_into()?))?;
    read += 8;

    let res = input[8..8 + len].to_vec();
    read += res.len();

    Ok((res, read))
}

pub fn bytes_le_to_vec_fr(input: &[u8]) -> Result<(Vec<Fr>, usize)> {
    let mut read: usize = 0;
    let mut res: Vec<Fr> = Vec::new();

    let len = usize::try_from(u64::from_le_bytes(input[0..8].try_into()?))?;
    read += 8;

    let el_size = fr_byte_size();
    for i in 0..len {
        let (curr_el, _) = bytes_le_to_fr(&input[8 + el_size * i..8 + el_size * (i + 1)]);
        res.push(curr_el);
        read += el_size;
    }

    Ok((res, read))
}

pub fn normalize_usize(input: usize) -> Vec<u8> {
    let mut normalized_usize = input.to_le_bytes().to_vec();
    normalized_usize.resize(8, 0);
    normalized_usize
}

pub fn bytes_le_to_vec_usize(input: &[u8]) -> Result<Vec<usize>> {
    let nof_elem = usize::try_from(u64::from_le_bytes(input[0..8].try_into()?))?;
    if nof_elem == 0 {
        Ok(vec![])
    } else {
        let elements: Vec<usize> = input[8..]
            .chunks(8)
            .map(|ch| usize::from_le_bytes(ch[0..8].try_into().unwrap()))
            .collect();
        Ok(elements)
    }
}

// using for test
pub fn generate_input_buffer() -> Cursor<String> {
    Cursor::new(json!({}).to_string())
}
