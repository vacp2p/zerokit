// This crate provides cross-module useful utilities (mainly type conversions) not necessarily specific to RLN

use crate::circuit::Fr;
use crate::error::ConversionError;
use ark_ff::PrimeField;
use num_bigint::{BigInt, BigUint};
use num_traits::Num;
use serde_json::json;
use std::io::Cursor;

#[inline(always)]
pub fn to_bigint(el: &Fr) -> BigInt {
    BigUint::from(*el).into()
}

#[inline(always)]
pub fn fr_byte_size() -> usize {
    let mbs = <Fr as PrimeField>::MODULUS_BIT_SIZE;
    ((mbs + 64 - (mbs % 64)) / 8) as usize
}

#[inline(always)]
pub fn str_to_fr(input: &str, radix: u32) -> Result<Fr, ConversionError> {
    if !(radix == 10 || radix == 16) {
        return Err(ConversionError::WrongRadix);
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

#[inline(always)]
pub fn bytes_le_to_fr(input: &[u8]) -> (Fr, usize) {
    let el_size = fr_byte_size();
    (
        Fr::from(BigUint::from_bytes_le(&input[0..el_size])),
        el_size,
    )
}

#[inline(always)]
pub fn fr_to_bytes_le(input: &Fr) -> Vec<u8> {
    let input_biguint: BigUint = (*input).into();
    let mut res = input_biguint.to_bytes_le();
    //BigUint conversion ignores most significant zero bytes. We restore them otherwise serialization will fail (length % 8 != 0)
    res.resize(fr_byte_size(), 0);
    res
}

#[inline(always)]
pub fn vec_fr_to_bytes_le(input: &[Fr]) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - 8 bytes for normalized vector length (usize)
    // - each Fr element requires fr_byte_size() bytes (typically 32 bytes)
    let mut bytes = Vec::with_capacity(8 + input.len() * fr_byte_size());

    // We store the vector length
    bytes.extend_from_slice(&normalize_usize(input.len()));

    // We store each element
    for el in input {
        bytes.extend_from_slice(&fr_to_bytes_le(el));
    }

    bytes
}

#[inline(always)]
pub fn vec_u8_to_bytes_le(input: &[u8]) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - 8 bytes for normalized vector length (usize)
    // - variable length input data
    let mut bytes = Vec::with_capacity(8 + input.len());

    // We store the vector length
    bytes.extend_from_slice(&normalize_usize(input.len()));

    // We store the input
    bytes.extend_from_slice(input);

    bytes
}

#[inline(always)]
pub fn bytes_le_to_vec_u8(input: &[u8]) -> Result<(Vec<u8>, usize), ConversionError> {
    let mut read: usize = 0;

    let len = usize::try_from(u64::from_le_bytes(input[0..8].try_into()?))?;
    read += 8;

    let res = input[8..8 + len].to_vec();
    read += res.len();

    Ok((res, read))
}

#[inline(always)]
pub fn bytes_le_to_vec_fr(input: &[u8]) -> Result<(Vec<Fr>, usize), ConversionError> {
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

#[inline(always)]
pub fn bytes_le_to_vec_usize(input: &[u8]) -> Result<Vec<usize>, ConversionError> {
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

/// Normalizes a `usize` into an 8-byte array, ensuring consistency across architectures.
/// On 32-bit systems, the result is zero-padded to 8 bytes.
/// On 64-bit systems, it directly represents the `usize` value.
#[inline(always)]
pub fn normalize_usize(input: usize) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    let input_bytes = input.to_le_bytes();
    bytes[..input_bytes.len()].copy_from_slice(&input_bytes);
    bytes
}

#[inline(always)] // using for test
pub fn generate_input_buffer() -> Cursor<String> {
    Cursor::new(json!({}).to_string())
}
