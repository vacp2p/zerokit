// This crate provides cross-module useful utilities (mainly type conversions) not necessarily specific to RLN

use crate::circuit::Fr;
use crate::error::ConversionError;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use num_bigint::{BigInt, BigUint};
use num_traits::Num;
use rand::Rng;
use ruint::aliases::U256;
use serde_json::json;
use std::io::Cursor;
use std::ops::Deref;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[inline(always)]
pub fn to_bigint(el: &Fr) -> BigInt {
    BigUint::from(*el).into()
}

#[inline(always)]
pub const fn fr_byte_size() -> usize {
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
pub fn bytes_be_to_fr(input: &[u8]) -> (Fr, usize) {
    let el_size = fr_byte_size();
    (
        Fr::from(BigUint::from_bytes_be(&input[0..el_size])),
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
pub fn fr_to_bytes_be(input: &Fr) -> Vec<u8> {
    let input_biguint: BigUint = (*input).into();
    let mut res = input_biguint.to_bytes_be();
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
    bytes.extend_from_slice(&normalize_usize_le(input.len()));

    // We store each element
    for el in input {
        bytes.extend_from_slice(&fr_to_bytes_le(el));
    }

    bytes
}

#[inline(always)]
pub fn vec_fr_to_bytes_be(input: &[Fr]) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - 8 bytes for normalized vector length (usize)
    // - each Fr element requires fr_byte_size() bytes (typically 32 bytes)
    let mut bytes = Vec::with_capacity(8 + input.len() * fr_byte_size());

    // We store the vector length
    bytes.extend_from_slice(&normalize_usize_be(input.len()));

    // We store each element
    for el in input {
        bytes.extend_from_slice(&fr_to_bytes_be(el));
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
    bytes.extend_from_slice(&normalize_usize_le(input.len()));

    // We store the input
    bytes.extend_from_slice(input);

    bytes
}

#[inline(always)]
pub fn vec_u8_to_bytes_be(input: &[u8]) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - 8 bytes for normalized vector length (usize)
    // - variable length input data
    let mut bytes = Vec::with_capacity(8 + input.len());

    // We store the vector length
    bytes.extend_from_slice(&normalize_usize_be(input.len()));

    // We store the input
    bytes.extend_from_slice(input);

    bytes
}

#[inline(always)]
pub fn bytes_le_to_vec_u8(input: &[u8]) -> Result<(Vec<u8>, usize), ConversionError> {
    let mut read: usize = 0;
    if input.len() < 8 {
        return Err(ConversionError::InsufficientData {
            expected: 8,
            actual: input.len(),
        });
    }
    let len = usize::try_from(u64::from_le_bytes(input[0..8].try_into()?))?;
    read += 8;
    if input.len() < 8 + len {
        return Err(ConversionError::InsufficientData {
            expected: 8 + len,
            actual: input.len(),
        });
    }
    let res = input[8..8 + len].to_vec();
    read += res.len();
    Ok((res, read))
}

#[inline(always)]
pub fn bytes_be_to_vec_u8(input: &[u8]) -> Result<(Vec<u8>, usize), ConversionError> {
    let mut read: usize = 0;
    if input.len() < 8 {
        return Err(ConversionError::InsufficientData {
            expected: 8,
            actual: input.len(),
        });
    }
    let len = usize::try_from(u64::from_be_bytes(input[0..8].try_into()?))?;
    read += 8;
    if input.len() < 8 + len {
        return Err(ConversionError::InsufficientData {
            expected: 8 + len,
            actual: input.len(),
        });
    }
    let res = input[8..8 + len].to_vec();
    read += res.len();
    Ok((res, read))
}

#[inline(always)]
pub fn bytes_le_to_vec_fr(input: &[u8]) -> Result<(Vec<Fr>, usize), ConversionError> {
    let mut read: usize = 0;
    if input.len() < 8 {
        return Err(ConversionError::InsufficientData {
            expected: 8,
            actual: input.len(),
        });
    }
    let len = usize::try_from(u64::from_le_bytes(input[0..8].try_into()?))?;
    read += 8;
    let el_size = fr_byte_size();
    if input.len() < 8 + len * el_size {
        return Err(ConversionError::InsufficientData {
            expected: 8 + len * el_size,
            actual: input.len(),
        });
    }
    let mut res: Vec<Fr> = Vec::with_capacity(len);
    for i in 0..len {
        let (curr_el, _) = bytes_le_to_fr(&input[8 + el_size * i..8 + el_size * (i + 1)]);
        res.push(curr_el);
        read += el_size;
    }
    Ok((res, read))
}

#[inline(always)]
pub fn bytes_be_to_vec_fr(input: &[u8]) -> Result<(Vec<Fr>, usize), ConversionError> {
    let mut read: usize = 0;
    if input.len() < 8 {
        return Err(ConversionError::InsufficientData {
            expected: 8,
            actual: input.len(),
        });
    }
    let len = usize::try_from(u64::from_be_bytes(input[0..8].try_into()?))?;
    read += 8;
    let el_size = fr_byte_size();
    if input.len() < 8 + len * el_size {
        return Err(ConversionError::InsufficientData {
            expected: 8 + len * el_size,
            actual: input.len(),
        });
    }
    let mut res: Vec<Fr> = Vec::with_capacity(len);
    for i in 0..len {
        let (curr_el, _) = bytes_be_to_fr(&input[8 + el_size * i..8 + el_size * (i + 1)]);
        res.push(curr_el);
        read += el_size;
    }
    Ok((res, read))
}

#[inline(always)]
pub fn bytes_be_to_vec_fr(input: &[u8]) -> Result<(Vec<Fr>, usize), ConversionError> {
    let mut read: usize = 0;
    let mut res: Vec<Fr> = Vec::new();

    let len = usize::try_from(u64::from_be_bytes(input[0..8].try_into()?))?;
    read += 8;

    let el_size = fr_byte_size();
    for i in 0..len {
        let (curr_el, _) = bytes_be_to_fr(&input[8 + el_size * i..8 + el_size * (i + 1)]);
        res.push(curr_el);
        read += el_size;
    }

    Ok((res, read))
}

#[inline(always)]
pub fn bytes_le_to_vec_usize(input: &[u8]) -> Result<Vec<usize>, ConversionError> {
    if input.len() < 8 {
        return Err(ConversionError::InsufficientData {
            expected: 8,
            actual: input.len(),
        });
    }
    let nof_elem = usize::try_from(u64::from_le_bytes(input[0..8].try_into()?))?;
    if nof_elem == 0 {
        Ok(vec![])
    } else {
        if input.len() < 8 + nof_elem * 8 {
            return Err(ConversionError::InsufficientData {
                expected: 8 + nof_elem * 8,
                actual: input.len(),
            });
        }
        let elements: Vec<usize> = input[8..]
            .chunks(8)
            .take(nof_elem)
            .map(|ch| usize::from_le_bytes(ch[0..8].try_into().unwrap()))
            .collect();
        Ok(elements)
    }
}

#[inline(always)]
pub fn bytes_be_to_vec_usize(input: &[u8]) -> Result<Vec<usize>, ConversionError> {
    if input.len() < 8 {
        return Err(ConversionError::InsufficientData {
            expected: 8,
            actual: input.len(),
        });
    }
    let nof_elem = usize::try_from(u64::from_be_bytes(input[0..8].try_into()?))?;
    if nof_elem == 0 {
        Ok(vec![])
    } else {
        if input.len() < 8 + nof_elem * 8 {
            return Err(ConversionError::InsufficientData {
                expected: 8 + nof_elem * 8,
                actual: input.len(),
            });
        }
        let elements: Vec<usize> = input[8..]
            .chunks(8)
            .take(nof_elem)
            .map(|ch| usize::from_be_bytes(ch[0..8].try_into().unwrap()))
            .collect();
        Ok(elements)
    }
}

/// Normalizes a `usize` into an 8-byte array, ensuring consistency across architectures.
/// On 32-bit systems, the result is zero-padded to 8 bytes.
/// On 64-bit systems, it directly represents the `usize` value.
#[inline(always)]
pub fn normalize_usize_le(input: usize) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    let input_bytes = input.to_le_bytes();
    bytes[..input_bytes.len()].copy_from_slice(&input_bytes);
    bytes
}

/// Normalizes a `usize` into an 8-byte array, ensuring consistency across architectures.
/// On 32-bit systems, the result is zero-padded to 8 bytes.
/// On 64-bit systems, it directly represents the `usize` value.
#[inline(always)]
pub fn normalize_usize_be(input: usize) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    let input_bytes = input.to_be_bytes();
    bytes[..input_bytes.len()].copy_from_slice(&input_bytes);
    bytes
}

#[inline(always)] // using for test
pub fn generate_input_buffer() -> Cursor<String> {
    Cursor::new(json!({}).to_string())
}

#[derive(
    Debug, Zeroize, ZeroizeOnDrop, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct IdSecret(ark_bn254::Fr);

impl IdSecret {
    pub fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut fr = Fr::rand(rng);
        let res = Self::from(&mut fr);
        // No need to zeroize fr (already zeroiz'ed in from implementation)
        #[allow(clippy::let_and_return)]
        res
    }

    pub fn from_bytes_le(input: &[u8]) -> (Self, usize) {
        let el_size = fr_byte_size();
        let b_uint = BigUint::from_bytes_le(&input[0..el_size]);
        let mut fr = Fr::from(b_uint);
        let res = IdSecret::from(&mut fr);
        // Note: no zeroize on b_uint as it has been moved
        (res, el_size)
    }

    pub(crate) fn to_bytes_le(&self) -> Zeroizing<Vec<u8>> {
        let input_biguint: BigUint = self.0.into();
        let mut res = input_biguint.to_bytes_le();
        res.resize(fr_byte_size(), 0);
        Zeroizing::new(res)
    }

    pub(crate) fn to_bytes_be(&self) -> Zeroizing<Vec<u8>> {
        let input_biguint: BigUint = self.0.into();
        let mut res = input_biguint.to_bytes_be();
        let to_insert_count = fr_byte_size().saturating_sub(res.len());
        if to_insert_count > 0 {
            // Insert multi 0 at index 0
            res.splice(0..0, std::iter::repeat_n(0, to_insert_count));
        }
        Zeroizing::new(res)
    }

    /// Warning: this can leak the secret value
    /// Warning: Leaked value is of type 'U256' which implement Copy (every copy will not be zeroized)
    pub(crate) fn to_u256(&self) -> U256 {
        let mut big_int = self.0.into_bigint();
        let res = U256::from_limbs(big_int.0);
        big_int.zeroize();
        res
    }
}

impl From<&mut Fr> for IdSecret {
    fn from(value: &mut Fr) -> Self {
        let id_secret = Self(*value);
        value.zeroize();
        id_secret
    }
}

impl Deref for IdSecret {
    type Target = Fr;

    /// Deref to &Fr
    ///
    /// Warning: this can leak the secret value
    /// Warning: Leaked value is of type 'Fr' which implement Copy (every copy will not be zeroized)
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub enum FrOrSecret {
    IdSecret(IdSecret),
    Fr(Fr),
}

impl From<Fr> for FrOrSecret {
    fn from(value: Fr) -> Self {
        FrOrSecret::Fr(value)
    }
}

impl From<IdSecret> for FrOrSecret {
    fn from(value: IdSecret) -> Self {
        FrOrSecret::IdSecret(value)
    }
}
