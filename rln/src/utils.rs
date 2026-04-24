// This crate provides cross-module useful utilities (mainly type conversions) not necessarily specific to RLN

use std::ops::Deref;

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use num_bigint::{BigInt, BigUint};
use num_traits::Num;
use rand::Rng;
#[cfg(not(target_arch = "wasm32"))]
use ruint::aliases::U256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    circuit::Fr,
    error::UtilsError,
    protocol::{FR_BYTE_SIZE, VEC_LEN_BYTE_SIZE},
};

/// Normalizes a `usize` into an 8-byte array, ensuring consistency across architectures.
/// On 32-bit systems, the result is zero-padded to 8 bytes.
/// On 64-bit systems, it directly represents the `usize` value.
#[inline(always)]
pub fn normalize_usize_le(input: usize) -> [u8; VEC_LEN_BYTE_SIZE] {
    let mut bytes = [0u8; VEC_LEN_BYTE_SIZE];
    let input_bytes = input.to_le_bytes();
    bytes[..input_bytes.len()].copy_from_slice(&input_bytes);
    bytes
}

/// Normalizes a `usize` into an 8-byte array, ensuring consistency across architectures.
/// On 32-bit systems, the result is zero-padded to 8 bytes.
/// On 64-bit systems, it directly represents the `usize` value.
#[inline(always)]
pub fn normalize_usize_be(input: usize) -> [u8; VEC_LEN_BYTE_SIZE] {
    let mut bytes = [0u8; VEC_LEN_BYTE_SIZE];
    let input_bytes = input.to_be_bytes();
    let offset = VEC_LEN_BYTE_SIZE - input_bytes.len();
    bytes[offset..].copy_from_slice(&input_bytes);
    bytes
}

#[inline(always)]
fn biguint_to_fr(val: BigUint) -> Result<Fr, UtilsError> {
    let bigint = <Fr as PrimeField>::BigInt::try_from(val)
        .map_err(|_| UtilsError::NonCanonicalFieldElement)?;
    Fr::from_bigint(bigint).ok_or(UtilsError::NonCanonicalFieldElement)
}

#[inline(always)]
pub fn to_bigint(el: &Fr) -> BigInt {
    BigUint::from(*el).into()
}

#[inline(always)]
pub fn str_to_fr(input: &str, radix: u32) -> Result<Fr, UtilsError> {
    if !(radix == 10 || radix == 16) {
        return Err(UtilsError::WrongRadix);
    }

    // We remove any quote present and we trim
    let single_quote: char = '\"';
    let mut input_clean = input.replace(single_quote, "");
    input_clean = input_clean.trim().to_string();

    if radix == 10 {
        biguint_to_fr(BigUint::from_str_radix(&input_clean, radix)?)
    } else {
        input_clean = input_clean.replace("0x", "");
        biguint_to_fr(BigUint::from_str_radix(&input_clean, radix)?)
    }
}

#[inline(always)]
pub fn bytes_le_to_fr(input: &[u8]) -> Result<(Fr, usize), UtilsError> {
    let el_size = FR_BYTE_SIZE;
    if input.len() < el_size {
        return Err(UtilsError::InsufficientData {
            expected: el_size,
            actual: input.len(),
        });
    }
    let fr = biguint_to_fr(BigUint::from_bytes_le(&input[0..el_size]))?;
    Ok((fr, el_size))
}

#[inline(always)]
pub fn bytes_be_to_fr(input: &[u8]) -> Result<(Fr, usize), UtilsError> {
    let el_size = FR_BYTE_SIZE;
    if input.len() < el_size {
        return Err(UtilsError::InsufficientData {
            expected: el_size,
            actual: input.len(),
        });
    }
    let fr = biguint_to_fr(BigUint::from_bytes_be(&input[0..el_size]))?;
    Ok((fr, el_size))
}

#[inline(always)]
pub fn fr_to_bytes_le(input: &Fr) -> Vec<u8> {
    let input_biguint: BigUint = (*input).into();
    let mut res = input_biguint.to_bytes_le();
    //BigUint conversion ignores most significant zero bytes. We restore them otherwise serialization will fail (length % 8 != 0)
    res.resize(FR_BYTE_SIZE, 0);
    res
}

#[inline(always)]
pub fn fr_to_bytes_be(input: &Fr) -> Vec<u8> {
    let input_biguint: BigUint = (*input).into();
    let mut res = input_biguint.to_bytes_be();
    // For BE, insert 0 at the start of the Vec
    let to_insert_count = FR_BYTE_SIZE.saturating_sub(res.len());
    if to_insert_count > 0 {
        // Insert multi 0 at index 0
        res.splice(0..0, std::iter::repeat_n(0, to_insert_count));
    }
    res
}

#[inline(always)]
pub fn vec_fr_to_bytes_le(input: &[Fr]) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - VEC_LEN_PREFIX_SIZE bytes for normalized vector length (usize)
    // - each Fr element requires FR_BYTE_SIZE bytes (typically 32 bytes)
    let mut bytes = Vec::with_capacity(VEC_LEN_BYTE_SIZE + input.len() * FR_BYTE_SIZE);

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
    // - VEC_LEN_PREFIX_SIZE bytes for normalized vector length (usize)
    // - each Fr element requires FR_BYTE_SIZE bytes (typically 32 bytes)
    let mut bytes = Vec::with_capacity(VEC_LEN_BYTE_SIZE + input.len() * FR_BYTE_SIZE);

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
    // - VEC_LEN_PREFIX_SIZE bytes for normalized vector length (usize)
    // - variable length input data
    let mut bytes = Vec::with_capacity(VEC_LEN_BYTE_SIZE + input.len());

    // We store the vector length
    bytes.extend_from_slice(&normalize_usize_le(input.len()));

    // We store the input
    bytes.extend_from_slice(input);

    bytes
}

#[inline(always)]
pub fn vec_u8_to_bytes_be(input: &[u8]) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - VEC_LEN_PREFIX_SIZE bytes for normalized vector length (usize)
    // - variable length input data
    let mut bytes = Vec::with_capacity(VEC_LEN_BYTE_SIZE + input.len());

    // We store the vector length
    bytes.extend_from_slice(&normalize_usize_be(input.len()));

    // We store the input
    bytes.extend_from_slice(input);

    bytes
}

#[inline(always)]
pub fn vec_bool_to_bytes_le(input: &[bool]) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - VEC_LEN_PREFIX_SIZE bytes for normalized vector length (usize)
    // - each bool requires 1 byte
    let mut bytes = Vec::with_capacity(VEC_LEN_BYTE_SIZE + input.len());

    // We store the vector length
    bytes.extend_from_slice(&normalize_usize_le(input.len()));

    // We store each bool as a single byte (0 or 1)
    for &b in input {
        bytes.push(b as u8);
    }

    bytes
}

#[inline(always)]
pub fn vec_bool_to_bytes_be(input: &[bool]) -> Vec<u8> {
    // Calculate capacity for Vec:
    // - VEC_LEN_PREFIX_SIZE bytes for normalized vector length (usize)
    // - each bool requires 1 byte
    let mut bytes = Vec::with_capacity(VEC_LEN_BYTE_SIZE + input.len());

    // We store the vector length
    bytes.extend_from_slice(&normalize_usize_be(input.len()));

    // We store each bool as a single byte (0 or 1)
    for &b in input {
        bytes.push(b as u8);
    }

    bytes
}

#[inline(always)]
pub fn bytes_le_to_vec_u8(input: &[u8]) -> Result<(Vec<u8>, usize), UtilsError> {
    let mut read: usize = 0;
    if input.len() < VEC_LEN_BYTE_SIZE {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE,
            actual: input.len(),
        });
    }
    let len = usize::try_from(u64::from_le_bytes(input[0..VEC_LEN_BYTE_SIZE].try_into()?))?;
    read += VEC_LEN_BYTE_SIZE;
    if len > input.len() - VEC_LEN_BYTE_SIZE {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE.saturating_add(len),
            actual: input.len(),
        });
    }
    let res = input[VEC_LEN_BYTE_SIZE..VEC_LEN_BYTE_SIZE + len].to_vec();
    read += res.len();
    Ok((res, read))
}

#[inline(always)]
pub fn bytes_be_to_vec_u8(input: &[u8]) -> Result<(Vec<u8>, usize), UtilsError> {
    let mut read: usize = 0;
    if input.len() < VEC_LEN_BYTE_SIZE {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE,
            actual: input.len(),
        });
    }
    let len = usize::try_from(u64::from_be_bytes(input[0..VEC_LEN_BYTE_SIZE].try_into()?))?;
    read += VEC_LEN_BYTE_SIZE;
    if len > input.len() - VEC_LEN_BYTE_SIZE {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE.saturating_add(len),
            actual: input.len(),
        });
    }
    let res = input[VEC_LEN_BYTE_SIZE..VEC_LEN_BYTE_SIZE + len].to_vec();
    read += res.len();
    Ok((res, read))
}

#[inline(always)]
pub fn bytes_le_to_vec_fr(input: &[u8]) -> Result<(Vec<Fr>, usize), UtilsError> {
    let mut read: usize = 0;
    if input.len() < VEC_LEN_BYTE_SIZE {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE,
            actual: input.len(),
        });
    }
    let len = usize::try_from(u64::from_le_bytes(input[0..VEC_LEN_BYTE_SIZE].try_into()?))?;
    read += VEC_LEN_BYTE_SIZE;
    let el_size = FR_BYTE_SIZE;
    if len > (input.len() - VEC_LEN_BYTE_SIZE) / el_size {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE.saturating_add(len.saturating_mul(el_size)),
            actual: input.len(),
        });
    }
    let mut res: Vec<Fr> = Vec::with_capacity(len);
    for i in 0..len {
        let start = VEC_LEN_BYTE_SIZE + el_size * i;
        let end = VEC_LEN_BYTE_SIZE + el_size * (i + 1);
        let (curr_el, _) = bytes_le_to_fr(&input[start..end])?;
        res.push(curr_el);
        read += el_size;
    }
    Ok((res, read))
}

#[inline(always)]
pub fn bytes_be_to_vec_fr(input: &[u8]) -> Result<(Vec<Fr>, usize), UtilsError> {
    let mut read: usize = 0;
    if input.len() < VEC_LEN_BYTE_SIZE {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE,
            actual: input.len(),
        });
    }
    let len = usize::try_from(u64::from_be_bytes(input[0..VEC_LEN_BYTE_SIZE].try_into()?))?;
    read += VEC_LEN_BYTE_SIZE;
    let el_size = FR_BYTE_SIZE;
    if len > (input.len() - VEC_LEN_BYTE_SIZE) / el_size {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE.saturating_add(len.saturating_mul(el_size)),
            actual: input.len(),
        });
    }
    let mut res: Vec<Fr> = Vec::with_capacity(len);
    for i in 0..len {
        let start = VEC_LEN_BYTE_SIZE + el_size * i;
        let end = VEC_LEN_BYTE_SIZE + el_size * (i + 1);
        let (curr_el, _) = bytes_be_to_fr(&input[start..end])?;
        res.push(curr_el);
        read += el_size;
    }
    Ok((res, read))
}

#[inline(always)]
pub fn bytes_le_to_vec_usize(input: &[u8]) -> Result<Vec<usize>, UtilsError> {
    if input.len() < VEC_LEN_BYTE_SIZE {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE,
            actual: input.len(),
        });
    }
    let nof_elem = usize::try_from(u64::from_le_bytes(input[0..VEC_LEN_BYTE_SIZE].try_into()?))?;
    if nof_elem == 0 {
        Ok(vec![])
    } else {
        if nof_elem > (input.len() - VEC_LEN_BYTE_SIZE) / VEC_LEN_BYTE_SIZE {
            return Err(UtilsError::InsufficientData {
                expected: VEC_LEN_BYTE_SIZE
                    .saturating_add(nof_elem.saturating_mul(VEC_LEN_BYTE_SIZE)),
                actual: input.len(),
            });
        }
        input[VEC_LEN_BYTE_SIZE..]
            .chunks_exact(VEC_LEN_BYTE_SIZE)
            .take(nof_elem)
            .map(|ch| {
                ch.try_into()
                    .map(usize::from_le_bytes)
                    .map_err(UtilsError::FromSlice)
            })
            .collect()
    }
}

#[inline(always)]
pub fn bytes_be_to_vec_usize(input: &[u8]) -> Result<Vec<usize>, UtilsError> {
    if input.len() < VEC_LEN_BYTE_SIZE {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE,
            actual: input.len(),
        });
    }
    let nof_elem = usize::try_from(u64::from_be_bytes(input[0..VEC_LEN_BYTE_SIZE].try_into()?))?;
    if nof_elem == 0 {
        Ok(vec![])
    } else {
        if nof_elem > (input.len() - VEC_LEN_BYTE_SIZE) / VEC_LEN_BYTE_SIZE {
            return Err(UtilsError::InsufficientData {
                expected: VEC_LEN_BYTE_SIZE
                    .saturating_add(nof_elem.saturating_mul(VEC_LEN_BYTE_SIZE)),
                actual: input.len(),
            });
        }
        input[VEC_LEN_BYTE_SIZE..]
            .chunks_exact(VEC_LEN_BYTE_SIZE)
            .take(nof_elem)
            .map(|ch| {
                ch.try_into()
                    .map(usize::from_be_bytes)
                    .map_err(UtilsError::FromSlice)
            })
            .collect()
    }
}

#[inline(always)]
pub fn bytes_le_to_vec_bool(input: &[u8]) -> Result<(Vec<bool>, usize), UtilsError> {
    let mut read: usize = 0;
    if input.len() < VEC_LEN_BYTE_SIZE {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE,
            actual: input.len(),
        });
    }
    let len = usize::try_from(u64::from_le_bytes(input[0..VEC_LEN_BYTE_SIZE].try_into()?))?;
    read += VEC_LEN_BYTE_SIZE;
    if len > input.len() - VEC_LEN_BYTE_SIZE {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE.saturating_add(len),
            actual: input.len(),
        });
    }
    let res: Vec<bool> = input[VEC_LEN_BYTE_SIZE..VEC_LEN_BYTE_SIZE + len]
        .iter()
        .map(|&b| b != 0)
        .collect();
    read += len;
    Ok((res, read))
}

#[inline(always)]
pub fn bytes_be_to_vec_bool(input: &[u8]) -> Result<(Vec<bool>, usize), UtilsError> {
    let mut read: usize = 0;
    if input.len() < VEC_LEN_BYTE_SIZE {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE,
            actual: input.len(),
        });
    }
    let len = usize::try_from(u64::from_be_bytes(input[0..VEC_LEN_BYTE_SIZE].try_into()?))?;
    read += VEC_LEN_BYTE_SIZE;
    if len > input.len() - VEC_LEN_BYTE_SIZE {
        return Err(UtilsError::InsufficientData {
            expected: VEC_LEN_BYTE_SIZE.saturating_add(len),
            actual: input.len(),
        });
    }
    let res: Vec<bool> = input[VEC_LEN_BYTE_SIZE..VEC_LEN_BYTE_SIZE + len]
        .iter()
        .map(|&b| b != 0)
        .collect();
    read += len;
    Ok((res, read))
}

#[derive(
    Debug, Zeroize, ZeroizeOnDrop, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct IdSecret(Fr);

impl IdSecret {
    pub fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut fr = Fr::rand(rng);
        let res = Self::from(&mut fr);
        // No need to zeroize fr (already zeroiz'ed in from implementation)
        #[allow(clippy::let_and_return)]
        res
    }

    pub fn from_bytes_le(input: &[u8]) -> Result<(Self, usize), UtilsError> {
        let el_size = FR_BYTE_SIZE;
        if input.len() < el_size {
            return Err(UtilsError::InsufficientData {
                expected: el_size,
                actual: input.len(),
            });
        }
        let mut fr = biguint_to_fr(BigUint::from_bytes_le(&input[0..el_size]))?;
        let res = IdSecret::from(&mut fr);
        Ok((res, el_size))
    }

    pub fn from_bytes_be(input: &[u8]) -> Result<(Self, usize), UtilsError> {
        let el_size = FR_BYTE_SIZE;
        if input.len() < el_size {
            return Err(UtilsError::InsufficientData {
                expected: el_size,
                actual: input.len(),
            });
        }
        let mut fr = biguint_to_fr(BigUint::from_bytes_be(&input[0..el_size]))?;
        let res = IdSecret::from(&mut fr);
        Ok((res, el_size))
    }

    pub fn to_bytes_le(&self) -> Zeroizing<Vec<u8>> {
        let input_biguint: BigUint = self.0.into();
        let mut res = input_biguint.to_bytes_le();
        res.resize(FR_BYTE_SIZE, 0);
        Zeroizing::new(res)
    }

    pub fn to_bytes_be(&self) -> Zeroizing<Vec<u8>> {
        let input_biguint: BigUint = self.0.into();
        let mut res = input_biguint.to_bytes_be();
        // For BE, insert 0 at the start of the Vec
        let to_insert_count = FR_BYTE_SIZE.saturating_sub(res.len());
        if to_insert_count > 0 {
            // Insert multi 0 at index 0
            res.splice(0..0, std::iter::repeat_n(0, to_insert_count));
        }
        Zeroizing::new(res)
    }

    /// Warning: this can leak the secret value
    /// Warning: Leaked value is of type 'U256' which implement Copy (every copy will not be zeroized)
    #[cfg(not(target_arch = "wasm32"))]
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

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) enum FrOrSecret {
    IdSecret(IdSecret),
    Fr(Fr),
}

#[cfg(not(target_arch = "wasm32"))]
impl From<Fr> for FrOrSecret {
    fn from(value: Fr) -> Self {
        FrOrSecret::Fr(value)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<IdSecret> for FrOrSecret {
    fn from(value: IdSecret) -> Self {
        FrOrSecret::IdSecret(value)
    }
}
