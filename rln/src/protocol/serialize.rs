// This module collects all serialization logic for RLN protocol types

use std::io::{Read, Write};

use ark_ff::PrimeField;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress,
    SerializationError as ArkSerializationError, Valid, Validate,
};
use zeroize::Zeroizing;

use super::{
    proof::{RLNProof, RLNProofValues, RLNProofValuesMulti, RLNProofValuesSingle},
    witness::{
        RLNPartialWitnessInput, RLNWitnessInput, RLNWitnessInputMulti, RLNWitnessInputSingle,
    },
};
use crate::{
    circuit::{Fr, IdSecret, Proof, COMPRESS_PROOF_SIZE},
    error::SerializationError,
};

/// Byte size of the enum variant tag prepended to serialized enum types.
pub const ENUM_TAG_SIZE: usize = 1;

/// Tag byte for the `Single` variant - Single message-id mode.
pub const ENUM_TAG_SINGLE: u8 = 0;

/// Tag byte for the `Multi` variant - Multi message-id mode.
pub const ENUM_TAG_MULTI: u8 = 1;

/// Byte size of a `Fr` field element aligned to 64-bit boundary, computed once at compile time.
pub const FR_BYTE_SIZE: usize = {
    // Get the modulus bit size of the scalar field
    let modulus_bits: u32 = Fr::MODULUS_BIT_SIZE;
    // Alignment boundary in bits for field element serialization
    let alignment_bits: u32 = 64;
    // Align to the next multiple of alignment_bits and convert to bytes
    ((modulus_bits + alignment_bits - (modulus_bits % alignment_bits)) / 8) as usize
};

/// Byte size of a single 64-bit limb used in `Fr` field element serialization.
pub const FR_LIMB_BYTE_SIZE: usize = 8;

/// Byte size of the length prefix used when serializing variable-length vectors.
pub const VEC_LEN_BYTE_SIZE: usize = 8;

/// Serializes a `usize` as an 8-byte big-endian length prefix.
/// On 32-bit systems, the result is zero-padded to 8 bytes.
/// On 64-bit systems, it directly represents the `usize` value.
fn serialize_usize_be(input: usize) -> [u8; VEC_LEN_BYTE_SIZE] {
    let mut bytes = [0u8; VEC_LEN_BYTE_SIZE];
    let input_bytes = input.to_be_bytes();
    let offset = VEC_LEN_BYTE_SIZE - input_bytes.len();
    bytes[offset..].copy_from_slice(&input_bytes);
    bytes
}

pub trait CanonicalSerializeBE {
    type Error: std::error::Error;

    fn serialize<W: Write>(&self, writer: W) -> Result<(), Self::Error>;
    fn serialized_size(&self) -> usize;
}

pub trait CanonicalDeserializeBE: Sized {
    type Error: std::error::Error;

    fn deserialize<R: Read>(reader: R) -> Result<Self, Self::Error>;
}

impl CanonicalSerializeBE for Fr {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        let bigint = self.into_bigint();
        let mut buf = [0u8; FR_BYTE_SIZE];
        for (i, &limb) in bigint.0.iter().rev().enumerate() {
            buf[i * FR_LIMB_BYTE_SIZE..(i + 1) * FR_LIMB_BYTE_SIZE]
                .copy_from_slice(&limb.to_be_bytes());
        }
        writer.write_all(buf.as_ref())?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        FR_BYTE_SIZE
    }
}

impl CanonicalDeserializeBE for Fr {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut buf = [0u8; FR_BYTE_SIZE];
        reader.read_exact(&mut buf)?;
        let mut limbs = [0u64; FR_BYTE_SIZE / FR_LIMB_BYTE_SIZE];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = i * FR_LIMB_BYTE_SIZE;
            *limb = u64::from_be_bytes(buf[start..start + FR_LIMB_BYTE_SIZE].try_into()?);
        }
        limbs.reverse();
        let bigint = ark_ff::BigInt(limbs);
        if bigint >= Fr::MODULUS {
            return Err(SerializationError::NonCanonicalFieldElement);
        }
        Ok(Fr::from(bigint))
    }
}

impl CanonicalSerializeBE for IdSecret {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        let bigint = Zeroizing::new(self.into_bigint());
        let mut buf = Zeroizing::new([0u8; FR_BYTE_SIZE]);
        for (i, &limb) in bigint.0.iter().rev().enumerate() {
            buf[i * FR_LIMB_BYTE_SIZE..(i + 1) * FR_LIMB_BYTE_SIZE]
                .copy_from_slice(&limb.to_be_bytes());
        }
        writer.write_all(buf.as_ref())?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        FR_BYTE_SIZE
    }
}

impl CanonicalDeserializeBE for IdSecret {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut buf = Zeroizing::new([0u8; FR_BYTE_SIZE]);
        reader.read_exact(buf.as_mut())?;
        let mut limbs = Zeroizing::new([0u64; FR_BYTE_SIZE / FR_LIMB_BYTE_SIZE]);
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = i * FR_LIMB_BYTE_SIZE;
            *limb = u64::from_be_bytes(buf[start..start + FR_LIMB_BYTE_SIZE].try_into()?);
        }
        limbs.reverse();
        let bigint = Zeroizing::new(ark_ff::BigInt(*limbs));
        if *bigint >= Fr::MODULUS {
            return Err(SerializationError::NonCanonicalFieldElement);
        }
        let mut fr = Fr::from(*bigint);
        Ok(IdSecret::from(&mut fr))
    }
}

impl CanonicalSerializeBE for Vec<Fr> {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        writer.write_all(&serialize_usize_be(self.len()))?;
        for fr in self {
            fr.serialize(&mut writer)?;
        }
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        VEC_LEN_BYTE_SIZE + FR_BYTE_SIZE * self.len()
    }
}

impl CanonicalDeserializeBE for Vec<Fr> {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut len_buf = [0u8; VEC_LEN_BYTE_SIZE];
        reader.read_exact(&mut len_buf)?;
        let count = usize::try_from(u64::from_be_bytes(len_buf))?;
        let mut result = Vec::new(); // DO NOT preallocate from untrusted length prefix
        for _ in 0..count {
            result.push(Fr::deserialize(&mut reader)?);
        }
        Ok(result)
    }
}

impl CanonicalSerializeBE for Vec<u8> {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        writer.write_all(&serialize_usize_be(self.len()))?;
        writer.write_all(self)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        VEC_LEN_BYTE_SIZE + self.len()
    }
}

impl CanonicalDeserializeBE for Vec<u8> {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut len_buf = [0u8; VEC_LEN_BYTE_SIZE];
        reader.read_exact(&mut len_buf)?;
        let count = u64::from_be_bytes(len_buf);
        let mut result = Vec::new(); // DO NOT preallocate from untrusted length prefix
        reader.take(count).read_to_end(&mut result)?;
        if result.len() as u64 != count {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        Ok(result)
    }
}

impl CanonicalSerializeBE for Vec<bool> {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        writer.write_all(&serialize_usize_be(self.len()))?;
        for &b in self {
            writer.write_all(&[b as u8])?;
        }
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        VEC_LEN_BYTE_SIZE + self.len()
    }
}

impl CanonicalDeserializeBE for Vec<bool> {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut len_buf = [0u8; VEC_LEN_BYTE_SIZE];
        reader.read_exact(&mut len_buf)?;
        let count = u64::from_be_bytes(len_buf);
        let mut result = Vec::new(); // DO NOT preallocate from untrusted length prefix
        reader.take(count).read_to_end(&mut result)?;
        if result.len() as u64 != count {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        result
            .into_iter()
            .map(|b| match b {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(SerializationError::NonCanonicalBool(b)),
            })
            .collect()
    }
}

impl Valid for RLNWitnessInput {
    fn check(&self) -> Result<(), ArkSerializationError> {
        match self {
            RLNWitnessInput::Single(inner) => inner.check(),
            RLNWitnessInput::Multi(inner) => inner.check(),
        }
    }
}

impl CanonicalSerialize for RLNWitnessInput {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), ArkSerializationError> {
        match self {
            RLNWitnessInput::Single(inner) => {
                ENUM_TAG_SINGLE.serialize_with_mode(&mut writer, compress)?;
                inner.serialize_with_mode(&mut writer, compress)
            }
            RLNWitnessInput::Multi(inner) => {
                ENUM_TAG_MULTI.serialize_with_mode(&mut writer, compress)?;
                inner.serialize_with_mode(&mut writer, compress)
            }
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        ENUM_TAG_SIZE
            + match self {
                RLNWitnessInput::Single(inner) => {
                    CanonicalSerialize::serialized_size(inner, compress)
                }
                RLNWitnessInput::Multi(inner) => {
                    CanonicalSerialize::serialized_size(inner, compress)
                }
            }
    }
}

impl CanonicalDeserialize for RLNWitnessInput {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, ArkSerializationError> {
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match tag {
            ENUM_TAG_SINGLE => Ok(RLNWitnessInput::Single(
                RLNWitnessInputSingle::deserialize_with_mode(reader, compress, validate)?,
            )),
            ENUM_TAG_MULTI => Ok(RLNWitnessInput::Multi(
                RLNWitnessInputMulti::deserialize_with_mode(reader, compress, validate)?,
            )),
            _ => Err(ArkSerializationError::InvalidData),
        }
    }
}

impl CanonicalSerializeBE for RLNWitnessInput {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        match self {
            RLNWitnessInput::Single(inner) => {
                writer.write_all(&[ENUM_TAG_SINGLE])?;
                inner.serialize(&mut writer)
            }
            RLNWitnessInput::Multi(inner) => {
                writer.write_all(&[ENUM_TAG_MULTI])?;
                inner.serialize(&mut writer)
            }
        }
    }

    fn serialized_size(&self) -> usize {
        ENUM_TAG_SIZE
            + match self {
                RLNWitnessInput::Single(inner) => CanonicalSerializeBE::serialized_size(inner),
                RLNWitnessInput::Multi(inner) => CanonicalSerializeBE::serialized_size(inner),
            }
    }
}

impl CanonicalDeserializeBE for RLNWitnessInput {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut tag = [0u8; ENUM_TAG_SIZE];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            ENUM_TAG_SINGLE => Ok(RLNWitnessInput::Single(RLNWitnessInputSingle::deserialize(
                reader,
            )?)),
            ENUM_TAG_MULTI => Ok(RLNWitnessInput::Multi(RLNWitnessInputMulti::deserialize(
                reader,
            )?)),
            _ => Err(ArkSerializationError::InvalidData.into()),
        }
    }
}

impl CanonicalSerializeBE for RLNWitnessInputSingle {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        self.identity_secret.serialize(&mut writer)?;
        self.user_message_limit.serialize(&mut writer)?;
        self.message_id.serialize(&mut writer)?;
        self.path_elements.serialize(&mut writer)?;
        self.identity_path_index.serialize(&mut writer)?;
        self.x.serialize(&mut writer)?;
        self.external_nullifier.serialize(&mut writer)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        CanonicalSerializeBE::serialized_size(&self.identity_secret)
            + CanonicalSerializeBE::serialized_size(&self.user_message_limit)
            + CanonicalSerializeBE::serialized_size(&self.message_id)
            + CanonicalSerializeBE::serialized_size(&self.path_elements)
            + CanonicalSerializeBE::serialized_size(&self.identity_path_index)
            + CanonicalSerializeBE::serialized_size(&self.x)
            + CanonicalSerializeBE::serialized_size(&self.external_nullifier)
    }
}

impl CanonicalDeserializeBE for RLNWitnessInputSingle {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let identity_secret = IdSecret::deserialize(&mut reader)?;
        let user_message_limit = Fr::deserialize(&mut reader)?;
        let message_id = Fr::deserialize(&mut reader)?;
        let path_elements = Vec::<Fr>::deserialize(&mut reader)?;
        let identity_path_index = Vec::<u8>::deserialize(&mut reader)?;
        let x = Fr::deserialize(&mut reader)?;
        let external_nullifier = Fr::deserialize(&mut reader)?;
        Ok(Self {
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        })
    }
}

impl CanonicalSerializeBE for RLNWitnessInputMulti {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        self.identity_secret.serialize(&mut writer)?;
        self.user_message_limit.serialize(&mut writer)?;
        self.path_elements.serialize(&mut writer)?;
        self.identity_path_index.serialize(&mut writer)?;
        self.x.serialize(&mut writer)?;
        self.external_nullifier.serialize(&mut writer)?;
        self.message_ids.serialize(&mut writer)?;
        self.selector_used.serialize(&mut writer)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        CanonicalSerializeBE::serialized_size(&self.identity_secret)
            + CanonicalSerializeBE::serialized_size(&self.user_message_limit)
            + CanonicalSerializeBE::serialized_size(&self.path_elements)
            + CanonicalSerializeBE::serialized_size(&self.identity_path_index)
            + CanonicalSerializeBE::serialized_size(&self.x)
            + CanonicalSerializeBE::serialized_size(&self.external_nullifier)
            + CanonicalSerializeBE::serialized_size(&self.message_ids)
            + CanonicalSerializeBE::serialized_size(&self.selector_used)
    }
}

impl CanonicalDeserializeBE for RLNWitnessInputMulti {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let identity_secret = IdSecret::deserialize(&mut reader)?;
        let user_message_limit = Fr::deserialize(&mut reader)?;
        let path_elements = Vec::<Fr>::deserialize(&mut reader)?;
        let identity_path_index = Vec::<u8>::deserialize(&mut reader)?;
        let x = Fr::deserialize(&mut reader)?;
        let external_nullifier = Fr::deserialize(&mut reader)?;
        let message_ids = Vec::<Fr>::deserialize(&mut reader)?;
        let selector_used = Vec::<bool>::deserialize(&mut reader)?;
        Ok(Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_ids,
            selector_used,
        })
    }
}

impl CanonicalSerializeBE for RLNPartialWitnessInput {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        self.identity_secret.serialize(&mut writer)?;
        self.user_message_limit.serialize(&mut writer)?;
        self.path_elements.serialize(&mut writer)?;
        self.identity_path_index.serialize(&mut writer)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        CanonicalSerializeBE::serialized_size(&self.identity_secret)
            + CanonicalSerializeBE::serialized_size(&self.user_message_limit)
            + CanonicalSerializeBE::serialized_size(&self.path_elements)
            + CanonicalSerializeBE::serialized_size(&self.identity_path_index)
    }
}

impl CanonicalDeserializeBE for RLNPartialWitnessInput {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let identity_secret = IdSecret::deserialize(&mut reader)?;
        let user_message_limit = Fr::deserialize(&mut reader)?;
        let path_elements = Vec::<Fr>::deserialize(&mut reader)?;
        let identity_path_index = Vec::<u8>::deserialize(&mut reader)?;
        Ok(Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
        })
    }
}

impl Valid for RLNProofValues {
    fn check(&self) -> Result<(), ArkSerializationError> {
        match self {
            RLNProofValues::Single(inner) => inner.check(),
            RLNProofValues::Multi(inner) => inner.check(),
        }
    }
}

impl CanonicalSerialize for RLNProofValues {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), ArkSerializationError> {
        match self {
            RLNProofValues::Single(inner) => {
                ENUM_TAG_SINGLE.serialize_with_mode(&mut writer, compress)?;
                inner.serialize_with_mode(&mut writer, compress)
            }
            RLNProofValues::Multi(inner) => {
                ENUM_TAG_MULTI.serialize_with_mode(&mut writer, compress)?;
                inner.serialize_with_mode(&mut writer, compress)
            }
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        ENUM_TAG_SIZE
            + match self {
                RLNProofValues::Single(inner) => {
                    CanonicalSerialize::serialized_size(inner, compress)
                }
                RLNProofValues::Multi(inner) => {
                    CanonicalSerialize::serialized_size(inner, compress)
                }
            }
    }
}

impl CanonicalDeserialize for RLNProofValues {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, ArkSerializationError> {
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match tag {
            ENUM_TAG_SINGLE => Ok(RLNProofValues::Single(
                RLNProofValuesSingle::deserialize_with_mode(reader, compress, validate)?,
            )),
            ENUM_TAG_MULTI => Ok(RLNProofValues::Multi(
                RLNProofValuesMulti::deserialize_with_mode(reader, compress, validate)?,
            )),
            _ => Err(ArkSerializationError::InvalidData),
        }
    }
}

impl CanonicalSerializeBE for RLNProofValues {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        match self {
            RLNProofValues::Single(inner) => {
                writer.write_all(&[ENUM_TAG_SINGLE])?;
                inner.serialize(&mut writer)
            }
            RLNProofValues::Multi(inner) => {
                writer.write_all(&[ENUM_TAG_MULTI])?;
                inner.serialize(&mut writer)
            }
        }
    }

    fn serialized_size(&self) -> usize {
        ENUM_TAG_SIZE
            + match self {
                RLNProofValues::Single(inner) => CanonicalSerializeBE::serialized_size(inner),
                RLNProofValues::Multi(inner) => CanonicalSerializeBE::serialized_size(inner),
            }
    }
}

impl CanonicalDeserializeBE for RLNProofValues {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut tag = [0u8; ENUM_TAG_SIZE];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            ENUM_TAG_SINGLE => Ok(RLNProofValues::Single(RLNProofValuesSingle::deserialize(
                reader,
            )?)),
            ENUM_TAG_MULTI => Ok(RLNProofValues::Multi(RLNProofValuesMulti::deserialize(
                reader,
            )?)),
            _ => Err(ArkSerializationError::InvalidData.into()),
        }
    }
}

impl CanonicalSerializeBE for RLNProofValuesSingle {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        self.y.serialize(&mut writer)?;
        self.root.serialize(&mut writer)?;
        self.nullifier.serialize(&mut writer)?;
        self.x.serialize(&mut writer)?;
        self.external_nullifier.serialize(&mut writer)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        CanonicalSerializeBE::serialized_size(&self.y)
            + CanonicalSerializeBE::serialized_size(&self.root)
            + CanonicalSerializeBE::serialized_size(&self.nullifier)
            + CanonicalSerializeBE::serialized_size(&self.x)
            + CanonicalSerializeBE::serialized_size(&self.external_nullifier)
    }
}

impl CanonicalDeserializeBE for RLNProofValuesSingle {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let y = Fr::deserialize(&mut reader)?;
        let root = Fr::deserialize(&mut reader)?;
        let nullifier = Fr::deserialize(&mut reader)?;
        let x = Fr::deserialize(&mut reader)?;
        let external_nullifier = Fr::deserialize(&mut reader)?;
        Ok(Self {
            y,
            root,
            nullifier,
            x,
            external_nullifier,
        })
    }
}

impl CanonicalSerializeBE for RLNProofValuesMulti {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        self.ys.serialize(&mut writer)?;
        self.root.serialize(&mut writer)?;
        self.nullifiers.serialize(&mut writer)?;
        self.x.serialize(&mut writer)?;
        self.external_nullifier.serialize(&mut writer)?;
        self.selector_used.serialize(&mut writer)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        CanonicalSerializeBE::serialized_size(&self.ys)
            + CanonicalSerializeBE::serialized_size(&self.root)
            + CanonicalSerializeBE::serialized_size(&self.nullifiers)
            + CanonicalSerializeBE::serialized_size(&self.x)
            + CanonicalSerializeBE::serialized_size(&self.external_nullifier)
            + CanonicalSerializeBE::serialized_size(&self.selector_used)
    }
}

impl CanonicalDeserializeBE for RLNProofValuesMulti {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let ys = Vec::<Fr>::deserialize(&mut reader)?;
        let root = Fr::deserialize(&mut reader)?;
        let nullifiers = Vec::<Fr>::deserialize(&mut reader)?;
        let x = Fr::deserialize(&mut reader)?;
        let external_nullifier = Fr::deserialize(&mut reader)?;
        let selector_used = Vec::<bool>::deserialize(&mut reader)?;
        Ok(Self {
            ys,
            root,
            nullifiers,
            x,
            external_nullifier,
            selector_used,
        })
    }
}

/// Serialization for types that combine LE and BE encodings in a single wire format.
///
/// Some types (e.g. [`RLNProof`]) contain fields with different encoding requirements:
/// the Groth16 proof bytes use arkworks compressed LE format, while the proof values use BE format.
pub trait CanonicalSerializeMixed: CanonicalSerialize {
    type Error: std::error::Error;

    fn serialize<W: Write>(&self, writer: W) -> Result<(), Self::Error>;
    fn serialized_size(&self) -> usize;
}

/// Deserialization for types that combine LE and BE encodings in a single wire format.
///
/// See [`CanonicalSerializeMixed`] for context on when this is needed.
pub trait CanonicalDeserializeMixed: CanonicalDeserialize {
    type Error: std::error::Error;

    fn deserialize<R: Read>(reader: R) -> Result<Self, Self::Error>;
}

impl CanonicalSerializeMixed for RLNProof {
    type Error = SerializationError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        self.proof.serialize_compressed(&mut writer)?;
        CanonicalSerializeBE::serialize(&self.values, &mut writer)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        COMPRESS_PROOF_SIZE + CanonicalSerializeBE::serialized_size(&self.values)
    }
}

impl CanonicalDeserializeMixed for RLNProof {
    type Error = SerializationError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let proof = Proof::deserialize_compressed(&mut reader)?;
        let values = <RLNProofValues as CanonicalDeserializeBE>::deserialize(&mut reader)?;
        Ok(RLNProof { proof, values })
    }
}
