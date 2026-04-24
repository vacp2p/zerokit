use std::io::{Read, Write};

use ark_ff::PrimeField;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use zeroize::{Zeroize, Zeroizing};

use super::{
    proof::{RLNProofValuesMulti, RLNProofValuesSingle, RLNProofValuesV3},
    witness::{
        RLNPartialWitnessInputV3, RLNWitnessInputMulti, RLNWitnessInputSingle, RLNWitnessInputV3,
    },
};
use crate::{
    circuit::Fr,
    error::{ProtocolError, UtilsError},
    utils::{normalize_usize_be, IdSecret},
};

/// Byte size of the enum variant tag prepended to serialized enum types.
pub const ENUM_TAG_SIZE: usize = 1;

/// Tag byte for the `Single` variant — Single message-id mode.
pub const ENUM_TAG_SINGLE: u8 = 0;

/// Tag byte for the `Multi` variant — Multi message-id mode.
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

pub trait CanonicalSerializeBE {
    type Error;

    fn serialize<W: Write>(&self, writer: W) -> Result<(), Self::Error>;
    fn serialized_size(&self) -> usize;
}

pub trait CanonicalDeserializeBE: Sized {
    type Error;

    fn deserialize<R: Read>(reader: R) -> Result<Self, Self::Error>;
}

impl CanonicalSerializeBE for Fr {
    type Error = UtilsError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        let bigint = self.into_bigint();
        let mut buf = [0u8; FR_BYTE_SIZE];
        for (i, &limb) in bigint.0.iter().rev().enumerate() {
            buf[i * FR_LIMB_BYTE_SIZE..(i + 1) * FR_LIMB_BYTE_SIZE]
                .copy_from_slice(&limb.to_be_bytes());
        }
        writer.write_all(&buf).map_err(UtilsError::IoError)
    }

    fn serialized_size(&self) -> usize {
        FR_BYTE_SIZE
    }
}

impl CanonicalDeserializeBE for Fr {
    type Error = UtilsError;

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
            return Err(UtilsError::NonCanonicalFieldElement);
        }
        Ok(Fr::from(bigint))
    }
}

impl CanonicalSerializeBE for IdSecret {
    type Error = UtilsError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        let mut bigint = self.into_bigint();
        let mut buf = Zeroizing::new([0u8; FR_BYTE_SIZE]);
        for (i, &limb) in bigint.0.iter().rev().enumerate() {
            buf[i * FR_LIMB_BYTE_SIZE..(i + 1) * FR_LIMB_BYTE_SIZE]
                .copy_from_slice(&limb.to_be_bytes());
        }
        let result = writer.write_all(buf.as_ref()).map_err(UtilsError::IoError);
        bigint.0.zeroize();
        result
    }

    fn serialized_size(&self) -> usize {
        FR_BYTE_SIZE
    }
}

impl CanonicalDeserializeBE for IdSecret {
    type Error = UtilsError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut buf = Zeroizing::new([0u8; FR_BYTE_SIZE]);
        reader.read_exact(buf.as_mut())?;
        let mut limbs = [0u64; FR_BYTE_SIZE / FR_LIMB_BYTE_SIZE];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let start = i * FR_LIMB_BYTE_SIZE;
            *limb = u64::from_be_bytes(buf[start..start + FR_LIMB_BYTE_SIZE].try_into()?);
        }
        limbs.reverse();
        let bigint = ark_ff::BigInt(limbs);
        if bigint >= Fr::MODULUS {
            return Err(UtilsError::NonCanonicalFieldElement);
        }
        let mut fr = Fr::from(bigint);
        Ok(IdSecret::from(&mut fr))
    }
}

impl CanonicalSerializeBE for Vec<Fr> {
    type Error = UtilsError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        writer
            .write_all(&normalize_usize_be(self.len()))
            .map_err(UtilsError::IoError)?;
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
    type Error = UtilsError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut len_buf = [0u8; VEC_LEN_BYTE_SIZE];
        reader.read_exact(&mut len_buf)?;
        let count = usize::try_from(u64::from_be_bytes(len_buf))?;
        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            result.push(Fr::deserialize(&mut reader)?);
        }
        Ok(result)
    }
}

impl CanonicalSerializeBE for Vec<u8> {
    type Error = UtilsError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        writer
            .write_all(&normalize_usize_be(self.len()))
            .map_err(UtilsError::IoError)?;
        writer.write_all(self).map_err(UtilsError::IoError)
    }

    fn serialized_size(&self) -> usize {
        VEC_LEN_BYTE_SIZE + self.len()
    }
}

impl CanonicalDeserializeBE for Vec<u8> {
    type Error = UtilsError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut len_buf = [0u8; VEC_LEN_BYTE_SIZE];
        reader.read_exact(&mut len_buf)?;
        let count = usize::try_from(u64::from_be_bytes(len_buf))?;
        let mut result = vec![0u8; count];
        reader.read_exact(&mut result)?;
        Ok(result)
    }
}

impl CanonicalSerializeBE for Vec<bool> {
    type Error = UtilsError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        writer
            .write_all(&normalize_usize_be(self.len()))
            .map_err(UtilsError::IoError)?;
        for &b in self {
            writer.write_all(&[b as u8]).map_err(UtilsError::IoError)?;
        }
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        VEC_LEN_BYTE_SIZE + self.len()
    }
}

impl CanonicalDeserializeBE for Vec<bool> {
    type Error = UtilsError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut len_buf = [0u8; VEC_LEN_BYTE_SIZE];
        reader.read_exact(&mut len_buf)?;
        let count = usize::try_from(u64::from_be_bytes(len_buf))?;
        let mut raw = vec![0u8; count];
        reader.read_exact(&mut raw)?;
        Ok(raw.into_iter().map(|b| b != 0).collect())
    }
}

impl Valid for RLNWitnessInputV3 {
    fn check(&self) -> Result<(), SerializationError> {
        match self {
            RLNWitnessInputV3::Single(inner) => inner.check(),
            RLNWitnessInputV3::Multi(inner) => inner.check(),
        }
    }
}

impl CanonicalSerialize for RLNWitnessInputV3 {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match self {
            RLNWitnessInputV3::Single(inner) => {
                ENUM_TAG_SINGLE.serialize_with_mode(&mut writer, compress)?;
                inner.serialize_with_mode(&mut writer, compress)
            }
            RLNWitnessInputV3::Multi(inner) => {
                ENUM_TAG_MULTI.serialize_with_mode(&mut writer, compress)?;
                inner.serialize_with_mode(&mut writer, compress)
            }
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        ENUM_TAG_SIZE
            + match self {
                RLNWitnessInputV3::Single(inner) => {
                    CanonicalSerialize::serialized_size(inner, compress)
                }
                RLNWitnessInputV3::Multi(inner) => {
                    CanonicalSerialize::serialized_size(inner, compress)
                }
            }
    }
}

impl CanonicalDeserialize for RLNWitnessInputV3 {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match tag {
            ENUM_TAG_SINGLE => Ok(RLNWitnessInputV3::Single(
                RLNWitnessInputSingle::deserialize_with_mode(reader, compress, validate)?,
            )),
            ENUM_TAG_MULTI => Ok(RLNWitnessInputV3::Multi(
                RLNWitnessInputMulti::deserialize_with_mode(reader, compress, validate)?,
            )),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl CanonicalSerializeBE for RLNWitnessInputV3 {
    type Error = ProtocolError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        match self {
            RLNWitnessInputV3::Single(inner) => {
                writer.write_all(&[ENUM_TAG_SINGLE])?;
                inner.serialize(&mut writer)
            }
            RLNWitnessInputV3::Multi(inner) => {
                writer.write_all(&[ENUM_TAG_MULTI])?;
                inner.serialize(&mut writer)
            }
        }
    }

    fn serialized_size(&self) -> usize {
        ENUM_TAG_SIZE
            + match self {
                RLNWitnessInputV3::Single(inner) => CanonicalSerializeBE::serialized_size(inner),
                RLNWitnessInputV3::Multi(inner) => CanonicalSerializeBE::serialized_size(inner),
            }
    }
}

impl CanonicalDeserializeBE for RLNWitnessInputV3 {
    type Error = ProtocolError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut tag = [0u8; ENUM_TAG_SIZE];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            ENUM_TAG_SINGLE => Ok(RLNWitnessInputV3::Single(
                RLNWitnessInputSingle::deserialize(reader)?,
            )),
            ENUM_TAG_MULTI => Ok(RLNWitnessInputV3::Multi(RLNWitnessInputMulti::deserialize(
                reader,
            )?)),
            _ => Err(ProtocolError::SerializationError(
                SerializationError::InvalidData,
            )),
        }
    }
}

impl CanonicalSerializeBE for RLNWitnessInputSingle {
    type Error = ProtocolError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        self.identity_secret.serialize(&mut writer)?;
        self.user_message_limit.serialize(&mut writer)?;
        self.path_elements.serialize(&mut writer)?;
        self.identity_path_index.serialize(&mut writer)?;
        self.x.serialize(&mut writer)?;
        self.external_nullifier.serialize(&mut writer)?;
        self.message_id.serialize(&mut writer)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        FR_BYTE_SIZE // identity_secret
            + FR_BYTE_SIZE // user_message_limit
            + VEC_LEN_BYTE_SIZE + FR_BYTE_SIZE * self.path_elements.len() // path_elements
            + VEC_LEN_BYTE_SIZE + self.identity_path_index.len() // identity_path_index
            + FR_BYTE_SIZE // x
            + FR_BYTE_SIZE // external_nullifier
            + FR_BYTE_SIZE // message_id
    }
}

impl CanonicalDeserializeBE for RLNWitnessInputSingle {
    type Error = ProtocolError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let identity_secret = IdSecret::deserialize(&mut reader)?;
        let user_message_limit = Fr::deserialize(&mut reader)?;
        let path_elements = Vec::<Fr>::deserialize(&mut reader)?;
        let identity_path_index = Vec::<u8>::deserialize(&mut reader)?;
        let x = Fr::deserialize(&mut reader)?;
        let external_nullifier = Fr::deserialize(&mut reader)?;
        let message_id = Fr::deserialize(&mut reader)?;
        Ok(Self {
            identity_secret,
            user_message_limit,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
            message_id,
        })
    }
}

impl CanonicalSerializeBE for RLNWitnessInputMulti {
    type Error = ProtocolError;

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
        FR_BYTE_SIZE // identity_secret
            + FR_BYTE_SIZE // user_message_limit
            + VEC_LEN_BYTE_SIZE + FR_BYTE_SIZE * self.path_elements.len() // path_elements
            + VEC_LEN_BYTE_SIZE + self.identity_path_index.len() // identity_path_index
            + FR_BYTE_SIZE // x
            + FR_BYTE_SIZE // external_nullifier
            + VEC_LEN_BYTE_SIZE + FR_BYTE_SIZE * self.message_ids.len() // message_ids
            + VEC_LEN_BYTE_SIZE + self.selector_used.len() // selector_used
    }
}

impl CanonicalDeserializeBE for RLNWitnessInputMulti {
    type Error = ProtocolError;

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

impl CanonicalSerializeBE for RLNPartialWitnessInputV3 {
    type Error = ProtocolError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        self.identity_secret.serialize(&mut writer)?;
        self.user_message_limit.serialize(&mut writer)?;
        self.path_elements.serialize(&mut writer)?;
        self.identity_path_index.serialize(&mut writer)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        FR_BYTE_SIZE // identity_secret
            + FR_BYTE_SIZE // user_message_limit
            + VEC_LEN_BYTE_SIZE + FR_BYTE_SIZE * self.path_elements.len() // path_elements
            + VEC_LEN_BYTE_SIZE + self.identity_path_index.len() // identity_path_index
    }
}

impl CanonicalDeserializeBE for RLNPartialWitnessInputV3 {
    type Error = ProtocolError;

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

impl Valid for RLNProofValuesV3 {
    fn check(&self) -> Result<(), SerializationError> {
        match self {
            RLNProofValuesV3::Single(inner) => inner.check(),
            RLNProofValuesV3::Multi(inner) => inner.check(),
        }
    }
}

impl CanonicalSerialize for RLNProofValuesV3 {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match self {
            RLNProofValuesV3::Single(inner) => {
                ENUM_TAG_SINGLE.serialize_with_mode(&mut writer, compress)?;
                inner.serialize_with_mode(&mut writer, compress)
            }
            RLNProofValuesV3::Multi(inner) => {
                ENUM_TAG_MULTI.serialize_with_mode(&mut writer, compress)?;
                inner.serialize_with_mode(&mut writer, compress)
            }
        }
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        ENUM_TAG_SIZE
            + match self {
                RLNProofValuesV3::Single(inner) => {
                    CanonicalSerialize::serialized_size(inner, compress)
                }
                RLNProofValuesV3::Multi(inner) => {
                    CanonicalSerialize::serialized_size(inner, compress)
                }
            }
    }
}

impl CanonicalDeserialize for RLNProofValuesV3 {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let tag = u8::deserialize_with_mode(&mut reader, compress, validate)?;
        match tag {
            ENUM_TAG_SINGLE => Ok(RLNProofValuesV3::Single(
                RLNProofValuesSingle::deserialize_with_mode(reader, compress, validate)?,
            )),
            ENUM_TAG_MULTI => Ok(RLNProofValuesV3::Multi(
                RLNProofValuesMulti::deserialize_with_mode(reader, compress, validate)?,
            )),
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl CanonicalSerializeBE for RLNProofValuesV3 {
    type Error = ProtocolError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        match self {
            RLNProofValuesV3::Single(inner) => {
                writer.write_all(&[ENUM_TAG_SINGLE])?;
                inner.serialize(&mut writer)
            }
            RLNProofValuesV3::Multi(inner) => {
                writer.write_all(&[ENUM_TAG_MULTI])?;
                inner.serialize(&mut writer)
            }
        }
    }

    fn serialized_size(&self) -> usize {
        ENUM_TAG_SIZE
            + match self {
                RLNProofValuesV3::Single(inner) => CanonicalSerializeBE::serialized_size(inner),
                RLNProofValuesV3::Multi(inner) => CanonicalSerializeBE::serialized_size(inner),
            }
    }
}

impl CanonicalDeserializeBE for RLNProofValuesV3 {
    type Error = ProtocolError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let mut tag = [0u8; ENUM_TAG_SIZE];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            ENUM_TAG_SINGLE => Ok(RLNProofValuesV3::Single(RLNProofValuesSingle::deserialize(
                reader,
            )?)),
            ENUM_TAG_MULTI => Ok(RLNProofValuesV3::Multi(RLNProofValuesMulti::deserialize(
                reader,
            )?)),
            _ => Err(ProtocolError::SerializationError(
                SerializationError::InvalidData,
            )),
        }
    }
}

impl CanonicalSerializeBE for RLNProofValuesSingle {
    type Error = ProtocolError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        self.root.serialize(&mut writer)?;
        self.x.serialize(&mut writer)?;
        self.external_nullifier.serialize(&mut writer)?;
        self.y.serialize(&mut writer)?;
        self.nullifier.serialize(&mut writer)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        FR_BYTE_SIZE // root
            + FR_BYTE_SIZE // x
            + FR_BYTE_SIZE // external_nullifier
            + FR_BYTE_SIZE // y
            + FR_BYTE_SIZE // nullifier
    }
}

impl CanonicalDeserializeBE for RLNProofValuesSingle {
    type Error = ProtocolError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let root = Fr::deserialize(&mut reader)?;
        let x = Fr::deserialize(&mut reader)?;
        let external_nullifier = Fr::deserialize(&mut reader)?;
        let y = Fr::deserialize(&mut reader)?;
        let nullifier = Fr::deserialize(&mut reader)?;
        Ok(Self {
            root,
            x,
            external_nullifier,
            y,
            nullifier,
        })
    }
}

impl CanonicalSerializeBE for RLNProofValuesMulti {
    type Error = ProtocolError;

    fn serialize<W: Write>(&self, mut writer: W) -> Result<(), Self::Error> {
        self.root.serialize(&mut writer)?;
        self.x.serialize(&mut writer)?;
        self.external_nullifier.serialize(&mut writer)?;
        self.ys.serialize(&mut writer)?;
        self.nullifiers.serialize(&mut writer)?;
        self.selector_used.serialize(&mut writer)?;
        Ok(())
    }

    fn serialized_size(&self) -> usize {
        FR_BYTE_SIZE // root
            + FR_BYTE_SIZE // x
            + FR_BYTE_SIZE // external_nullifier
            + VEC_LEN_BYTE_SIZE + FR_BYTE_SIZE * self.ys.len() // ys
            + VEC_LEN_BYTE_SIZE + FR_BYTE_SIZE * self.nullifiers.len() // nullifiers
            + VEC_LEN_BYTE_SIZE + self.selector_used.len() // selector_used
    }
}

impl CanonicalDeserializeBE for RLNProofValuesMulti {
    type Error = ProtocolError;

    fn deserialize<R: Read>(mut reader: R) -> Result<Self, Self::Error> {
        let root = Fr::deserialize(&mut reader)?;
        let x = Fr::deserialize(&mut reader)?;
        let external_nullifier = Fr::deserialize(&mut reader)?;
        let ys = Vec::<Fr>::deserialize(&mut reader)?;
        let nullifiers = Vec::<Fr>::deserialize(&mut reader)?;
        let selector_used = Vec::<bool>::deserialize(&mut reader)?;
        Ok(Self {
            root,
            x,
            external_nullifier,
            ys,
            nullifiers,
            selector_used,
        })
    }
}
