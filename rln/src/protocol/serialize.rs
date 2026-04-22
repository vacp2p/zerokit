use std::io::{Read, Write};

/// Byte size of the enum variant tag prepended to serialized enum types.
pub const ENUM_TAG_SIZE: usize = 1;

/// Tag byte for the `Single` variant — single message mode.
pub const ENUM_TAG_SINGLE: u8 = 0;

/// Tag byte for the `Multi` variant — multi message mode.
pub const ENUM_TAG_MULTI: u8 = 1;

pub trait CanonicalSerializeBE {
    type Error;

    fn serialize<W: Write>(&self, writer: W) -> Result<(), Self::Error>;
    fn serialized_size(&self) -> usize;
}

pub trait CanonicalDeserializeBE: Sized {
    type Error;

    fn deserialize<R: Read>(reader: R) -> Result<Self, Self::Error>;
}
