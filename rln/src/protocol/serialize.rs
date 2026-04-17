use std::io::{Read, Write};

use ark_serialize::{EmptyFlags, Flags};

pub trait CanonicalSerializeBE {
    type Error;

    fn serialize_with_flags<W: Write, F: Flags>(
        &self,
        writer: W,
        flags: F,
    ) -> Result<(), Self::Error>;

    fn serialized_size_with_flags<F: Flags>(&self) -> usize;

    fn serialize<W: Write>(&self, writer: W) -> Result<(), Self::Error> {
        self.serialize_with_flags(writer, EmptyFlags)
    }

    fn serialized_size(&self) -> usize {
        self.serialized_size_with_flags::<EmptyFlags>()
    }
}

pub trait CanonicalDeserializeBE: Sized {
    type Error;

    fn deserialize_with_flags<R: Read, F: Flags>(reader: R) -> Result<(Self, F), Self::Error>;

    fn deserialize<R: Read>(reader: R) -> Result<Self, Self::Error> {
        Ok(Self::deserialize_with_flags::<R, EmptyFlags>(reader)?.0)
    }
}
