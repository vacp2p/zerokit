use std::io::{Read, Write};

pub trait CanonicalSerializeBE {
    type Error;

    fn serialize_be<W: Write>(&self, writer: W) -> Result<(), Self::Error>;

    fn serialized_size_be(&self) -> usize;
}

pub trait CanonicalDeserializeBE: Sized {
    type Error;

    fn deserialize_be<R: Read>(reader: R) -> Result<Self, Self::Error>;
}
