use std::io::{Read, Write};

pub trait CanonicalSerializeBE {
    type Error;

    fn serialize<W: Write>(&self, writer: W) -> Result<(), Self::Error>;

    fn serialized_size(&self) -> usize;
}

pub trait CanonicalDeserializeBE: Sized {
    type Error;

    fn deserialize<R: Read>(reader: R) -> Result<Self, Self::Error>;
}
