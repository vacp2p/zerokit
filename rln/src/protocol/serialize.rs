use std::io::{Read, Write};

pub trait CanonicalSerializeBE {
    type Error;

    fn serialize_be<W: Write>(&self, writer: W) -> Result<(), Self::Error>;

    fn serialized_size_be(&self) -> usize;

    fn to_bytes_be(&self) -> Result<Vec<u8>, Self::Error> {
        let mut buf = Vec::with_capacity(self.serialized_size_be());
        self.serialize_be(&mut buf)?;
        Ok(buf)
    }
}

pub trait CanonicalDeserializeBE: Sized {
    type Error;

    fn deserialize_be<R: Read>(reader: R) -> Result<Self, Self::Error>;

    fn from_bytes_be(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::deserialize_be(bytes)
    }
}
