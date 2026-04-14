use std::io::{Read, Write};

use ark_serialize::{Compress, SerializationError, Valid, Validate};

pub trait CanonicalSerializeBE {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError>;

    fn serialized_size(&self, compress: Compress) -> usize;

    fn serialize_compressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.serialize_with_mode(writer, Compress::Yes)
    }

    fn compressed_size(&self) -> usize {
        self.serialized_size(Compress::Yes)
    }

    fn serialize_uncompressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.serialize_with_mode(writer, Compress::No)
    }

    fn uncompressed_size(&self) -> usize {
        self.serialized_size(Compress::No)
    }
}

pub trait CanonicalDeserializeBE: Valid {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError>;

    fn deserialize_compressed<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_mode(reader, Compress::Yes, Validate::Yes)
    }

    fn deserialize_compressed_unchecked<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_mode(reader, Compress::Yes, Validate::No)
    }

    fn deserialize_uncompressed<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_mode(reader, Compress::No, Validate::Yes)
    }

    fn deserialize_uncompressed_unchecked<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Self::deserialize_with_mode(reader, Compress::No, Validate::No)
    }
}
