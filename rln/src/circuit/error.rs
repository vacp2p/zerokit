#[derive(Debug, thiserror::Error)]
pub enum ZKeyReadError {
    #[error("Empty zkey bytes provided")]
    EmptyBytes,
    #[error("{0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}
