#[derive(Debug, thiserror::Error)]
pub enum ZKeyReadError {
    #[error("No proving key found!")]
    EmptyBytes,
    #[error("{0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}
