#[derive(Debug, thiserror::Error)]
pub enum ZKeyReadError {
    #[error("Empty zkey bytes provided")]
    EmptyBytes,
    #[error("{0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

#[derive(Debug, thiserror::Error)]
pub enum WitnessCalcError {
    #[error("Failed to deserialize witness calculation graph: {0}")]
    GraphDeserialization(#[from] std::io::Error),
    #[error("Invalid input length for '{name}': expected {expected}, got {actual}")]
    InvalidInputLength {
        name: String,
        expected: usize,
        actual: usize,
    },
    #[error("Missing required input: {0}")]
    MissingInput(String),
}
