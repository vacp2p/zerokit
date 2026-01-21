/// Errors that can occur during zkey reading operations
#[derive(Debug, thiserror::Error)]
pub enum ZKeyReadError {
    #[error("Empty zkey bytes provided")]
    EmptyBytes,
    #[error("{0}")]
    SerializationError(#[from] ark_serialize::SerializationError),
}

/// Errors that can occur during witness calculation graph reading operations
#[derive(Debug, thiserror::Error)]
pub enum GraphReadError {
    #[error("Empty graph bytes provided")]
    EmptyBytes,
    #[error("Failed to deserialize witness calculation graph: {0}")]
    GraphDeserialization(#[from] std::io::Error),
    #[error("Tree depth mismatch: circuit expects depth {expected}, but {actual} was provided")]
    TreeDepthMismatch { expected: usize, actual: usize },
}

/// Errors that can occur during witness calculation
#[derive(Debug, thiserror::Error)]
pub enum WitnessCalcError {
    #[error("Failed to evaluate witness calculation graph: {0}")]
    GraphEvaluation(String),
    #[error("Invalid input length for '{name}': expected {expected}, got {actual}")]
    InvalidInputLength {
        name: String,
        expected: usize,
        actual: usize,
    },
    #[error("Missing required input: {0}")]
    MissingInput(String),
}
