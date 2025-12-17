/// Errors that can occur during Poseidon hash computations
#[derive(Debug, thiserror::Error)]
pub enum PoseidonError {
    #[error("No parameters found for input length {0}")]
    NoParametersForInputLength(usize),
    #[error("Empty input provided")]
    EmptyInput,
}
