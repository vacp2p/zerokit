#[derive(thiserror::Error, Debug)]
pub enum PoseidonError {
    #[error("No parameters found for input length {0}")]
    NoParametersForInputLength(usize),
    #[error("Empty input provided")]
    EmptyInput,
}
