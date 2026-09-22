/// Errors that can occur during Poseidon hash computations
#[derive(Debug, thiserror::Error)]
pub enum PoseidonError {
    #[error(
        "No parameters found for input length {0} (POSEIDON_ROUND_PARAMS supports 1..=16 inputs)"
    )]
    NoParametersForInputLength(usize),
    #[error("Empty input provided")]
    EmptyInput,
}

/// Errors that can occur during Poseidon2 hash computations
#[derive(Debug, thiserror::Error)]
pub enum Poseidon2Error {
    #[error(
        "No parameters found for input length {0} (POSEIDON2_ROUND_PARAMS supports 1..=3 inputs)"
    )]
    NoParametersForInputLength(usize),
    #[error("Empty input provided")]
    EmptyInput,
    #[error("Unsupported state width {0} (the Poseidon2 permutation supports widths 2..=4)")]
    UnsupportedStateWidth(usize),
}
