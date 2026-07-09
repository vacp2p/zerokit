// This module defines the hash function abstraction shared by all zerokit modules.

/// Defines the interface for a hash function over a prime field, used by all zerokit modules.
pub trait ZerokitHasher {
    /// Type of the hashed elements.
    type Scalar;

    /// Hashes an arbitrary-length slice of field elements to a single field element.
    fn hash(input: &[Self::Scalar]) -> Self::Scalar;
}
