// This module defines the hash function abstraction shared by all zerokit modules.

use std::fmt::Debug;

/// Defines the interface for a hash function over a prime field, used by all zerokit modules.
pub trait ZerokitHasher {
    /// Type of the hashed elements, also used as the Merkle tree node type.
    type Scalar: Debug + Copy + Eq + Default + Send + Sync;

    /// Hashes an arbitrary-length slice of field elements to a single field element.
    fn hash(input: &[Self::Scalar]) -> Self::Scalar;
}
