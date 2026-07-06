// This module defines the hash function abstraction shared by all zerokit modules.

use std::{
    fmt::{Debug, Display},
    str::FromStr,
};

/// Defines the interface for a hash function over a prime field, used by all zerokit modules.
pub trait ZerokitHasher {
    /// Type of the hashed elements, also used as the Merkle tree node type.
    type Fr: Clone + Copy + Eq + Default + Debug + Display + FromStr + Send + Sync;

    /// Hashes an arbitrary-length slice of field elements to a single field element.
    fn hash(input: &[Self::Fr]) -> Self::Fr;
}

/// Shorthand for the element type of a [`ZerokitHasher`].
pub type FrOf<H> = <H as ZerokitHasher>::Fr;
