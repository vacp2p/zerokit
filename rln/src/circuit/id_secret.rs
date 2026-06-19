use std::ops::Deref;

use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use ruint::aliases::U256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Fr;

/// Secret field-element wrapper zeroized on drop.
#[derive(
    Debug, Zeroize, ZeroizeOnDrop, Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize,
)]
pub struct IdSecret(Fr);

impl IdSecret {
    pub fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut fr = Fr::rand(rng);
        let res = Self::from(&mut fr);
        // No need to zeroize fr (already zeroiz'ed in from implementation)
        #[allow(clippy::let_and_return)]
        res
    }

    /// Warning: this can leak the secret value
    /// Warning: Leaked value is of type 'U256' which implement Copy (every copy will not be zeroized)
    pub(crate) fn to_u256(&self) -> U256 {
        let mut big_int = self.0.into_bigint();
        let res = U256::from_limbs(big_int.0);
        big_int.zeroize(); // wipe the secret limbs after copying them into the leaked U256
        res
    }
}

impl From<&mut Fr> for IdSecret {
    fn from(value: &mut Fr) -> Self {
        let id_secret = Self(*value);
        value.zeroize(); // clear the caller-owned source Fr after the secret moved into IdSecret
        id_secret
    }
}

impl Deref for IdSecret {
    type Target = Fr;

    /// Deref to &Fr
    ///
    /// Warning: this can leak the secret value
    /// Warning: Leaked value is of type 'Fr' which implement Copy (every copy will not be zeroized)
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) enum FrOrSecret {
    IdSecret(IdSecret),
    Fr(Fr),
}

impl From<Fr> for FrOrSecret {
    fn from(value: Fr) -> Self {
        FrOrSecret::Fr(value)
    }
}

impl From<IdSecret> for FrOrSecret {
    fn from(value: IdSecret) -> Self {
        FrOrSecret::IdSecret(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_id_secret_from_fr_zeroizes_source() {
        let mut fr = Fr::from(42);
        let id_secret = IdSecret::from(&mut fr);

        assert_ne!(fr, Fr::from(42));
        assert_eq!(*id_secret, Fr::from(42));
    }
}
