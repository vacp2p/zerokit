use std::{fmt, ops::Deref};

use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;
use ruint::aliases::U256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::Fr;

/// Secret field-element wrapper zeroized on drop.
#[derive(Clone, PartialEq, CanonicalSerialize, CanonicalDeserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretFr(Fr);

impl fmt::Debug for SecretFr {
    /// Redacts the wrapped secret so `{:?}` never prints the plaintext field element.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretFr(********)")
    }
}

impl SecretFr {
    /// Samples a random secret field element from `rng`.
    pub fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let mut fr = Fr::rand(rng);
        let res = Self::from(&mut fr);
        // No need to zeroize fr (already zeroiz'ed in from implementation)
        #[allow(clippy::let_and_return)]
        res
    }

    /// Warning: this can leak the secret value
    /// Warning: Leaked value is of type 'U256' which implement Copy (every copy will not be
    /// zeroized)
    pub(crate) fn to_u256(&self) -> U256 {
        let mut big_int = self.0.into_bigint();
        let res = U256::from_limbs(big_int.0);
        big_int.zeroize(); // wipe the secret limbs after copying them into the leaked U256
        res
    }
}

impl From<&mut Fr> for SecretFr {
    fn from(value: &mut Fr) -> Self {
        let id_secret = Self(*value);
        value.zeroize(); // clear the caller-owned source Fr after the secret moved into SecretFr
        id_secret
    }
}

impl Deref for SecretFr {
    type Target = Fr;

    /// Deref to &Fr
    ///
    /// Warning: this can leak the secret value
    /// Warning: Leaked value is of type 'Fr' which implement Copy (every copy will not be zeroized)
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// FrOrSecret is a wrapper type that can hold either a SecretFr or a regular Fr.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) enum FrOrSecret {
    SecretFr(SecretFr),
    Fr(Fr),
}

impl From<Fr> for FrOrSecret {
    fn from(value: Fr) -> Self {
        FrOrSecret::Fr(value)
    }
}

impl From<SecretFr> for FrOrSecret {
    fn from(value: SecretFr) -> Self {
        FrOrSecret::SecretFr(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_secret_fr() {
        let mut fr = Fr::from(42);
        let id_secret = SecretFr::from(&mut fr);

        assert_ne!(fr, Fr::from(42));
        assert_eq!(*id_secret, Fr::from(42));

        let secret = SecretFr(Fr::from(42));
        assert_eq!(format!("{secret:?}"), "SecretFr(********)");
    }
}
