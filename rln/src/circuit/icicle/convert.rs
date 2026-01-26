// This crate is based on the code by Ingonyama. Its preimage can be found here:
// https://github.com/ingonyama-zk/icicle/blob/main/examples/rust/arkworks-icicle-conversions

use ark_bn254::{Fr as ArkFr, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, Field as ArkField, PrimeField};
use icicle_bn254::curve::{
    BaseField as IcicleBaseField, G1Affine as IcicleG1Affine, G1Projective as IcicleG1Projective,
    G2Affine as IcicleG2Affine, G2BaseField as IcicleG2BaseField,
    G2Projective as IcicleG2Projective, ScalarField as IcicleScalar,
};
use icicle_core::{
    affine::Affine as IcicleAffineTrait, bignum::BigNum, projective::Projective as IcicleProjective,
};

#[inline]
fn from_ark<T, I>(ark: &T) -> I
where
    T: ArkField,
    I: BigNum,
{
    let mut ark_bytes = vec![];
    for base_elem in ark.to_base_prime_field_elements() {
        ark_bytes.extend_from_slice(&base_elem.into_bigint().to_bytes_le());
    }
    I::from_bytes_le(&ark_bytes)
}

/// Convert arkworks Fr scalar to ICICLE scalar
#[inline]
pub(crate) fn ark_fr_to_icicle(scalar: &ArkFr) -> IcicleScalar {
    from_ark(scalar)
}

/// Convert slice of arkworks Fr scalars to ICICLE scalars
pub(crate) fn ark_frs_to_icicle(scalars: &[ArkFr]) -> Vec<IcicleScalar> {
    scalars.iter().map(ark_fr_to_icicle).collect()
}

/// Convert ICICLE scalar to arkworks Fr
#[inline]
pub(crate) fn icicle_to_ark_fr(scalar: &IcicleScalar) -> ArkFr {
    let bytes = scalar.to_bytes_le();
    ArkFr::from_le_bytes_mod_order(&bytes)
}

/// Convert slice of ICICLE scalars to arkworks Fr
#[allow(dead_code)]
pub(crate) fn icicle_to_ark_frs(scalars: &[IcicleScalar]) -> Vec<ArkFr> {
    scalars.iter().map(icicle_to_ark_fr).collect()
}

/// Convert arkworks G1Affine point to ICICLE G1Affine
#[inline]
pub(crate) fn ark_g1_to_icicle(point: &ArkG1Affine) -> IcicleG1Affine {
    if point.is_zero() {
        return IcicleG1Affine::zero();
    }

    IcicleG1Affine {
        x: from_ark::<_, IcicleBaseField>(&point.x().unwrap()),
        y: from_ark::<_, IcicleBaseField>(&point.y().unwrap()),
    }
}

/// Convert slice of arkworks G1Affine points to ICICLE G1Affine
pub(crate) fn ark_g1s_to_icicle(points: &[ArkG1Affine]) -> Vec<IcicleG1Affine> {
    points.iter().map(ark_g1_to_icicle).collect()
}

/// Convert ICICLE G1Projective to arkworks G1Affine
#[inline]
pub(crate) fn icicle_g1_proj_to_ark(point: &IcicleG1Projective) -> ark_bn254::G1Affine {
    use ark_bn254::{Fq, G1Affine};

    // Convert to affine in ICICLE
    let affine: IcicleG1Affine = point.to_affine();

    // Check for zero point
    if affine == IcicleG1Affine::zero() {
        return G1Affine::zero();
    }

    let x_bytes = affine.x.to_bytes_le();
    let y_bytes = affine.y.to_bytes_le();

    let x = Fq::from_le_bytes_mod_order(&x_bytes);
    let y = Fq::from_le_bytes_mod_order(&y_bytes);

    G1Affine::new_unchecked(x, y)
}

/// Convert arkworks G2Affine point to ICICLE G2Affine
#[inline]
pub(crate) fn ark_g2_to_icicle(point: &ArkG2Affine) -> IcicleG2Affine {
    if point.is_zero() {
        return IcicleG2Affine::zero();
    }

    // G2 coordinates are in Fq2 (extension field)
    let x = point.x().unwrap();
    let y = point.y().unwrap();

    // Fq2 has c0 and c1 components - combine into extension field format
    let x_c0_bytes = x.c0.into_bigint().to_bytes_le();
    let x_c1_bytes = x.c1.into_bigint().to_bytes_le();
    let y_c0_bytes = y.c0.into_bigint().to_bytes_le();
    let y_c1_bytes = y.c1.into_bigint().to_bytes_le();

    // Combine into extension field format for ICICLE
    let mut x_bytes = [0u8; 64];
    let mut y_bytes = [0u8; 64];

    x_bytes[..32].copy_from_slice(&x_c0_bytes);
    x_bytes[32..].copy_from_slice(&x_c1_bytes);
    y_bytes[..32].copy_from_slice(&y_c0_bytes);
    y_bytes[32..].copy_from_slice(&y_c1_bytes);

    let x_field = IcicleG2BaseField::from_bytes_le(&x_bytes);
    let y_field = IcicleG2BaseField::from_bytes_le(&y_bytes);

    IcicleG2Affine {
        x: x_field,
        y: y_field,
    }
}

/// Convert slice of arkworks G2Affine points to ICICLE G2Affine
pub(crate) fn ark_g2s_to_icicle(points: &[ArkG2Affine]) -> Vec<IcicleG2Affine> {
    points.iter().map(ark_g2_to_icicle).collect()
}

/// Convert ICICLE G2Projective to arkworks G2Affine
#[inline]
pub(crate) fn icicle_g2_proj_to_ark(point: &IcicleG2Projective) -> ArkG2Affine {
    use ark_bn254::{Fq, Fq2, G2Affine};

    let affine: IcicleG2Affine = point.to_affine();

    if affine == IcicleG2Affine::zero() {
        return G2Affine::zero();
    }

    let x_bytes = affine.x.to_bytes_le();
    let y_bytes = affine.y.to_bytes_le();

    // Split back into c0, c1 components
    let x_c0 = Fq::from_le_bytes_mod_order(&x_bytes[..32]);
    let x_c1 = Fq::from_le_bytes_mod_order(&x_bytes[32..64]);
    let y_c0 = Fq::from_le_bytes_mod_order(&y_bytes[..32]);
    let y_c1 = Fq::from_le_bytes_mod_order(&y_bytes[32..64]);

    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);

    G2Affine::new_unchecked(x, y)
}

#[cfg(test)]
mod tests {
    use ark_std::UniformRand;

    use super::*;

    #[test]
    fn test_scalar_roundtrip() {
        let mut rng = ark_std::test_rng();
        for _ in 0..100 {
            let ark_scalar = ArkFr::rand(&mut rng);
            let icicle_scalar = ark_fr_to_icicle(&ark_scalar);
            let back = icicle_to_ark_fr(&icicle_scalar);
            assert_eq!(ark_scalar, back);
        }
    }

    #[test]
    fn test_g1_conversion() {
        use ark_bn254::G1Projective;
        use ark_ec::CurveGroup;

        let mut rng = ark_std::test_rng();
        for _ in 0..10 {
            let ark_point = G1Projective::rand(&mut rng).into_affine();
            let icicle_point = ark_g1_to_icicle(&ark_point);
            // Basic sanity check - point should not be zero unless input was zero
            if !ark_point.is_zero() {
                assert!(icicle_point != IcicleG1Affine::zero());
            }
        }
    }
}
