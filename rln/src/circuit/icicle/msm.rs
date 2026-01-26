use ark_bn254::{Fr as ArkFr, G1Affine as ArkG1Affine, G2Affine as ArkG2Affine};
use ark_ec::AffineRepr;
use ark_ff::Zero;
use icicle_bn254::curve::{G1Projective as IcicleG1Projective, G2Projective as IcicleG2Projective};
use icicle_core::{
    msm::{msm, MSMConfig},
    projective::Projective as IcicleProjective,
};
use icicle_runtime::memory::HostSlice;

use super::convert::{
    ark_frs_to_icicle, ark_g1s_to_icicle, ark_g2s_to_icicle, icicle_g1_proj_to_ark,
    icicle_g2_proj_to_ark,
};
use crate::error::ProtocolError;

/// Perform MSM on G1 using ICICLE
pub fn icicle_msm_g1(
    scalars: &[ArkFr],
    points: &[ArkG1Affine],
) -> Result<ark_bn254::G1Projective, ProtocolError> {
    if scalars.is_empty() || points.is_empty() {
        return Ok(ark_bn254::G1Projective::zero());
    }

    // Convert to ICICLE types
    let icicle_scalars = ark_frs_to_icicle(scalars);
    let icicle_points = ark_g1s_to_icicle(points);

    // Prepare result
    let mut result = vec![IcicleG1Projective::zero()];

    // Perform MSM
    let cfg = MSMConfig::default();
    msm(
        HostSlice::from_slice(&icicle_scalars),
        HostSlice::from_slice(&icicle_points),
        &cfg,
        HostSlice::from_mut_slice(&mut result),
    )?;

    // Convert back to arkworks
    let affine = icicle_g1_proj_to_ark(&result[0]);
    Ok(affine.into_group())
}

/// Perform MSM on G2 using ICICLE
pub fn icicle_msm_g2(
    scalars: &[ArkFr],
    points: &[ArkG2Affine],
) -> Result<ark_bn254::G2Projective, ProtocolError> {
    if scalars.is_empty() || points.is_empty() {
        return Ok(ark_bn254::G2Projective::zero());
    }

    // Convert to ICICLE types
    let icicle_scalars = ark_frs_to_icicle(scalars);
    let icicle_points = ark_g2s_to_icicle(points);

    // Prepare result
    let mut result = vec![IcicleG2Projective::zero()];

    // Perform MSM
    let cfg = MSMConfig::default();
    msm(
        HostSlice::from_slice(&icicle_scalars),
        HostSlice::from_slice(&icicle_points),
        &cfg,
        HostSlice::from_mut_slice(&mut result),
    )?;

    // Convert back to arkworks
    let affine = icicle_g2_proj_to_ark(&result[0]);
    Ok(affine.into_group())
}
