use std::ops::Mul;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;

use crate::{
    circuit::{
        icicle::msm::{icicle_msm_g1, icicle_msm_g2},
        ArkG2Affine, Fr, G1Affine, G1Projective, G2Projective, Proof, ProvingKey,
    },
    error::ProtocolError,
};

/// Calculate coefficient for proof element using ICICLE MSM
fn calculate_coeff_g1_icicle(
    initial: G1Projective,
    query: &[G1Affine],
    vk_param: G1Affine,
    assignment: &[Fr],
) -> Result<G1Projective, ProtocolError> {
    let el = query[0];

    // MSM for query[1..] with assignment
    let msm_result = if query.len() > 1 && !assignment.is_empty() {
        icicle_msm_g1(assignment, &query[1..])?
    } else {
        G1Projective::zero()
    };

    let mut res = initial;
    res += el.into_group();
    res += msm_result;
    res += vk_param.into_group();

    Ok(res)
}

/// Calculate coefficient for G2 proof element using ICICLE MSM
fn calculate_coeff_g2_icicle(
    initial: G2Projective,
    query: &[ArkG2Affine],
    vk_param: ArkG2Affine,
    assignment: &[Fr],
) -> Result<G2Projective, ProtocolError> {
    let el = query[0];

    // MSM for query[1..] with assignment
    let msm_result = if query.len() > 1 && !assignment.is_empty() {
        icicle_msm_g2(assignment, &query[1..])?
    } else {
        G2Projective::zero()
    };

    let mut res = initial;
    res += el.into_group();
    res += msm_result;
    res += vk_param.into_group();

    Ok(res)
}

/// Generates a zkSNARK proof using ICICLE GPU acceleration.
pub fn create_proof_with_icicle_msm(
    pk: &ProvingKey,
    r: Fr,
    s: Fr,
    h: &[Fr],
    input_assignment: &[Fr],
    aux_assignment: &[Fr],
) -> Result<Proof, ProtocolError> {
    // h_acc = MSM(pk.h_query, h)
    let h_acc = icicle_msm_g1(h, &pk.h_query)?;

    // l_aux_acc = MSM(pk.l_query, aux_assignment)
    let l_aux_acc = icicle_msm_g1(aux_assignment, &pk.l_query)?;

    // r_s_delta_g1 = pk.delta_g1 * (r * s)
    let r_s_delta_g1 = pk.delta_g1.mul(r * s);

    // Combine assignments
    let assignment: Vec<Fr> = input_assignment
        .iter()
        .chain(aux_assignment.iter())
        .copied()
        .collect();

    // Compute A
    // g_a = calculate_coeff(r * delta_g1, pk.a_query, pk.vk.alpha_g1, assignment)
    let r_g1 = pk.delta_g1.mul(r);
    let g_a = calculate_coeff_g1_icicle(r_g1, &pk.a_query, pk.vk.alpha_g1, &assignment)?;
    let s_g_a = g_a.mul(s);

    // Compute B in G1 (only if r != 0)
    let g1_b = if !r.is_zero() {
        let s_g1 = pk.delta_g1.mul(s);
        calculate_coeff_g1_icicle(s_g1, &pk.b_g1_query, pk.beta_g1, &assignment)?
    } else {
        ark_bn254::G1Projective::zero()
    };

    // Compute B in G2
    let s_g2 = pk.vk.delta_g2.mul(s);
    let g2_b = calculate_coeff_g2_icicle(s_g2, &pk.b_g2_query, pk.vk.beta_g2, &assignment)?;
    let r_g1_b = g1_b.mul(r);

    // Compute C
    let mut g_c = s_g_a;
    g_c += r_g1_b;
    g_c -= r_s_delta_g1;
    g_c += l_aux_acc;
    g_c += h_acc;

    Ok(Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    })
}
