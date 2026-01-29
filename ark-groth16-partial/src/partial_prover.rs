use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, Zero};
use ark_groth16::{Proof, ProvingKey};
use ark_groth16::r1cs_to_qap::R1CSToQAP;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSynthesizer, SynthesisError, Result as R1CSResult, ConstraintSystem, OptimizationGoal, SynthesisMode};
use ark_std::rand::RngCore;
use ark_std::{marker::PhantomData, ops::Mul, vec::Vec, UniformRand};


/// A partial assignment (witness)
/// `None` means "unknown" or changing part of the witness, `Some` means fixed and can be precomputed.
#[derive(Clone, Debug, PartialEq)]
pub struct PartialAssignment<F: PrimeField> {
    /// Assignment entries, ordered as (public inputs excluding 1) || (witness/aux)
    pub values: Vec<Option<F>>,
}
impl<F: PrimeField> PartialAssignment<F> {
    pub fn new(values: Vec<Option<F>>) -> Self {
        Self { values }
    }
}

/// Precomputed partial proof elements for a given `PartialAssignment`
#[derive(Clone, Debug, PartialEq)]
pub struct PartialProof<E: Pairing> {
    /// For each entry in `PartialAssignment::values`.
    pub mask: Vec<bool>,
    /// partial_pi_a = [alpha]_1 + sum z_j*[A_j]_1
    pub partial_pi_a: E::G1,
    /// partial_rho = [beta]_1  + sum z_j*[B_j]_1
    pub partial_rho: E::G1,
    /// partial_pi_b = [beta]_2  + sum z_j*[B_j]_2
    pub partial_pi_b: E::G2,
    /// partial_pi_c =             sum z_j*[K_j]_1
    pub partial_pi_c: E::G1,
}

/// Wrapper API generating partial proofs for ark-Groth16
pub struct Groth16Partial<E: Pairing, QAP: R1CSToQAP = LibsnarkReduction> {
    _p: PhantomData<(E, QAP)>,
}


impl<E: Pairing, QAP: R1CSToQAP> Groth16Partial<E, QAP> {
    /// Precompute a partial proof from a partial assignment.
    #[inline]
    pub fn prove_partial(
        pk: &ProvingKey<E>,
        partial_assignment: &PartialAssignment<E::ScalarField>,
    ) -> PartialProof<E> {
        create_partial_proof_from_assignment(pk, partial_assignment)
    }

    /// Finish a proof using precomputed matrices and full assignment (public/instance || witness).
    #[inline]
    pub fn finish_proof_with_reduction_and_matrices(
        pk: &ProvingKey<E>,
        partial: &PartialProof<E>,
        r: E::ScalarField,
        s: E::ScalarField,
        matrices: &ConstraintMatrices<E::ScalarField>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment_qap: &[E::ScalarField],
    ) -> R1CSResult<Proof<E>> {
        finish_proof_with_reduction_and_matrices::<E, QAP>(
            pk,
            partial,
            r,
            s,
            matrices,
            num_inputs,
            num_constraints,
            full_assignment_qap,
        )
    }

    /// Finish a proof from a circuit and a partial proof, sampling blinding/randomness with `rng`.
    #[inline]
    pub fn finish_proof<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        pk: &ProvingKey<E>,
        circuit: C,
        rng: &mut R,
        partial: &PartialProof<E>,
    ) -> Result<Proof<E>, SynthesisError> {
        finish_proof::<E, QAP, C, R>(pk, circuit, rng, partial).map_err(Into::into)
    }
}

/// MSM for a given list of points and scalars.
fn msm<G: CurveGroup>(points: &[G::Affine], scalars: &[G::ScalarField]) -> G {
    if points.is_empty() {
        return G::zero();
    }
    let scalars_bigint = scalars
        .iter()
        .map(|s| s.into_bigint())
        .collect::<Vec<_>>();
    G::msm_bigint(points, &scalars_bigint)
}

/// Precompute MSMs for a given partial assignment (witnesses).
/// `partial_assignment` is ordered as (public inputs excluding 1) || (witness/aux).
fn create_partial_proof_from_assignment<E: Pairing>(
    pk: &ProvingKey<E>,
    partial_assignment: &PartialAssignment<E::ScalarField>,
) -> PartialProof<E> {
    let num_inputs = pk.vk.gamma_abc_g1.len(); // this includes the "1" input
    let num_aux = pk.l_query.len();
    let expected_len = num_inputs + num_aux - 1;

    assert_eq!(
        partial_assignment.values.len(),
        expected_len,
        "partial assignment has wrong length"
    );

    // create a boolean mask of whether each entry is known
    let mask = partial_assignment
        .values
        .iter()
        .map(|v| v.is_some())
        .collect::<Vec<_>>();

    let mut a1_points = Vec::new();
    let mut scalars = Vec::new(); // these are the public input + known witnesses
    let mut b1_points = Vec::new();
    let mut b2_points = Vec::new();

    for (i, val) in partial_assignment.values.iter().enumerate() {
        if let Some(s) = val {
            // query[0] is the "1" input, so we offset by 1.
            a1_points.push(pk.a_query[1 + i]);
            b1_points.push(pk.b_g1_query[1 + i]);
            b2_points.push(pk.b_g2_query[1 + i]);
            scalars.push(*s);
        }
    }

    let mut l_points = Vec::new();
    let mut l_scalars = Vec::new(); // these are the public inputs and known witnesses
    let aux_start = num_inputs - 1; // skip the public input and "1"
    for (i, val) in partial_assignment.values.iter().enumerate().skip(aux_start) {
        if let Some(s) = val {
            l_points.push(pk.l_query[i - aux_start]);
            l_scalars.push(*s);
        }
    }

    // 4 MSMs
    let a_msm = msm::<E::G1>(&a1_points, &scalars);
    let b1_msm = msm::<E::G1>(&b1_points, &scalars);
    let b2_msm = msm::<E::G2>(&b2_points, &scalars);
    let l_msm = msm::<E::G1>(&l_points, &l_scalars);

    // partial_pi_a = [alpha]_1 + [A_0]_1 + sum(z_j * [A_j]_1) , where z_j = known witnesses
    let mut partial_pi_a = pk.vk.alpha_g1.into();
    partial_pi_a += &pk.a_query[0];
    partial_pi_a += &a_msm;
    // partial_rho = [beta]_1 + [B_0]_1 + sum(z_j * [B_j]1)
    let mut partial_rho = pk.beta_g1.into();
    partial_rho += &pk.b_g1_query[0];
    partial_rho += &b1_msm;
    // partial_pi_b = [beta]_2 + [B_0]_2 + sum(z_j * [B_j]_2)
    let mut partial_pi_b = pk.vk.beta_g2.into();
    partial_pi_b += &pk.b_g2_query[0];
    partial_pi_b += &b2_msm;

    PartialProof {
        mask,
        partial_pi_a,
        partial_rho,
        partial_pi_b,
        partial_pi_c: l_msm,
    }
}

/// Finish a partial proof once the full witness/assignment and QAP `h` are known.
fn finish_partial_proof_with_assignment<E: Pairing>(
    pk: &ProvingKey<E>,
    partial: &PartialProof<E>,
    full_assignment: &[E::ScalarField],
    h: &[E::ScalarField],
    r: E::ScalarField,
    s: E::ScalarField,
) -> R1CSResult<Proof<E>> {
    let num_inputs = pk.vk.gamma_abc_g1.len(); // this includes the "1" input
    let num_aux = pk.l_query.len();
    let expected_len = num_inputs + num_aux - 1;

    assert_eq!(full_assignment.len(), expected_len, "assignment length mismatch");
    assert_eq!(partial.mask.len(), expected_len, "mask length mismatch");

    let mut a1_points = Vec::new();
    let mut scalars = Vec::new(); // these are the public input + known witnesses
    let mut b1_points = Vec::new();
    let mut b2_points = Vec::new();

    for (i, s_i) in full_assignment.iter().enumerate() {
        if !partial.mask[i] {
            a1_points.push(pk.a_query[1 + i]);
            b1_points.push(pk.b_g1_query[1 + i]);
            b2_points.push(pk.b_g2_query[1 + i]);
            scalars.push(*s_i);
        }
    }

    let aux_start = num_inputs - 1;
    let mut l_points = Vec::new();
    let mut l_scalars = Vec::new();
    for (i, s_i) in full_assignment.iter().enumerate().skip(aux_start) {
        if !partial.mask[i] {
            l_points.push(pk.l_query[i - aux_start]);
            l_scalars.push(*s_i);
        }
    }

    // 4 MSMs
    let a_msm_rem = msm::<E::G1>(&a1_points, &scalars);
    let b1_msm_rem = msm::<E::G1>(&b1_points, &scalars);
    let b2_msm_rem = msm::<E::G2>(&b2_points, &scalars);
    let l_msm_rem = msm::<E::G1>(&l_points, &l_scalars);
    // random blinding r and s
    let r_g1 = pk.delta_g1.mul(r);
    let s_g1 = pk.delta_g1.mul(s);
    let s_g2 = pk.vk.delta_g2.mul(s);

    // g_a = partial_pi_a + remaining A MSM + r*delta_g1 (blinding)
    let mut g_a = partial.partial_pi_a + a_msm_rem;
    g_a += &r_g1;
    // g1_b = partial_rho + remaining B_g1 MSM + s*delta_g1
    // this is only when r != 0 , when r = 0 then no zk
    // this is to be consistent with ark-Groth16
    let g1_b = if !r.is_zero() {
        let mut acc = partial.partial_rho + b1_msm_rem;
        acc += &s_g1;
        acc
    } else {
        E::G1::zero()
    };
    // g2_b = partial_pi_b + remaining B_g2 MSM + s*delta_g2
    let mut g2_b = partial.partial_pi_b + b2_msm_rem;
    g2_b += &s_g2;
    // l_acc = partial_pi_c + remaining L MSM
    let l_acc = partial.partial_pi_c + l_msm_rem;
    // h_acc = MSM of quotient polynomial coefficients with h_query
    let h_assignment = h
        .iter()
        .map(|s_i| s_i.into_bigint())
        .collect::<Vec<_>>();
    let h_acc = E::G1::msm_bigint(&pk.h_query, &h_assignment);

    let r_s_delta_g1 = pk.delta_g1 * (r * s);
    let s_g_a = g_a * &s;
    let r_g1_b = g1_b * &r;

    // g_c = s*[A]_1 + r*[B]_1 - r*s*[delta]_1 + L + H
    let mut g_c = s_g_a;
    g_c += &r_g1_b;
    g_c -= &r_s_delta_g1;
    g_c += &l_acc;
    g_c += &h_acc;

    Ok(Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    })
}

/// Finish a proof using precomputed matrices and full assignment (public inputs || witness).
fn finish_proof_with_reduction_and_matrices<E, QAP>(
    pk: &ProvingKey<E>,
    partial: &PartialProof<E>,
    r: E::ScalarField,
    s: E::ScalarField,
    matrices: &ConstraintMatrices<E::ScalarField>,
    num_inputs: usize,
    num_constraints: usize,
    full_assignment_qap: &[E::ScalarField],
) -> R1CSResult<Proof<E>>
where
    E: Pairing,
    QAP: R1CSToQAP,
{
    let h = QAP::witness_map_from_matrices::<E::ScalarField, GeneralEvaluationDomain<E::ScalarField>>(
        matrices,
        num_inputs,
        num_constraints,
        full_assignment_qap,
    )?;

    // take (instance excluding "1" || witness)
    let full_assignment = full_assignment_qap[1..].to_vec();

    finish_partial_proof_with_assignment(pk, partial, &full_assignment, &h, r, s)
}

/// Finish a proof from a circuit and a partial proof, sampling blinding/randomness using `rng`
/// this is similar API to `prove(...)` ark-Groth16
fn finish_proof<E, QAP, C, R>(
    pk: &ProvingKey<E>,
    circuit: C,
    rng: &mut R,
    partial: &PartialProof<E>,
) -> R1CSResult<Proof<E>>
where
    E: Pairing,
    QAP: R1CSToQAP,
    C: ConstraintSynthesizer<E::ScalarField>,
    R: RngCore,
{
    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);

    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
    });

    circuit.generate_constraints(cs.clone())?;
    cs.finalize();

    debug_assert!(cs.is_satisfied().unwrap());

    let h = QAP::witness_map::<E::ScalarField, GeneralEvaluationDomain<E::ScalarField>>(cs.clone())?;

    let prover = cs.borrow().unwrap();
    let full_assignment = [
        prover.instance_assignment.as_slice()[1..].to_vec(),
        prover.witness_assignment.as_slice().to_vec(),
    ]
        .concat();

    finish_partial_proof_with_assignment(pk, partial, &full_assignment, &h, r, s)
}