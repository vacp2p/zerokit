use std::marker::PhantomData;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_groth16::{Proof, ProvingKey};
use ark_groth16::r1cs_to_qap::R1CSToQAP;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSynthesizer, SynthesisError, Result as R1CSResult};
use ark_std::rand::RngCore;

/// A partial assignment (witness)
/// `None` means "unknown" or changing part of the witness, `Some` means fixed and can be precomputed.
#[derive(Clone, Debug, PartialEq)]
pub struct PartialAssignment<F: PrimeField> {
    /// Assignment entries for (excluding 1)
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
        todo!()
    }

    /// Finish a proof using precomputed matrices and full assignment (instance || witness).
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
        todo!()
    }

    /// Finish a proof from a circuit and a partial proof, sampling randomness via `rng`.
    #[inline]
    pub fn finish_proof<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        pk: &ProvingKey<E>,
        circuit: C,
        rng: &mut R,
        partial: &PartialProof<E>,
    ) -> Result<Proof<E>, SynthesisError> {
        todo!()
    }
}