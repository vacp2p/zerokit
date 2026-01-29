use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError, SynthesisMode};
use ark_std::test_rng;
use ark_std::rand::{RngCore, SeedableRng};
use ark_std::UniformRand;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16_partial::partial_prover::{Groth16Partial, PartialAssignment};

/// simple dummy multiplication circuit
#[derive(Copy, Clone)]
struct MulCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MulCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            a *= &b;
            Ok(a)
        })?;

        cs.enforce_constraint(
            ark_relations::lc!() + a,
            ark_relations::lc!() + b,
            ark_relations::lc!() + c,
        )?;
        Ok(())
    }
}

fn build_cs<F: Field>(circuit: MulCircuit<F>) -> ConstraintSystemRef<F> {
    let cs = ConstraintSystem::new_ref();
    cs.set_mode(SynthesisMode::Prove {
        construct_matrices: true,
    });
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    assert!(cs.is_satisfied().unwrap());
    cs
}

#[test]
fn partial_proof_test() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<Bn254>::setup(
        MulCircuit::<Fr> { a: None, b: None },
        &mut rng,
    ).unwrap();
    let pvk = prepare_verifying_key::<Bn254>(&vk);

    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let mut c = a;
    c *= b;

    // Partial witness: fix public input (c) and one witness (a), leave b unknown
    let mut partial_vals = vec![None; 3];
    partial_vals[0] = Some(c);
    partial_vals[1] = Some(a);
    let partial = Groth16Partial::<Bn254, LibsnarkReduction>::prove_partial(&pk, &PartialAssignment::new(partial_vals));
    // finish the proof
    let mut rng_partial = rng.clone();
    let finished_partial_proof = Groth16Partial::<Bn254, LibsnarkReduction>::finish_proof(
        &pk,
        MulCircuit::<Fr> { a: Some(a), b: Some(b) },
        &mut rng_partial,
        &partial,
    ).unwrap();

    // this is the proof with full witness
    let mut rng_full = rng.clone(); // clone rng so we get the same randomness
    let proof_full = Groth16::<Bn254, LibsnarkReduction>::prove(
        &pk,
        MulCircuit::<Fr> { a: Some(a), b: Some(b) },
        &mut rng_full
    ).unwrap();

    assert_eq!(finished_partial_proof, proof_full);
    assert!(
        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[c], &finished_partial_proof).unwrap()
    );
    assert!(
        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[c], &proof_full).unwrap()
    );
}

#[test]
fn partial_proof_with_matrices_test() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = ark_groth16::Groth16::<Bn254>::setup(
        MulCircuit::<Fr> { a: None, b: None },
        &mut rng,
    ).unwrap();
    let pvk = prepare_verifying_key::<Bn254>(&vk);

    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    let mut c = a;
    c *= b;

    let cs = build_cs(MulCircuit::<Fr> { a: Some(a), b: Some(b) });
    let matrices = cs.to_matrices().unwrap();
    let num_inputs = cs.num_instance_variables();
    let num_constraints = cs.num_constraints();
    let prover = cs.borrow().unwrap();
    let full_assignment_qap = [
        prover.instance_assignment.as_slice(),
        prover.witness_assignment.as_slice(),
    ].concat();

    // Partial witness: fix public input (c) and one witness (a), leave b unknown.
    let mut partial_vals = vec![None; 3];
    partial_vals[0] = Some(c);
    partial_vals[1] = Some(a);
    // partial proof
    let partial = Groth16Partial::<Bn254, LibsnarkReduction>::prove_partial(&pk, &PartialAssignment::new(partial_vals));
    // finish the proof
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let finished_partial_proof = Groth16Partial::<
        Bn254,
        LibsnarkReduction,
    >::finish_proof_with_matrices(
        &pk,
        &partial,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        &full_assignment_qap,
    ).unwrap();

    // this is the proof with full witness
    let proof_full = Groth16::<Bn254>::create_proof_with_reduction_and_matrices(
        &pk,
        r,
        s,
        &matrices,
        num_inputs,
        num_constraints,
        &full_assignment_qap,
    ).unwrap();

    assert_eq!(finished_partial_proof, proof_full);
    assert!(
        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[c], &finished_partial_proof).unwrap()
    );
    assert!(
        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[c], &proof_full).unwrap()
    );
}