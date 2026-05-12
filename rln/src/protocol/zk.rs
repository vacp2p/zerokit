use ark_groth16::{prepare_verifying_key, Groth16};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use num_bigint::BigInt;
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::{
        circuit::{
            iden3calc::{calc_witness, calc_witness_partial},
            PartialProof,
        },
        partial_proof::{Groth16Partial, PartialAssignment},
        prelude::RLNPartialWitnessInputV3,
    },
    ark_std::rand::thread_rng,
};

use crate::{
    circuit::{qap::CircomReduction, ArkGroth16Backend, Curve, Fr, Proof},
    error::{ProtocolError, RLNError},
    prelude::{CanonicalDeserializeBE, CanonicalSerializeBE},
    protocol::{
        proof::{calculated_witness_to_field_elements, RLNProofValuesV3},
        witness::RLNWitnessInputV3,
    },
    utils::IdSecret,
};

pub trait RLNZkProof {
    type Witness: CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE;
    type Values: RecoverSecret
        + TryFrom<Self::Witness>
        + CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE;
    type Proof: CanonicalSerialize + CanonicalDeserialize;
    type Error;

    fn generate_proof(
        &self,
        witness: Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::Error>;

    fn generate_proof_with_witness(
        &self,
        calculated_witness: Vec<BigInt>,
        witness: Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::Error>;

    fn verify(&self, proof: &Self::Proof, values: &Self::Values) -> Result<bool, Self::Error>;
}

pub trait RecoverSecret<Rhs = Self> {
    type Error;

    fn recover_secret(&self, other: &Rhs) -> Result<IdSecret, Self::Error>;
}

pub trait RLNPartialZkProof: RLNZkProof {
    type PartialWitness: CanonicalSerialize
        + CanonicalDeserialize
        + CanonicalSerializeBE
        + CanonicalDeserializeBE;
    type PartialProof: CanonicalSerialize + CanonicalDeserialize;

    fn generate_partial_proof(
        &self,
        witness: Self::PartialWitness,
    ) -> Result<Self::PartialProof, Self::Error>;

    fn finish_proof(
        &self,
        partial: Self::PartialProof,
        witness: Self::Witness,
    ) -> Result<Self::Proof, Self::Error>;
}

impl RLNZkProof for ArkGroth16Backend {
    type Witness = RLNWitnessInputV3;
    type Values = RLNProofValuesV3;
    type Proof = Proof;
    type Error = RLNError;

    fn generate_proof(
        &self,
        witness: Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::Error> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            witness.validate_against_graph(&self.graph)?;

            let inputs = witness
                .to_circuit_inputs()
                .into_iter()
                .map(|(k, v)| (k.to_string(), v));
            let full_assignment = calc_witness(inputs, &self.graph).map_err(ProtocolError::from)?;

            let mut rng = thread_rng();
            let r = Fr::rand(&mut rng);
            let s = Fr::rand(&mut rng);

            let proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
                &self.zkey.0,
                r,
                s,
                &self.zkey.1,
                self.zkey.1.num_instance_variables,
                self.zkey.1.num_constraints,
                full_assignment.as_slice(),
            )
            .map_err(ProtocolError::from)?;

            let values = RLNProofValuesV3::try_from(witness)?;
            Ok((proof, values))
        }
        #[cfg(target_arch = "wasm32")]
        unreachable!(
            "generate_proof requires a circuit graph; use generate_proof_with_witness on WASM instead"
        )
    }

    fn generate_proof_with_witness(
        &self,
        calculated_witness: Vec<BigInt>,
        witness: Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::Error> {
        #[cfg(not(target_arch = "wasm32"))]
        witness.validate_against_graph(&self.graph)?;

        let full_assignment = calculated_witness_to_field_elements::<Curve>(calculated_witness)
            .map_err(RLNError::from)?;

        let mut rng = ark_std::rand::thread_rng();
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);

        let proof = Groth16::<_, CircomReduction>::create_proof_with_reduction_and_matrices(
            &self.zkey.0,
            r,
            s,
            &self.zkey.1,
            self.zkey.1.num_instance_variables,
            self.zkey.1.num_constraints,
            full_assignment.as_slice(),
        )
        .map_err(ProtocolError::from)?;

        let values = RLNProofValuesV3::try_from(witness)?;
        Ok((proof, values))
    }

    fn verify(&self, proof: &Self::Proof, values: &Self::Values) -> Result<bool, Self::Error> {
        let public_inputs: Vec<Fr> = match values {
            RLNProofValuesV3::Single(v) => {
                vec![v.y, v.root, v.nullifier, v.x, v.external_nullifier]
            }
            RLNProofValuesV3::Multi(v) => {
                let mut inputs = Vec::with_capacity(3 * v.ys.len() + 3);
                inputs.extend_from_slice(&v.ys);
                inputs.push(v.root);
                inputs.extend_from_slice(&v.nullifiers);
                inputs.push(v.x);
                inputs.push(v.external_nullifier);
                for &used in &v.selector_used {
                    inputs.push(Fr::from(used));
                }
                inputs
            }
        };
        let pvk = prepare_verifying_key(&self.zkey.0.vk);
        let verified = Groth16::<_, CircomReduction>::verify_proof(&pvk, proof, &public_inputs)
            .map_err(ProtocolError::from)?;
        Ok(verified)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl RLNPartialZkProof for ArkGroth16Backend {
    type PartialWitness = RLNPartialWitnessInputV3;
    type PartialProof = PartialProof;

    fn generate_partial_proof(
        &self,
        witness: Self::PartialWitness,
    ) -> Result<Self::PartialProof, Self::Error> {
        witness.validate_against_graph(&self.graph)?;

        let inputs = witness
            .to_circuit_inputs(self.graph.max_out)
            .into_iter()
            .map(|(k, v)| (k.to_string(), v));
        let full_assignment =
            calc_witness_partial(inputs, &self.graph).map_err(ProtocolError::from)?;

        let mut partial_values = Vec::with_capacity(full_assignment.len() - 1);
        partial_values.extend_from_slice(&full_assignment[1..]);
        let partial_assignment = PartialAssignment::new(partial_values);
        let partial_proof =
            Groth16Partial::<_, CircomReduction>::prove_partial(&self.zkey.0, &partial_assignment)?;
        Ok(partial_proof)
    }

    fn finish_proof(
        &self,
        partial: Self::PartialProof,
        witness: Self::Witness,
    ) -> Result<Self::Proof, Self::Error> {
        witness.validate_against_graph(&self.graph)?;

        let inputs = witness
            .to_circuit_inputs()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v));
        let full_assignment = calc_witness(inputs, &self.graph).map_err(ProtocolError::from)?;

        let mut rng = thread_rng();
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);

        let proof = Groth16Partial::<_, CircomReduction>::finish_proof_with_matrices(
            &self.zkey.0,
            &partial,
            r,
            s,
            &self.zkey.1,
            self.zkey.1.num_instance_variables,
            self.zkey.1.num_constraints,
            full_assignment.as_slice(),
        )?;
        Ok(proof)
    }
}
