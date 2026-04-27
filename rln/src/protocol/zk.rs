use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::{
        circuit::{
            iden3calc::calc_witness, qap::CircomReduction, ArkGroth16Backend, PartialProof, Proof,
        },
        error::{ProtocolError, RLNError},
        prelude::RLNPartialWitnessInputV3,
        protocol::{
            mode::MessageMode, witness::inputs_for_witness_calculation_v3, RLNProofValuesV3,
            RLNWitnessInputV3,
        },
    },
    ark_groth16::{prepare_verifying_key, Groth16},
    ark_std::{rand::thread_rng, UniformRand},
};

use crate::{
    circuit::Fr,
    prelude::{CanonicalDeserializeBE, CanonicalSerializeBE},
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

    fn verify(&self, proof: &Self::Proof, values: &Self::Values) -> Result<bool, Self::Error>;
}

pub trait RecoverSecret<Rhs = Self> {
    type Error;

    fn recover_secret(&self, other: &Rhs) -> Result<Fr, Self::Error>;
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

#[cfg(not(target_arch = "wasm32"))]
impl RLNZkProof for ArkGroth16Backend {
    type Witness = RLNWitnessInputV3;
    type Values = RLNProofValuesV3;
    type Proof = Proof;
    type Error = RLNError;

    fn generate_proof(
        &self,
        witness: Self::Witness,
    ) -> Result<(Self::Proof, Self::Values), Self::Error> {
        let tree_depth = self.graph.tree_depth;
        let graph_mode = MessageMode::from(&self.graph);

        let (path_len, index_len, witness_mode) = match &witness {
            RLNWitnessInputV3::Single(w) => (
                w.path_elements.len(),
                w.identity_path_index.len(),
                MessageMode::SingleV1,
            ),
            RLNWitnessInputV3::Multi(w) => (
                w.path_elements.len(),
                w.identity_path_index.len(),
                MessageMode::MultiV1 {
                    max_out: w.message_ids.len(),
                },
            ),
        };

        if witness_mode != graph_mode {
            return Err(ProtocolError::MessageModeAndGraphMismatch {
                witness_mode,
                graph_mode,
            }
            .into());
        }
        if path_len != tree_depth {
            return Err(ProtocolError::FieldLengthMismatch(
                "path_elements",
                path_len,
                "tree_depth",
                tree_depth,
            )
            .into());
        }
        if index_len != tree_depth {
            return Err(ProtocolError::FieldLengthMismatch(
                "identity_path_index",
                index_len,
                "tree_depth",
                tree_depth,
            )
            .into());
        }

        let inputs = inputs_for_witness_calculation_v3(&witness)
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
        _witness: Self::PartialWitness,
    ) -> Result<Self::PartialProof, Self::Error> {
        todo!()
    }

    fn finish_proof(
        &self,
        _partial: Self::PartialProof,
        _witness: Self::Witness,
    ) -> Result<Self::Proof, Self::Error> {
        todo!()
    }
}
