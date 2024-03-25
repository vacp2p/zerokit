use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig};
use ark_ec::bn::Bn;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_std::rand::thread_rng;

use ark_bn254::{Bn254, Config};
use ark_groth16::{
    // prover::create_random_proof_with_reduction as prove, generator::generate_random_parameters_with_reduction, prepare_verifying_key, verifier::verify_proof,
    Groth16, Proof, ProvingKey
};
use ark_groth16::prepare_verifying_key;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use color_eyre::{Report, Result};
use std::io::{Read, Write};

pub struct Multiplier {
    circom: CircomCircuit<Bn254>,
    params: ProvingKey<Bn254>,
}

impl Multiplier {
    // TODO Break this apart here
    pub fn new() -> Result<Multiplier> {
        let cfg = CircomConfig::<Bn254>::new(
            "./resources/circom2_multiplier2.wasm",
            "./resources/circom2_multiplier2.r1cs",
        )?;

        let mut builder = CircomBuilder::new(cfg);
        builder.push_input("a", 3);
        builder.push_input("b", 11);

        // create an empty instance for setting it up
        let circom = builder.setup();

        let mut rng = thread_rng();

        let params = Groth16::<Bn<ark_bn254::Config>, LibsnarkReduction>::generate_random_parameters_with_reduction::<CircomCircuit<Bn<Config>>>(circom, &mut rng)?;

        let circom = builder.build()?;

        Ok(Multiplier { circom, params })
    }

    // TODO Input Read
    pub fn prove<W: Write>(&self, result_data: W) -> Result<()> {
        let mut rng = thread_rng();

        // XXX: There's probably a better way to do this
        let circom = self.circom.clone();
        let params = self.params.clone();

        let proof = Groth16::<Bn<ark_bn254::Config>, LibsnarkReduction>::create_random_proof_with_reduction(circom, &params, &mut rng)?;

        // XXX: Unclear if this is different from other serialization(s)
        proof.serialize_compressed(result_data)?;

        Ok(())
    }

    pub fn verify<R: Read>(&self, input_data: R) -> Result<bool> {
        let proof = Proof::deserialize_compressed(input_data)?;

        let pvk = prepare_verifying_key(&self.params.vk);

        // XXX Part of input data?
        let inputs = self
            .circom
            .get_public_inputs()
            .ok_or(Report::msg("no public inputs"))?;

        let verified = Groth16::<Bn<ark_bn254::Config>, LibsnarkReduction>::verify_proof(&pvk, &proof, &inputs)?;

        Ok(verified)
    }
}

impl Default for Multiplier {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
