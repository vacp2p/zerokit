use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig};
use ark_std::rand::thread_rng;

use ark_bn254::Bn254;
use ark_groth16::{
    create_random_proof as prove, generate_random_parameters, prepare_verifying_key, verify_proof,
    Proof, ProvingKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use color_eyre::Report;
use std::io::{Read, Write};

pub struct Multiplier {
    circom: CircomCircuit<Bn254>,
    params: ProvingKey<Bn254>,
}

impl Multiplier {
    // TODO Break this apart here
    pub fn new() -> color_eyre::Result<Multiplier> {
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

        let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng)?;

        let circom = builder.build()?;

        //let inputs = circom.get_public_inputs().unwrap();

        Ok(Multiplier { circom, params })
    }

    // TODO Input Read
    pub fn prove<W: Write>(&self, result_data: W) -> color_eyre::Result<()> {
        let mut rng = thread_rng();

        // XXX: There's probably a better way to do this
        let circom = self.circom.clone();
        let params = self.params.clone();

        let proof = prove(circom, &params, &mut rng)?;

        // XXX: Unclear if this is different from other serialization(s)
        proof.serialize(result_data)?;

        Ok(())
    }

    pub fn verify<R: Read>(&self, input_data: R) -> color_eyre::Result<bool> {
        let proof = Proof::deserialize(input_data)?;

        let pvk = prepare_verifying_key(&self.params.vk);

        // XXX Part of input data?
        let inputs = self.circom.get_public_inputs().ok_or(Report::msg("no public inputs"))?;

        let verified = verify_proof(&pvk, &proof, &inputs)?;

        Ok(verified)
    }
}

impl Default for Multiplier {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
