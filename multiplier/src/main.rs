use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::{Report, Result};

use ark_bn254::Bn254;
use ark_groth16::{prepare_verifying_key, Groth16,
};

fn groth16_proof_example() -> Result<()> {
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
    let params = Groth16::<Bn254>::generate_random_parameters_with_reduction(circom, &mut rng)?;

    let circom = builder.build()?;

    let inputs = circom
        .get_public_inputs()
        .ok_or(Report::msg("no public inputs"))?;

    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(circom, &params, &mut rng)?;

    let pvk = prepare_verifying_key(&params.vk);

    match Groth16::<Bn254>::verify_proof(&pvk, &proof, &inputs) {
        Ok(_) => Ok(()),
        Err(_) => Err(Report::msg("not verified")),
    }
}

fn main() {
    println!("Hello, world!");

    match groth16_proof_example() {
        Ok(_) => println!("Success"),
        Err(_) => println!("Error"),
    }
}
