use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bn254::Bn254;
use ark_groth16::{
    create_random_proof as prove, generate_random_parameters, prepare_verifying_key, verify_proof,
};

// Tracing
use tracing::{span, event, Level};
use ark_relations::r1cs::{ConstraintTrace, ConstraintLayer, ConstraintSystem, TracingMode};
use tracing_subscriber::layer::SubscriberExt;


fn groth16_proof_example() -> Result<()> {
    println!("Circom 1");

    // Tracing to help with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let trace = ConstraintTrace::capture();
    println!("Trace is: {:?}", trace);

    let cfg = CircomConfig::<Bn254>::new(
        "./resources/withdraw.wasm",
        "./resources/withdraw.r1cs",
    )?;

    // Test
    let trace = ConstraintTrace::capture();
    println!("Trace is: {:?}", trace);

    println!("Circom 2");
    let mut builder = CircomBuilder::new(cfg);


    println!("Circom 3");
    // XXX Here - probably is inputs don't match,
    // but would like the tracing to tell me this
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng)?;

    let circom = builder.build()?;

    let inputs = circom.get_public_inputs().unwrap();

    let proof = prove(circom, &params, &mut rng)?;

    let pvk = prepare_verifying_key(&params.vk);

    let verified = verify_proof(&pvk, &proof, &inputs)?;

    assert!(verified);

    Ok(())
}

fn main() {
    println!("Hello, world!");

    match groth16_proof_example() {
        Ok(_) => println!("Success"),
        Err(_) => println!("Error"),
    }
}
