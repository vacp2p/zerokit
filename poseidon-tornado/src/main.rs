use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bn254::Bn254;
use ark_groth16::{
    create_random_proof as prove, generate_random_parameters, prepare_verifying_key, verify_proof,
};

use num_bigint::BigInt;

// Tracing
use tracing::{span, event, Level};
use ark_relations::r1cs::{ConstraintTrace, ConstraintLayer, ConstraintSystem, TracingMode};
use tracing_subscriber::layer::SubscriberExt;

// JSON
use serde::Deserialize;
use serde_json;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WitnessInput {
    root: String,
    nullifier_hash: String,
    recipient: String,
    relayer: String,
    //fee: String,
    fee: i32,
    nullifier: String,
    path_elements: Vec<String>,
    path_indices: Vec<i32>,
}

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

    // From poseidon-tornado JSON witness
    let input_json_str = r#"
{"root":"0x11cd2b4d61ad61dee506cac59c657e269cbbf5fbd548cd2f1d41dedaf4293748",
 "nullifierHash":"0x285edfd6d2499ea9eea742d4ece6a4668efbbf93b4c2194d9e086997ad59aa4f",
 "recipient":"0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
 "relayer":"0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
 "fee":0,
 "nullifier":"34284017061184348684424679404576688",
 "pathElements":["21663839004416932945382355908790599225266501822907911457504978515578255421292",
                 "0x13e37f2d6cb86c78ccc1788607c2b199788c6bb0a615a21f2e7a8e88384222f8",
                 "0x217126fa352c326896e8c2803eec8fd63ad50cf65edfef27a41a9e32dc622765",
                 "0x0e28a61a9b3e91007d5a9e3ada18e1b24d6d230c618388ee5df34cacd7397eee",
                 "0x27953447a6979839536badc5425ed15fadb0e292e9bc36f92f0aa5cfa5013587",
                 "0x194191edbfb91d10f6a7afd315f33095410c7801c47175c2df6dc2cce0e3affc",
                 "0x1733dece17d71190516dbaf1927936fa643dc7079fc0cc731de9d6845a47741f",
                 "0x267855a7dc75db39d81d17f95d0a7aa572bf5ae19f4db0e84221d2b2ef999219",
                 "0x1184e11836b4c36ad8238a340ecc0985eeba665327e33e9b0e3641027c27620d",
                 "0x0702ab83a135d7f55350ab1bfaa90babd8fc1d2b3e6a7215381a7b2213d6c5ce",
                 "0x2eecc0de814cfd8c57ce882babb2e30d1da56621aef7a47f3291cffeaec26ad7",
                 "0x280bc02145c155d5833585b6c7b08501055157dd30ce005319621dc462d33b47",
                 "0x045132221d1fa0a7f4aed8acd2cbec1e2189b7732ccb2ec272b9c60f0d5afc5b",
                 "0x27f427ccbf58a44b1270abbe4eda6ba53bd6ac4d88cf1e00a13c4371ce71d366",
                 "0x1617eaae5064f26e8f8a6493ae92bfded7fde71b65df1ca6d5dcec0df70b2cef",
                 "0x20c6b400d0ea1b15435703c31c31ee63ad7ba5c8da66cec2796feacea575abca",
                 "0x09589ddb438723f53a8e57bdada7c5f8ed67e8fece3889a73618732965645eec",
                 "0x0064b6a738a5ff537db7b220f3394f0ecbd35bfd355c5425dc1166bf3236079b",
                 "0x095de56281b1d5055e897c3574ff790d5ee81dbc5df784ad2d67795e557c9e9f",
                 "0x11cf2e2887aa21963a6ec14289183efe4d4c60f14ecd3d6fe0beebdf855a9b63"
],
 "pathIndices":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}
"#;

    let witness_input : WitnessInput = serde_json::from_str(input_json_str).expect("JSON was not well-formatted");

    println!("JSON: {:?}", witness_input);

    println!("Circom 2");

    let mut builder = CircomBuilder::new(cfg);

    // XXX Seems like a mix between BigInt and hex-encoded - radix 10 and 16 mixed?
    // Especially problematic for pathElements - let's try and see

    builder.push_input(
        "root",
        BigInt::parse_bytes(
            witness_input.root.strip_prefix("0x").unwrap().as_bytes(),
            16,
        )
        .unwrap(),
    );

    builder.push_input(
        "nullifierHash",
        BigInt::parse_bytes(
            witness_input.nullifier_hash.strip_prefix("0x").unwrap().as_bytes(),
            16,
        )
        .unwrap(),
    );

    builder.push_input(
        "recipient",
        BigInt::parse_bytes(
            witness_input.recipient.strip_prefix("0x").unwrap().as_bytes(),
            16,
        )
        .unwrap(),
    );

    builder.push_input(
        "relayer",
        BigInt::parse_bytes(
            witness_input.relayer.strip_prefix("0x").unwrap().as_bytes(),
            16,
        )
        .unwrap(),
    );

    // XXX
    builder.push_input(
        "fee",
        witness_input.fee
        //BigInt::parse_bytes(witness_input.fee.as_bytes(), 10).unwrap(),
    );

     builder.push_input(
        "nullifer",
        BigInt::parse_bytes(witness_input.nullifier.as_bytes(), 10).unwrap(),
    );

    // XXX We have a mix here - conditionally push? seems smelly
    for v in witness_input.path_elements.iter() {
        if v.starts_with("0x") {
            builder.push_input(
                "pathElements",
                BigInt::parse_bytes(v.strip_prefix("0x").unwrap().as_bytes(), 16,).unwrap(),
            );
        } else {
            builder.push_input(
                "pathElements",
                BigInt::parse_bytes(v.as_bytes(), 10).unwrap(),
            );
        }
    }

    for v in witness_input.path_indices.iter() {
        builder.push_input("pathIndices", BigInt::from(*v));
    }

    // XXX
    println!("Circom 3 - builder");
    println!("Builder input:\n {:#?}", builder.inputs);

    // but would like the tracing to tell me this
    //
    // what are the public inputs here
    //
    //  From poseidon-tornado
    // const witness = {
    //     // Public
    //     root,
    //     nullifierHash,
    //     recipient,
    //     relayer,
    //     fee,
    //     // Private
    //     nullifier: BigNumber.from(deposit.nullifier).toBigInt(),
    //     pathElements: path_elements,
    //     pathIndices: path_index,
    // };

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
