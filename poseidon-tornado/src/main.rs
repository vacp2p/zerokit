use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bn254::Bn254;
use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};

use num_bigint::BigInt;

// Tracing
use ark_relations::r1cs::{ConstraintLayer, ConstraintTrace, TracingMode};
//use tracing::{event, span, Level};
use tracing_subscriber::layer::SubscriberExt;

// JSON
use serde::Deserialize;
//use serde_json;

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

// Poseidon-tornado
fn groth16_proof_example() -> Result<()> {
    // Tracing to help with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let trace = ConstraintTrace::capture();
    println!("Trace is: {:?}", trace);

    let cfg = CircomConfig::<Bn254>::new("./resources/withdraw.wasm", "./resources/withdraw.r1cs")?;

    // Test
    let trace = ConstraintTrace::capture();
    println!("Trace is: {:?}", trace);

    // From poseidon-tornado JSON witness
    // Input generated with https://github.com/oskarth/poseidon-tornado/commit/db64ad09fdb16ad310ba395fc73520f87ad7d344
    // With nullifier set to 0
    let input_json_str = r#"
{
  "root": "17777834528943231885798890273562835075271930126129561600279382876922601684948",
  "nullifierHash": "8506691148847834795277894036216352001616813487121834991716343668271924769133",
  "recipient": "344073830386746567427978432078835137280280269756",
  "relayer": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  "fee": 0,
  "nullifier": "0",
  "pathElements": [
    "21663839004416932945382355908790599225266501822907911457504978515578255421292",
    "8995896153219992062710898675021891003404871425075198597897889079729967997688",
    "15126246733515326086631621937388047923581111613947275249184377560170833782629",
    "6404200169958188928270149728908101781856690902670925316782889389790091378414",
    "17903822129909817717122288064678017104411031693253675943446999432073303897479",
    "11423673436710698439362231088473903829893023095386581732682931796661338615804",
    "10494842461667482273766668782207799332467432901404302674544629280016211342367",
    "17400501067905286947724900644309270241576392716005448085614420258732805558809",
    "7924095784194248701091699324325620647610183513781643345297447650838438175245",
    "3170907381568164996048434627595073437765146540390351066869729445199396390350",
    "21224698076141654110749227566074000819685780865045032659353546489395159395031",
    "18113275293366123216771546175954550524914431153457717566389477633419482708807",
    "1952712013602708178570747052202251655221844679392349715649271315658568301659",
    "18071586466641072671725723167170872238457150900980957071031663421538421560166",
    "9993139859464142980356243228522899168680191731482953959604385644693217291503",
    "14825089209834329031146290681677780462512538924857394026404638992248153156554",
    "4227387664466178643628175945231814400524887119677268757709033164980107894508",
    "177945332589823419436506514313470826662740485666603469953512016396504401819",
    "4236715569920417171293504597566056255435509785944924295068274306682611080863",
    "8055374341341620501424923482910636721817757020788836089492629714380498049891"
  ],
  "pathIndices": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]}
"#;

    let witness_input: WitnessInput =
        serde_json::from_str(input_json_str).expect("JSON was not well-formatted");

    println!("Witness input JSON: {:?}", witness_input);

    let mut builder = CircomBuilder::new(cfg);

    builder.push_input(
        "root",
        BigInt::parse_bytes(witness_input.root.as_bytes(), 10).unwrap(),
    );

    builder.push_input(
        "nullifierHash",
        BigInt::parse_bytes(witness_input.nullifier_hash.as_bytes(), 10).unwrap(),
    );

    builder.push_input(
        "recipient",
        BigInt::parse_bytes(witness_input.recipient.as_bytes(), 10).unwrap(),
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
        witness_input.fee, //BigInt::parse_bytes(witness_input.fee.as_bytes(), 10).unwrap(),
    );

    builder.push_input(
        "nullifier",
        BigInt::parse_bytes(witness_input.nullifier.as_bytes(), 10).unwrap(),
    );

    for v in witness_input.path_elements.iter() {
        builder.push_input(
            "pathElements",
            BigInt::parse_bytes(v.as_bytes(), 10).unwrap(),
        );
    }

    for v in witness_input.path_indices.iter() {
        builder.push_input("pathIndices", BigInt::from(*v));
    }

    println!("Builder input:\n {:#?}", builder.inputs);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng)?;

    let circom = builder.build()?;

    let inputs = circom.get_public_inputs().unwrap();

    println!("Public inputs {:#?} ", inputs);

    let proof = create_random_proof(circom, &params, &mut rng)?;

    println!("Proof: {:?}", proof);

    let pvk = prepare_verifying_key(&params.vk);

    let verified = verify_proof(&pvk, &proof, &inputs)?;

    assert!(verified);

    Ok(())
}

fn main() {
    println!("tornado-poseidon example proof");

    // Tornado-core
    match groth16_proof_example() {
        Ok(_) => println!("Success"),
        Err(_) => println!("Error"),
    }
}
