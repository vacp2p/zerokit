use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bn254::Bn254;
use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};

use num_bigint::BigInt;

// JSON
use serde::Deserialize;
use serde_json;

// XXX look over
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositInput {
    root: String,
    nullifier_hash: String,
    relayer: String,
    recipient: String,
    fee: String,
    refund: String,
    nullifier: String,
    secret: String,
    path_elements: Vec<String>,
    path_indices: Vec<i32>,
}



// Poseidon-tornado
fn groth16_proof_example() -> Result<()> {
    println!("Circom 1");

    let cfg = CircomConfig::<Bn254>::new(
        "./resources/withdraw.wasm",
        "./resources/withdraw.r1cs",
     )?;

    // XXX: Weird mix here
    // From poseidon-tornado JSON witness
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

    let witness_input : WitnessInput = serde_json::from_str(input_json_str).expect("JSON was not well-formatted");

    println!("JSON: {:?}", witness_input);

    println!("Circom 2");

    let mut builder = CircomBuilder::new(cfg);

    // XXX Seems like a mix between BigInt and hex-encoded - radix 10 and 16 mixed?
    // Especially problematic for pathElements - let's try and see

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
        // BigInt::parse_bytes(
        //     witness_input.recipient.strip_prefix("0x").unwrap().as_bytes(),
        //     16,
        // )
        // .unwrap(),
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
        witness_input.fee
        //BigInt::parse_bytes(witness_input.fee.as_bytes(), 10).unwrap(),
    );

     builder.push_input(
        "nullifier",
        BigInt::parse_bytes(witness_input.nullifier.as_bytes(), 10).unwrap(),
    );

    // XXX We have a mix here - conditionally push? seems smelly
    for v in witness_input.path_elements.iter() {
            builder.push_input(
                "pathElements",
                BigInt::parse_bytes(v.as_bytes(), 10).unwrap(),
            );
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

    println!("Inputs {:#?} ", inputs);

    let proof = create_random_proof(circom, &params, &mut rng)?;

    println!("Proof: {:?}", proof);

    let pvk = prepare_verifying_key(&params.vk);

    let verified = verify_proof(&pvk, &proof, &inputs)?;

    assert!(verified);

    Ok(())
}


// tornado-core
fn groth16_proof_example2() -> Result<()> {
    println!("Circom 1");

    // XXX Using other input.json here to check, based on tornado-cash proper
    let input_json_str = r#"
    {
        "root": "16580815572075448356340562071457318374788383705496843314621489741537959124258",
        "nullifierHash": "10700765031549737019695892226146175986360939787941694441715836142154146527645",
        "relayer": "0x8EBb0380a0C88a743867A14409AED16eb3eC93eA",
        "recipient": "768046622761304935951257164293598741076624715619",
        "fee": "50000000000000000",
        "refund": "100000000000000000",
        "nullifier": "337750441743537117259945809957681472613953802882236680664715428204316132880",
        "secret": "173631503638659843485100444520947221493771326223250355257366689899361589280",
        "pathElements": [
            "21663839004416932945382355908790599225266501822907911457504978515578255421292",
            "16923532097304556005972200564242292693309333953544141029519619077135960040221",
            "7833458610320835472520144237082236871909694928684820466656733259024982655488",
            "14506027710748750947258687001455876266559341618222612722926156490737302846427",
            "4766583705360062980279572762279781527342845808161105063909171241304075622345",
            "16640205414190175414380077665118269450294358858897019640557533278896634808665",
            "13024477302430254842915163302704885770955784224100349847438808884122720088412",
            "11345696205391376769769683860277269518617256738724086786512014734609753488820",
            "17235543131546745471991808272245772046758360534180976603221801364506032471936",
            "155962837046691114236524362966874066300454611955781275944230309195800494087",
            "14030416097908897320437553787826300082392928432242046897689557706485311282736",
            "12626316503845421241020584259526236205728737442715389902276517188414400172517",
            "6729873933803351171051407921027021443029157982378522227479748669930764447503",
            "12963910739953248305308691828220784129233893953613908022664851984069510335421",
            "8697310796973811813791996651816817650608143394255750603240183429036696711432",
            "9001816533475173848300051969191408053495003693097546138634479732228054209462",
            "13882856022500117449912597249521445907860641470008251408376408693167665584212",
            "6167697920744083294431071781953545901493956884412099107903554924846764168938",
            "16572499860108808790864031418434474032816278079272694833180094335573354127261",
            "11544818037702067293688063426012553693851444915243122674915303779243865603077"
        ],
        "pathIndices": [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]
    }
    "#;

    let input_deposit : DepositInput =
        serde_json::from_str(input_json_str).expect("JSON was not well-formatted");

    println!("JSON: {:?}", input_deposit);

    let cfg = CircomConfig::<Bn254>::new(
        "./resources/tornado-core/withdraw.wasm",
        "./resources/tornado-core/withdraw.r1cs",
     )?;

    println!("Circom 2");

    let mut builder = CircomBuilder::new(cfg);

    // XXX Seems like a mix between BigInt and hex-encoded - radix 10 and 16 mixed?
    // Especially problematic for pathElements - let's try and see

    builder.push_input(
        "root",
        BigInt::parse_bytes(input_deposit.root.as_bytes(), 10).unwrap(),
    );

    builder.push_input(
        "nullifierHash",
        BigInt::parse_bytes(input_deposit.nullifier_hash.as_bytes(), 10).unwrap(),
    );

    builder.push_input(
        "recipient",
        BigInt::parse_bytes(input_deposit.recipient.as_bytes(), 10).unwrap(),
    );

    builder.push_input(
        "relayer",
        BigInt::parse_bytes(
            input_deposit.relayer.strip_prefix("0x").unwrap().as_bytes(),
            16,
        )
        .unwrap(),
    );

    builder.push_input(
        "fee",
        BigInt::parse_bytes(input_deposit.fee.as_bytes(), 10).unwrap(),
    );

    builder.push_input(
        "refund",
        BigInt::parse_bytes(input_deposit.refund.as_bytes(), 10).unwrap(),
    );


    // Fucking hell... nullifier not nullifer. FFS.
     builder.push_input(
        "nullifier",
        BigInt::parse_bytes(input_deposit.nullifier.as_bytes(), 10).unwrap(),
    );


    builder.push_input(
        "secret",
        BigInt::parse_bytes(input_deposit.secret.as_bytes(), 10).unwrap(),
    );

    for v in input_deposit.path_elements.iter() {
            builder.push_input(
                "pathElements",
                BigInt::parse_bytes(v.as_bytes(), 10).unwrap(),
            );
    }

    for v in input_deposit.path_indices.iter() {
        builder.push_input("pathIndices", BigInt::from(*v));
    }

    // XXX
    println!("Circom 3 - builder");
    println!("Builder input:\n {:#?}", builder.inputs);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng)?;

    let circom = builder.build()?;

    let inputs = circom.get_public_inputs().unwrap();

    println!("Inputs {:#?} ", inputs);

    let proof = create_random_proof(circom, &params, &mut rng).unwrap();

    println!("Proof: {:?}", proof);

    let pvk = prepare_verifying_key(&params.vk);

    let verified = verify_proof(&pvk, &proof, &inputs)?;

    assert!(verified);

    Ok(())
}



fn main() {
    println!("Hello, world!");

    // Tornado-core
    match groth16_proof_example() {
        Ok(_) => println!("Success"),
        Err(_) => println!("Error"),
    }
}
