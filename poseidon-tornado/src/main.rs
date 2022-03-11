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


     builder.push_input(
        "nullifer",
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
    match groth16_proof_example2() {
        Ok(_) => println!("Success"),
        Err(_) => println!("Error"),
    }
}
