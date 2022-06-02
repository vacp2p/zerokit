use color_eyre::Result;

// Tracing
use ark_relations::r1cs::{ConstraintLayer, ConstraintTrace, TracingMode};
use tracing_subscriber::layer::SubscriberExt;

// JSON

use rln::circuit::{CIRCOM, VK, ZKEY};
use rln::protocol::{generate_proof, rln_witness_from_json, verify_proof};

// RLN
fn groth16_proof_example() -> Result<()> {
    // Tracing to help with debugging
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let trace = ConstraintTrace::capture();
    println!("Trace is: {:?}", trace);

    // From rln JSON witness
    // Input generated with https://github.com/oskarth/zk-kit/commit/b6a872f7160c7c14e10a0ea40acab99cbb23c9a8
    let input_json_str = r#"
        {
          "identity_secret": "12825549237505733615964533204745049909430608936689388901883576945030025938736",
          "path_elements": [
            "18622655742232062119094611065896226799484910997537830749762961454045300666333",
            "20590447254980891299813706518821659736846425329007960381537122689749540452732",
            "7423237065226347324353380772367382631490014989348495481811164164159255474657",
            "11286972368698509976183087595462810875513684078608517520839298933882497716792",
            "3607627140608796879659380071776844901612302623152076817094415224584923813162",
            "19712377064642672829441595136074946683621277828620209496774504837737984048981",
            "20775607673010627194014556968476266066927294572720319469184847051418138353016",
            "3396914609616007258851405644437304192397291162432396347162513310381425243293",
            "21551820661461729022865262380882070649935529853313286572328683688269863701601",
            "6573136701248752079028194407151022595060682063033565181951145966236778420039",
            "12413880268183407374852357075976609371175688755676981206018884971008854919922",
            "14271763308400718165336499097156975241954733520325982997864342600795471836726",
            "20066985985293572387227381049700832219069292839614107140851619262827735677018",
            "9394776414966240069580838672673694685292165040808226440647796406499139370960",
            "11331146992410411304059858900317123658895005918277453009197229807340014528524"
          ],
          "identity_path_index": [
            1,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
          ],
          "x": "8143228284048792769012135629627737459844825626241842423967352803501040982",
          "epoch": "0x0000005b612540fc986b42322f8cb91c2273afad58ed006fdba0c97b4b16b12f",
          "rln_identifier": "11412926387081627876309792396682864042420635853496105400039841573530884328439"
        }
    "#;

    // We generate all relevant keys
    let proving_key = &ZKEY();
    let verification_key = &VK();
    let builder = CIRCOM();

    // We compute witness from the json input example
    let rln_witness = rln_witness_from_json(input_json_str);

    // Let's generate a zkSNARK proof
    let (proof, inputs) = generate_proof(builder, proving_key, rln_witness).unwrap();

    // Let's verify the proof
    let verified = verify_proof(verification_key, proof, inputs);

    assert!(verified.unwrap());

    Ok(())
}

fn main() {
    println!("rln example proof");

    match groth16_proof_example() {
        Ok(_) => println!("Success"),
        Err(_) => println!("Error"),
    }
}
