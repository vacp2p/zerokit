use crate::merkle::IncrementalMerkleTree;
use crate::poseidon::{Poseidon as PoseidonHasher, PoseidonParams};
use semaphore::hash::Hash;
use semaphore::poseidon_tree::PoseidonTree;

use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig};
use ark_std::rand::thread_rng;

use ark_bn254::Bn254;
use ark_groth16::{
    create_random_proof as prove, generate_random_parameters, prepare_verifying_key, verify_proof,
    Proof, ProvingKey,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// , SerializationError};

use std::io::{self, Read, Write};

use num_bigint::BigInt;

// JSON
use serde::Deserialize;
use serde_json;

// XXX
use bellman::pairing::ff::{Field, PrimeField, PrimeFieldRepr, ScalarEngine};
use sapling_crypto::bellman::pairing::bn256::Bn256;

// TODO Add Engine here? i.e. <E: Engine> not <Bn254>
// NOTE Bn254 vs Bn256 mismatch! Tree is originally Bn256
// TODO Figure out Bn254 vs Bn256 mismatch
pub struct RLN {
    circom: CircomCircuit<Bn254>,
    params: ProvingKey<Bn254>,
    // TODO Replace Bn256 with Bn254 here
    //tree: IncrementalMerkleTree<Bn256>,
    tree: PoseidonTree,
}

#[derive(Debug, Deserialize)]
//#[serde(rename_all = "camelCase")]
struct WitnessInput {
    identity_secret: String,
    path_elements: Vec<String>,
    identity_path_index: Vec<i32>,
    x: String,
    epoch: String,
    rln_identifier: String,
}

impl RLN {
    // TODO Break this apart here
    pub fn new() -> RLN {
        let cfg =
            CircomConfig::<Bn254>::new("./resources/rln.wasm", "./resources/rln.r1cs").unwrap();

        // TODO Refactor
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

        let witness_input: WitnessInput =
            serde_json::from_str(input_json_str).expect("JSON was not well-formatted");

        println!("Witness input JSON: {:?}", witness_input);

        let mut builder = CircomBuilder::new(cfg);

        builder.push_input(
            "identity_secret",
            BigInt::parse_bytes(witness_input.identity_secret.as_bytes(), 10).unwrap(),
        );

        for v in witness_input.path_elements.iter() {
            builder.push_input(
                "path_elements",
                BigInt::parse_bytes(v.as_bytes(), 10).unwrap(),
            );
        }

        for v in witness_input.identity_path_index.iter() {
            builder.push_input("identity_path_index", BigInt::from(*v));
        }

        builder.push_input(
            "x",
            BigInt::parse_bytes(witness_input.x.as_bytes(), 10).unwrap(),
        );

        builder.push_input(
            "epoch",
            BigInt::parse_bytes(
                witness_input.epoch.strip_prefix("0x").unwrap().as_bytes(),
                16,
            )
            .unwrap(),
        );

        builder.push_input(
            "rln_identifier",
            BigInt::parse_bytes(witness_input.rln_identifier.as_bytes(), 10).unwrap(),
        );

        println!("Builder input:\n {:#?}", builder.inputs);

        // create an empty instance for setting it up
        let circom = builder.setup();

        let mut rng = thread_rng();
        let params = generate_random_parameters::<Bn254, _, _>(circom, &mut rng).unwrap();

        let circom = builder.build().unwrap();

        let inputs = circom.get_public_inputs().unwrap();

        println!("Public inputs {:#?} ", inputs);

        // Sapling based tree
        // // TODO Add as parameter(s)
        // let merkle_depth: usize = 3;
        // let poseidon_params = PoseidonParams::<Bn256>::new(8, 55, 3, None, None, None);
        // let hasher = PoseidonHasher::new(poseidon_params.clone());
        // let tree = IncrementalMerkleTree::empty(hasher, merkle_depth);

        const LEAF: Hash = Hash::from_bytes_be([0u8; 32]);
        let mut tree = PoseidonTree::new(21, LEAF);

        RLN {
            circom,
            params,
            tree,
        }
    }

    /// returns current membership root
    /// * `root` is a scalar field element in 32 bytes
    pub fn get_root<W: Write>(&self, mut result_data: W) -> io::Result<()> {
        //let root = self.tree.get_root();
        // Converts PrimeFieldRepr into LE
        //root.into_repr().write_le(&mut result_data)?;

        //returns H::Hash, which is a 256 bit hash value
        let root = self.tree.root();
        // TODO Return root as LE here
        //root.write_le(&mut result_data)?;
        println!("NYI: root le write buffer {:#?}", root);
        Ok(())
    }

    // TODO Input Read
    pub fn prove<W: Write>(&self, result_data: W) -> io::Result<()> {
        let mut rng = thread_rng();

        // XXX: There's probably a better way to do this
        let circom = self.circom.clone();
        let params = self.params.clone();

        //let proof = create_random_proof(circom, &params, &mut rng)?;

        let proof = prove(circom, &params, &mut rng).unwrap();

        println!("Proof: {:?}", proof);

        // XXX: Unclear if this is different from other serialization(s)
        let _ = proof.serialize(result_data).unwrap();

        Ok(())
    }

    pub fn verify<R: Read>(&self, input_data: R) -> io::Result<bool> {
        let proof = Proof::deserialize(input_data).unwrap();

        let pvk = prepare_verifying_key(&self.params.vk);

        // XXX Part of input data?
        let inputs = self.circom.get_public_inputs().unwrap();

        let verified = verify_proof(&pvk, &proof, &inputs).unwrap();

        Ok(verified)
    }
}

impl Default for RLN {
    fn default() -> Self {
        Self::new()
    }
}

// NOTE: Expensive test, ignoring by default
#[ignore]
#[test]
fn rln_proof() {
    let mul = RLN::new();
    //let inputs = mul.circom.get_public_inputs().unwrap();

    let mut output_data: Vec<u8> = Vec::new();
    let _ = mul.prove(&mut output_data);

    let proof_data = &output_data[..];

    // XXX Pass as arg?
    //let pvk = prepare_verifying_key(&mul.params.vk);

    let verified = mul.verify(proof_data).unwrap();

    assert!(verified);
}
