#![allow(dead_code)]
#![allow(unused_imports)]

use crate::circuit::{CIRCOM, VK, ZKEY};
use ark_bn254::{Fr, Parameters};
use ark_ec::bn::Bn;
use ark_std::str::FromStr;

pub mod circuit;
pub mod ffi;
pub mod protocol;
pub mod public;
pub mod utils;

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol::*;
    use hex_literal::hex;
    use num_bigint::BigInt;
    use semaphore::{
        hash::Hash, hash_to_field, identity::Identity, poseidon_hash, poseidon_tree::PoseidonTree,
        Field,
    };

    #[test]
    // We test Merkle Tree generation, proofs and verification
    fn test_merkle_proof() {
        let tree_height = 16;
        let leaf_index = 3;

        // generate identity
        // We follow zk-kit approach for identity generation
        let id = Identity::from_seed(b"test-merkle-proof");
        let identity_secret = poseidon_hash(&vec![id.trapdoor, id.nullifier]);
        let id_commitment = poseidon_hash(&vec![identity_secret]);

        // generate merkle tree
        let default_leaf = Field::from(0);
        let mut tree = PoseidonTree::new(tree_height, default_leaf);
        tree.set(leaf_index, id_commitment.into());

        // We check correct computation of the root
        let root = tree.root();
        assert_eq!(
            root,
            Field::from_str("0x27401a4559ce263630907ce3b77c570649e28ede22d2a7f5296839627a16e870")
                .unwrap()
        );

        let merkle_proof = tree.proof(leaf_index).expect("proof should exist");
        let path_elements = get_path_elements(&merkle_proof);
        let identity_path_index = get_identity_path_index(&merkle_proof);

        // We check correct computation of the path and indexes
        let expected_path_elements = vec![
            Field::from_str("0x0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            Field::from_str("0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864")
                .unwrap(),
            Field::from_str("0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1")
                .unwrap(),
            Field::from_str("0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238")
                .unwrap(),
            Field::from_str("0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a")
                .unwrap(),
            Field::from_str("0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55")
                .unwrap(),
            Field::from_str("0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78")
                .unwrap(),
            Field::from_str("0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d")
                .unwrap(),
            Field::from_str("0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61")
                .unwrap(),
            Field::from_str("0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747")
                .unwrap(),
            Field::from_str("0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2")
                .unwrap(),
            Field::from_str("0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636")
                .unwrap(),
            Field::from_str("0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a")
                .unwrap(),
            Field::from_str("0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0")
                .unwrap(),
            Field::from_str("0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c")
                .unwrap(),
        ];

        let expected_identity_path_index: Vec<u8> =
            vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(path_elements, expected_path_elements);
        assert_eq!(identity_path_index, expected_identity_path_index);

        // We check correct verification of the proof
        assert!(tree.verify(id_commitment.into(), &merkle_proof));
    }

    #[test]
    // We test a RLN proof generation and verification
    fn test_witness_from_json() {
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
        let proof = generate_proof(builder, proving_key, &rln_witness).unwrap();

        let proof_values = proof_values_from_witness(&rln_witness);

        // Let's verify the proof
        let verified = verify_proof(verification_key, proof, &proof_values);

        assert!(verified.unwrap());
    }

    #[test]
    // We test a RLN proof generation and verification
    fn test_end_to_end() {
        let tree_height = 16;
        let leaf_index = 3;

        // Generate identity
        // We follow zk-kit approach for identity generation
        let id = Identity::from_seed(b"hello");
        let identity_secret = poseidon_hash(&vec![id.trapdoor, id.nullifier]);
        let id_commitment = poseidon_hash(&vec![identity_secret]);

        //// generate merkle tree
        let default_leaf = Field::from(0);
        let mut tree = PoseidonTree::new(tree_height, default_leaf);
        tree.set(leaf_index, id_commitment.into());

        let merkle_proof = tree.proof(leaf_index).expect("proof should exist");

        let signal = b"hey hey";
        let x = hash_to_field(signal);

        // We set the remaining values to random ones
        let epoch = hash_to_field(b"test-epoch");
        let rln_identifier = hash_to_field(b"test-rln-identifier");

        let rln_witness: RLNWitnessInput =
            rln_witness_from_values(identity_secret, &merkle_proof, x, epoch, rln_identifier);

        // We generate all relevant keys
        let proving_key = &ZKEY();
        let verification_key = &VK();
        let builder = CIRCOM();

        // Let's generate a zkSNARK proof
        let proof = generate_proof(builder, proving_key, &rln_witness).unwrap();

        let proof_values = proof_values_from_witness(&rln_witness);

        // Let's verify the proof
        let success = verify_proof(verification_key, proof, &proof_values).unwrap();

        assert!(success);
    }
}
