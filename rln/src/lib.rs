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

pub type Field = Fr;

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
            "0",
            "14744269619966411208579211824598458697587494354926760081771325075741142829156",
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
            "11331146992410411304059858900317123658895005918277453009197229807340014528524",
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
        let (proof, inputs) = generate_proof(builder, proving_key, rln_witness).unwrap();

        // Let's verify the proof
        let success = verify_proof(verification_key, proof, inputs).unwrap();

        assert!(success);
    }
}
