use crate::circuit::{Curve, Fr, TEST_TREE_HEIGHT};
use crate::hashers::{hash_to_field, poseidon_hash as utils_poseidon_hash};
use crate::protocol::*;
use crate::public::RLN;
use crate::utils::*;
use ark_groth16::Proof as ArkProof;
use ark_serialize::{CanonicalDeserialize, Read};
use num_bigint::BigInt;
use std::io::Cursor;
use std::str::FromStr;
use utils::ZerokitMerkleTree;

use ark_std::{rand::thread_rng, UniformRand};
use rand::Rng;
use serde_json::{json, Value};

#[test]
// We test merkle batch Merkle tree additions
fn test_merkle_operations() {
    let tree_height = TEST_TREE_HEIGHT;
    let no_of_leaves = 256;

    // We generate a vector of random leaves
    let mut leaves: Vec<Fr> = Vec::new();
    let mut rng = thread_rng();
    for _ in 0..no_of_leaves {
        leaves.push(Fr::rand(&mut rng));
    }

    // We create a new tree
    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    // We first add leaves one by one specifying the index
    for (i, leaf) in leaves.iter().enumerate() {
        // We check if the number of leaves set is consistent
        assert_eq!(rln.tree.leaves_set(), i);

        let mut buffer = Cursor::new(fr_to_bytes_le(&leaf));
        rln.set_leaf(i, &mut buffer).unwrap();
    }

    // We get the root of the tree obtained adding one leaf per time
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_single, _) = bytes_le_to_fr(&buffer.into_inner());

    // We reset the tree to default
    rln.set_tree(tree_height).unwrap();

    // We add leaves one by one using the internal index (new leaves goes in next available position)
    for leaf in &leaves {
        let mut buffer = Cursor::new(fr_to_bytes_le(&leaf));
        rln.set_next_leaf(&mut buffer).unwrap();
    }

    // We check if numbers of leaves set is consistent
    assert_eq!(rln.tree.leaves_set(), no_of_leaves);

    // We get the root of the tree obtained adding leaves using the internal index
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_next, _) = bytes_le_to_fr(&buffer.into_inner());

    assert_eq!(root_single, root_next);

    // We reset the tree to default
    rln.set_tree(tree_height).unwrap();

    // We add leaves in a batch into the tree
    let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
    rln.init_tree_with_leaves(&mut buffer).unwrap();

    // We check if number of leaves set is consistent
    assert_eq!(rln.tree.leaves_set(), no_of_leaves);

    // We get the root of the tree obtained adding leaves in batch
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_batch, _) = bytes_le_to_fr(&buffer.into_inner());

    assert_eq!(root_single, root_batch);

    // We now delete all leaves set and check if the root corresponds to the empty tree root
    // delete calls over indexes higher than no_of_leaves are ignored and will not increase self.tree.next_index
    for i in 0..no_of_leaves {
        rln.delete_leaf(i).unwrap();
    }

    // We check if number of leaves set is consistent
    assert_eq!(rln.tree.leaves_set(), no_of_leaves);

    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_delete, _) = bytes_le_to_fr(&buffer.into_inner());

    // We reset the tree to default
    rln.set_tree(tree_height).unwrap();

    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_empty, _) = bytes_le_to_fr(&buffer.into_inner());

    assert_eq!(root_delete, root_empty);
}

#[test]
// We test leaf setting with a custom index, to enable batch updates to the root
// Uses `set_leaves_from` to set leaves in a batch, from index `start_index`
fn test_leaf_setting_with_index() {
    let tree_height = TEST_TREE_HEIGHT;
    let no_of_leaves = 256;

    // We generate a vector of random leaves
    let mut leaves: Vec<Fr> = Vec::new();
    let mut rng = thread_rng();
    for _ in 0..no_of_leaves {
        leaves.push(Fr::rand(&mut rng));
    }

    // set_index is the index from which we start setting leaves
    // random number between 0..no_of_leaves
    let set_index = rng.gen_range(0..no_of_leaves) as usize;

    // We create a new tree
    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    // We add leaves in a batch into the tree
    let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
    rln.init_tree_with_leaves(&mut buffer).unwrap();

    // We check if number of leaves set is consistent
    assert_eq!(rln.tree.leaves_set(), no_of_leaves);

    // We get the root of the tree obtained adding leaves in batch
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_batch_with_init, _) = bytes_le_to_fr(&buffer.into_inner());

    // `init_tree_with_leaves` resets the tree to the height it was initialized with, using `set_tree`

    // We add leaves in a batch starting from index 0..set_index
    let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves[0..set_index]).unwrap());
    rln.init_tree_with_leaves(&mut buffer).unwrap();

    // We add the remaining n leaves in a batch starting from index m
    let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves[set_index..]).unwrap());
    rln.set_leaves_from(set_index, &mut buffer).unwrap();

    // We check if number of leaves set is consistent
    assert_eq!(rln.tree.leaves_set(), no_of_leaves);

    // We get the root of the tree obtained adding leaves in batch
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_batch_with_custom_index, _) = bytes_le_to_fr(&buffer.into_inner());

    assert_eq!(root_batch_with_init, root_batch_with_custom_index);

    // We reset the tree to default
    rln.set_tree(tree_height).unwrap();

    // We add leaves one by one using the internal index (new leaves goes in next available position)
    for leaf in &leaves {
        let mut buffer = Cursor::new(fr_to_bytes_le(&leaf));
        rln.set_next_leaf(&mut buffer).unwrap();
    }

    // We check if numbers of leaves set is consistent
    assert_eq!(rln.tree.leaves_set(), no_of_leaves);

    // We get the root of the tree obtained adding leaves using the internal index
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_single_additions, _) = bytes_le_to_fr(&buffer.into_inner());

    assert_eq!(root_batch_with_init, root_single_additions);

    rln.flush().unwrap();
}

#[test]
// Tests the atomic_operation fn, which set_leaves_from uses internally
fn test_atomic_operation() {
    let tree_height = TEST_TREE_HEIGHT;
    let no_of_leaves = 256;

    // We generate a vector of random leaves
    let mut leaves: Vec<Fr> = Vec::new();
    let mut rng = thread_rng();
    for _ in 0..no_of_leaves {
        leaves.push(Fr::rand(&mut rng));
    }

    // We create a new tree
    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    // We add leaves in a batch into the tree
    let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
    rln.init_tree_with_leaves(&mut buffer).unwrap();

    // We check if number of leaves set is consistent
    assert_eq!(rln.tree.leaves_set(), no_of_leaves);

    // We get the root of the tree obtained adding leaves in batch
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_after_insertion, _) = bytes_le_to_fr(&buffer.into_inner());

    // We check if number of leaves set is consistent
    assert_eq!(rln.tree.leaves_set(), no_of_leaves);

    let last_leaf = leaves.last().unwrap();
    let last_leaf_index = no_of_leaves - 1;
    let indices = vec![last_leaf_index as u8];
    let last_leaf = vec![*last_leaf];
    let indices_buffer = Cursor::new(vec_u8_to_bytes_le(&indices).unwrap());
    let leaves_buffer = Cursor::new(vec_fr_to_bytes_le(&last_leaf).unwrap());

    rln.atomic_operation(last_leaf_index, leaves_buffer, indices_buffer)
        .unwrap();

    // We get the root of the tree obtained after a no-op
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_after_noop, _) = bytes_le_to_fr(&buffer.into_inner());

    assert_eq!(root_after_insertion, root_after_noop);
}

#[test]
fn test_atomic_operation_zero_indexed() {
    // Test duplicated from https://github.com/waku-org/go-zerokit-rln/pull/12/files
    let tree_height = TEST_TREE_HEIGHT;
    let no_of_leaves = 256;

    // We generate a vector of random leaves
    let mut leaves: Vec<Fr> = Vec::new();
    let mut rng = thread_rng();
    for _ in 0..no_of_leaves {
        leaves.push(Fr::rand(&mut rng));
    }

    // We create a new tree
    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    // We add leaves in a batch into the tree
    let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
    rln.init_tree_with_leaves(&mut buffer).unwrap();

    // We check if number of leaves set is consistent
    assert_eq!(rln.tree.leaves_set(), no_of_leaves);

    // We get the root of the tree obtained adding leaves in batch
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_after_insertion, _) = bytes_le_to_fr(&buffer.into_inner());

    let zero_index = 0;
    let indices = vec![zero_index as u8];
    let zero_leaf: Vec<Fr> = vec![];
    let indices_buffer = Cursor::new(vec_u8_to_bytes_le(&indices).unwrap());
    let leaves_buffer = Cursor::new(vec_fr_to_bytes_le(&zero_leaf).unwrap());
    rln.atomic_operation(0, leaves_buffer, indices_buffer)
        .unwrap();

    // We get the root of the tree obtained after a deletion
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_after_deletion, _) = bytes_le_to_fr(&buffer.into_inner());

    assert_ne!(root_after_insertion, root_after_deletion);
}

#[test]
fn test_atomic_operation_consistency() {
    // Test duplicated from https://github.com/waku-org/go-zerokit-rln/pull/12/files
    let tree_height = TEST_TREE_HEIGHT;
    let no_of_leaves = 256;

    // We generate a vector of random leaves
    let mut leaves: Vec<Fr> = Vec::new();
    let mut rng = thread_rng();
    for _ in 0..no_of_leaves {
        leaves.push(Fr::rand(&mut rng));
    }

    // We create a new tree
    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    // We add leaves in a batch into the tree
    let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
    rln.init_tree_with_leaves(&mut buffer).unwrap();

    // We check if number of leaves set is consistent
    assert_eq!(rln.tree.leaves_set(), no_of_leaves);

    // We get the root of the tree obtained adding leaves in batch
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_after_insertion, _) = bytes_le_to_fr(&buffer.into_inner());

    let set_index = rng.gen_range(0..no_of_leaves) as usize;
    let indices = vec![set_index as u8];
    let zero_leaf: Vec<Fr> = vec![];
    let indices_buffer = Cursor::new(vec_u8_to_bytes_le(&indices).unwrap());
    let leaves_buffer = Cursor::new(vec_fr_to_bytes_le(&zero_leaf).unwrap());
    rln.atomic_operation(0, leaves_buffer, indices_buffer)
        .unwrap();

    // We get the root of the tree obtained after a deletion
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_after_deletion, _) = bytes_le_to_fr(&buffer.into_inner());

    assert_ne!(root_after_insertion, root_after_deletion);

    // We get the leaf
    let mut output_buffer = Cursor::new(Vec::<u8>::new());
    rln.get_leaf(set_index, &mut output_buffer).unwrap();
    let (received_leaf, _) = bytes_le_to_fr(output_buffer.into_inner().as_ref());

    assert_eq!(received_leaf, Fr::from(0));
}

#[allow(unused_must_use)]
#[test]
// This test checks if `set_leaves_from` throws an error when the index is out of bounds
fn test_set_leaves_bad_index() {
    let tree_height = TEST_TREE_HEIGHT;
    let no_of_leaves = 256;

    // We generate a vector of random leaves
    let mut leaves: Vec<Fr> = Vec::new();
    let mut rng = thread_rng();
    for _ in 0..no_of_leaves {
        leaves.push(Fr::rand(&mut rng));
    }
    let bad_index = (1 << tree_height) - rng.gen_range(0..no_of_leaves) as usize;

    // We create a new tree
    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    // Get root of empty tree
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_empty, _) = bytes_le_to_fr(&buffer.into_inner());

    // We add leaves in a batch into the tree
    let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
    rln.set_leaves_from(bad_index, &mut buffer)
        .expect_err("Should throw an error");

    // We check if number of leaves set is consistent
    assert_eq!(rln.tree.leaves_set(), 0);

    // Get the root of the tree
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root_after_bad_set, _) = bytes_le_to_fr(&buffer.into_inner());

    assert_eq!(root_empty, root_after_bad_set);
}

fn fq_from_str(s: String) -> ark_bn254::Fq {
    ark_bn254::Fq::from_str(&s).unwrap()
}

fn g1_from_str(g1: &[String]) -> ark_bn254::G1Affine {
    let x = fq_from_str(g1[0].clone());
    let y = fq_from_str(g1[1].clone());
    let z = fq_from_str(g1[2].clone());
    ark_bn254::G1Affine::from(ark_bn254::G1Projective::new(x, y, z))
}

fn g2_from_str(g2: &[Vec<String>]) -> ark_bn254::G2Affine {
    let c0 = fq_from_str(g2[0][0].clone());
    let c1 = fq_from_str(g2[0][1].clone());
    let x = ark_bn254::Fq2::new(c0, c1);

    let c0 = fq_from_str(g2[1][0].clone());
    let c1 = fq_from_str(g2[1][1].clone());
    let y = ark_bn254::Fq2::new(c0, c1);

    let c0 = fq_from_str(g2[2][0].clone());
    let c1 = fq_from_str(g2[2][1].clone());
    let z = ark_bn254::Fq2::new(c0, c1);

    ark_bn254::G2Affine::from(ark_bn254::G2Projective::new(x, y, z))
}

fn value_to_string_vec(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .into_iter()
        .map(|val| val.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn test_groth16_proof_hardcoded() {
    let tree_height = TEST_TREE_HEIGHT;

    let rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    let valid_snarkjs_proof = json!({
     "pi_a": [
      "606446415626469993821291758185575230335423926365686267140465300918089871829",
      "14881534001609371078663128199084130129622943308489025453376548677995646280161",
      "1"
     ],
     "pi_b": [
      [
       "18053812507994813734583839134426913715767914942522332114506614735770984570178",
       "11219916332635123001710279198522635266707985651975761715977705052386984005181"
      ],
      [
       "17371289494006920912949790045699521359436706797224428511776122168520286372970",
       "14038575727257298083893642903204723310279435927688342924358714639926373603890"
      ],
      [
       "1",
       "0"
      ]
     ],
     "pi_c": [
      "17701377127561410274754535747274973758826089226897242202671882899370780845888",
      "12608543716397255084418384146504333522628400182843246910626782513289789807030",
      "1"
     ],
     "protocol": "groth16",
     "curve": "bn128"
    });
    let valid_ark_proof = ArkProof {
        a: g1_from_str(&value_to_string_vec(&valid_snarkjs_proof["pi_a"])),
        b: g2_from_str(
            &valid_snarkjs_proof["pi_b"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| value_to_string_vec(item))
                .collect::<Vec<Vec<String>>>(),
        ),
        c: g1_from_str(&value_to_string_vec(&valid_snarkjs_proof["pi_c"])),
    };

    let valid_proof_values = RLNProofValues {
        x: str_to_fr(
            "20645213238265527935869146898028115621427162613172918400241870500502509785943",
            10,
        )
        .unwrap(),
        external_nullifier: str_to_fr(
            "21074405743803627666274838159589343934394162804826017440941339048886754734203",
            10,
        )
        .unwrap(),
        y: str_to_fr(
            "16401008481486069296141645075505218976370369489687327284155463920202585288271",
            10,
        )
        .unwrap(),
        root: str_to_fr(
            "8502402278351299594663821509741133196466235670407051417832304486953898514733",
            10,
        )
        .unwrap(),
        nullifier: str_to_fr(
            "9102791780887227194595604713537772536258726662792598131262022534710887343694",
            10,
        )
        .unwrap(),
    };

    let verified = verify_proof(&rln.verification_key, &valid_ark_proof, &valid_proof_values);
    assert!(verified.unwrap());
}

#[test]
// This test is similar to the one in lib, but uses only public API
fn test_groth16_proof() {
    let tree_height = TEST_TREE_HEIGHT;

    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    // Note: we only test Groth16 proof generation, so we ignore setting the tree in the RLN object
    let rln_witness = random_rln_witness(tree_height);
    let proof_values = proof_values_from_witness(&rln_witness).unwrap();

    // We compute a Groth16 proof
    let mut input_buffer = Cursor::new(serialize_witness(&rln_witness).unwrap());
    let mut output_buffer = Cursor::new(Vec::<u8>::new());
    rln.prove(&mut input_buffer, &mut output_buffer).unwrap();
    let serialized_proof = output_buffer.into_inner();

    // Before checking public verify API, we check that the (deserialized) proof generated by prove is actually valid
    let proof = ArkProof::deserialize_compressed(&mut Cursor::new(&serialized_proof)).unwrap();
    let verified = verify_proof(&rln.verification_key, &proof, &proof_values);
    // dbg!(verified.unwrap());
    assert!(verified.unwrap());

    // We prepare the input to prove API, consisting of serialized_proof (compressed, 4*32 bytes) || serialized_proof_values (6*32 bytes)
    let serialized_proof_values = serialize_proof_values(&proof_values);
    let mut verify_data = Vec::<u8>::new();
    verify_data.extend(&serialized_proof);
    verify_data.extend(&serialized_proof_values);
    let mut input_buffer = Cursor::new(verify_data);

    // We verify the Groth16 proof against the provided proof values
    let verified = rln.verify(&mut input_buffer).unwrap();

    assert!(verified);
}

#[test]
fn test_rln_proof() {
    let tree_height = TEST_TREE_HEIGHT;
    let no_of_leaves = 256;

    // We generate a vector of random leaves
    let mut leaves: Vec<Fr> = Vec::new();
    let mut rng = thread_rng();
    for _ in 0..no_of_leaves {
        let id_commitment = Fr::rand(&mut rng);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, Fr::from(100)]);
        leaves.push(rate_commitment);
    }

    // We create a new RLN instance
    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    // We add leaves in a batch into the tree
    let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
    rln.init_tree_with_leaves(&mut buffer).unwrap();

    // Generate identity pair
    let (identity_secret_hash, id_commitment) = keygen();

    // We set as leaf rate_commitment after storing its index
    let identity_index = rln.tree.leaves_set();
    let user_message_limit = Fr::from(65535);
    let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);
    let mut buffer = Cursor::new(fr_to_bytes_le(&rate_commitment));
    rln.set_next_leaf(&mut buffer).unwrap();

    // We generate a random signal
    let mut rng = rand::thread_rng();
    let signal: [u8; 32] = rng.gen();

    // We generate a random epoch
    let epoch = hash_to_field(b"test-epoch");
    // We generate a random rln_identifier
    let rln_identifier = hash_to_field(b"test-rln-identifier");

    // We prepare input for generate_rln_proof API
    let mut serialized: Vec<u8> = Vec::new();
    serialized.append(&mut fr_to_bytes_le(&identity_secret_hash));
    serialized.append(&mut normalize_usize(identity_index));
    serialized.append(&mut fr_to_bytes_le(&user_message_limit));
    serialized.append(&mut fr_to_bytes_le(&Fr::from(1)));
    serialized.append(&mut fr_to_bytes_le(&utils_poseidon_hash(&[
        epoch,
        rln_identifier,
    ])));
    serialized.append(&mut normalize_usize(signal.len()));
    serialized.append(&mut signal.to_vec());

    let mut input_buffer = Cursor::new(serialized);
    let mut output_buffer = Cursor::new(Vec::<u8>::new());
    rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
        .unwrap();

    // output_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
    let mut proof_data = output_buffer.into_inner();

    // We prepare input for verify_rln_proof API
    // input_data is  [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var> ]
    // that is [ proof_data || signal_len<8> | signal<var> ]
    proof_data.append(&mut normalize_usize(signal.len()));
    proof_data.append(&mut signal.to_vec());

    let mut input_buffer = Cursor::new(proof_data);
    let verified = rln.verify_rln_proof(&mut input_buffer).unwrap();

    assert!(verified);
}

#[test]
fn test_rln_with_witness() {
    let tree_height = TEST_TREE_HEIGHT;
    let no_of_leaves = 256;

    // We generate a vector of random leaves
    let mut leaves: Vec<Fr> = Vec::new();
    let mut rng = thread_rng();
    for _ in 0..no_of_leaves {
        leaves.push(Fr::rand(&mut rng));
    }

    // We create a new RLN instance
    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    // We add leaves in a batch into the tree
    let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
    rln.init_tree_with_leaves(&mut buffer).unwrap();

    // Generate identity pair
    let (identity_secret_hash, id_commitment) = keygen();

    // We set as leaf rate_commitment after storing its index
    let identity_index = rln.tree.leaves_set();
    let user_message_limit = Fr::from(100);
    let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);
    let mut buffer = Cursor::new(fr_to_bytes_le(&rate_commitment));
    rln.set_next_leaf(&mut buffer).unwrap();

    // We generate a random signal
    let mut rng = rand::thread_rng();
    let signal: [u8; 32] = rng.gen();

    // We generate a random epoch
    let epoch = hash_to_field(b"test-epoch");
    // We generate a random rln_identifier
    let rln_identifier = hash_to_field(b"test-rln-identifier");

    // We prepare input for generate_rln_proof API
    // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
    let mut serialized: Vec<u8> = Vec::new();
    serialized.append(&mut fr_to_bytes_le(&identity_secret_hash));
    serialized.append(&mut normalize_usize(identity_index));
    serialized.append(&mut fr_to_bytes_le(&user_message_limit));
    serialized.append(&mut fr_to_bytes_le(&Fr::from(1)));
    serialized.append(&mut fr_to_bytes_le(&utils_poseidon_hash(&[
        epoch,
        rln_identifier,
    ])));
    serialized.append(&mut normalize_usize(signal.len()));
    serialized.append(&mut signal.to_vec());

    let mut input_buffer = Cursor::new(serialized);

    // We read input RLN witness and we serialize_compressed it
    let mut witness_byte: Vec<u8> = Vec::new();
    input_buffer.read_to_end(&mut witness_byte).unwrap();
    let (rln_witness, _) = proof_inputs_to_rln_witness(&mut rln.tree, &witness_byte).unwrap();

    let serialized_witness = serialize_witness(&rln_witness).unwrap();

    // Calculate witness outside zerokit (simulating what JS is doing)
    let inputs = inputs_for_witness_calculation(&rln_witness)
        .unwrap()
        .into_iter()
        .map(|(name, values)| (name.to_string(), values));
    let calculated_witness = rln
        .witness_calculator
        .lock()
        .expect("witness_calculator mutex should not get poisoned")
        .calculate_witness_element::<Curve, _>(inputs, false)
        .map_err(ProofError::WitnessError)
        .unwrap();

    let calculated_witness_vec: Vec<BigInt> = calculated_witness
        .into_iter()
        .map(|v| to_bigint(&v).unwrap())
        .collect();

    // Generating the proof
    let mut output_buffer = Cursor::new(Vec::<u8>::new());
    rln.generate_rln_proof_with_witness(
        calculated_witness_vec,
        serialized_witness,
        &mut output_buffer,
    )
    .unwrap();

    // output_data is  [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
    let mut proof_data = output_buffer.into_inner();

    // We prepare input for verify_rln_proof API
    // input_data is  [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var> ]
    // that is [ proof_data || signal_len<8> | signal<var> ]
    proof_data.append(&mut normalize_usize(signal.len()));
    proof_data.append(&mut signal.to_vec());

    let mut input_buffer = Cursor::new(proof_data);
    let verified = rln.verify_rln_proof(&mut input_buffer).unwrap();

    assert!(verified);
}

#[test]
fn proof_verification_with_roots() {
    // The first part is similar to test_rln_with_witness
    let tree_height = TEST_TREE_HEIGHT;
    let no_of_leaves = 256;

    // We generate a vector of random leaves
    let mut leaves: Vec<Fr> = Vec::new();
    let mut rng = thread_rng();
    for _ in 0..no_of_leaves {
        leaves.push(Fr::rand(&mut rng));
    }

    // We create a new RLN instance
    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    // We add leaves in a batch into the tree
    let mut buffer = Cursor::new(vec_fr_to_bytes_le(&leaves).unwrap());
    rln.init_tree_with_leaves(&mut buffer).unwrap();

    // Generate identity pair
    let (identity_secret_hash, id_commitment) = keygen();

    // We set as leaf id_commitment after storing its index
    let identity_index = rln.tree.leaves_set();
    let user_message_limit = Fr::from(100);
    let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);
    let mut buffer = Cursor::new(fr_to_bytes_le(&rate_commitment));
    rln.set_next_leaf(&mut buffer).unwrap();

    // We generate a random signal
    let mut rng = thread_rng();
    let signal: [u8; 32] = rng.gen();

    // We generate a random epoch
    let epoch = hash_to_field(b"test-epoch");
    // We generate a random rln_identifier
    let rln_identifier = hash_to_field(b"test-rln-identifier");
    let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);

    // We prepare input for generate_rln_proof API
    // input_data is [ identity_secret<32> | id_index<8> | external_nullifier<32> | user_message_limit<32> | message_id<32> | signal_len<8> | signal<var> ]
    let mut serialized: Vec<u8> = Vec::new();
    serialized.append(&mut fr_to_bytes_le(&identity_secret_hash));
    serialized.append(&mut normalize_usize(identity_index));
    serialized.append(&mut fr_to_bytes_le(&user_message_limit));
    serialized.append(&mut fr_to_bytes_le(&Fr::from(1)));
    serialized.append(&mut fr_to_bytes_le(&external_nullifier));
    serialized.append(&mut normalize_usize(signal.len()));
    serialized.append(&mut signal.to_vec());

    let mut input_buffer = Cursor::new(serialized);
    let mut output_buffer = Cursor::new(Vec::<u8>::new());
    rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
        .unwrap();

    // output_data is  [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
    let mut proof_data = output_buffer.into_inner();

    // We prepare input for verify_rln_proof API
    // input_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var> ]
    // that is [ proof_data || signal_len<8> | signal<var> ]
    proof_data.append(&mut normalize_usize(signal.len()));
    proof_data.append(&mut signal.to_vec());
    let input_buffer = Cursor::new(proof_data);

    // If no roots is provided, proof validation is skipped and if the remaining proof values are valid, the proof will be correctly verified
    let mut roots_serialized: Vec<u8> = Vec::new();
    let mut roots_buffer = Cursor::new(roots_serialized.clone());
    let verified = rln
        .verify_with_roots(&mut input_buffer.clone(), &mut roots_buffer)
        .unwrap();

    assert!(verified);

    // We serialize in the roots buffer some random values and we check that the proof is not verified since doesn't contain the correct root the proof refers to
    for _ in 0..5 {
        roots_serialized.append(&mut fr_to_bytes_le(&Fr::rand(&mut rng)));
    }
    roots_buffer = Cursor::new(roots_serialized.clone());
    let verified = rln
        .verify_with_roots(&mut input_buffer.clone(), &mut roots_buffer)
        .unwrap();

    assert_eq!(verified, false);

    // We get the root of the tree obtained adding one leaf per time
    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_root(&mut buffer).unwrap();
    let (root, _) = bytes_le_to_fr(&buffer.into_inner());

    // We add the real root and we check if now the proof is verified
    roots_serialized.append(&mut fr_to_bytes_le(&root));
    roots_buffer = Cursor::new(roots_serialized.clone());
    let verified = rln
        .verify_with_roots(&mut input_buffer.clone(), &mut roots_buffer)
        .unwrap();

    assert!(verified);
}

#[test]
fn test_recover_id_secret() {
    let tree_height = TEST_TREE_HEIGHT;

    // We create a new RLN instance
    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    // Generate identity pair
    let (identity_secret_hash, id_commitment) = keygen();
    let user_message_limit = Fr::from(100);
    let message_id = Fr::from(0);
    let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);

    // We set as leaf id_commitment after storing its index
    let identity_index = rln.tree.leaves_set();
    let mut buffer = Cursor::new(fr_to_bytes_le(&rate_commitment));
    rln.set_next_leaf(&mut buffer).unwrap();

    // We generate two random signals
    let mut rng = rand::thread_rng();
    let signal1: [u8; 32] = rng.gen();

    let signal2: [u8; 32] = rng.gen();

    // We generate a random epoch
    let epoch = hash_to_field(b"test-epoch");
    // We generate a random rln_identifier
    let rln_identifier = hash_to_field(b"test-rln-identifier");
    let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);

    // We generate two proofs using same epoch but different signals.

    // We prepare input for generate_rln_proof API
    let mut serialized1: Vec<u8> = Vec::new();
    serialized1.append(&mut fr_to_bytes_le(&identity_secret_hash));
    serialized1.append(&mut normalize_usize(identity_index));
    serialized1.append(&mut fr_to_bytes_le(&user_message_limit));
    serialized1.append(&mut fr_to_bytes_le(&message_id));
    serialized1.append(&mut fr_to_bytes_le(&external_nullifier));

    // The first part is the same for both proof input, so we clone
    let mut serialized2 = serialized1.clone();

    // We attach the first signal to the first proof input
    serialized1.append(&mut normalize_usize(signal1.len()));
    serialized1.append(&mut signal1.to_vec());

    // We attach the second signal to the first proof input
    serialized2.append(&mut normalize_usize(signal2.len()));
    serialized2.append(&mut signal2.to_vec());

    // We generate the first proof
    let mut input_buffer = Cursor::new(serialized1);
    let mut output_buffer = Cursor::new(Vec::<u8>::new());
    rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
        .unwrap();
    let proof_data_1 = output_buffer.into_inner();

    // We generate the second proof
    let mut input_buffer = Cursor::new(serialized2);
    let mut output_buffer = Cursor::new(Vec::<u8>::new());
    rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
        .unwrap();
    let proof_data_2 = output_buffer.into_inner();

    let mut input_proof_data_1 = Cursor::new(proof_data_1.clone());
    let mut input_proof_data_2 = Cursor::new(proof_data_2);
    let mut output_buffer = Cursor::new(Vec::<u8>::new());
    rln.recover_id_secret(
        &mut input_proof_data_1,
        &mut input_proof_data_2,
        &mut output_buffer,
    )
    .unwrap();

    let serialized_identity_secret_hash = output_buffer.into_inner();

    // We ensure that a non-empty value is written to output_buffer
    assert!(!serialized_identity_secret_hash.is_empty());

    // We check if the recovered identity secret hash corresponds to the original one
    let (recovered_identity_secret_hash, _) = bytes_le_to_fr(&serialized_identity_secret_hash);
    assert_eq!(recovered_identity_secret_hash, identity_secret_hash);

    // We now test that computing identity_secret_hash is unsuccessful if shares computed from two different identity secret hashes but within same epoch are passed

    // We generate a new identity pair
    let (identity_secret_hash_new, id_commitment_new) = keygen();
    let rate_commitment_new = utils_poseidon_hash(&[id_commitment_new, user_message_limit]);

    // We add it to the tree
    let identity_index_new = rln.tree.leaves_set();
    let mut buffer = Cursor::new(fr_to_bytes_le(&rate_commitment_new));
    rln.set_next_leaf(&mut buffer).unwrap();

    // We generate a random signals
    let signal3: [u8; 32] = rng.gen();

    // We prepare proof input. Note that epoch is the same as before
    let mut serialized3: Vec<u8> = Vec::new();
    serialized3.append(&mut fr_to_bytes_le(&identity_secret_hash_new));
    serialized3.append(&mut normalize_usize(identity_index_new));
    serialized3.append(&mut fr_to_bytes_le(&user_message_limit));
    serialized3.append(&mut fr_to_bytes_le(&message_id));
    serialized3.append(&mut fr_to_bytes_le(&external_nullifier));
    serialized3.append(&mut normalize_usize(signal3.len()));
    serialized3.append(&mut signal3.to_vec());

    // We generate the proof
    let mut input_buffer = Cursor::new(serialized3);
    let mut output_buffer = Cursor::new(Vec::<u8>::new());
    rln.generate_rln_proof(&mut input_buffer, &mut output_buffer)
        .unwrap();
    let proof_data_3 = output_buffer.into_inner();

    // We attempt to recover the secret using share1 (coming from identity_secret_hash) and share3 (coming from identity_secret_hash_new)

    let mut input_proof_data_1 = Cursor::new(proof_data_1.clone());
    let mut input_proof_data_3 = Cursor::new(proof_data_3);
    let mut output_buffer = Cursor::new(Vec::<u8>::new());
    rln.recover_id_secret(
        &mut input_proof_data_1,
        &mut input_proof_data_3,
        &mut output_buffer,
    )
    .unwrap();

    let serialized_identity_secret_hash = output_buffer.into_inner();
    let (recovered_identity_secret_hash_new, _) = bytes_le_to_fr(&serialized_identity_secret_hash);

    // ensure that the recovered secret does not match with either of the
    // used secrets in proof generation
    assert_ne!(recovered_identity_secret_hash_new, identity_secret_hash_new);
}

#[test]
fn test_get_leaf() {
    // We generate a random tree
    let tree_height = 10;
    let mut rng = thread_rng();
    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    // We generate a random leaf
    let leaf = Fr::rand(&mut rng);

    // We generate a random index
    let index = rng.gen_range(0..rln.tree.capacity());

    // We add the leaf to the tree
    let mut buffer = Cursor::new(fr_to_bytes_le(&leaf));
    rln.set_leaf(index, &mut buffer).unwrap();

    // We get the leaf
    let mut output_buffer = Cursor::new(Vec::<u8>::new());
    rln.get_leaf(index, &mut output_buffer).unwrap();

    // We ensure that the leaf is the same as the one we added
    let (received_leaf, _) = bytes_le_to_fr(output_buffer.into_inner().as_ref());
    assert_eq!(received_leaf, leaf);
}

#[test]
fn test_valid_metadata() {
    let tree_height = TEST_TREE_HEIGHT;

    let mut rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    let arbitrary_metadata: &[u8] = b"block_number:200000";
    rln.set_metadata(arbitrary_metadata).unwrap();

    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_metadata(&mut buffer).unwrap();
    let received_metadata = buffer.into_inner();

    assert_eq!(arbitrary_metadata, received_metadata);
}

#[test]
fn test_empty_metadata() {
    let tree_height = TEST_TREE_HEIGHT;

    let rln = RLN::new(tree_height, generate_input_buffer()).unwrap();

    let mut buffer = Cursor::new(Vec::<u8>::new());
    rln.get_metadata(&mut buffer).unwrap();
    let received_metadata = buffer.into_inner();

    assert_eq!(received_metadata.len(), 0);
}
