#[cfg(test)]
mod test {
    use std::str::FromStr;

    use rand::{thread_rng, Rng};
    use rln::prelude::*;
    use serde_json::{json, Value};

    fn fq_from_str(s: &str) -> Fq {
        Fq::from_str(s).unwrap()
    }

    fn g1_from_str(g1: &[String]) -> G1Affine {
        let x = fq_from_str(&g1[0]);
        let y = fq_from_str(&g1[1]);
        let z = fq_from_str(&g1[2]);
        G1Affine::from(G1Projective::new(x, y, z))
    }

    fn g2_from_str(g2: &[Vec<String>]) -> G2Affine {
        let c0 = fq_from_str(&g2[0][0]);
        let c1 = fq_from_str(&g2[0][1]);
        let x = Fq2::new(c0, c1);

        let c0 = fq_from_str(&g2[1][0]);
        let c1 = fq_from_str(&g2[1][1]);
        let y = Fq2::new(c0, c1);

        let c0 = fq_from_str(&g2[2][0]);
        let c1 = fq_from_str(&g2[2][1]);
        let z = Fq2::new(c0, c1);

        G2Affine::from(G2Projective::new(x, y, z))
    }

    fn value_to_string_vec(value: &Value) -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|val| val.as_str().unwrap().to_string())
            .collect()
    }

    fn new_single_message_witness(
        identity_secret: IdSecret,
        user_message_limit: Fr,
        message_id: Fr,
        path_elements: Vec<Fr>,
        identity_path_index: Vec<u8>,
        x: Fr,
        external_nullifier: Fr,
    ) -> Result<RLNWitnessInput, ProtocolError> {
        #[cfg(not(feature = "multi-message-id"))]
        {
            RLNWitnessInput::new(
                identity_secret,
                user_message_limit,
                message_id,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
            )
        }
        #[cfg(feature = "multi-message-id")]
        {
            RLNWitnessInput::new(
                identity_secret,
                user_message_limit,
                Some(message_id),
                None,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
                None,
            )
        }
    }

    fn random_rln_witness(tree_depth: usize) -> Result<RLNWitnessInput, ProtocolError> {
        let mut rng = thread_rng();

        let identity_secret = IdSecret::rand(&mut rng);
        let x = hash_to_field_le(&rng.gen::<[u8; 32]>()).unwrap();
        let epoch = hash_to_field_le(&rng.gen::<[u8; 32]>()).unwrap();
        let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();

        let mut path_elements: Vec<Fr> = Vec::new();
        let mut identity_path_index: Vec<u8> = Vec::new();

        for _ in 0..tree_depth {
            path_elements.push(hash_to_field_le(&rng.gen::<[u8; 32]>()).unwrap());
            identity_path_index.push(rng.gen_range(0..2) as u8);
        }

        let user_message_limit = Fr::from(100);
        let message_id = Fr::from(1);
        let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();

        new_single_message_witness(
            identity_secret,
            user_message_limit,
            message_id,
            path_elements,
            identity_path_index,
            x,
            external_nullifier,
        )
    }

    #[test]
    fn test_groth16_proof_hardcoded() {
        #[cfg(not(feature = "stateless"))]
        let rln = RLN::new(DEFAULT_TREE_DEPTH, "").unwrap();
        #[cfg(feature = "stateless")]
        let rln = RLN::new().unwrap();

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
        let valid_ark_proof = Proof {
            a: g1_from_str(&value_to_string_vec(&valid_snarkjs_proof["pi_a"])),
            b: g2_from_str(
                &valid_snarkjs_proof["pi_b"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(value_to_string_vec)
                    .collect::<Vec<Vec<String>>>(),
            ),
            c: g1_from_str(&value_to_string_vec(&valid_snarkjs_proof["pi_c"])),
        };

        let x = str_to_fr(
            "20645213238265527935869146898028115621427162613172918400241870500502509785943",
            10,
        )
        .unwrap();

        let valid_proof_values = RLNProofValues {
            x,
            external_nullifier: str_to_fr(
                "21074405743803627666274838159589343934394162804826017440941339048886754734203",
                10,
            )
            .unwrap(),
            #[cfg(not(feature = "multi-message-id"))]
            y: str_to_fr(
                "16401008481486069296141645075505218976370369489687327284155463920202585288271",
                10,
            )
            .unwrap(),
            #[cfg(feature = "multi-message-id")]
            y: Some(
                str_to_fr(
                    "16401008481486069296141645075505218976370369489687327284155463920202585288271",
                    10,
                )
                .unwrap(),
            ),
            #[cfg(feature = "multi-message-id")]
            ys: None,
            root: str_to_fr(
                "8502402278351299594663821509741133196466235670407051417832304486953898514733",
                10,
            )
            .unwrap(),
            #[cfg(not(feature = "multi-message-id"))]
            nullifier: str_to_fr(
                "9102791780887227194595604713537772536258726662792598131262022534710887343694",
                10,
            )
            .unwrap(),
            #[cfg(feature = "multi-message-id")]
            nullifier: Some(
                str_to_fr(
                    "9102791780887227194595604713537772536258726662792598131262022534710887343694",
                    10,
                )
                .unwrap(),
            ),
            #[cfg(feature = "multi-message-id")]
            nullifiers: None,
            #[cfg(feature = "multi-message-id")]
            selector_used: None,
        };

        let verified = rln
            .verify_with_roots(&valid_ark_proof, &valid_proof_values, &x, &[])
            .is_ok();

        assert!(verified);
    }

    #[test]
    fn test_groth16_proof() {
        let tree_depth = DEFAULT_TREE_DEPTH;

        #[cfg(not(feature = "stateless"))]
        let rln = RLN::new(tree_depth, "").unwrap();
        #[cfg(feature = "stateless")]
        let rln = RLN::new().unwrap();

        // Note: we only test Groth16 proof generation, so we ignore setting the tree in the RLN object
        let rln_witness = random_rln_witness(tree_depth).unwrap();

        // We compute a Groth16 proof and proof values
        let (proof, proof_values) = rln.generate_rln_proof(&rln_witness).unwrap();

        // We verify the Groth16 proof against the provided proof values
        let verified = rln.verify_zk_proof(&proof, &proof_values).is_ok();

        assert!(verified);
    }

    #[test]
    fn test_initialization_with_params() {
        let zkey_data = include_bytes!("../resources/tree_depth_20/rln_final.arkzkey").to_vec();
        let graph_data = include_bytes!("../resources/tree_depth_20/graph.bin").to_vec();

        #[cfg(all(not(target_arch = "wasm32"), not(feature = "stateless")))]
        assert!(RLN::new_with_params(DEFAULT_TREE_DEPTH, zkey_data, graph_data, "").is_ok());

        #[cfg(all(not(target_arch = "wasm32"), feature = "stateless"))]
        assert!(RLN::new_with_params(zkey_data, graph_data).is_ok());
    }

    #[cfg(not(feature = "stateless"))]
    mod tree_test {
        use ark_std::{rand::thread_rng, UniformRand};
        use rand::{rngs::ThreadRng, Rng};
        use rln::prelude::*;
        use serde_json::json;

        use super::new_single_message_witness;

        const NO_OF_LEAVES: usize = 256;

        fn setup_rln_proof(
            mutate_path_elements: bool,
        ) -> (RLN, Proof, RLNProofValues, Fr, ThreadRng) {
            let tree_depth = DEFAULT_TREE_DEPTH;

            let mut leaves: Vec<Fr> = Vec::new();
            let mut rng = thread_rng();
            for _ in 0..NO_OF_LEAVES {
                leaves.push(Fr::rand(&mut rng));
            }

            let mut rln = RLN::new(tree_depth, "").unwrap();
            rln.init_tree_with_leaves(leaves.clone()).unwrap();

            let (identity_secret, id_commitment) = keygen().unwrap();
            let identity_index = rln.leaves_set();
            let user_message_limit = Fr::from(100);
            let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();
            rln.set_next_leaf(rate_commitment).unwrap();

            let signal: [u8; 32] = rng.gen();
            let epoch = hash_to_field_le(b"test-epoch").unwrap();
            let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
            let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();
            let message_id = Fr::from(1);
            let x = hash_to_field_le(&signal).unwrap();

            let (mut path_elements, identity_path_index) =
                rln.get_merkle_proof(identity_index).unwrap();

            // Mutate path_elements if requested (simulating mutated path_element)
            if mutate_path_elements && !path_elements.is_empty() {
                path_elements[0] = Fr::rand(&mut rng);
            }

            let rln_witness = new_single_message_witness(
                identity_secret,
                user_message_limit,
                message_id,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
            )
            .unwrap();

            let (proof, proof_values) = rln.generate_rln_proof(&rln_witness).unwrap();

            (rln, proof, proof_values, x, rng)
        }

        #[test]
        // We test merkle batch Merkle tree additions
        fn test_merkle_operations() {
            let tree_depth = DEFAULT_TREE_DEPTH;

            // We generate a vector of random leaves
            let mut leaves: Vec<Fr> = Vec::new();
            let mut rng = thread_rng();
            for _ in 0..NO_OF_LEAVES {
                leaves.push(Fr::rand(&mut rng));
            }

            // We create a new tree
            let mut rln = RLN::new(tree_depth, "").unwrap();

            // We first add leaves one by one specifying the index
            for (i, leaf) in leaves.iter().enumerate() {
                // We check if the number of leaves set is consistent
                assert_eq!(rln.leaves_set(), i);

                rln.set_leaf(i, *leaf).unwrap();
            }

            // We get the root of the tree obtained adding one leaf per time
            let root_single = rln.get_root();

            // We reset the tree to default
            rln.set_tree(tree_depth).unwrap();

            // We add leaves one by one using the internal index (new leaves goes in next available position)
            for leaf in &leaves {
                rln.set_next_leaf(*leaf).unwrap();
            }

            // We check if numbers of leaves set is consistent
            assert_eq!(rln.leaves_set(), NO_OF_LEAVES);

            // We get the root of the tree obtained adding leaves using the internal index
            let root_next = rln.get_root();

            // We check if roots are the same
            assert_eq!(root_single, root_next);

            // We reset the tree to default
            rln.set_tree(tree_depth).unwrap();

            // We add leaves in a batch into the tree
            rln.init_tree_with_leaves(leaves.clone()).unwrap();

            // We check if number of leaves set is consistent
            assert_eq!(rln.leaves_set(), NO_OF_LEAVES);

            // We get the root of the tree obtained adding leaves in batch
            let root_batch = rln.get_root();

            // We check if roots are the same
            assert_eq!(root_single, root_batch);

            // We now delete all leaves set and check if the root corresponds to the empty tree root
            // delete calls over indexes higher than no_of_leaves are ignored and will not increase self.tree.next_index
            for i in 0..NO_OF_LEAVES {
                rln.delete_leaf(i).unwrap();
            }

            // We check if number of leaves set is consistent
            assert_eq!(rln.leaves_set(), NO_OF_LEAVES);

            // We get the root of the tree obtained deleting all leaves
            let root_delete = rln.get_root();

            // We reset the tree to default
            rln.set_tree(tree_depth).unwrap();

            // We get the root of the empty tree
            let root_empty = rln.get_root();

            // We check if roots are the same
            assert_eq!(root_delete, root_empty);
        }

        #[test]
        // This test is similar to the one in ffi.rs but it uses the RLN object directly
        // Uses `set_leaves_from` to set leaves in a batch
        fn test_leaf_setting_with_index() {
            let tree_depth = DEFAULT_TREE_DEPTH;

            // We generate a vector of random leaves
            let mut leaves: Vec<Fr> = Vec::new();
            let mut rng = thread_rng();
            for _ in 0..NO_OF_LEAVES {
                leaves.push(Fr::rand(&mut rng));
            }

            // set_index is the index from which we start setting leaves
            // random number between 0..no_of_leaves
            let set_index = rng.gen_range(0..NO_OF_LEAVES) as usize;

            // We create a new tree
            let mut rln = RLN::new(tree_depth, "").unwrap();

            // We add leaves in a batch into the tree
            rln.init_tree_with_leaves(leaves.clone()).unwrap();

            // We check if number of leaves set is consistent
            assert_eq!(rln.leaves_set(), NO_OF_LEAVES);

            // We get the root of the tree obtained adding leaves in batch
            let root_batch_with_init = rln.get_root();

            // `init_tree_with_leaves` resets the tree to the depth it was initialized with, using `set_tree`

            // We add leaves in a batch starting from index 0..set_index
            rln.init_tree_with_leaves(leaves[0..set_index].to_vec())
                .unwrap();

            // We add the remaining n leaves in a batch starting from index set_index
            rln.set_leaves_from(set_index, leaves[set_index..].to_vec())
                .unwrap();

            // We check if number of leaves set is consistent
            assert_eq!(rln.leaves_set(), NO_OF_LEAVES);

            // We get the root of the tree obtained adding leaves in batch
            let root_batch_with_custom_index = rln.get_root();

            assert_eq!(root_batch_with_init, root_batch_with_custom_index);

            // We reset the tree to default
            rln.set_tree(tree_depth).unwrap();

            // We add leaves one by one using the internal index (new leaves goes in next available position)
            for leaf in &leaves {
                rln.set_next_leaf(*leaf).unwrap();
            }

            // We check if numbers of leaves set is consistent
            assert_eq!(rln.leaves_set(), NO_OF_LEAVES);

            // We get the root of the tree obtained adding leaves using the internal index
            let root_single_additions = rln.get_root();

            assert_eq!(root_batch_with_init, root_single_additions);

            rln.flush().unwrap();
        }

        #[test]
        // This test is similar to the one in ffi.rs but it uses the RLN object directly
        // Tests the atomic_operation fn, which set_leaves_from uses internally
        fn test_atomic_operation() {
            let tree_depth = DEFAULT_TREE_DEPTH;

            // We generate a vector of random leaves
            let mut leaves: Vec<Fr> = Vec::new();
            let mut rng = thread_rng();
            for _ in 0..NO_OF_LEAVES {
                leaves.push(Fr::rand(&mut rng));
            }

            // We create a new tree
            let mut rln = RLN::new(tree_depth, "").unwrap();

            // We add leaves in a batch into the tree
            rln.init_tree_with_leaves(leaves.clone()).unwrap();

            // We check if number of leaves set is consistent
            assert_eq!(rln.leaves_set(), NO_OF_LEAVES);

            // We get the root of the tree obtained adding leaves in batch
            let root_after_insertion = rln.get_root();

            // We check if number of leaves set is consistent
            assert_eq!(rln.leaves_set(), NO_OF_LEAVES);

            let last_leaf = *leaves.last().unwrap();
            let last_leaf_index = NO_OF_LEAVES - 1;
            let indices = vec![last_leaf_index];
            let last_leaf_vec = vec![last_leaf];

            rln.atomic_operation(last_leaf_index, last_leaf_vec, indices)
                .unwrap();

            // We get the root of the tree obtained after a no-op
            let root_after_noop = rln.get_root();

            assert_eq!(root_after_insertion, root_after_noop);
        }

        #[test]
        fn test_atomic_operation_zero_indexed() {
            // Test duplicated from https://github.com/waku-org/go-zerokit-rln/pull/12/files
            let tree_depth = DEFAULT_TREE_DEPTH;

            // We generate a vector of random leaves
            let mut leaves: Vec<Fr> = Vec::new();
            let mut rng = thread_rng();
            for _ in 0..NO_OF_LEAVES {
                leaves.push(Fr::rand(&mut rng));
            }

            // We create a new tree
            let mut rln = RLN::new(tree_depth, "").unwrap();

            // We add leaves in a batch into the tree
            rln.init_tree_with_leaves(leaves.clone()).unwrap();

            // We check if number of leaves set is consistent
            assert_eq!(rln.leaves_set(), NO_OF_LEAVES);

            // We get the root of the tree obtained adding leaves in batch
            let root_after_insertion = rln.get_root();

            let zero_index = 0;
            let indices = vec![zero_index];
            let zero_leaf: Vec<Fr> = vec![];
            rln.atomic_operation(0, zero_leaf, indices).unwrap();

            // We get the root of the tree obtained after a deletion
            let root_after_deletion = rln.get_root();

            assert_ne!(root_after_insertion, root_after_deletion);
        }

        #[test]
        fn test_atomic_operation_consistency() {
            // Test duplicated from https://github.com/waku-org/go-zerokit-rln/pull/12/files
            let tree_depth = DEFAULT_TREE_DEPTH;

            // We generate a vector of random leaves
            let mut leaves: Vec<Fr> = Vec::new();
            let mut rng = thread_rng();
            for _ in 0..NO_OF_LEAVES {
                leaves.push(Fr::rand(&mut rng));
            }

            // We create a new tree
            let mut rln = RLN::new(tree_depth, "").unwrap();

            // We add leaves in a batch into the tree
            rln.init_tree_with_leaves(leaves.clone()).unwrap();

            // We check if number of leaves set is consistent
            assert_eq!(rln.leaves_set(), NO_OF_LEAVES);

            // We get the root of the tree obtained adding leaves in batch
            let root_after_insertion = rln.get_root();

            let set_index = rng.gen_range(0..NO_OF_LEAVES) as usize;
            let indices = vec![set_index];
            let zero_leaf: Vec<Fr> = vec![];
            rln.atomic_operation(0, zero_leaf, indices).unwrap();

            // We get the root of the tree obtained after a deletion
            let root_after_deletion = rln.get_root();

            assert_ne!(root_after_insertion, root_after_deletion);

            // We get the leaf
            let received_leaf = rln.get_leaf(set_index).unwrap();

            assert_eq!(received_leaf, Fr::from(0));
        }

        #[test]
        // This test is similar to the one in ffi.rs but it uses the RLN object directly
        // This test checks if `set_leaves_from` throws an error when the index is out of bounds
        fn test_set_leaves_bad_index() {
            let tree_depth = DEFAULT_TREE_DEPTH;

            // We generate a vector of random leaves
            let mut leaves: Vec<Fr> = Vec::new();
            let mut rng = thread_rng();
            for _ in 0..NO_OF_LEAVES {
                leaves.push(Fr::rand(&mut rng));
            }
            let bad_index = (1 << tree_depth) - rng.gen_range(0..NO_OF_LEAVES) as usize;

            // We create a new tree
            let mut rln = RLN::new(tree_depth, "").unwrap();

            // Get root of empty tree
            let root_empty = rln.get_root();

            // We add leaves in a batch into the tree
            assert!(rln.set_leaves_from(bad_index, leaves).is_err());

            // We check if number of leaves set is consistent
            assert_eq!(rln.leaves_set(), 0);

            // Get root of tree after attempted set
            let root_after_bad_set = rln.get_root();

            assert_eq!(root_empty, root_after_bad_set);
        }

        #[test]
        fn test_get_leaf() {
            // We generate a random tree
            let tree_depth = 10;
            let mut rng = thread_rng();
            let mut rln = RLN::new(tree_depth, "").unwrap();

            // We generate a random leaf
            let leaf = Fr::rand(&mut rng);

            // We generate a random index
            let index = rng.gen_range(0..(1 << tree_depth));

            // We add the leaf to the tree
            rln.set_leaf(index, leaf).unwrap();

            // We get the leaf
            let received_leaf = rln.get_leaf(index).unwrap();

            // We ensure that the leaf is the same as the one we added
            assert_eq!(received_leaf, leaf);
        }

        #[test]
        fn test_valid_metadata() {
            let tree_depth = DEFAULT_TREE_DEPTH;

            let mut rln = RLN::new(tree_depth, "").unwrap();

            let arbitrary_metadata: &[u8] = b"block_number:200000";
            rln.set_metadata(arbitrary_metadata).unwrap();

            let received_metadata = rln.get_metadata().unwrap();

            assert_eq!(arbitrary_metadata, received_metadata);
        }

        #[test]
        fn test_empty_metadata() {
            let tree_depth = DEFAULT_TREE_DEPTH;

            let rln = RLN::new(tree_depth, "").unwrap();

            let received_metadata = rln.get_metadata().unwrap();

            assert_eq!(received_metadata.len(), 0);
        }

        #[test]
        fn test_rln_proof() {
            let tree_depth = DEFAULT_TREE_DEPTH;

            // We generate a vector of random leaves
            let mut leaves: Vec<Fr> = Vec::new();
            let mut rng = thread_rng();
            for _ in 0..NO_OF_LEAVES {
                let id_commitment = Fr::rand(&mut rng);
                let rate_commitment = poseidon_hash(&[id_commitment, Fr::from(100)]).unwrap();
                leaves.push(rate_commitment);
            }

            // We create a new RLN instance
            let mut rln = RLN::new(tree_depth, "").unwrap();

            // We add leaves in a batch into the tree
            rln.init_tree_with_leaves(leaves.clone()).unwrap();

            // Generate identity pair
            let (identity_secret, id_commitment) = keygen().unwrap();

            // We set as leaf rate_commitment after storing its index
            let identity_index = rln.leaves_set();
            let user_message_limit = Fr::from(65535);
            let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();
            rln.set_next_leaf(rate_commitment).unwrap();

            // We generate a random signal
            let mut rng = rand::thread_rng();
            let signal: [u8; 32] = rng.gen();

            // We generate a random epoch
            let epoch = hash_to_field_le(b"test-epoch").unwrap();
            // We generate a random rln_identifier
            let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
            // We generate a external nullifier
            let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();
            // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
            let message_id = Fr::from(1);

            // Hash the signal to get x
            let x = hash_to_field_le(&signal).unwrap();

            // Get merkle proof for the identity
            let (path_elements, identity_path_index) =
                rln.get_merkle_proof(identity_index).unwrap();

            // Create RLN witness
            let rln_witness = new_single_message_witness(
                identity_secret,
                user_message_limit,
                message_id,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
            )
            .unwrap();

            // Generate proof
            let (proof, proof_values) = rln.generate_rln_proof(&rln_witness).unwrap();

            // Verify proof
            let verified = rln.verify_rln_proof(&proof, &proof_values, &x).is_ok();

            assert!(verified);
        }

        #[test]
        fn test_rln_with_witness() {
            let tree_depth = DEFAULT_TREE_DEPTH;

            // We generate a vector of random leaves
            let mut leaves: Vec<Fr> = Vec::new();
            let mut rng = thread_rng();
            for _ in 0..NO_OF_LEAVES {
                leaves.push(Fr::rand(&mut rng));
            }

            // We create a new RLN instance
            let mut rln = RLN::new(tree_depth, "").unwrap();

            // We add leaves in a batch into the tree
            rln.init_tree_with_leaves(leaves.clone()).unwrap();

            // Generate identity pair
            let (identity_secret, id_commitment) = keygen().unwrap();

            // We set as leaf rate_commitment after storing its index
            let identity_index = rln.leaves_set();
            let user_message_limit = Fr::from(100);
            let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();
            rln.set_next_leaf(rate_commitment).unwrap();

            // We generate a random signal
            let mut rng = rand::thread_rng();
            let signal: [u8; 32] = rng.gen();

            // We generate a random epoch
            let epoch = hash_to_field_le(b"test-epoch").unwrap();
            // We generate a random rln_identifier
            let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
            // We generate a external nullifier
            let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();
            // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
            let message_id = Fr::from(1);

            // Hash the signal to get x
            let x = hash_to_field_le(&signal).unwrap();

            // Get merkle proof for the identity
            let (path_elements, identity_path_index) =
                rln.get_merkle_proof(identity_index).unwrap();

            // Create RLN witness
            let rln_witness = new_single_message_witness(
                identity_secret,
                user_message_limit,
                message_id,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
            )
            .unwrap();

            // Generate proof using witness
            let (proof, proof_values) = rln.generate_rln_proof(&rln_witness).unwrap();

            // Verify proof
            let verified = rln.verify_rln_proof(&proof, &proof_values, &x).is_ok();

            assert!(verified);
        }

        #[test]
        fn proof_verification_with_roots() {
            // The first part is similar to test_rln_with_witness
            let tree_depth = DEFAULT_TREE_DEPTH;

            // We generate a vector of random leaves
            let mut leaves: Vec<Fr> = Vec::new();
            let mut rng = thread_rng();
            for _ in 0..NO_OF_LEAVES {
                leaves.push(Fr::rand(&mut rng));
            }

            // We create a new RLN instance
            let mut rln = RLN::new(tree_depth, "").unwrap();

            // We add leaves in a batch into the tree
            rln.init_tree_with_leaves(leaves.clone()).unwrap();

            // Generate identity pair
            let (identity_secret, id_commitment) = keygen().unwrap();

            // We set as leaf rate_commitment after storing its index
            let identity_index = rln.leaves_set();
            let user_message_limit = Fr::from(100);
            let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();
            rln.set_next_leaf(rate_commitment).unwrap();

            // We generate a random signal
            let mut rng = thread_rng();
            let signal: [u8; 32] = rng.gen();

            // We generate a random epoch
            let epoch = hash_to_field_le(b"test-epoch").unwrap();
            // We generate a random rln_identifier
            let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
            // We generate a external nullifier
            let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();
            // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
            let message_id = Fr::from(1);

            // Hash the signal to get x
            let x = hash_to_field_le(&signal).unwrap();

            // Get merkle proof for the identity
            let (path_elements, identity_path_index) =
                rln.get_merkle_proof(identity_index).unwrap();

            // Create RLN witness
            let rln_witness = new_single_message_witness(
                identity_secret,
                user_message_limit,
                message_id,
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
            )
            .unwrap();

            // Generate proof
            let (proof, proof_values) = rln.generate_rln_proof(&rln_witness).unwrap();

            // If no roots is provided, proof validation is skipped and if the remaining proof values are valid, the proof will be correctly verified
            let empty_roots: Vec<Fr> = vec![];
            let verified = rln
                .verify_with_roots(&proof, &proof_values, &x, &empty_roots)
                .is_ok();

            assert!(verified);

            // We serialize random roots and check that the proof is not verified since it doesn't contain the correct root
            let mut random_roots: Vec<Fr> = Vec::new();
            for _ in 0..5 {
                random_roots.push(Fr::rand(&mut rng));
            }
            let verified = rln
                .verify_with_roots(&proof, &proof_values, &x, &random_roots)
                .is_ok();

            assert!(!verified);

            // We get the root of the tree
            let root = rln.get_root();

            // We add the real root and we check if now the proof is verified
            random_roots.push(root);
            let verified = rln
                .verify_with_roots(&proof, &proof_values, &x, &random_roots)
                .is_ok();

            assert!(verified);
        }

        #[test]
        fn test_recover_id_secret() {
            let tree_depth = DEFAULT_TREE_DEPTH;

            // We create a new RLN instance
            let mut rln = RLN::new(tree_depth, "").unwrap();

            // Generate identity pair
            let (identity_secret, id_commitment) = keygen().unwrap();
            let user_message_limit = Fr::from(100);
            let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();

            // We set as leaf rate_commitment, its index would be equal to 0 since tree is empty
            let identity_index = rln.leaves_set();
            rln.set_next_leaf(rate_commitment).unwrap();

            // We generate two proofs using same epoch but different signals.

            // We generate two random signals
            let mut rng = rand::thread_rng();
            let signal1: [u8; 32] = rng.gen();
            let signal2: [u8; 32] = rng.gen();

            // We generate a random epoch
            let epoch = hash_to_field_le(b"test-epoch").unwrap();
            // We generate a random rln_identifier
            let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
            // We generate a external nullifier
            let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();
            // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
            let message_id = Fr::from(1);

            // Hash the signals to get x values
            let x1 = hash_to_field_le(&signal1).unwrap();
            let x2 = hash_to_field_le(&signal2).unwrap();

            // Get merkle proof for the identity
            let (path_elements, identity_path_index) =
                rln.get_merkle_proof(identity_index).unwrap();

            // Create RLN witnesses for both signals
            let rln_witness1 = new_single_message_witness(
                identity_secret.clone(),
                user_message_limit,
                message_id,
                path_elements.clone(),
                identity_path_index.clone(),
                x1,
                external_nullifier,
            )
            .unwrap();

            let rln_witness2 = new_single_message_witness(
                identity_secret.clone(),
                user_message_limit,
                message_id,
                path_elements.clone(),
                identity_path_index.clone(),
                x2,
                external_nullifier,
            )
            .unwrap();

            // Generate the first proof
            let (_proof1, proof_values_1) = rln.generate_rln_proof(&rln_witness1).unwrap();

            // Generate the second proof
            let (_proof2, proof_values_2) = rln.generate_rln_proof(&rln_witness2).unwrap();

            // Recover identity secret from two proof values
            let recovered_identity_secret =
                recover_id_secret(&proof_values_1, &proof_values_2).unwrap();

            // We check if the recovered identity secret corresponds to the original one
            assert_eq!(*recovered_identity_secret, *identity_secret);

            // We now test that computing identity_secret is unsuccessful if shares computed from two different identity secret but within same epoch are passed

            // We generate a new identity pair
            let (identity_secret_new, id_commitment_new) = keygen().unwrap();
            let rate_commitment_new =
                poseidon_hash(&[id_commitment_new, user_message_limit]).unwrap();

            // We add it to the tree
            let identity_index_new = rln.leaves_set();
            rln.set_next_leaf(rate_commitment_new).unwrap();

            // We generate a random signal
            let signal3: [u8; 32] = rng.gen();
            let x3 = hash_to_field_le(&signal3).unwrap();

            // Get merkle proof for the new identity
            let (path_elements_new, identity_path_index_new) =
                rln.get_merkle_proof(identity_index_new).unwrap();

            // We prepare proof input. Note that epoch is the same as before
            let rln_witness3 = new_single_message_witness(
                identity_secret.clone(),
                user_message_limit,
                message_id,
                path_elements_new,
                identity_path_index_new,
                x3,
                external_nullifier,
            )
            .unwrap();

            // We generate the proof
            let (_proof3, proof_values_3) = rln.generate_rln_proof(&rln_witness3).unwrap();

            // We attempt to recover the secret using share1 (coming from identity_secret) and share3 (coming from identity_secret_new)
            let recovered_identity_secret_new =
                recover_id_secret(&proof_values_1, &proof_values_3).unwrap();

            // ensure that the recovered secret does not match with either of the
            // used secrets in proof generation
            assert_ne!(*recovered_identity_secret_new, *identity_secret_new);
        }

        #[test]
        fn test_tree_config_input_trait() {
            let empty_json_input = "";
            let rln_with_empty_json_config = RLN::new(DEFAULT_TREE_DEPTH, empty_json_input);
            assert!(rln_with_empty_json_config.is_ok());

            let json_config = json!({
                "tree_config": {
                    "path": "/tmp/pmtree-test-path",
                    "temporary": false,
                    "cache_capacity": 1073741824,
                    "flush_every_ms": 500,
                    "mode": "HighThroughput",
                    "use_compression": false
                }
            });
            let json_input = json_config.to_string();
            let rln_with_json_config = RLN::new(DEFAULT_TREE_DEPTH, json_input.as_str());
            assert!(rln_with_json_config.is_ok());

            let default_pmtree_config = PmtreeConfig::default();
            let rln_with_default_tree_config = RLN::new(DEFAULT_TREE_DEPTH, default_pmtree_config);
            assert!(rln_with_default_tree_config.is_ok());

            let custom_pmtree_config = PmtreeConfig::builder()
                .temporary(true)
                .use_compression(false)
                .build();
            let rln_with_custom_tree_config =
                RLN::new(DEFAULT_TREE_DEPTH, custom_pmtree_config.unwrap());
            assert!(rln_with_custom_tree_config.is_ok());
        }

        #[test]
        fn test_verify_rln_proof_failure_mutated_external_nullifier() {
            let (rln, proof, mut proof_values, x, _rng) = setup_rln_proof(false);

            // Mutate external_nullifier by adding 1
            proof_values.external_nullifier += Fr::from(1);

            // Verification should fail
            let verified = rln.verify_rln_proof(&proof, &proof_values, &x).is_ok();
            assert!(!verified);
        }

        #[test]
        fn test_verify_rln_proof_failure_mutated_x() {
            let (rln, proof, proof_values, _, mut rng) = setup_rln_proof(false);

            // Generate unrelated x
            let mutated_x = Fr::rand(&mut rng);

            // Verification should fail
            let verified = rln
                .verify_rln_proof(&proof, &proof_values, &mutated_x)
                .is_ok();
            assert!(!verified);
        }

        #[test]
        fn test_verify_rln_proof_failure_mutated_nullifier() {
            let (rln, proof, mut proof_values, x, mut rng) = setup_rln_proof(false);

            // Mutate nullifier (simulating mutated message_id)
            #[cfg(not(feature = "multi-message-id"))]
            {
                proof_values.nullifier = Fr::rand(&mut rng);
            }
            #[cfg(feature = "multi-message-id")]
            {
                proof_values.nullifier = Some(Fr::rand(&mut rng));
            }

            // Verification should fail
            let verified = rln.verify_rln_proof(&proof, &proof_values, &x).is_ok();
            assert!(!verified);
        }

        #[test]
        fn test_verify_rln_proof_failure_mutated_root() {
            let (rln, proof, mut proof_values, x, mut rng) = setup_rln_proof(false);

            // Mutate root (simulating mutated path_element)
            proof_values.root = Fr::rand(&mut rng);

            // Verification should fail
            let verified = rln.verify_rln_proof(&proof, &proof_values, &x).is_ok();
            assert!(!verified);
        }

        #[test]
        fn test_verify_with_roots_failure_mutated_external_nullifier() {
            let (rln, proof, mut proof_values, x, _rng) = setup_rln_proof(false);
            let roots = vec![rln.get_root()];

            // Mutate external_nullifier by adding 1
            proof_values.external_nullifier += Fr::from(1);

            // Verification should fail
            let verified = rln
                .verify_with_roots(&proof, &proof_values, &x, &roots)
                .is_ok();
            assert!(!verified);
        }

        #[test]
        fn test_verify_with_roots_failure_mutated_x() {
            let (rln, proof, proof_values, _, mut rng) = setup_rln_proof(false);
            let roots = vec![rln.get_root()];

            // Mutate x
            let mutated_x = Fr::rand(&mut rng);

            // Verification should fail
            let verified = rln
                .verify_with_roots(&proof, &proof_values, &mutated_x, &roots)
                .is_ok();
            assert!(!verified);
        }

        #[test]
        fn test_verify_with_roots_failure_mutated_nullifier() {
            let (rln, proof, mut proof_values, x, mut rng) = setup_rln_proof(false);
            let roots = vec![rln.get_root()];

            // Mutate nullifier (simulating mutated message_id)
            #[cfg(not(feature = "multi-message-id"))]
            {
                proof_values.nullifier = Fr::rand(&mut rng);
            }
            #[cfg(feature = "multi-message-id")]
            {
                proof_values.nullifier = Some(Fr::rand(&mut rng));
            }

            // Verification should fail
            let verified = rln
                .verify_with_roots(&proof, &proof_values, &x, &roots)
                .is_ok();
            assert!(!verified);
        }
        #[test]
        fn test_verify_with_roots_failure_mutated_root() {
            let (rln, proof, proof_values, x, _rng) = setup_rln_proof(true);
            let roots = vec![rln.get_root()];

            // Verification should fail due to mutated path_elements leading to wrong root
            let verified = rln
                .verify_with_roots(&proof, &proof_values, &x, &roots)
                .is_ok();

            assert!(!verified);
        }

        #[test]
        fn test_verify_rln_proof_failure_mutated_proof_a() {
            let (rln, proof, proof_values, x, _rng) = setup_rln_proof(false);

            // Mutate proof.a by changing its x coordinate
            let mut mutated_proof = proof.clone();
            mutated_proof.a.x += Fq::from(1);

            // Verification should fail
            let verified = rln
                .verify_rln_proof(&mutated_proof, &proof_values, &x)
                .is_ok();
            assert!(!verified);
        }

        #[test]
        fn test_verify_rln_proof_failure_mutated_proof_b() {
            let (rln, proof, proof_values, x, _rng) = setup_rln_proof(false);

            // Mutate proof.b by changing its x.c0 coordinate
            let mut mutated_proof = proof.clone();
            mutated_proof.b.x.c0 += Fq::from(1);

            // Verification should fail
            let verified = rln
                .verify_rln_proof(&mutated_proof, &proof_values, &x)
                .is_ok();
            assert!(!verified);
        }

        #[test]
        fn test_verify_rln_proof_failure_mutated_proof_c() {
            let (rln, proof, proof_values, x, _rng) = setup_rln_proof(false);

            // Mutate proof.c by changing its x coordinate
            let mut mutated_proof = proof.clone();
            mutated_proof.c.x += Fq::from(1);

            // Verification should fail
            let verified = rln
                .verify_rln_proof(&mutated_proof, &proof_values, &x)
                .is_ok();
            assert!(!verified);
        }
    }

    #[cfg(feature = "stateless")]
    mod stateless_test {
        use ark_std::{rand::thread_rng, UniformRand};
        use rand::Rng;
        use rln::prelude::*;
        use zerokit_utils::merkle_tree::{
            OptimalMerkleTree, ZerokitMerkleProof, ZerokitMerkleTree,
        };

        use super::DEFAULT_TREE_DEPTH;
        use crate::test::{new_single_message_witness, random_rln_witness};

        type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

        #[test]
        fn test_stateless_rln_proof() {
            // We create a new RLN instance
            let rln = RLN::new().unwrap();

            let default_leaf = Fr::from(0);
            let mut tree: OptimalMerkleTree<PoseidonHash> = OptimalMerkleTree::new(
                DEFAULT_TREE_DEPTH,
                default_leaf,
                ConfigOf::<OptimalMerkleTree<PoseidonHash>>::default(),
            )
            .unwrap();

            // Generate identity pair
            let (identity_secret, id_commitment) = keygen().unwrap();

            // We set as leaf rate_commitment after storing its index
            let identity_index = tree.leaves_set();
            let user_message_limit = Fr::from(100);
            let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();
            tree.update_next(rate_commitment).unwrap();

            // We generate a random signal
            let mut rng = thread_rng();
            let signal: [u8; 32] = rng.gen();

            // We generate a random epoch
            let epoch = hash_to_field_le(b"test-epoch").unwrap();
            // We generate a random rln_identifier
            let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
            let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();

            // Hash the signal to get x
            let x = hash_to_field_le(&signal).unwrap();
            let merkle_proof = tree.proof(identity_index).unwrap();
            let message_id = Fr::from(1);

            let rln_witness = new_single_message_witness(
                identity_secret,
                user_message_limit,
                message_id,
                merkle_proof.get_path_elements(),
                merkle_proof.get_path_index(),
                x,
                external_nullifier,
            )
            .unwrap();

            // Generate proof
            let (proof, proof_values) = rln.generate_rln_proof(&rln_witness).unwrap();

            // If no roots is provided, proof validation is skipped and if the remaining proof values are valid, the proof will be correctly verified
            let empty_roots: Vec<Fr> = vec![];
            let verified = rln
                .verify_with_roots(&proof, &proof_values, &x, &empty_roots)
                .is_ok();

            assert!(verified);

            // We check that the proof is not verified with random roots
            let mut random_roots: Vec<Fr> = Vec::new();
            for _ in 0..5 {
                random_roots.push(Fr::rand(&mut rng));
            }
            let verified = rln
                .verify_with_roots(&proof, &proof_values, &x, &random_roots)
                .is_ok();

            assert!(!verified);

            // We get the root of the tree obtained adding one leaf per time
            let root = tree.root();

            // We add the real root and we check if now the proof is verified
            random_roots.push(root);
            let verified = rln
                .verify_with_roots(&proof, &proof_values, &x, &random_roots)
                .is_ok();

            assert!(verified);
        }

        #[test]
        fn test_stateless_recover_id_secret() {
            // We create a new RLN instance
            let rln = RLN::new().unwrap();

            let default_leaf = Fr::from(0);
            let mut tree: OptimalMerkleTree<PoseidonHash> = OptimalMerkleTree::new(
                DEFAULT_TREE_DEPTH,
                default_leaf,
                ConfigOf::<OptimalMerkleTree<PoseidonHash>>::default(),
            )
            .unwrap();

            // Generate identity pair
            let (identity_secret, id_commitment) = keygen().unwrap();
            let user_message_limit = Fr::from(100);
            let rate_commitment = poseidon_hash(&[id_commitment, user_message_limit]).unwrap();
            tree.update_next(rate_commitment).unwrap();

            // We generate a random epoch
            let epoch = hash_to_field_le(b"test-epoch").unwrap();
            // We generate a random rln_identifier
            let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
            let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();

            // We generate a random signal
            let mut rng = thread_rng();
            let signal1: [u8; 32] = rng.gen();
            let x1 = hash_to_field_le(&signal1).unwrap();

            let signal2: [u8; 32] = rng.gen();
            let x2 = hash_to_field_le(&signal2).unwrap();

            let identity_index = tree.leaves_set();
            let merkle_proof = tree.proof(identity_index).unwrap();
            let message_id = Fr::from(1);

            let rln_witness1 = new_single_message_witness(
                identity_secret.clone(),
                user_message_limit,
                message_id,
                merkle_proof.get_path_elements(),
                merkle_proof.get_path_index(),
                x1,
                external_nullifier,
            )
            .unwrap();

            let rln_witness2 = new_single_message_witness(
                identity_secret.clone(),
                user_message_limit,
                message_id,
                merkle_proof.get_path_elements(),
                merkle_proof.get_path_index(),
                x2,
                external_nullifier,
            )
            .unwrap();

            // Generate proofs
            let (_proof1, proof_values_1) = rln.generate_rln_proof(&rln_witness1).unwrap();
            let (_proof2, proof_values_2) = rln.generate_rln_proof(&rln_witness2).unwrap();

            // Recover identity secret from two proof values
            let recovered_identity_secret =
                recover_id_secret(&proof_values_1, &proof_values_2).unwrap();

            // We check if the recovered identity secret corresponds to the original one
            assert_eq!(*recovered_identity_secret, *identity_secret);

            // We now test that computing identity_secret is unsuccessful if shares computed from two different identity secret but within same epoch are passed

            // We generate a new identity pair
            let (identity_secret_new, id_commitment_new) = keygen().unwrap();
            let rate_commitment_new =
                poseidon_hash(&[id_commitment_new, user_message_limit]).unwrap();
            tree.update_next(rate_commitment_new).unwrap();

            let signal3: [u8; 32] = rng.gen();
            let x3 = hash_to_field_le(&signal3).unwrap();

            let identity_index_new = tree.leaves_set();
            let merkle_proof_new = tree.proof(identity_index_new).unwrap();

            let rln_witness3 = new_single_message_witness(
                identity_secret_new.clone(),
                user_message_limit,
                message_id,
                merkle_proof_new.get_path_elements(),
                merkle_proof_new.get_path_index(),
                x3,
                external_nullifier,
            )
            .unwrap();

            // Generate proof with different identity
            let (_proof3, proof_values_3) = rln.generate_rln_proof(&rln_witness3).unwrap();

            // Attempt to recover secret from mismatched shares
            let recovered_identity_secret_new =
                recover_id_secret(&proof_values_1, &proof_values_3).unwrap();

            // ensure that the recovered secret does not match with either of the
            // used secrets in proof generation
            assert_ne!(*recovered_identity_secret_new, *identity_secret_new);
        }

        #[test]
        fn test_rln_resource_errors() {
            // Test missing rln_final.arkzkey
            let invalid_zkey_data = vec![];
            let result = RLN::new_with_params(invalid_zkey_data, vec![1, 2, 3]);
            assert!(result.is_err());
            assert!(matches!(result.err().unwrap(), RLNError::ZKey(_)));

            // Test invalid rln_final.arkzkey
            let invalid_zkey_data = vec![0u8; 100]; // Invalid zkey data
            let result = RLN::new_with_params(invalid_zkey_data, vec![1, 2, 3]);
            assert!(result.is_err());
            assert!(matches!(result.err().unwrap(), RLNError::ZKey(_)));

            // Test missing/invalid graph.bin - this would typically fail during proof generation
            let valid_zkey_data =
                include_bytes!("../resources/tree_depth_20/rln_final.arkzkey").to_vec();
            let invalid_graph_data = vec![];
            let result = RLN::new_with_params(valid_zkey_data, invalid_graph_data);
            assert!(matches!(result.err().unwrap(), RLNError::Graph(_)));

            // Test mismatched tree depth - using zkey from different depth
            let zkey_depth_10 =
                include_bytes!("../resources/tree_depth_10/rln_final.arkzkey").to_vec();
            let graph_depth_20 = include_bytes!("../resources/tree_depth_20/graph.bin").to_vec();
            let rln = RLN::new_with_params(zkey_depth_10, graph_depth_20).unwrap();

            // Create witness with wrong tree depth (16 instead of 20)
            let rln_witness_wrong_depth = random_rln_witness(16).unwrap();
            let proof_result = rln.generate_rln_proof(&rln_witness_wrong_depth);
            // Proof generation should fail due to depth mismatch between witness and circuit
            assert!(matches!(
                proof_result.err().unwrap(),
                RLNError::Protocol(ProtocolError::WitnessCalc(_))
            ));
        }
    }

    #[cfg(feature = "multi-message-id")]
    mod multi_message_id_test {
        use rand::{thread_rng, Rng};
        use rln::prelude::*;

        fn random_path(depth: usize) -> (Vec<Fr>, Vec<u8>) {
            let mut rng = thread_rng();
            let mut path_elements = Vec::new();
            let mut identity_path_index = Vec::new();
            for _ in 0..depth {
                path_elements.push(hash_to_field_le(&rng.gen::<[u8; 32]>()).unwrap());
                identity_path_index.push(rng.gen_range(0..2) as u8);
            }
            (path_elements, identity_path_index)
        }

        #[test]
        fn test_multi_message_witness_validation() {
            let mut rng = thread_rng();
            let identity_secret = IdSecret::rand(&mut rng);
            let user_message_limit = Fr::from(10);
            let (path_elements, identity_path_index) = random_path(DEFAULT_TREE_DEPTH);
            let x = hash_to_field_le(&rng.gen::<[u8; 32]>()).unwrap();
            let external_nullifier = hash_to_field_le(&rng.gen::<[u8; 32]>()).unwrap();

            // Both message_id and message_ids set → BothMessageIdSet
            assert!(matches!(
                RLNWitnessInput::new(
                    identity_secret.clone(),
                    user_message_limit,
                    Some(Fr::from(1)),
                    Some(vec![Fr::from(0), Fr::from(1)]),
                    path_elements.clone(),
                    identity_path_index.clone(),
                    x,
                    external_nullifier,
                    Some(vec![true, true]),
                )
                .unwrap_err(),
                ProtocolError::BothMessageIdSet
            ));

            // Neither set → NoMessageIdSet
            assert!(matches!(
                RLNWitnessInput::new(
                    identity_secret.clone(),
                    user_message_limit,
                    None,
                    None,
                    path_elements.clone(),
                    identity_path_index.clone(),
                    x,
                    external_nullifier,
                    None,
                )
                .unwrap_err(),
                ProtocolError::NoMessageIdSet
            ));

            // Empty message_ids → NoMessageIdSet
            assert!(matches!(
                RLNWitnessInput::new(
                    identity_secret.clone(),
                    user_message_limit,
                    None,
                    Some(vec![]),
                    path_elements.clone(),
                    identity_path_index.clone(),
                    x,
                    external_nullifier,
                    Some(vec![]),
                )
                .unwrap_err(),
                ProtocolError::NoMessageIdSet
            ));

            // message_ids without selector_used → InvalidSelectorUsed
            assert!(matches!(
                RLNWitnessInput::new(
                    identity_secret.clone(),
                    user_message_limit,
                    None,
                    Some(vec![Fr::from(0), Fr::from(1)]),
                    path_elements.clone(),
                    identity_path_index.clone(),
                    x,
                    external_nullifier,
                    None,
                )
                .unwrap_err(),
                ProtocolError::InvalidSelectorUsed
            ));

            // Mismatched selector_used length → InvalidSelectorUsed
            assert!(matches!(
                RLNWitnessInput::new(
                    identity_secret.clone(),
                    user_message_limit,
                    None,
                    Some(vec![Fr::from(0), Fr::from(1)]),
                    path_elements.clone(),
                    identity_path_index.clone(),
                    x,
                    external_nullifier,
                    Some(vec![true]),
                )
                .unwrap_err(),
                ProtocolError::InvalidSelectorUsed
            ));

            // Active message_id >= limit → InvalidMessageId
            assert!(matches!(
                RLNWitnessInput::new(
                    identity_secret.clone(),
                    user_message_limit,
                    None,
                    Some(vec![Fr::from(0), Fr::from(10)]),
                    path_elements.clone(),
                    identity_path_index.clone(),
                    x,
                    external_nullifier,
                    Some(vec![true, true]),
                )
                .unwrap_err(),
                ProtocolError::InvalidMessageId(_, _)
            ));

            // Inactive message_id >= limit → OK
            assert!(RLNWitnessInput::new(
                identity_secret.clone(),
                user_message_limit,
                None,
                Some(vec![Fr::from(0), Fr::from(10)]),
                path_elements.clone(),
                identity_path_index.clone(),
                x,
                external_nullifier,
                Some(vec![true, false]),
            )
            .is_ok());

            // Zero user_message_limit → ZeroUserMessageLimit
            assert!(matches!(
                RLNWitnessInput::new(
                    identity_secret.clone(),
                    Fr::from(0),
                    None,
                    Some(vec![Fr::from(0)]),
                    path_elements.clone(),
                    identity_path_index.clone(),
                    x,
                    external_nullifier,
                    Some(vec![true]),
                )
                .unwrap_err(),
                ProtocolError::ZeroUserMessageLimit
            ));

            // Valid multi-message witness
            assert!(RLNWitnessInput::new(
                identity_secret,
                user_message_limit,
                None,
                Some(vec![Fr::from(0), Fr::from(1), Fr::from(2), Fr::from(3)]),
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
                Some(vec![true, true, false, false]),
            )
            .is_ok());
        }

        #[test]
        fn test_multi_message_rln_proof() {
            let zkey_data =
                include_bytes!("../resources/tree_depth_20/multi_message_id/rln_final.arkzkey")
                    .to_vec();
            let graph_data =
                include_bytes!("../resources/tree_depth_20/multi_message_id/graph.bin").to_vec();

            let rln = RLN::new_with_params(DEFAULT_TREE_DEPTH, zkey_data, graph_data, "").unwrap();

            let mut rng = thread_rng();
            let (identity_secret, _) = keygen().unwrap();
            let user_message_limit = Fr::from(10);
            let (path_elements, identity_path_index) = random_path(DEFAULT_TREE_DEPTH);

            let epoch = hash_to_field_le(b"test-epoch").unwrap();
            let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
            let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();

            let signal: [u8; 32] = rng.gen();
            let x = hash_to_field_le(&signal).unwrap();

            let message_ids = vec![Fr::from(0), Fr::from(1), Fr::from(2), Fr::from(3)];
            let selector_used = vec![false, true, true, false];

            let witness = RLNWitnessInput::new(
                identity_secret,
                user_message_limit,
                None,
                Some(message_ids),
                path_elements,
                identity_path_index,
                x,
                external_nullifier,
                Some(selector_used.clone()),
            )
            .unwrap();

            let (proof, proof_values) = rln.generate_rln_proof(&witness).unwrap();

            // Verify proof values structure
            assert!(proof_values.y.is_none());
            assert!(proof_values.ys.is_some());
            assert!(proof_values.nullifier.is_none());
            assert!(proof_values.nullifiers.is_some());
            assert!(proof_values.selector_used.is_some());

            let ys = proof_values.ys.as_ref().unwrap();
            let nullifiers = proof_values.nullifiers.as_ref().unwrap();
            let selector = proof_values.selector_used.as_ref().unwrap();
            assert_eq!(ys.len(), 4);
            assert_eq!(nullifiers.len(), 4);
            assert_eq!(*selector, selector_used);

            // Inactive slots should have zero values
            assert_eq!(ys[0], Fr::from(0));
            assert_eq!(ys[3], Fr::from(0));
            assert_eq!(nullifiers[0], Fr::from(0));
            assert_eq!(nullifiers[3], Fr::from(0));

            // Active slots should have non-zero values
            assert_ne!(ys[1], Fr::from(0));
            assert_ne!(ys[2], Fr::from(0));
            assert_ne!(nullifiers[1], Fr::from(0));
            assert_ne!(nullifiers[2], Fr::from(0));

            // Verify zk proof
            let verified = rln.verify_zk_proof(&proof, &proof_values).unwrap();
            assert!(verified);
        }

        #[test]
        fn test_multi_message_recover_id_secret() {
            let zkey_data =
                include_bytes!("../resources/tree_depth_20/multi_message_id/rln_final.arkzkey")
                    .to_vec();
            let graph_data =
                include_bytes!("../resources/tree_depth_20/multi_message_id/graph.bin").to_vec();

            let rln = RLN::new_with_params(DEFAULT_TREE_DEPTH, zkey_data, graph_data, "").unwrap();

            let mut rng = thread_rng();
            let (identity_secret, _) = keygen().unwrap();
            let user_message_limit = Fr::from(10);
            let (path_elements, identity_path_index) = random_path(DEFAULT_TREE_DEPTH);

            let epoch = hash_to_field_le(b"test-epoch").unwrap();
            let rln_identifier = hash_to_field_le(b"test-rln-identifier").unwrap();
            let external_nullifier = poseidon_hash(&[epoch, rln_identifier]).unwrap();

            let signal1: [u8; 32] = rng.gen();
            let x1 = hash_to_field_le(&signal1).unwrap();
            let signal2: [u8; 32] = rng.gen();
            let x2 = hash_to_field_le(&signal2).unwrap();

            // Both witnesses use the same active message slots
            let message_ids = vec![Fr::from(0), Fr::from(1), Fr::from(2), Fr::from(3)];
            let selector_used = vec![true, true, false, false];

            let witness1 = RLNWitnessInput::new(
                identity_secret.clone(),
                user_message_limit,
                None,
                Some(message_ids.clone()),
                path_elements.clone(),
                identity_path_index.clone(),
                x1,
                external_nullifier,
                Some(selector_used.clone()),
            )
            .unwrap();

            let witness2 = RLNWitnessInput::new(
                identity_secret.clone(),
                user_message_limit,
                None,
                Some(message_ids),
                path_elements.clone(),
                identity_path_index.clone(),
                x2,
                external_nullifier,
                Some(selector_used),
            )
            .unwrap();

            let (_, proof_values_1) = rln.generate_rln_proof(&witness1).unwrap();
            let (_, proof_values_2) = rln.generate_rln_proof(&witness2).unwrap();

            // Recovery should succeed with matching nullifiers
            let recovered = recover_id_secret(&proof_values_1, &proof_values_2).unwrap();
            assert_eq!(*recovered, *identity_secret);

            // Test recovery fails with different identities (no matching nullifiers)
            let (identity_secret_new, _) = keygen().unwrap();
            let signal3: [u8; 32] = rng.gen();
            let x3 = hash_to_field_le(&signal3).unwrap();

            let witness3 = RLNWitnessInput::new(
                identity_secret_new,
                user_message_limit,
                None,
                Some(vec![Fr::from(0), Fr::from(1), Fr::from(2), Fr::from(3)]),
                path_elements,
                identity_path_index,
                x3,
                external_nullifier,
                Some(vec![true, true, false, false]),
            )
            .unwrap();

            let (_, proof_values_3) = rln.generate_rln_proof(&witness3).unwrap();

            // Different identities produce different nullifiers, so no matching nullifier
            let recovered_result = recover_id_secret(&proof_values_1, &proof_values_3);
            assert!(matches!(
                recovered_result.unwrap_err(),
                ProtocolError::IdSecretRecovery
            ));
        }
    }
}
