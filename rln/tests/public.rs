#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod test {
    use std::str::FromStr;

    use ark_std::UniformRand;
    use rand::{rngs::ThreadRng, thread_rng, Rng};
    use rln::prelude::*;
    use serde_json::{json, Value};
    use zerokit_utils::merkle_tree::{ZerokitMerkleProof, ZerokitMerkleTree};

    const NO_OF_LEAVES: usize = 256;

    type StatefulRLN = RLN<Stateful<PmTree>, ArkGroth16Backend>;

    fn fq_from_str(s: &str) -> Fq {
        Fq::from_str(s).unwrap()
    }

    fn fr_from_dec(s: &str) -> Fr {
        Fr::from_str(s).unwrap()
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

    fn ark_proof_from_snarkjs(snarkjs_proof: &Value) -> Proof {
        Proof {
            a: g1_from_str(&value_to_string_vec(&snarkjs_proof["pi_a"])),
            b: g2_from_str(
                &snarkjs_proof["pi_b"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(value_to_string_vec)
                    .collect::<Vec<Vec<String>>>(),
            ),
            c: g1_from_str(&value_to_string_vec(&snarkjs_proof["pi_c"])),
        }
    }

    fn random_merkle_proof(depth: usize) -> (Vec<Fr>, Vec<u8>) {
        let mut rng = thread_rng();
        let mut path_elements = Vec::new();
        let mut identity_path_index = Vec::new();
        for _ in 0..depth {
            path_elements.push(hash_to_field_le(&rng.gen::<[u8; 32]>()));
            identity_path_index.push(rng.gen_range(0..2) as u8);
        }
        (path_elements, identity_path_index)
    }

    fn random_rln_witness(tree_depth: usize) -> RLNWitnessInput {
        let mut rng = thread_rng();

        let identity_secret = IdSecret::rand(&mut rng);
        let x = hash_to_field_le(&rng.gen::<[u8; 32]>());
        let epoch = hash_to_field_le(&rng.gen::<[u8; 32]>());
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        let external_nullifier = poseidon_hash_pair(epoch, rln_identifier);

        let (path_elements, identity_path_index) = random_merkle_proof(tree_depth);

        RLNWitnessInput::new_single()
            .identity_secret(identity_secret)
            .user_message_limit(Fr::from(100))
            .path_elements(path_elements)
            .identity_path_index(identity_path_index)
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(Fr::from(1))
            .build()
            .unwrap()
    }

    fn create_rln(tree_depth: usize) -> StatefulRLN {
        RLNBuilder::stateful()
            .tree(PmTree::default(tree_depth).unwrap())
            .build()
    }

    fn random_leaves(rng: &mut ThreadRng) -> Vec<Fr> {
        (0..NO_OF_LEAVES).map(|_| Fr::rand(rng)).collect()
    }

    fn setup_rln_proof(
        mutate_path_elements: bool,
    ) -> (StatefulRLN, Proof, RLNProofValues, Fr, ThreadRng) {
        let mut rng = thread_rng();
        let leaves = random_leaves(&mut rng);

        let mut rln = create_rln(DEFAULT_TREE_DEPTH);
        rln.init_tree_with_leaves(leaves).unwrap();

        let (identity_secret, id_commitment) = keygen();
        let identity_index = rln.leaves_set();
        let user_message_limit = Fr::from(100);
        let rate_commitment = poseidon_hash_pair(id_commitment, user_message_limit);
        rln.set_next_leaf(rate_commitment).unwrap();

        let signal: [u8; 32] = rng.gen();
        let epoch = hash_to_field_le(b"test-epoch");
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        let external_nullifier = poseidon_hash_pair(epoch, rln_identifier);
        let x = hash_to_field_le(&signal);

        let merkle_proof = rln.get_merkle_proof(identity_index).unwrap();
        let mut path_elements = merkle_proof.get_path_elements();
        let identity_path_index = merkle_proof.get_path_index();

        if mutate_path_elements && !path_elements.is_empty() {
            path_elements[0] = Fr::rand(&mut rng);
        }

        let rln_witness = RLNWitnessInput::new_single()
            .identity_secret(identity_secret)
            .user_message_limit(user_message_limit)
            .path_elements(path_elements)
            .identity_path_index(identity_path_index)
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(Fr::from(1))
            .build()
            .unwrap();

        let (proof, proof_values) = rln.generate_proof(&rln_witness).unwrap();

        (rln, proof, proof_values, x, rng)
    }

    #[test]
    fn test_groth16_proof_hardcoded_single() {
        let rln = RLNBuilder::stateless().build();

        let snarkjs_proof = json!({
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
                ["1", "0"]
            ],
            "pi_c": [
                "17701377127561410274754535747274973758826089226897242202671882899370780845888",
                "12608543716397255084418384146504333522628400182843246910626782513289789807030",
                "1"
            ],
            "protocol": "groth16",
            "curve": "bn128"
        });

        let x = fr_from_dec(
            "20645213238265527935869146898028115621427162613172918400241870500502509785943",
        );
        let proof_values = RLNProofValues::Single(RLNProofValuesSingle {
            root: fr_from_dec(
                "8502402278351299594663821509741133196466235670407051417832304486953898514733",
            ),
            y: fr_from_dec(
                "16401008481486069296141645075505218976370369489687327284155463920202585288271",
            ),
            nullifier: fr_from_dec(
                "9102791780887227194595604713537772536258726662792598131262022534710887343694",
            ),
            x,
            external_nullifier: fr_from_dec(
                "21074405743803627666274838159589343934394162804826017440941339048886754734203",
            ),
        });

        let ark_proof = ark_proof_from_snarkjs(&snarkjs_proof);
        assert!(rln
            .verify_with_signal(&ark_proof, &proof_values, &x)
            .is_ok());
    }

    #[test]
    fn test_groth16_proof_hardcoded_multi() {
        let rln = RLNBuilder::stateless()
            .graph(default_graph_multi().clone())
            .zkey(default_zkey_multi().clone())
            .build();

        let snarkjs_proof = json!({
            "pi_a": [
                "18065030346679405936314703365313027854666139282416381597863520591326000485770",
                "14771860444670385955411380174213497474946229693924900012944518111443580986423",
                "1"
            ],
            "pi_b": [
                [
                    "6735720011967965811552770307926073251484071544628748265245982358598709514632",
                    "20834884037174490293404784720629481437908298314108873169352614850721890028313"
                ],
                [
                    "4833697662524472564312290961485074084149848067709427572820222800371260836955",
                    "17340414833348271743289107618101329696856992134080888054049600143320812961128"
                ],
                ["1", "0"]
            ],
            "pi_c": [
                "15995592009555866776210915003813915385299392333518806237517816627481425816425",
                "1089017666060567296165116465606820653924283171865888164456509348741884249923",
                "1"
            ],
            "protocol": "groth16",
            "curve": "bn128"
        });

        let x = fr_from_dec(
            "19797305253341717859481321525229680688216104810745023646128001903445473018856",
        );
        let proof_values = RLNProofValues::Multi(RLNProofValuesMulti {
            root: fr_from_dec(
                "3431095415998240809893928695882631208288185026672939778030884659225595068838",
            ),
            x,
            external_nullifier: fr_from_dec(
                "21092292729219847360221935824233974597185442347481349054190488583986042064831",
            ),
            ys: vec![
                fr_from_dec(
                    "143052188957058141710854771333369177356024382963719479956590549598262357586",
                ),
                Fr::from(0),
                Fr::from(0),
                Fr::from(0),
            ],
            nullifiers: vec![
                fr_from_dec(
                    "8499590175743632905717993598500718325843782253409297097332874882649203313309",
                ),
                Fr::from(0),
                Fr::from(0),
                Fr::from(0),
            ],
            selector_used: vec![true, false, false, false],
        });

        let ark_proof = ark_proof_from_snarkjs(&snarkjs_proof);
        assert!(rln
            .verify_with_signal(&ark_proof, &proof_values, &x)
            .is_ok());
    }

    #[test]
    fn test_initialization_with_params() {
        let zkey_data = include_bytes!("../resources/tree_depth_20/rln_final.arkzkey");
        let graph_data = include_bytes!("../resources/tree_depth_20/graph.bin");

        let zkey = zkey_from_raw(zkey_data).unwrap();
        let graph = graph_from_raw(graph_data, Some(DEFAULT_TREE_DEPTH), None).unwrap();

        let rln = RLNBuilder::stateless().zkey(zkey).graph(graph).build();
        let rln_witness = random_rln_witness(DEFAULT_TREE_DEPTH);
        let (proof, proof_values) = rln.generate_proof(&rln_witness).unwrap();
        assert!(rln.verify(&proof, &proof_values).unwrap());
    }

    #[test]
    fn test_rln_resource_errors() {
        // Empty rln_final.arkzkey
        assert!(zkey_from_raw(&[]).is_err());

        // Invalid rln_final.arkzkey
        assert!(zkey_from_raw(&[0u8; 100]).is_err());

        // Empty graph.bin
        assert!(graph_from_raw(&[], None, None).is_err());

        // Invalid graph.bin
        assert!(graph_from_raw(&[1, 2, 3], None, None).is_err());

        // Mismatched tree depth between graph and expectation
        let graph_depth_20 = include_bytes!("../resources/tree_depth_20/graph.bin");
        assert!(graph_from_raw(graph_depth_20, Some(10), None).is_err());

        // Witness with wrong tree depth fails proof generation against the circuit
        let zkey_depth_10 = include_bytes!("../resources/tree_depth_10/rln_final.arkzkey");
        let zkey = zkey_from_raw(zkey_depth_10).unwrap();
        let graph = graph_from_raw(graph_depth_20, Some(DEFAULT_TREE_DEPTH), None).unwrap();
        let rln = RLNBuilder::stateless().zkey(zkey).graph(graph).build();

        let rln_witness_wrong_depth = random_rln_witness(10);
        assert!(matches!(
            rln.generate_proof(&rln_witness_wrong_depth),
            Err(GenerateProofError::PathElementsLengthMismatch(_, _))
        ));
    }

    #[test]
    fn test_merkle_operations() {
        let mut rng = thread_rng();
        let leaves = random_leaves(&mut rng);

        let mut rln = create_rln(DEFAULT_TREE_DEPTH);

        for (i, leaf) in leaves.iter().enumerate() {
            assert_eq!(rln.leaves_set(), i);
            rln.set_leaf(i, *leaf).unwrap();
        }

        let root_single = rln.get_root();

        // Reset by creating a new instance, then re-add via internal index
        // NOTE: `init_tree_with_leaves(vec![])` panics inside pmtree (PR11).
        let mut rln = create_rln(DEFAULT_TREE_DEPTH);
        for leaf in &leaves {
            rln.set_next_leaf(*leaf).unwrap();
        }
        assert_eq!(rln.leaves_set(), NO_OF_LEAVES);
        assert_eq!(rln.get_root(), root_single);

        // Batch insert
        rln.init_tree_with_leaves(leaves.clone()).unwrap();
        assert_eq!(rln.leaves_set(), NO_OF_LEAVES);
        assert_eq!(rln.get_root(), root_single);

        // Delete every leaf; root must match a fresh empty tree
        for i in 0..NO_OF_LEAVES {
            rln.delete_leaf(i).unwrap();
        }
        assert_eq!(rln.leaves_set(), NO_OF_LEAVES);
        let root_after_delete = rln.get_root();

        let rln_empty = create_rln(DEFAULT_TREE_DEPTH);
        assert_eq!(root_after_delete, rln_empty.get_root());
    }

    #[test]
    fn test_leaf_setting_with_index() {
        let mut rng = thread_rng();
        let leaves = random_leaves(&mut rng);
        let set_index = rng.gen_range(0..NO_OF_LEAVES) as usize;

        let mut rln = create_rln(DEFAULT_TREE_DEPTH);
        rln.init_tree_with_leaves(leaves.clone()).unwrap();
        assert_eq!(rln.leaves_set(), NO_OF_LEAVES);
        let root_batch = rln.get_root();

        let mut rln = create_rln(DEFAULT_TREE_DEPTH);
        rln.init_tree_with_leaves(leaves[0..set_index].to_vec())
            .unwrap();
        rln.set_leaves_from(set_index, leaves[set_index..].to_vec())
            .unwrap();
        assert_eq!(rln.leaves_set(), NO_OF_LEAVES);
        assert_eq!(rln.get_root(), root_batch);

        let mut rln = create_rln(DEFAULT_TREE_DEPTH);
        for leaf in &leaves {
            rln.set_next_leaf(*leaf).unwrap();
        }
        assert_eq!(rln.leaves_set(), NO_OF_LEAVES);
        assert_eq!(rln.get_root(), root_batch);

        rln.flush().unwrap();
    }

    #[test]
    fn test_atomic_operation() {
        let leaves = random_leaves(&mut thread_rng());

        let mut rln = create_rln(DEFAULT_TREE_DEPTH);
        rln.init_tree_with_leaves(leaves.clone()).unwrap();
        assert_eq!(rln.leaves_set(), NO_OF_LEAVES);
        let root_after_insert = rln.get_root();

        // Atomic set+delete on the same index is a no-op
        let last_leaf = *leaves.last().unwrap();
        let last_leaf_index = NO_OF_LEAVES - 1;
        rln.atomic_operation(last_leaf_index, vec![last_leaf], vec![last_leaf_index])
            .unwrap();

        assert_eq!(rln.get_root(), root_after_insert);
    }

    #[test]
    fn test_atomic_operation_zero_indexed() {
        // Reproduced from https://github.com/waku-org/go-zerokit-rln/pull/12/files
        let leaves = random_leaves(&mut thread_rng());

        let mut rln = create_rln(DEFAULT_TREE_DEPTH);
        rln.init_tree_with_leaves(leaves).unwrap();
        let root_after_insert = rln.get_root();

        rln.atomic_operation(0, vec![], vec![0]).unwrap();
        assert_ne!(rln.get_root(), root_after_insert);
    }

    #[test]
    fn test_atomic_operation_consistency() {
        // Reproduced from https://github.com/waku-org/go-zerokit-rln/pull/12/files
        let mut rng = thread_rng();
        let leaves = random_leaves(&mut rng);

        let mut rln = create_rln(DEFAULT_TREE_DEPTH);
        rln.init_tree_with_leaves(leaves).unwrap();
        let root_after_insert = rln.get_root();

        let set_index = rng.gen_range(0..NO_OF_LEAVES) as usize;
        rln.atomic_operation(0, vec![], vec![set_index]).unwrap();

        assert_ne!(rln.get_root(), root_after_insert);
        assert_eq!(rln.get_leaf(set_index).unwrap(), Fr::from(0));
    }

    #[test]
    fn test_set_leaves_bad_index() {
        let mut rng = thread_rng();
        let leaves = random_leaves(&mut rng);
        let bad_index = (1 << DEFAULT_TREE_DEPTH) - rng.gen_range(0..NO_OF_LEAVES) as usize;

        let mut rln = create_rln(DEFAULT_TREE_DEPTH);
        let root_empty = rln.get_root();

        assert!(rln.set_leaves_from(bad_index, leaves).is_err());

        assert_eq!(rln.leaves_set(), 0);
        assert_eq!(rln.get_root(), root_empty);
    }

    #[test]
    fn test_get_leaf() {
        let tree_depth = 10;
        let mut rng = thread_rng();
        let mut rln = create_rln(tree_depth);

        let leaf = Fr::rand(&mut rng);
        let index = rng.gen_range(0..(1 << tree_depth));

        rln.set_leaf(index, leaf).unwrap();
        assert_eq!(rln.get_leaf(index).unwrap(), leaf);
    }

    #[test]
    fn test_valid_metadata() {
        let mut rln = create_rln(DEFAULT_TREE_DEPTH);

        let arbitrary_metadata: &[u8] = b"block_number:200000";
        rln.set_metadata(arbitrary_metadata).unwrap();

        assert_eq!(rln.get_metadata().unwrap(), arbitrary_metadata);
    }

    #[test]
    fn test_empty_metadata() {
        let rln = create_rln(DEFAULT_TREE_DEPTH);
        assert!(rln.get_metadata().unwrap().is_empty());
    }

    #[test]
    fn test_stateful_rln_proof() {
        let mut rng = thread_rng();
        let mut leaves: Vec<Fr> = Vec::new();
        for _ in 0..NO_OF_LEAVES {
            let id_commitment = Fr::rand(&mut rng);
            let rate_commitment = poseidon_hash_pair(id_commitment, Fr::from(100));
            leaves.push(rate_commitment);
        }

        let mut rln = create_rln(DEFAULT_TREE_DEPTH);
        rln.init_tree_with_leaves(leaves).unwrap();

        let (identity_secret, id_commitment) = keygen();
        let identity_index = rln.leaves_set();
        let user_message_limit = Fr::from(65535);
        let rate_commitment = poseidon_hash_pair(id_commitment, user_message_limit);
        rln.set_next_leaf(rate_commitment).unwrap();

        let signal: [u8; 32] = rng.gen();
        let epoch = hash_to_field_le(b"test-epoch");
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        let external_nullifier = poseidon_hash_pair(epoch, rln_identifier);
        let x = hash_to_field_le(&signal);

        let merkle_proof = rln.get_merkle_proof(identity_index).unwrap();

        let rln_witness = RLNWitnessInput::new_single()
            .identity_secret(identity_secret)
            .user_message_limit(user_message_limit)
            .path_elements(merkle_proof.get_path_elements())
            .identity_path_index(merkle_proof.get_path_index())
            .x(x)
            .external_nullifier(external_nullifier)
            .message_id(Fr::from(1))
            .build()
            .unwrap();

        let (proof, proof_values) = rln.generate_proof(&rln_witness).unwrap();

        assert!(rln.verify(&proof, &proof_values).unwrap());
        assert_eq!(proof_values.root(), rln.get_root());
    }

    #[test]
    fn test_verify_with_roots_against_real_tree_root() {
        let (rln, proof, proof_values, x, mut rng) = setup_rln_proof(false);

        // Empty roots skip the root check
        assert!(rln
            .verify_with_roots(&proof, &proof_values, &x, &[])
            .is_ok());

        // Random roots reject
        let random_roots: Vec<Fr> = (0..5).map(|_| Fr::rand(&mut rng)).collect();
        assert!(matches!(
            rln.verify_with_roots(&proof, &proof_values, &x, &random_roots),
            Err(VerifyProofError::InvalidRoot)
        ));

        // Real tree root accepts
        let mut roots = random_roots;
        roots.push(rln.get_root());
        assert!(rln
            .verify_with_roots(&proof, &proof_values, &x, &roots)
            .is_ok());
    }

    #[test]
    fn test_recover_secret_with_tree_proof() {
        let mut rln = create_rln(DEFAULT_TREE_DEPTH);

        let (identity_secret, id_commitment) = keygen();
        let user_message_limit = Fr::from(100);
        let rate_commitment = poseidon_hash_pair(id_commitment, user_message_limit);

        let identity_index = rln.leaves_set();
        rln.set_next_leaf(rate_commitment).unwrap();

        let mut rng = rand::thread_rng();
        let signal1: [u8; 32] = rng.gen();
        let signal2: [u8; 32] = rng.gen();

        let epoch = hash_to_field_le(b"test-epoch");
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        let external_nullifier = poseidon_hash_pair(epoch, rln_identifier);

        let x1 = hash_to_field_le(&signal1);
        let x2 = hash_to_field_le(&signal2);

        let merkle_proof = rln.get_merkle_proof(identity_index).unwrap();

        let make_witness = |x: Fr| -> RLNWitnessInput {
            RLNWitnessInput::new_single()
                .identity_secret(identity_secret.clone())
                .user_message_limit(user_message_limit)
                .path_elements(merkle_proof.get_path_elements())
                .identity_path_index(merkle_proof.get_path_index())
                .x(x)
                .external_nullifier(external_nullifier)
                .message_id(Fr::from(1))
                .build()
                .unwrap()
        };

        let (_proof1, proof_values_1) = rln.generate_proof(&make_witness(x1)).unwrap();
        let (_proof2, proof_values_2) = rln.generate_proof(&make_witness(x2)).unwrap();

        assert_eq!(
            proof_values_1.recover_secret(&proof_values_2).unwrap(),
            identity_secret
        );

        // Recovery must fail when shares come from two different identity secrets
        let (identity_secret_new, id_commitment_new) = keygen();
        let rate_commitment_new = poseidon_hash_pair(id_commitment_new, user_message_limit);

        let identity_index_new = rln.leaves_set();
        rln.set_next_leaf(rate_commitment_new).unwrap();

        let signal3: [u8; 32] = rng.gen();
        let x3 = hash_to_field_le(&signal3);

        let merkle_proof_new = rln.get_merkle_proof(identity_index_new).unwrap();

        let rln_witness3 = RLNWitnessInput::new_single()
            .identity_secret(identity_secret_new)
            .user_message_limit(user_message_limit)
            .path_elements(merkle_proof_new.get_path_elements())
            .identity_path_index(merkle_proof_new.get_path_index())
            .x(x3)
            .external_nullifier(external_nullifier)
            .message_id(Fr::from(1))
            .build()
            .unwrap();

        let (_proof3, proof_values_3) = rln.generate_proof(&rln_witness3).unwrap();

        assert!(matches!(
            proof_values_1.recover_secret(&proof_values_3),
            Err(RecoverSecretError::NoMatchingNullifier)
        ));
    }

    #[test]
    fn test_verify_failure_mutated_proof_points() {
        let (rln, proof, proof_values, _x, _rng) = setup_rln_proof(false);

        let mut mutated_a = proof.clone();
        mutated_a.a.x += Fq::from(1);
        assert!(!rln.verify(&mutated_a, &proof_values).unwrap_or(false));

        let mut mutated_b = proof.clone();
        mutated_b.b.x.c0 += Fq::from(1);
        assert!(!rln.verify(&mutated_b, &proof_values).unwrap_or(false));

        let mut mutated_c = proof.clone();
        mutated_c.c.x += Fq::from(1);
        assert!(!rln.verify(&mutated_c, &proof_values).unwrap_or(false));
    }

    #[test]
    fn test_verify_with_roots_fails_for_mutated_path_elements() {
        let (rln, proof, proof_values, x, _rng) = setup_rln_proof(true);
        let roots = vec![rln.get_root()];

        assert!(matches!(
            rln.verify_with_roots(&proof, &proof_values, &x, &roots),
            Err(VerifyProofError::InvalidRoot)
        ));
    }
}
