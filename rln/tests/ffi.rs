#[cfg(test)]
#[cfg(not(feature = "stateless"))]
mod test {
    use std::{fs::File, io::Read};

    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;
    use rln::{
        circuit::{Fr, DEFAULT_TREE_DEPTH},
        ffi::{ffi_rln::*, ffi_tree::*, ffi_utils::*},
        hashers::{hash_to_field_le, poseidon_hash as utils_poseidon_hash},
        protocol::*,
        utils::*,
    };
    use safer_ffi::prelude::repr_c;
    use serde_json::json;
    use zeroize::Zeroize;

    const NO_OF_LEAVES: usize = 256;

    fn create_rln_instance() -> repr_c::Box<FFI_RLN> {
        let input_config = json!({}).to_string();
        let c_str = std::ffi::CString::new(input_config).unwrap();
        match ffi_rln_new(DEFAULT_TREE_DEPTH, c_str.as_c_str().into()) {
            CResult {
                ok: Some(rln),
                err: None,
            } => rln,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("RLN object creation failed: {}", err),
            _ => unreachable!(),
        }
    }

    fn set_leaves_init(ffi_rln_instance: &mut repr_c::Box<FFI_RLN>, leaves: &[Fr]) {
        let leaves_vec: repr_c::Vec<CFr> = leaves
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        ffi_init_tree_with_leaves(ffi_rln_instance, &leaves_vec);
    }

    fn get_random_leaves() -> Vec<Fr> {
        let mut rng = thread_rng();
        (0..NO_OF_LEAVES).map(|_| Fr::rand(&mut rng)).collect()
    }

    fn get_tree_root(ffi_rln_instance: &repr_c::Box<FFI_RLN>) -> Fr {
        let root_cfr = ffi_get_root(ffi_rln_instance);
        **root_cfr
    }

    fn identity_pair_gen() -> (IdSecret, Fr) {
        let key_gen = ffi_key_gen();
        let mut id_secret_fr = *key_gen[0];
        let id_secret_hash = IdSecret::from(&mut id_secret_fr);
        let id_commitment = *key_gen[1];
        (id_secret_hash, id_commitment)
    }

    fn rln_proof_gen(
        ffi_rln_instance: &repr_c::Box<FFI_RLN>,
        identity_secret: &CFr,
        user_message_limit: &CFr,
        message_id: &CFr,
        x: &CFr,
        external_nullifier: &CFr,
        leaf_index: usize,
    ) -> repr_c::Box<FFI_RLNProof> {
        // Get merkle proof for the leaf index
        let merkle_proof = match ffi_get_proof(ffi_rln_instance, leaf_index) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get merkle proof call failed: {}", err),
            _ => unreachable!(),
        };

        // Create witness input
        let witness = match ffi_rln_witness_input_new(
            identity_secret,
            user_message_limit,
            message_id,
            &merkle_proof.path_elements,
            &merkle_proof.path_index,
            x,
            external_nullifier,
        ) {
            CResult {
                ok: Some(witness),
                err: None,
            } => witness,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("witness creation call failed: {}", err),
            _ => unreachable!(),
        };

        // Generate proof from witness
        let proof = match ffi_generate_rln_proof(ffi_rln_instance, &witness) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("generate rln proof call failed: {}", err),
            _ => unreachable!(),
        };

        proof
    }

    #[test]
    // We test merkle batch Merkle tree additions
    fn test_merkle_operations_ffi() {
        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let mut ffi_rln_instance = create_rln_instance();

        // We first add leaves one by one specifying the index
        for (i, leaf) in leaves.iter().enumerate() {
            // We prepare the rate_commitment and we set the leaf at provided index
            let result = ffi_set_leaf(&mut ffi_rln_instance, i, &CFr::from(*leaf));
            if !result.ok {
                panic!("set leaf call failed: {:?}", result.err);
            }
        }

        // We get the root of the tree obtained adding one leaf per time
        let root_single = get_tree_root(&ffi_rln_instance);

        // We reset the tree to default
        let result = ffi_set_tree(&mut ffi_rln_instance, DEFAULT_TREE_DEPTH);
        if !result.ok {
            panic!("set tree call failed: {:?}", result.err);
        }

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let result = ffi_set_next_leaf(&mut ffi_rln_instance, &CFr::from(*leaf));
            if !result.ok {
                panic!("set next leaf call failed: {:?}", result.err);
            }
        }

        // We get the root of the tree obtained adding leaves using the internal index
        let root_next = get_tree_root(&ffi_rln_instance);

        // We check if roots are the same
        assert_eq!(root_single, root_next);

        // We reset the tree to default
        let result = ffi_set_tree(&mut ffi_rln_instance, DEFAULT_TREE_DEPTH);
        if !result.ok {
            panic!("set tree call failed: {:?}", result.err);
        }

        // We add leaves in a batch into the tree
        set_leaves_init(&mut ffi_rln_instance, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_batch = get_tree_root(&ffi_rln_instance);

        // We check if roots are the same
        assert_eq!(root_single, root_batch);

        // We now delete all leaves set and check if the root corresponds to the empty tree root
        // delete calls over indexes higher than no_of_leaves are ignored and will not increase self.tree.next_index
        for i in 0..NO_OF_LEAVES {
            let result = ffi_delete_leaf(&mut ffi_rln_instance, i);
            if !result.ok {
                panic!("delete leaf call failed: {:?}", result.err);
            }
        }

        // We get the root of the tree obtained deleting all leaves
        let root_delete = get_tree_root(&ffi_rln_instance);

        // We reset the tree to default
        let result = ffi_set_tree(&mut ffi_rln_instance, DEFAULT_TREE_DEPTH);
        if !result.ok {
            panic!("set tree call failed: {:?}", result.err);
        }

        // We get the root of the empty tree
        let root_empty = get_tree_root(&ffi_rln_instance);

        // We check if roots are the same
        assert_eq!(root_delete, root_empty);
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    // Uses `set_leaves_from` to set leaves in a batch
    fn test_leaf_setting_with_index_ffi() {
        // We create a RLN instance
        let mut ffi_rln_instance = create_rln_instance();
        assert_eq!(ffi_leaves_set(&ffi_rln_instance), 0);

        // We generate a vector of random leaves
        let leaves = get_random_leaves();

        // set_index is the index from which we start setting leaves
        // random number between 0..no_of_leaves
        let mut rng = thread_rng();
        let set_index = rng.gen_range(0..NO_OF_LEAVES) as usize;
        println!("set_index: {set_index}");

        // We add leaves in a batch into the tree
        set_leaves_init(&mut ffi_rln_instance, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_batch_with_init = get_tree_root(&ffi_rln_instance);

        // `init_tree_with_leaves` resets the tree to the depth it was initialized with, using `set_tree`

        // We add leaves in a batch starting from index 0..set_index
        set_leaves_init(&mut ffi_rln_instance, &leaves[0..set_index]);

        // We add the remaining n leaves in a batch starting from index set_index
        let leaves_vec: repr_c::Vec<CFr> = leaves[set_index..]
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        let result = ffi_set_leaves_from(&mut ffi_rln_instance, set_index, &leaves_vec);
        if !result.ok {
            panic!("set leaves from call failed: {:?}", result.err);
        }

        // We get the root of the tree obtained adding leaves in batch
        let root_batch_with_custom_index = get_tree_root(&ffi_rln_instance);
        assert_eq!(
            root_batch_with_init, root_batch_with_custom_index,
            "root batch !="
        );

        // We reset the tree to default
        let result = ffi_set_tree(&mut ffi_rln_instance, DEFAULT_TREE_DEPTH);
        if !result.ok {
            panic!("set tree call failed: {:?}", result.err);
        }

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let result = ffi_set_next_leaf(&mut ffi_rln_instance, &CFr::from(*leaf));
            if !result.ok {
                panic!("set next leaf call failed: {:?}", result.err);
            }
        }

        // We get the root of the tree obtained adding leaves using the internal index
        let root_single_additions = get_tree_root(&ffi_rln_instance);
        assert_eq!(
            root_batch_with_init, root_single_additions,
            "root single additions !="
        );
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    fn test_atomic_operation_ffi() {
        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let mut ffi_rln_instance = create_rln_instance();

        // We add leaves in a batch into the tree
        set_leaves_init(&mut ffi_rln_instance, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_after_insertion = get_tree_root(&ffi_rln_instance);

        let last_leaf = leaves.last().unwrap();
        let last_leaf_index = NO_OF_LEAVES - 1;
        let indices: repr_c::Vec<usize> = vec![last_leaf_index].into();
        let last_leaf_vec: repr_c::Vec<CFr> = vec![CFr::from(*last_leaf)].into();

        let result = ffi_atomic_operation(
            &mut ffi_rln_instance,
            last_leaf_index,
            &last_leaf_vec,
            &indices,
        );
        if !result.ok {
            panic!("atomic operation call failed: {:?}", result.err);
        }

        // We get the root of the tree obtained after a no-op
        let root_after_noop = get_tree_root(&ffi_rln_instance);
        assert_eq!(root_after_insertion, root_after_noop);
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    fn test_set_leaves_bad_index_ffi() {
        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let mut ffi_rln_instance = create_rln_instance();

        let mut rng = thread_rng();
        let bad_index = (1 << DEFAULT_TREE_DEPTH) - rng.gen_range(0..NO_OF_LEAVES) as usize;

        // Get root of empty tree
        let root_empty = get_tree_root(&ffi_rln_instance);

        // We add leaves in a batch into the tree
        let leaves_vec: repr_c::Vec<CFr> = leaves
            .iter()
            .map(|fr| CFr::from(*fr))
            .collect::<Vec<_>>()
            .into();
        ffi_set_leaves_from(&mut ffi_rln_instance, bad_index, &leaves_vec);

        // Get root of tree after attempted set
        let root_after_bad_set = get_tree_root(&ffi_rln_instance);
        assert_eq!(root_empty, root_after_bad_set);
    }

    #[test]
    // This test is similar to the one in lib, but uses only public C API
    fn test_merkle_proof_ffi() {
        let leaf_index = 3;
        // We create a RLN instance
        let mut ffi_rln_instance = create_rln_instance();

        // generate identity
        let mut identity_secret_ = hash_to_field_le(b"test-merkle-proof");
        let identity_secret = IdSecret::from(&mut identity_secret_);
        let mut to_hash = [*identity_secret.clone()];
        let id_commitment = utils_poseidon_hash(&to_hash);
        to_hash[0].zeroize();
        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);

        // We prepare id_commitment and we set the leaf at provided index
        let result = ffi_set_leaf(
            &mut ffi_rln_instance,
            leaf_index,
            &CFr::from(rate_commitment),
        );
        if !result.ok {
            panic!("set leaf call failed: {:?}", result.err);
        }

        // We obtain the Merkle tree root
        let root = get_tree_root(&ffi_rln_instance);

        use ark_ff::BigInt;
        assert_eq!(
            root,
            BigInt([
                4939322235247991215,
                5110804094006647505,
                4427606543677101242,
                910933464535675827
            ])
            .into()
        );

        // We obtain the Merkle proof
        let proof = match ffi_get_proof(&ffi_rln_instance, leaf_index) {
            CResult {
                ok: Some(proof),
                err: None,
            } => proof,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get merkle proof call failed: {}", err),
            _ => unreachable!(),
        };

        let path_elements: Vec<Fr> = proof.path_elements.iter().map(|cfr| **cfr).collect();
        let identity_path_index: Vec<u8> = proof.path_index.iter().copied().collect();

        // We check correct computation of the path and indexes
        let expected_path_elements: Vec<Fr> = [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
            "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1",
            "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238",
            "0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a",
            "0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55",
            "0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78",
            "0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d",
            "0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61",
            "0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747",
            "0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2",
            "0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636",
            "0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a",
            "0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0",
            "0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c",
            "0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92",
            "0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323",
            "0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992",
            "0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f",
            "0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca",
        ]
        .map(|e| str_to_fr(e, 16).unwrap())
        .to_vec();

        let expected_identity_path_index: Vec<u8> =
            vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(path_elements, expected_path_elements);
        assert_eq!(identity_path_index, expected_identity_path_index);

        // We double check that the proof computed from public API is correct
        let root_from_proof = compute_tree_root(
            &identity_secret,
            &user_message_limit,
            &path_elements,
            &identity_path_index,
        );

        assert_eq!(root, root_from_proof);
    }

    #[test]
    // Creating a RLN with raw data should generate same results as using a path to resources
    fn test_rln_raw_ffi() {
        // We create a RLN instance
        let ffi_rln_instance = create_rln_instance();

        // We obtain the root from the RLN instance
        let root_rln_folder = get_tree_root(&ffi_rln_instance);

        let zkey_path = "./resources/tree_depth_20/rln_final.arkzkey";
        let mut zkey_file = File::open(zkey_path).expect("no file found");
        let metadata = std::fs::metadata(zkey_path).expect("unable to read metadata");
        let mut zkey_data = vec![0; metadata.len() as usize];
        zkey_file
            .read_exact(&mut zkey_data)
            .expect("buffer overflow");

        let graph_data = "./resources/tree_depth_20/graph.bin";
        let mut graph_file = File::open(graph_data).expect("no file found");
        let metadata = std::fs::metadata(graph_data).expect("unable to read metadata");
        let mut graph_buffer = vec![0; metadata.len() as usize];
        graph_file
            .read_exact(&mut graph_buffer)
            .expect("buffer overflow");

        // Creating a RLN instance passing the raw data
        let tree_config = "".to_string();
        let c_str = std::ffi::CString::new(tree_config).unwrap();
        let ffi_rln_instance2 = match ffi_rln_new_with_params(
            DEFAULT_TREE_DEPTH,
            &zkey_data.into(),
            &graph_buffer.into(),
            c_str.as_c_str().into(),
        ) {
            CResult {
                ok: Some(rln),
                err: None,
            } => rln,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("RLN object creation failed: {}", err),
            _ => unreachable!(),
        };

        // We obtain the root from the RLN instance containing raw data
        // And compare that the same root was generated
        let root_rln_raw = get_tree_root(&ffi_rln_instance2);
        assert_eq!(root_rln_folder, root_rln_raw);
    }

    #[test]
    // Computes and verifies an RLN ZK proof using FFI APIs
    fn test_rln_proof_ffi() {
        let user_message_limit = Fr::from(100);

        // We generate a vector of random leaves
        let mut rng = thread_rng();
        let leaves: Vec<Fr> = (0..NO_OF_LEAVES)
            .map(|_| utils_poseidon_hash(&[Fr::rand(&mut rng), Fr::from(100)]))
            .collect();

        // We create a RLN instance
        let mut ffi_rln_instance = create_rln_instance();

        // We add leaves in a batch into the tree
        set_leaves_init(&mut ffi_rln_instance, &leaves);

        // We generate a new identity pair
        let (identity_secret, id_commitment) = identity_pair_gen();
        let identity_index: usize = NO_OF_LEAVES;

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field_le(b"test-epoch");
        // We generate a random rln_identifier
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        // We generate a external nullifier
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);
        // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
        let message_id = Fr::from(1);

        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);

        // We set as leaf rate_commitment, its index would be equal to no_of_leaves
        let result = ffi_set_next_leaf(&mut ffi_rln_instance, &CFr::from(rate_commitment));
        if !result.ok {
            panic!("set next leaf call failed: {:?}", result.err);
        }

        // Hash the signal to get x
        let x = hash_to_field_le(&signal);

        let rln_proof = rln_proof_gen(
            &ffi_rln_instance,
            &CFr::from(*identity_secret),
            &CFr::from(user_message_limit),
            &CFr::from(message_id),
            &CFr::from(x),
            &CFr::from(external_nullifier),
            identity_index,
        );

        assert!(ffi_verify_rln_proof(&ffi_rln_instance, &rln_proof, &CFr::from(x)).ok);
    }

    #[test]
    // Computes and verifies an RLN ZK proof by checking proof's root against an input roots buffer
    fn test_verify_with_roots_ffi() {
        let user_message_limit = Fr::from(100);

        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let mut ffi_rln_instance = create_rln_instance();

        // We add leaves in a batch into the tree
        set_leaves_init(&mut ffi_rln_instance, &leaves);

        // We generate a new identity pair
        let (identity_secret, id_commitment) = identity_pair_gen();
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);
        let identity_index: usize = NO_OF_LEAVES;

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field_le(b"test-epoch");
        // We generate a random rln_identifier
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        // We generate a external nullifier
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);
        // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
        let message_id = Fr::from(1);

        // We set as leaf rate_commitment, its index would be equal to no_of_leaves
        let result = ffi_set_next_leaf(&mut ffi_rln_instance, &CFr::from(rate_commitment));
        if !result.ok {
            panic!("set next leaf call failed: {:?}", result.err);
        }

        // Hash the signal to get x
        let x = hash_to_field_le(&signal);

        let rln_proof = rln_proof_gen(
            &ffi_rln_instance,
            &CFr::from(*identity_secret),
            &CFr::from(user_message_limit),
            &CFr::from(message_id),
            &CFr::from(x),
            &CFr::from(external_nullifier),
            identity_index,
        );

        // We test verify_with_roots

        // We first try to verify against an empty buffer of roots.
        // In this case, since no root is provided, proof's root check is skipped and proof is verified if other proof values are valid
        let roots_empty: repr_c::Vec<CFr> = vec![].into();

        assert!(
            ffi_verify_with_roots(&ffi_rln_instance, &rln_proof, &roots_empty, &CFr::from(x)).ok
        );

        // We then try to verify against some random values not containing the correct one.
        let mut roots_random: Vec<CFr> = Vec::new();
        for _ in 0..5 {
            roots_random.push(CFr::from(Fr::rand(&mut rng)));
        }
        let roots_random_vec: repr_c::Vec<CFr> = roots_random.into();

        assert!(
            !ffi_verify_with_roots(
                &ffi_rln_instance,
                &rln_proof,
                &roots_random_vec,
                &CFr::from(x),
            )
            .ok
        );

        // We finally include the correct root
        // We get the root of the tree obtained adding one leaf per time
        let root = get_tree_root(&ffi_rln_instance);

        // We include the root and verify the proof
        let mut roots_with_correct: Vec<CFr> = Vec::new();
        for _ in 0..5 {
            roots_with_correct.push(CFr::from(Fr::rand(&mut rng)));
        }
        roots_with_correct.push(CFr::from(root));
        let roots_correct_vec: repr_c::Vec<CFr> = roots_with_correct.into();

        assert!(
            ffi_verify_with_roots(
                &ffi_rln_instance,
                &rln_proof,
                &roots_correct_vec,
                &CFr::from(x),
            )
            .ok
        );
    }

    #[test]
    // Computes and verifies an RLN ZK proof using FFI APIs and recovers identity secret
    fn test_recover_id_secret_ffi() {
        // We create a RLN instance
        let mut ffi_rln_instance = create_rln_instance();

        // We generate a new identity pair
        let (identity_secret, id_commitment) = identity_pair_gen();

        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);

        // We set as leaf rate_commitment, its index would be equal to 0 since tree is empty
        let result = ffi_set_next_leaf(&mut ffi_rln_instance, &CFr::from(rate_commitment));
        if !result.ok {
            panic!("set next leaf call failed: {:?}", result.err);
        }

        let identity_index: usize = 0;

        // We generate two proofs using same epoch but different signals.

        // We generate two random signals
        let mut rng = rand::thread_rng();
        let signal1: [u8; 32] = rng.gen();
        let signal2: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field_le(b"test-epoch");
        // We generate a random rln_identifier
        let rln_identifier = hash_to_field_le(b"test-rln-identifier");
        // We generate a external nullifier
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);
        // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
        let message_id = Fr::from(1);

        // Hash the signals to get x
        let x1 = hash_to_field_le(&signal1);
        let x2 = hash_to_field_le(&signal2);

        // Generate proofs using witness-based API
        // We call generate_rln_proof for first proof values
        let rln_proof1 = rln_proof_gen(
            &ffi_rln_instance,
            &CFr::from(*identity_secret.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(message_id),
            &CFr::from(x1),
            &CFr::from(external_nullifier),
            identity_index,
        );

        // We call generate_rln_proof for second proof values
        let rln_proof2 = rln_proof_gen(
            &ffi_rln_instance,
            &CFr::from(*identity_secret.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(message_id),
            &CFr::from(x2),
            &CFr::from(external_nullifier),
            identity_index,
        );

        let recovered_id_secret_cfr = match ffi_recover_id_secret(
            &ffi_rln_proof_get_values(&rln_proof1),
            &ffi_rln_proof_get_values(&rln_proof2),
        ) {
            CResult {
                ok: Some(secret),
                err: None,
            } => secret,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("recover id secret call failed: {}", err),
            _ => unreachable!(),
        };

        // We check if the recovered identity secret hash corresponds to the original one
        let recovered_identity_secret = *recovered_id_secret_cfr;
        assert_eq!(recovered_identity_secret, *identity_secret);

        // We now test that computing identity_secret is unsuccessful if shares computed from two different identity secret hashes but within same epoch are passed

        // We generate a new identity pair
        let (identity_secret_new, id_commitment_new) = identity_pair_gen();
        let rate_commitment_new = utils_poseidon_hash(&[id_commitment_new, user_message_limit]);

        // We set as leaf id_commitment, its index would be equal to 1 since at 0 there is id_commitment
        let result = ffi_set_next_leaf(&mut ffi_rln_instance, &CFr::from(rate_commitment_new));
        if !result.ok {
            panic!("set next leaf call failed: {:?}", result.err);
        }

        let identity_index_new: usize = 1;

        // We generate a random signal
        let signal3: [u8; 32] = rng.gen();
        let x3 = hash_to_field_le(&signal3);

        let rln_proof3 = rln_proof_gen(
            &ffi_rln_instance,
            &CFr::from(*identity_secret_new.clone()),
            &CFr::from(user_message_limit),
            &CFr::from(message_id),
            &CFr::from(x3),
            &CFr::from(external_nullifier),
            identity_index_new,
        );

        // We attempt to recover the secret using share1 (coming from identity_secret) and share3 (coming from identity_secret_new)

        let recovered_id_secret_new_cfr = match ffi_recover_id_secret(
            &ffi_rln_proof_get_values(&rln_proof1),
            &ffi_rln_proof_get_values(&rln_proof3),
        ) {
            CResult {
                ok: Some(secret),
                err: None,
            } => secret,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("recover id secret call failed: {}", err),
            _ => unreachable!(),
        };

        let recovered_identity_secret_new = recovered_id_secret_new_cfr;

        // ensure that the recovered secret does not match with either of the
        // used secrets in proof generation
        assert_ne!(*recovered_identity_secret_new, *identity_secret_new);
    }

    #[test]
    fn test_get_leaf_ffi() {
        // We create a RLN instance
        let no_of_leaves = 1 << DEFAULT_TREE_DEPTH;

        // We create a RLN instance
        let mut ffi_rln_instance = create_rln_instance();

        // We generate a new identity tuple from an input seed
        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let key_gen = ffi_seeded_extended_key_gen(&seed_bytes.into());
        assert_eq!(key_gen.len(), 4, "seeded extended key gen call failed");
        let id_commitment = *key_gen[3];

        // We insert the id_commitment into the tree at a random index
        let mut rng = thread_rng();
        let index = rng.gen_range(0..no_of_leaves) as usize;
        let result = ffi_set_leaf(&mut ffi_rln_instance, index, &CFr::from(id_commitment));
        if !result.ok {
            panic!("set leaf call failed: {:?}", result.err);
        }

        // We get the leaf at the same index
        let received_id_commitment_cfr = match ffi_get_leaf(&ffi_rln_instance, index) {
            CResult {
                ok: Some(leaf),
                err: None,
            } => leaf,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get leaf call failed: {}", err),
            _ => unreachable!(),
        };
        let received_id_commitment = *received_id_commitment_cfr;

        // We check that the received id_commitment is the same as the one we inserted
        assert_eq!(received_id_commitment, id_commitment);
    }

    #[test]
    fn test_valid_metadata_ffi() {
        // We create a RLN instance
        let mut ffi_rln_instance = create_rln_instance();

        let seed_bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let result = ffi_set_metadata(&mut ffi_rln_instance, &seed_bytes.clone().into());
        if !result.ok {
            panic!("set_metadata call failed: {:?}", result.err);
        }

        let metadata = match ffi_get_metadata(&ffi_rln_instance) {
            CResult {
                ok: Some(data),
                err: None,
            } => data,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get_metadata call failed: {}", err),
            _ => unreachable!(),
        };

        assert_eq!(metadata.iter().copied().collect::<Vec<u8>>(), seed_bytes);
    }

    #[test]
    fn test_empty_metadata_ffi() {
        // We create a RLN instance
        let ffi_rln_instance = create_rln_instance();

        let metadata = match ffi_get_metadata(&ffi_rln_instance) {
            CResult {
                ok: Some(data),
                err: None,
            } => data,
            CResult {
                ok: None,
                err: Some(err),
            } => panic!("get_metadata call failed: {}", err),
            _ => unreachable!(),
        };

        assert_eq!(metadata.len(), 0);
    }
}
