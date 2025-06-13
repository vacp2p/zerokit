#[cfg(test)]
#[cfg(not(feature = "stateless"))]
mod test {
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;
    use rln::circuit::{Fr, TEST_TREE_HEIGHT};
    use rln::ffi::{hash as ffi_hash, poseidon_hash as ffi_poseidon_hash, *};
    use rln::hashers::{hash_to_field, poseidon_hash as utils_poseidon_hash, ROUND_PARAMS};
    use rln::protocol::*;
    use rln::public::RLN;
    use rln::utils::*;
    use serde_json::json;
    use std::fs::File;
    use std::io::Read;
    use std::mem::MaybeUninit;
    use std::time::{Duration, Instant};

    const NO_OF_LEAVES: usize = 256;

    fn create_rln_instance() -> &'static mut RLN {
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_config = json!({}).to_string();
        let input_buffer = &Buffer::from(input_config.as_bytes());
        let success = new(TEST_TREE_HEIGHT, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        unsafe { &mut *rln_pointer.assume_init() }
    }

    fn set_leaves_init(rln_pointer: &mut RLN, leaves: &[Fr]) {
        let leaves_ser = vec_fr_to_bytes_le(&leaves);
        let input_buffer = &Buffer::from(leaves_ser.as_ref());
        let success = init_tree_with_leaves(rln_pointer, input_buffer);
        assert!(success, "init tree with leaves call failed");
        assert_eq!(rln_pointer.leaves_set(), leaves.len());
    }

    fn get_random_leaves() -> Vec<Fr> {
        let mut rng = thread_rng();
        (0..NO_OF_LEAVES).map(|_| Fr::rand(&mut rng)).collect()
    }

    fn get_tree_root(rln_pointer: &mut RLN) -> Fr {
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root, _) = bytes_le_to_fr(&result_data);
        root
    }

    fn identity_pair_gen(rln_pointer: &mut RLN) -> (IdSecret, Fr) {
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = key_gen(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "key gen call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        // FIXME: zeroize?
        let (identity_secret_hash, read) = bytes_le_to_fr(&result_data);
        let (id_commitment, _) = bytes_le_to_fr(&result_data[read..].to_vec());
        (IdSecret::from(identity_secret_hash), id_commitment)
    }

    fn rln_proof_gen(rln_pointer: &mut RLN, serialized: &[u8]) -> Vec<u8> {
        let input_buffer = &Buffer::from(serialized);
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = generate_rln_proof(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "generate rln proof call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        <&[u8]>::from(&output_buffer).to_vec()
    }

    #[test]
    // We test merkle batch Merkle tree additions
    fn test_merkle_operations_ffi() {
        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We first add leaves one by one specifying the index
        for (i, leaf) in leaves.iter().enumerate() {
            // We prepare the rate_commitment and we set the leaf at provided index
            let leaf_ser = fr_to_bytes_le(&leaf);
            let input_buffer = &Buffer::from(leaf_ser.as_ref());
            let success = set_leaf(rln_pointer, i, input_buffer);
            assert!(success, "set leaf call failed");
        }

        // We get the root of the tree obtained adding one leaf per time
        let root_single = get_tree_root(rln_pointer);

        // We reset the tree to default
        let success = set_tree(rln_pointer, TEST_TREE_HEIGHT);
        assert!(success, "set tree call failed");

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let leaf_ser = fr_to_bytes_le(&leaf);
            let input_buffer = &Buffer::from(leaf_ser.as_ref());
            let success = set_next_leaf(rln_pointer, input_buffer);
            assert!(success, "set next leaf call failed");
        }

        // We get the root of the tree obtained adding leaves using the internal index
        let root_next = get_tree_root(rln_pointer);

        // We check if roots are the same
        assert_eq!(root_single, root_next);

        // We reset the tree to default
        let success = set_tree(rln_pointer, TEST_TREE_HEIGHT);
        assert!(success, "set tree call failed");

        // We add leaves in a batch into the tree
        set_leaves_init(rln_pointer, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_batch = get_tree_root(rln_pointer);

        // We check if roots are the same
        assert_eq!(root_single, root_batch);

        // We now delete all leaves set and check if the root corresponds to the empty tree root
        // delete calls over indexes higher than no_of_leaves are ignored and will not increase self.tree.next_index
        for i in 0..NO_OF_LEAVES {
            let success = delete_leaf(rln_pointer, i);
            assert!(success, "delete leaf call failed");
        }

        // We get the root of the tree obtained deleting all leaves
        let root_delete = get_tree_root(rln_pointer);

        // We reset the tree to default
        let success = set_tree(rln_pointer, TEST_TREE_HEIGHT);
        assert!(success, "set tree call failed");

        // We get the root of the empty tree
        let root_empty = get_tree_root(rln_pointer);

        // We check if roots are the same
        assert_eq!(root_delete, root_empty);
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    // Uses `set_leaves_from` to set leaves in a batch
    fn test_leaf_setting_with_index_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();
        assert_eq!(rln_pointer.leaves_set(), 0);

        // We generate a vector of random leaves
        let leaves = get_random_leaves();

        // set_index is the index from which we start setting leaves
        // random number between 0..no_of_leaves
        let mut rng = thread_rng();
        let set_index = rng.gen_range(0..NO_OF_LEAVES) as usize;
        println!("set_index: {}", set_index);

        // We add leaves in a batch into the tree
        set_leaves_init(rln_pointer, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_batch_with_init = get_tree_root(rln_pointer);

        // `init_tree_with_leaves` resets the tree to the height it was initialized with, using `set_tree`

        // We add leaves in a batch starting from index 0..set_index
        set_leaves_init(rln_pointer, &leaves[0..set_index]);

        // We add the remaining n leaves in a batch starting from index set_index
        let leaves_n = vec_fr_to_bytes_le(&leaves[set_index..]);
        let buffer = &Buffer::from(leaves_n.as_ref());
        let success = set_leaves_from(rln_pointer, set_index, buffer);
        assert!(success, "set leaves from call failed");

        // We get the root of the tree obtained adding leaves in batch
        let root_batch_with_custom_index = get_tree_root(rln_pointer);
        assert_eq!(
            root_batch_with_init, root_batch_with_custom_index,
            "root batch !="
        );

        // We reset the tree to default
        let success = set_tree(rln_pointer, TEST_TREE_HEIGHT);
        assert!(success, "set tree call failed");

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let leaf_ser = fr_to_bytes_le(&leaf);
            let input_buffer = &Buffer::from(leaf_ser.as_ref());
            let success = set_next_leaf(rln_pointer, input_buffer);
            assert!(success, "set next leaf call failed");
        }

        // We get the root of the tree obtained adding leaves using the internal index
        let root_single_additions = get_tree_root(rln_pointer);
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
        let rln_pointer = create_rln_instance();

        // We add leaves in a batch into the tree
        set_leaves_init(rln_pointer, &leaves);

        // We get the root of the tree obtained adding leaves in batch
        let root_after_insertion = get_tree_root(rln_pointer);

        let last_leaf = leaves.last().unwrap();
        let last_leaf_index = NO_OF_LEAVES - 1;
        let indices = vec![last_leaf_index as u8];
        let last_leaf = vec![*last_leaf];
        let indices = vec_u8_to_bytes_le(&indices);
        let indices_buffer = &Buffer::from(indices.as_ref());
        let leaves = vec_fr_to_bytes_le(&last_leaf);
        let leaves_buffer = &Buffer::from(leaves.as_ref());

        let success = atomic_operation(
            rln_pointer,
            last_leaf_index as usize,
            leaves_buffer,
            indices_buffer,
        );
        assert!(success, "atomic operation call failed");

        // We get the root of the tree obtained after a no-op
        let root_after_noop = get_tree_root(rln_pointer);
        assert_eq!(root_after_insertion, root_after_noop);
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    fn test_set_leaves_bad_index_ffi() {
        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        let mut rng = thread_rng();
        let bad_index = (1 << TEST_TREE_HEIGHT) - rng.gen_range(0..NO_OF_LEAVES) as usize;

        // Get root of empty tree
        let root_empty = get_tree_root(rln_pointer);

        // We add leaves in a batch into the tree
        let leaves = vec_fr_to_bytes_le(&leaves);
        let buffer = &Buffer::from(leaves.as_ref());
        let success = set_leaves_from(rln_pointer, bad_index, buffer);
        assert!(!success, "set leaves from call succeeded");

        // Get root of tree after attempted set
        let root_after_bad_set = get_tree_root(rln_pointer);
        assert_eq!(root_empty, root_after_bad_set);
    }

    #[test]
    // This test is similar to the one in lib, but uses only public C API
    fn test_merkle_proof_ffi() {
        let leaf_index = 3;
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // generate identity
        let identity_secret_hash = hash_to_field(b"test-merkle-proof");
        let id_commitment = utils_poseidon_hash(&[identity_secret_hash]);
        let identity_secret_hash = IdSecret::from(identity_secret_hash);
        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);

        // We prepare id_commitment and we set the leaf at provided index
        let leaf_ser = fr_to_bytes_le(&rate_commitment);
        let input_buffer = &Buffer::from(leaf_ser.as_ref());
        let success = set_leaf(rln_pointer, leaf_index, input_buffer);
        assert!(success, "set leaf call failed");

        // We obtain the Merkle tree root
        let root = get_tree_root(rln_pointer);

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

        // We obtain the Merkle tree root
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_proof(rln_pointer, leaf_index, output_buffer.as_mut_ptr());
        assert!(success, "get merkle proof call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();

        let (path_elements, read) = bytes_le_to_vec_fr(&result_data).unwrap();
        let (identity_path_index, _) = bytes_le_to_vec_u8(&result_data[read..].to_vec()).unwrap();

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
            &identity_secret_hash,
            &user_message_limit,
            &path_elements,
            &identity_path_index,
        );

        assert_eq!(root, root_from_proof);
    }

    #[test]
    // Benchmarks proof generation and verification
    fn test_groth16_proofs_performance_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We compute some benchmarks regarding proof and verify API calls
        // Note that circuit loading requires some initial overhead.
        // Once the circuit is loaded (i.e., when the RLN object is created), proof generation and verification times should be similar at each call.
        let sample_size = 100;
        let mut prove_time: u128 = 0;
        let mut verify_time: u128 = 0;

        for _ in 0..sample_size {
            // We generate random witness instances and relative proof values
            let rln_witness = random_rln_witness(TEST_TREE_HEIGHT);
            let proof_values = proof_values_from_witness(&rln_witness).unwrap();

            // We prepare id_commitment and we set the leaf at provided index
            let rln_witness_ser = serialize_witness(&rln_witness).unwrap();
            let input_buffer = &Buffer::from(rln_witness_ser.as_ref());
            let mut output_buffer = MaybeUninit::<Buffer>::uninit();
            let now = Instant::now();
            let success = prove(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
            prove_time += now.elapsed().as_nanos();
            assert!(success, "prove call failed");
            let output_buffer = unsafe { output_buffer.assume_init() };

            // We read the returned proof and we append proof values for verify
            let serialized_proof = <&[u8]>::from(&output_buffer).to_vec();
            let serialized_proof_values = serialize_proof_values(&proof_values);
            let mut verify_data = Vec::<u8>::new();
            verify_data.extend(&serialized_proof);
            verify_data.extend(&serialized_proof_values);

            // We prepare input proof values and we call verify
            let input_buffer = &Buffer::from(verify_data.as_ref());
            let mut proof_is_valid: bool = false;
            let proof_is_valid_ptr = &mut proof_is_valid as *mut bool;
            let now = Instant::now();
            let success = verify(rln_pointer, input_buffer, proof_is_valid_ptr);
            verify_time += now.elapsed().as_nanos();
            assert!(success, "verify call failed");
            assert_eq!(proof_is_valid, true);
        }

        println!(
            "Average prove API call time: {:?}",
            Duration::from_nanos((prove_time / sample_size).try_into().unwrap())
        );
        println!(
            "Average verify API call time: {:?}",
            Duration::from_nanos((verify_time / sample_size).try_into().unwrap())
        );
    }

    #[test]
    // Creating a RLN with raw data should generate same results as using a path to resources
    fn test_rln_raw_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We obtain the root from the RLN instance
        let root_rln_folder = get_tree_root(rln_pointer);

        #[cfg(feature = "arkzkey")]
        let zkey_path = "./resources/tree_height_20/rln_final.arkzkey";
        #[cfg(not(feature = "arkzkey"))]
        let zkey_path = "./resources/tree_height_20/rln_final.zkey";
        let mut zkey_file = File::open(&zkey_path).expect("no file found");
        let metadata = std::fs::metadata(&zkey_path).expect("unable to read metadata");
        let mut zkey_buffer = vec![0; metadata.len() as usize];
        zkey_file
            .read_exact(&mut zkey_buffer)
            .expect("buffer overflow");

        let zkey_data = &Buffer::from(&zkey_buffer[..]);

        let graph_data = "./resources/tree_height_20/graph.bin";
        let mut graph_file = File::open(&graph_data).expect("no file found");
        let metadata = std::fs::metadata(&graph_data).expect("unable to read metadata");
        let mut graph_buffer = vec![0; metadata.len() as usize];
        graph_file
            .read_exact(&mut graph_buffer)
            .expect("buffer overflow");

        let graph_data = &Buffer::from(&graph_buffer[..]);

        // Creating a RLN instance passing the raw data
        let mut rln_pointer_raw_bytes = MaybeUninit::<*mut RLN>::uninit();
        let tree_config = "".to_string();
        let tree_config_buffer = &Buffer::from(tree_config.as_bytes());
        let success = new_with_params(
            TEST_TREE_HEIGHT,
            zkey_data,
            graph_data,
            tree_config_buffer,
            rln_pointer_raw_bytes.as_mut_ptr(),
        );
        assert!(success, "RLN object creation failed");
        let rln_pointer2 = unsafe { &mut *rln_pointer_raw_bytes.assume_init() };

        // We obtain the root from the RLN instance containing raw data
        // And compare that the same root was generated
        let root_rln_raw = get_tree_root(rln_pointer2);
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
        let rln_pointer = create_rln_instance();

        // We add leaves in a batch into the tree
        set_leaves_init(rln_pointer, &leaves);

        // We generate a new identity pair
        let (identity_secret_hash, id_commitment) = identity_pair_gen(rln_pointer);
        let identity_index: usize = NO_OF_LEAVES;

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");
        // We generate a random rln_identifier
        let rln_identifier = hash_to_field(b"test-rln-identifier");
        // We generate a external nullifier
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);
        // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
        let message_id = Fr::from(1);

        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);

        // We set as leaf rate_commitment, its index would be equal to no_of_leaves
        let leaf_ser = fr_to_bytes_le(&rate_commitment);
        let input_buffer = &Buffer::from(leaf_ser.as_ref());
        let success = set_next_leaf(rln_pointer, input_buffer);
        assert!(success, "set next leaf call failed");

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | user_message_limit<32> | message_id<32> | external_nullifier<32> | signal_len<8> | signal<var> ]
        let prove_input = prepare_prove_input(
            identity_secret_hash,
            identity_index,
            user_message_limit,
            message_id,
            external_nullifier,
            &signal,
        );
        // We call generate_rln_proof
        // result_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
        let proof_data = rln_proof_gen(rln_pointer, prove_input.as_ref());

        // We prepare input for verify_rln_proof API
        // input_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var> ]
        // that is [ proof_data || signal_len<8> | signal<var> ]
        let verify_input = prepare_verify_input(proof_data, &signal);

        // We call verify_rln_proof
        let input_buffer = &Buffer::from(verify_input.as_ref());
        let mut proof_is_valid: bool = false;
        let proof_is_valid_ptr = &mut proof_is_valid as *mut bool;
        let success = verify_rln_proof(rln_pointer, input_buffer, proof_is_valid_ptr);
        assert!(success, "verify call failed");
        assert_eq!(proof_is_valid, true);
    }

    #[test]
    // Computes and verifies an RLN ZK proof by checking proof's root against an input roots buffer
    fn test_verify_with_roots_ffi() {
        // First part similar to test_rln_proof_ffi
        let user_message_limit = Fr::from(100);

        // We generate a vector of random leaves
        let leaves = get_random_leaves();
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We add leaves in a batch into the tree
        set_leaves_init(rln_pointer, &leaves);

        // We generate a new identity pair
        let (identity_secret_hash, id_commitment) = identity_pair_gen(rln_pointer);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);
        let identity_index: usize = NO_OF_LEAVES;

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");
        // We generate a random rln_identifier
        let rln_identifier = hash_to_field(b"test-rln-identifier");
        // We generate a external nullifier
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);
        // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
        let message_id = Fr::from(1);

        // We set as leaf rate_commitment, its index would be equal to no_of_leaves
        let leaf_ser = fr_to_bytes_le(&rate_commitment);
        let input_buffer = &Buffer::from(leaf_ser.as_ref());
        let success = set_next_leaf(rln_pointer, input_buffer);
        assert!(success, "set next leaf call failed");

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | user_message_limit<32> | message_id<32> | external_nullifier<32> | signal_len<8> | signal<var> ]
        let prove_input = prepare_prove_input(
            identity_secret_hash,
            identity_index,
            user_message_limit,
            message_id,
            external_nullifier,
            &signal,
        );

        // We call generate_rln_proof
        // result_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
        let proof_data = rln_proof_gen(rln_pointer, prove_input.as_ref());

        // We prepare input for verify_rln_proof API
        // input_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> | signal_len<8> | signal<var> ]
        // that is [ proof_data || signal_len<8> | signal<var> ]
        let verify_input = prepare_verify_input(proof_data.clone(), &signal);

        // We test verify_with_roots

        // We first try to verify against an empty buffer of roots.
        // In this case, since no root is provided, proof's root check is skipped and proof is verified if other proof values are valid
        let mut roots_data: Vec<u8> = Vec::new();

        let input_buffer = &Buffer::from(verify_input.as_ref());
        let roots_buffer = &Buffer::from(roots_data.as_ref());
        let mut proof_is_valid: bool = false;
        let proof_is_valid_ptr = &mut proof_is_valid as *mut bool;
        let success =
            verify_with_roots(rln_pointer, input_buffer, roots_buffer, proof_is_valid_ptr);
        assert!(success, "verify call failed");
        // Proof should be valid
        assert_eq!(proof_is_valid, true);

        // We then try to verify against some random values not containing the correct one.
        for _ in 0..5 {
            roots_data.append(&mut fr_to_bytes_le(&Fr::rand(&mut rng)));
        }
        let input_buffer = &Buffer::from(verify_input.as_ref());
        let roots_buffer = &Buffer::from(roots_data.as_ref());
        let mut proof_is_valid: bool = false;
        let proof_is_valid_ptr = &mut proof_is_valid as *mut bool;
        let success =
            verify_with_roots(rln_pointer, input_buffer, roots_buffer, proof_is_valid_ptr);
        assert!(success, "verify call failed");
        // Proof should be invalid.
        assert_eq!(proof_is_valid, false);

        // We finally include the correct root
        // We get the root of the tree obtained adding one leaf per time
        let root = get_tree_root(rln_pointer);

        // We include the root and verify the proof
        roots_data.append(&mut fr_to_bytes_le(&root));
        let input_buffer = &Buffer::from(verify_input.as_ref());
        let roots_buffer = &Buffer::from(roots_data.as_ref());
        let mut proof_is_valid: bool = false;
        let proof_is_valid_ptr = &mut proof_is_valid as *mut bool;
        let success =
            verify_with_roots(rln_pointer, input_buffer, roots_buffer, proof_is_valid_ptr);
        assert!(success, "verify call failed");
        // Proof should be valid.
        assert_eq!(proof_is_valid, true);
    }

    #[test]
    // Computes and verifies an RLN ZK proof using FFI APIs
    fn test_recover_id_secret_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We generate a new identity pair
        let (identity_secret_hash, id_commitment) = identity_pair_gen(rln_pointer);

        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);

        // We set as leaf rate_commitment, its index would be equal to 0 since tree is empty
        let leaf_ser = fr_to_bytes_le(&rate_commitment);
        let input_buffer = &Buffer::from(leaf_ser.as_ref());
        let success = set_next_leaf(rln_pointer, input_buffer);
        assert!(success, "set next leaf call failed");

        let identity_index: usize = 0;

        // We generate two proofs using same epoch but different signals.

        // We generate two random signals
        let mut rng = rand::thread_rng();
        let signal1: [u8; 32] = rng.gen();

        // We generate two random signals
        let signal2: [u8; 32] = rng.gen();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");
        // We generate a random rln_identifier
        let rln_identifier = hash_to_field(b"test-rln-identifier");
        // We generate a external nullifier
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);
        // We choose a message_id satisfy 0 <= message_id < MESSAGE_LIMIT
        let message_id = Fr::from(1);

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | user_message_limit<32> | message_id<32> | external_nullifier<32> | signal_len<8> | signal<var> ]
        let prove_input1 = prepare_prove_input(
            identity_secret_hash.clone(),
            identity_index,
            user_message_limit,
            message_id,
            external_nullifier,
            &signal1,
        );

        let prove_input2 = prepare_prove_input(
            identity_secret_hash.clone(),
            identity_index,
            user_message_limit,
            message_id,
            external_nullifier,
            &signal2,
        );

        // We call generate_rln_proof for first proof values
        // result_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
        let proof_data_1 = rln_proof_gen(rln_pointer, prove_input1.as_ref());

        // We call generate_rln_proof
        // result_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
        let proof_data_2 = rln_proof_gen(rln_pointer, prove_input2.as_ref());

        let input_proof_buffer_1 = &Buffer::from(proof_data_1.as_ref());
        let input_proof_buffer_2 = &Buffer::from(proof_data_2.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = recover_id_secret(
            rln_pointer,
            input_proof_buffer_1,
            input_proof_buffer_2,
            output_buffer.as_mut_ptr(),
        );
        assert!(success, "recover id secret call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let serialized_identity_secret_hash = <&[u8]>::from(&output_buffer).to_vec();

        // We passed two shares for the same secret, so recovery should be successful
        // To check it, we ensure that recovered identity secret hash is empty
        assert!(!serialized_identity_secret_hash.is_empty());

        // We check if the recovered identity secret hash corresponds to the original one
        let (recovered_identity_secret_hash, _) = bytes_le_to_fr(&serialized_identity_secret_hash);
        assert_eq!(recovered_identity_secret_hash, identity_secret_hash.clone().into());

        // We now test that computing identity_secret_hash is unsuccessful if shares computed from two different identity secret hashes but within same epoch are passed

        // We generate a new identity pair
        let (identity_secret_hash_new, id_commitment_new) = identity_pair_gen(rln_pointer);
        let rate_commitment_new = utils_poseidon_hash(&[id_commitment_new, user_message_limit]);

        // We set as leaf id_commitment, its index would be equal to 1 since at 0 there is id_commitment
        let leaf_ser = fr_to_bytes_le(&rate_commitment_new);
        let input_buffer = &Buffer::from(leaf_ser.as_ref());
        let success = set_next_leaf(rln_pointer, input_buffer);
        assert!(success, "set next leaf call failed");

        let identity_index_new: usize = 1;

        // We generate a random signals
        let signal3: [u8; 32] = rng.gen();

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        // Note that epoch is the same as before
        let prove_input3 = prepare_prove_input(
            identity_secret_hash.clone(),
            identity_index_new,
            user_message_limit,
            message_id,
            external_nullifier,
            &signal3,
        );

        // We call generate_rln_proof
        // result_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
        let proof_data_3 = rln_proof_gen(rln_pointer, prove_input3.as_ref());

        // We attempt to recover the secret using share1 (coming from identity_secret_hash) and share3 (coming from identity_secret_hash_new)

        let input_proof_buffer_1 = &Buffer::from(proof_data_1.as_ref());
        let input_proof_buffer_3 = &Buffer::from(proof_data_3.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = recover_id_secret(
            rln_pointer,
            input_proof_buffer_1,
            input_proof_buffer_3,
            output_buffer.as_mut_ptr(),
        );
        assert!(success, "recover id secret call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let serialized_identity_secret_hash = <&[u8]>::from(&output_buffer).to_vec();
        let (recovered_identity_secret_hash_new, _) =
            bytes_le_to_fr(&serialized_identity_secret_hash);

        // ensure that the recovered secret does not match with either of the
        // used secrets in proof generation
        assert_ne!(recovered_identity_secret_hash_new, identity_secret_hash_new.into());
    }

    #[test]
    // Tests hash to field using FFI APIs
    fn test_seeded_keygen_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We generate a new identity pair from an input seed
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let input_buffer = &Buffer::from(seed_bytes);
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = seeded_key_gen(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "seeded key gen call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (identity_secret_hash, read) = bytes_le_to_fr(&result_data);
        let (id_commitment, _) = bytes_le_to_fr(&result_data[read..].to_vec());

        // We check against expected values
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        );
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0xbf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f",
            16,
        );

        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_bytes.unwrap()
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes.unwrap());
    }

    #[test]
    // Tests hash to field using FFI APIs
    fn test_seeded_extended_keygen_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We generate a new identity tuple from an input seed
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let input_buffer = &Buffer::from(seed_bytes);
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success =
            seeded_extended_key_gen(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "seeded key gen call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
            deserialize_identity_tuple(result_data);

        // We check against expected values
        let expected_identity_trapdoor_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        );
        let expected_identity_nullifier_seed_bytes = str_to_fr(
            "0x1f18714c7bc83b5bca9e89d404cf6f2f585bc4c0f7ed8b53742b7e2b298f50b4",
            16,
        );
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x2aca62aaa7abaf3686fff2caf00f55ab9462dc12db5b5d4bcf3994e671f8e521",
            16,
        );
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0x68b66aa0a8320d2e56842581553285393188714c48f9b17acd198b4f1734c5c",
            16,
        );

        assert_eq!(
            identity_trapdoor,
            expected_identity_trapdoor_seed_bytes.unwrap()
        );
        assert_eq!(
            identity_nullifier,
            expected_identity_nullifier_seed_bytes.unwrap()
        );
        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_bytes.unwrap()
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes.unwrap());
    }

    #[test]
    // Tests hash to field using FFI APIs
    fn test_hash_to_field_ffi() {
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        // We prepare id_commitment and we set the leaf at provided index
        let input_buffer = &Buffer::from(signal.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = ffi_hash(input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "hash call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };

        // We read the returned proof and we append proof values for verify
        let serialized_hash = <&[u8]>::from(&output_buffer).to_vec();
        let (hash1, _) = bytes_le_to_fr(&serialized_hash);

        let hash2 = hash_to_field(&signal);

        assert_eq!(hash1, hash2);
    }

    #[test]
    // Test Poseidon hash FFI
    fn test_poseidon_hash_ffi() {
        // generate random number between 1..ROUND_PARAMS.len()
        let mut rng = thread_rng();
        let number_of_inputs = rng.gen_range(1..ROUND_PARAMS.len());
        let mut inputs = Vec::with_capacity(number_of_inputs);
        for _ in 0..number_of_inputs {
            inputs.push(Fr::rand(&mut rng));
        }
        let inputs_ser = vec_fr_to_bytes_le(&inputs);
        let input_buffer = &Buffer::from(inputs_ser.as_ref());

        let expected_hash = utils_poseidon_hash(inputs.as_ref());

        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = ffi_poseidon_hash(input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "poseidon hash call failed");

        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (received_hash, _) = bytes_le_to_fr(&result_data);

        assert_eq!(received_hash, expected_hash);
    }

    #[test]
    fn test_get_leaf_ffi() {
        // We create a RLN instance
        let no_of_leaves = 1 << TEST_TREE_HEIGHT;

        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We generate a new identity tuple from an input seed
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let input_buffer = &Buffer::from(seed_bytes);
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success =
            seeded_extended_key_gen(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "seeded key gen call failed");

        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (_, _, _, id_commitment) = deserialize_identity_tuple(result_data);

        // We insert the id_commitment into the tree at a random index
        let mut rng = thread_rng();
        let index = rng.gen_range(0..no_of_leaves) as usize;
        let leaf = fr_to_bytes_le(&id_commitment);
        let input_buffer = &Buffer::from(leaf.as_ref());
        let success = set_leaf(rln_pointer, index, input_buffer);
        assert!(success, "set leaf call failed");

        // We get the leaf at the same index
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_leaf(rln_pointer, index, output_buffer.as_mut_ptr());
        assert!(success, "get leaf call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (received_id_commitment, _) = bytes_le_to_fr(&result_data);

        // We check that the received id_commitment is the same as the one we inserted
        assert_eq!(received_id_commitment, id_commitment);
    }

    #[test]
    fn test_valid_metadata_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let input_buffer = &Buffer::from(seed_bytes);

        let success = set_metadata(rln_pointer, input_buffer);
        assert!(success, "set_metadata call failed");

        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_metadata(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get_metadata call failed");

        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();

        assert_eq!(result_data, seed_bytes.to_vec());
    }

    #[test]
    fn test_empty_metadata_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_metadata(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get_metadata call failed");

        let output_buffer = unsafe { output_buffer.assume_init() };
        assert_eq!(output_buffer.len, 0);
    }
}

#[cfg(test)]
#[cfg(feature = "stateless")]
mod stateless_test {
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;
    use rln::circuit::*;
    use rln::ffi::generate_rln_proof_with_witness;
    use rln::ffi::{hash as ffi_hash, poseidon_hash as ffi_poseidon_hash, *};
    use rln::hashers::{hash_to_field, poseidon_hash as utils_poseidon_hash, ROUND_PARAMS};
    use rln::poseidon_tree::PoseidonTree;
    use rln::protocol::*;
    use rln::public::RLN;
    use rln::utils::*;
    use std::mem::MaybeUninit;
    use std::time::{Duration, Instant};
    use utils::ZerokitMerkleTree;

    type ConfigOf<T> = <T as ZerokitMerkleTree>::Config;

    fn create_rln_instance() -> &'static mut RLN {
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let success = new(rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        unsafe { &mut *rln_pointer.assume_init() }
    }

    fn identity_pair_gen(rln_pointer: &mut RLN) -> (Fr, Fr) {
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = key_gen(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "key gen call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (identity_secret_hash, read) = bytes_le_to_fr(&result_data);
        let (id_commitment, _) = bytes_le_to_fr(&result_data[read..].to_vec());
        (identity_secret_hash, id_commitment)
    }

    fn rln_proof_gen_with_witness(rln_pointer: &mut RLN, serialized: &[u8]) -> Vec<u8> {
        let input_buffer = &Buffer::from(serialized);
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success =
            generate_rln_proof_with_witness(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "generate rln proof call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        <&[u8]>::from(&output_buffer).to_vec()
    }

    #[test]
    fn test_recover_id_secret_stateless_ffi() {
        let default_leaf = Fr::from(0);
        let mut tree = PoseidonTree::new(
            TEST_TREE_HEIGHT,
            default_leaf,
            ConfigOf::<PoseidonTree>::default(),
        )
        .unwrap();

        let rln_pointer = create_rln_instance();

        // We generate a new identity pair
        let (identity_secret_hash, id_commitment) = identity_pair_gen(rln_pointer);

        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);
        tree.update_next(rate_commitment).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");
        let rln_identifier = hash_to_field(b"test-rln-identifier");
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);

        // We generate two proofs using same epoch but different signals.
        // We generate a random signal
        let mut rng = thread_rng();
        let signal1: [u8; 32] = rng.gen();
        let x1 = hash_to_field(&signal1);

        let signal2: [u8; 32] = rng.gen();
        let x2 = hash_to_field(&signal2);

        let identity_index = tree.leaves_set();
        let merkle_proof = tree.proof(identity_index).expect("proof should exist");

        // We prepare input for generate_rln_proof API
        let rln_witness1 = rln_witness_from_values(
            identity_secret_hash,
            &merkle_proof,
            x1,
            external_nullifier,
            user_message_limit,
            Fr::from(1),
        )
        .unwrap();
        let serialized1 = serialize_witness(&rln_witness1).unwrap();

        let rln_witness2 = rln_witness_from_values(
            identity_secret_hash,
            &merkle_proof,
            x2,
            external_nullifier,
            user_message_limit,
            Fr::from(1),
        )
        .unwrap();
        let serialized2 = serialize_witness(&rln_witness2).unwrap();

        // We call generate_rln_proof for first proof values
        // result_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
        let proof_data_1 = rln_proof_gen_with_witness(rln_pointer, serialized1.as_ref());

        // We call generate_rln_proof
        // result_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
        let proof_data_2 = rln_proof_gen_with_witness(rln_pointer, serialized2.as_ref());

        let input_proof_buffer_1 = &Buffer::from(proof_data_1.as_ref());
        let input_proof_buffer_2 = &Buffer::from(proof_data_2.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = recover_id_secret(
            rln_pointer,
            input_proof_buffer_1,
            input_proof_buffer_2,
            output_buffer.as_mut_ptr(),
        );
        assert!(success, "recover id secret call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let serialized_identity_secret_hash = <&[u8]>::from(&output_buffer).to_vec();

        // We passed two shares for the same secret, so recovery should be successful
        // To check it, we ensure that recovered identity secret hash is empty
        assert!(!serialized_identity_secret_hash.is_empty());

        // We check if the recovered identity secret hash corresponds to the original one
        let (recovered_identity_secret_hash, _) = bytes_le_to_fr(&serialized_identity_secret_hash);
        assert_eq!(recovered_identity_secret_hash, identity_secret_hash);

        // We now test that computing identity_secret_hash is unsuccessful if shares computed from two different identity secret hashes but within same epoch are passed

        // We generate a new identity pair
        let (identity_secret_hash_new, id_commitment_new) = identity_pair_gen(rln_pointer);
        let rate_commitment_new = utils_poseidon_hash(&[id_commitment_new, user_message_limit]);
        tree.update_next(rate_commitment_new).unwrap();

        // We generate a random signals
        let signal3: [u8; 32] = rng.gen();
        let x3 = hash_to_field(&signal3);

        let identity_index_new = tree.leaves_set();
        let merkle_proof_new = tree.proof(identity_index_new).expect("proof should exist");

        let rln_witness3 = rln_witness_from_values(
            identity_secret_hash_new,
            &merkle_proof_new,
            x3,
            external_nullifier,
            user_message_limit,
            Fr::from(1),
        )
        .unwrap();
        let serialized3 = serialize_witness(&rln_witness3).unwrap();

        // We call generate_rln_proof
        // result_data is [ proof<128> | root<32> | external_nullifier<32> | x<32> | y<32> | nullifier<32> ]
        let proof_data_3 = rln_proof_gen_with_witness(rln_pointer, serialized3.as_ref());

        // We attempt to recover the secret using share1 (coming from identity_secret_hash) and share3 (coming from identity_secret_hash_new)

        let input_proof_buffer_1 = &Buffer::from(proof_data_1.as_ref());
        let input_proof_buffer_3 = &Buffer::from(proof_data_3.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = recover_id_secret(
            rln_pointer,
            input_proof_buffer_1,
            input_proof_buffer_3,
            output_buffer.as_mut_ptr(),
        );
        assert!(success, "recover id secret call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let serialized_identity_secret_hash = <&[u8]>::from(&output_buffer).to_vec();
        let (recovered_identity_secret_hash_new, _) =
            bytes_le_to_fr(&serialized_identity_secret_hash);

        // ensure that the recovered secret does not match with either of the
        // used secrets in proof generation
        assert_ne!(recovered_identity_secret_hash_new, identity_secret_hash_new);
    }

    #[test]
    fn test_verify_with_roots_stateless_ffi() {
        let default_leaf = Fr::from(0);
        let mut tree = PoseidonTree::new(
            TEST_TREE_HEIGHT,
            default_leaf,
            ConfigOf::<PoseidonTree>::default(),
        )
        .unwrap();

        let rln_pointer = create_rln_instance();

        // We generate a new identity pair
        let (identity_secret_hash, id_commitment) = identity_pair_gen(rln_pointer);

        let identity_index = tree.leaves_set();
        let user_message_limit = Fr::from(100);
        let rate_commitment = utils_poseidon_hash(&[id_commitment, user_message_limit]);
        tree.update_next(rate_commitment).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");
        let rln_identifier = hash_to_field(b"test-rln-identifier");
        let external_nullifier = utils_poseidon_hash(&[epoch, rln_identifier]);

        // We generate two proofs using same epoch but different signals.
        // We generate a random signal
        let mut rng = thread_rng();
        let signal: [u8; 32] = rng.gen();
        let x = hash_to_field(&signal);

        let merkle_proof = tree.proof(identity_index).expect("proof should exist");

        // We prepare input for generate_rln_proof API
        let rln_witness = rln_witness_from_values(
            identity_secret_hash,
            &merkle_proof,
            x,
            external_nullifier,
            user_message_limit,
            Fr::from(1),
        )
        .unwrap();

        let serialized = serialize_witness(&rln_witness).unwrap();
        let proof_data = rln_proof_gen_with_witness(rln_pointer, serialized.as_ref());

        let verify_input = prepare_verify_input(proof_data.clone(), &signal);

        // If no roots is provided, proof validation is skipped and if the remaining proof values are valid, the proof will be correctly verified
        let mut roots_data: Vec<u8> = Vec::new();

        let input_buffer = &Buffer::from(verify_input.as_ref());
        let roots_buffer = &Buffer::from(roots_data.as_ref());
        let mut proof_is_valid: bool = false;
        let proof_is_valid_ptr = &mut proof_is_valid as *mut bool;
        let success =
            verify_with_roots(rln_pointer, input_buffer, roots_buffer, proof_is_valid_ptr);
        assert!(success, "verify call failed");
        // Proof should be valid
        assert_eq!(proof_is_valid, true);

        // We serialize in the roots buffer some random values and we check that the proof is not verified since doesn't contain the correct root the proof refers to
        for _ in 0..5 {
            roots_data.append(&mut fr_to_bytes_le(&Fr::rand(&mut rng)));
        }
        let input_buffer = &Buffer::from(verify_input.as_ref());
        let roots_buffer = &Buffer::from(roots_data.as_ref());
        let mut proof_is_valid: bool = false;
        let proof_is_valid_ptr = &mut proof_is_valid as *mut bool;
        let success =
            verify_with_roots(rln_pointer, input_buffer, roots_buffer, proof_is_valid_ptr);
        assert!(success, "verify call failed");
        // Proof should be invalid.
        assert_eq!(proof_is_valid, false);

        // We get the root of the tree obtained adding one leaf per time
        let root = tree.root();

        // We add the real root and we check if now the proof is verified
        roots_data.append(&mut fr_to_bytes_le(&root));
        let input_buffer = &Buffer::from(verify_input.as_ref());
        let roots_buffer = &Buffer::from(roots_data.as_ref());
        let mut proof_is_valid: bool = false;
        let proof_is_valid_ptr = &mut proof_is_valid as *mut bool;
        let success =
            verify_with_roots(rln_pointer, input_buffer, roots_buffer, proof_is_valid_ptr);
        assert!(success, "verify call failed");
        // Proof should be valid.
        assert_eq!(proof_is_valid, true);
    }

    #[test]
    fn test_groth16_proofs_performance_stateless_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We compute some benchmarks regarding proof and verify API calls
        // Note that circuit loading requires some initial overhead.
        // Once the circuit is loaded (i.e., when the RLN object is created), proof generation and verification times should be similar at each call.
        let sample_size = 100;
        let mut prove_time: u128 = 0;
        let mut verify_time: u128 = 0;

        for _ in 0..sample_size {
            // We generate random witness instances and relative proof values
            let rln_witness = random_rln_witness(TEST_TREE_HEIGHT);
            let proof_values = proof_values_from_witness(&rln_witness).unwrap();

            // We prepare id_commitment and we set the leaf at provided index
            let rln_witness_ser = serialize_witness(&rln_witness).unwrap();
            let input_buffer = &Buffer::from(rln_witness_ser.as_ref());
            let mut output_buffer = MaybeUninit::<Buffer>::uninit();
            let now = Instant::now();
            let success = prove(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
            prove_time += now.elapsed().as_nanos();
            assert!(success, "prove call failed");
            let output_buffer = unsafe { output_buffer.assume_init() };

            // We read the returned proof and we append proof values for verify
            let serialized_proof = <&[u8]>::from(&output_buffer).to_vec();
            let serialized_proof_values = serialize_proof_values(&proof_values);
            let mut verify_data = Vec::<u8>::new();
            verify_data.extend(&serialized_proof);
            verify_data.extend(&serialized_proof_values);

            // We prepare input proof values and we call verify
            let input_buffer = &Buffer::from(verify_data.as_ref());
            let mut proof_is_valid: bool = false;
            let proof_is_valid_ptr = &mut proof_is_valid as *mut bool;
            let now = Instant::now();
            let success = verify(rln_pointer, input_buffer, proof_is_valid_ptr);
            verify_time += now.elapsed().as_nanos();
            assert!(success, "verify call failed");
            assert_eq!(proof_is_valid, true);
        }

        println!(
            "Average prove API call time: {:?}",
            Duration::from_nanos((prove_time / sample_size).try_into().unwrap())
        );
        println!(
            "Average verify API call time: {:?}",
            Duration::from_nanos((verify_time / sample_size).try_into().unwrap())
        );
    }

    #[test]
    // Tests hash to field using FFI APIs
    fn test_seeded_keygen_stateless_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We generate a new identity pair from an input seed
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let input_buffer = &Buffer::from(seed_bytes);
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = seeded_key_gen(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "seeded key gen call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (identity_secret_hash, read) = bytes_le_to_fr(&result_data);
        let (id_commitment, _) = bytes_le_to_fr(&result_data[read..].to_vec());

        // We check against expected values
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        );
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0xbf16d2b5c0d6f9d9d561e05bfca16a81b4b873bb063508fae360d8c74cef51f",
            16,
        );

        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_bytes.unwrap()
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes.unwrap());
    }

    #[test]
    // Tests hash to field using FFI APIs
    fn test_seeded_extended_keygen_stateless_ffi() {
        // We create a RLN instance
        let rln_pointer = create_rln_instance();

        // We generate a new identity tuple from an input seed
        let seed_bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let input_buffer = &Buffer::from(seed_bytes);
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success =
            seeded_extended_key_gen(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "seeded key gen call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (identity_trapdoor, identity_nullifier, identity_secret_hash, id_commitment) =
            deserialize_identity_tuple(result_data);

        // We check against expected values
        let expected_identity_trapdoor_seed_bytes = str_to_fr(
            "0x766ce6c7e7a01bdf5b3f257616f603918c30946fa23480f2859c597817e6716",
            16,
        );
        let expected_identity_nullifier_seed_bytes = str_to_fr(
            "0x1f18714c7bc83b5bca9e89d404cf6f2f585bc4c0f7ed8b53742b7e2b298f50b4",
            16,
        );
        let expected_identity_secret_hash_seed_bytes = str_to_fr(
            "0x2aca62aaa7abaf3686fff2caf00f55ab9462dc12db5b5d4bcf3994e671f8e521",
            16,
        );
        let expected_id_commitment_seed_bytes = str_to_fr(
            "0x68b66aa0a8320d2e56842581553285393188714c48f9b17acd198b4f1734c5c",
            16,
        );

        assert_eq!(
            identity_trapdoor,
            expected_identity_trapdoor_seed_bytes.unwrap()
        );
        assert_eq!(
            identity_nullifier,
            expected_identity_nullifier_seed_bytes.unwrap()
        );
        assert_eq!(
            identity_secret_hash,
            expected_identity_secret_hash_seed_bytes.unwrap()
        );
        assert_eq!(id_commitment, expected_id_commitment_seed_bytes.unwrap());
    }

    #[test]
    // Tests hash to field using FFI APIs
    fn test_hash_to_field_stateless_ffi() {
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        // We prepare id_commitment and we set the leaf at provided index
        let input_buffer = &Buffer::from(signal.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = ffi_hash(input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "hash call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };

        // We read the returned proof and we append proof values for verify
        let serialized_hash = <&[u8]>::from(&output_buffer).to_vec();
        let (hash1, _) = bytes_le_to_fr(&serialized_hash);

        let hash2 = hash_to_field(&signal);

        assert_eq!(hash1, hash2);
    }

    #[test]
    // Test Poseidon hash FFI
    fn test_poseidon_hash_stateless_ffi() {
        // generate random number between 1..ROUND_PARAMS.len()
        let mut rng = thread_rng();
        let number_of_inputs = rng.gen_range(1..ROUND_PARAMS.len());
        let mut inputs = Vec::with_capacity(number_of_inputs);
        for _ in 0..number_of_inputs {
            inputs.push(Fr::rand(&mut rng));
        }
        let inputs_ser = vec_fr_to_bytes_le(&inputs);
        let input_buffer = &Buffer::from(inputs_ser.as_ref());

        let expected_hash = utils_poseidon_hash(inputs.as_ref());

        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = ffi_poseidon_hash(input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "poseidon hash call failed");

        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (received_hash, _) = bytes_le_to_fr(&result_data);

        assert_eq!(received_hash, expected_hash);
    }
}
