#[cfg(test)]
mod test {
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;
    use rln::circuit::*;
    use rln::ffi::{hash as ffi_hash, poseidon_hash as ffi_poseidon_hash, *};
    use rln::poseidon_hash::{poseidon_hash as utils_poseidon_hash, ROUND_PARAMS};
    use rln::protocol::*;
    use rln::public::RLN;
    use rln::utils::*;
    use std::fs::File;
    use std::io::Read;
    use std::mem::MaybeUninit;
    use std::time::{Duration, Instant};

    #[test]
    // We test merkle batch Merkle tree additions
    fn test_merkle_operations_ffi() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

        // We first add leaves one by one specifying the index
        for (i, leaf) in leaves.iter().enumerate() {
            // We prepare id_commitment and we set the leaf at provided index
            let leaf_ser = fr_to_bytes_le(&leaf);
            let input_buffer = &Buffer::from(leaf_ser.as_ref());
            let success = set_leaf(rln_pointer, i, input_buffer);
            assert!(success, "set leaf call failed");
        }

        // We get the root of the tree obtained adding one leaf per time
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_single, _) = bytes_le_to_fr(&result_data);

        // We reset the tree to default
        let success = set_tree(rln_pointer, tree_height);
        assert!(success, "set tree call failed");

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let leaf_ser = fr_to_bytes_le(&leaf);
            let input_buffer = &Buffer::from(leaf_ser.as_ref());
            let success = set_next_leaf(rln_pointer, input_buffer);
            assert!(success, "set next leaf call failed");
        }

        // We get the root of the tree obtained adding leaves using the internal index
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_next, _) = bytes_le_to_fr(&result_data);

        // We check if roots are the same
        assert_eq!(root_single, root_next);

        // We reset the tree to default
        let success = set_tree(rln_pointer, tree_height);
        assert!(success, "set tree call failed");

        // We add leaves in a batch into the tree
        let leaves_ser = vec_fr_to_bytes_le(&leaves).unwrap();
        let input_buffer = &Buffer::from(leaves_ser.as_ref());
        let success = init_tree_with_leaves(rln_pointer, input_buffer);
        assert!(success, "init tree with leaves call failed");

        // We get the root of the tree obtained adding leaves in batch
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_batch, _) = bytes_le_to_fr(&result_data);

        // We check if roots are the same
        assert_eq!(root_single, root_batch);

        // We now delete all leaves set and check if the root corresponds to the empty tree root
        // delete calls over indexes higher than no_of_leaves are ignored and will not increase self.tree.next_index
        let delete_range = 2 * no_of_leaves;
        for i in 0..delete_range {
            let success = delete_leaf(rln_pointer, i);
            assert!(success, "delete leaf call failed");
        }

        // We get the root of the tree obtained deleting all leaves
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_delete, _) = bytes_le_to_fr(&result_data);

        // We reset the tree to default
        let success = set_tree(rln_pointer, tree_height);
        assert!(success, "set tree call failed");

        // We get the root of the empty tree
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_empty, _) = bytes_le_to_fr(&result_data);

        // We check if roots are the same
        assert_eq!(root_delete, root_empty);
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    // Uses `set_leaves_from` to set leaves in a batch
    fn test_leaf_setting_with_index_ffi() {
        // We create a new tree
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // set_index is the index from which we start setting leaves
        // random number between 0..no_of_leaves
        let set_index = rng.gen_range(0..no_of_leaves) as usize;

        // We add leaves in a batch into the tree
        let leaves_ser = vec_fr_to_bytes_le(&leaves).unwrap();
        let input_buffer = &Buffer::from(leaves_ser.as_ref());
        let success = init_tree_with_leaves(rln_pointer, input_buffer);
        assert!(success, "init tree with leaves call failed");

        // We get the root of the tree obtained adding leaves in batch
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");

        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_batch_with_init, _) = bytes_le_to_fr(&result_data);

        // `init_tree_with_leaves` resets the tree to the height it was initialized with, using `set_tree`

        // We add leaves in a batch starting from index 0..set_index
        let leaves_m = vec_fr_to_bytes_le(&leaves[0..set_index]).unwrap();
        let buffer = &Buffer::from(leaves_m.as_ref());
        let success = init_tree_with_leaves(rln_pointer, buffer);
        assert!(success, "init tree with leaves call failed");

        // We add the remaining n leaves in a batch starting from index set_index
        let leaves_n = vec_fr_to_bytes_le(&leaves[set_index..]).unwrap();
        let buffer = &Buffer::from(leaves_n.as_ref());
        let success = set_leaves_from(rln_pointer, set_index, buffer);
        assert!(success, "set leaves from call failed");

        // We get the root of the tree obtained adding leaves in batch
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");

        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_batch_with_custom_index, _) = bytes_le_to_fr(&result_data);

        assert_eq!(root_batch_with_init, root_batch_with_custom_index);

        // We reset the tree to default
        let success = set_tree(rln_pointer, tree_height);
        assert!(success, "set tree call failed");

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let leaf_ser = fr_to_bytes_le(&leaf);
            let input_buffer = &Buffer::from(leaf_ser.as_ref());
            let success = set_next_leaf(rln_pointer, input_buffer);
            assert!(success, "set next leaf call failed");
        }

        // We get the root of the tree obtained adding leaves using the internal index
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");

        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_single_additions, _) = bytes_le_to_fr(&result_data);

        assert_eq!(root_batch_with_init, root_single_additions);
    }

    #[test]
    // This test is similar to the one in public.rs but it uses the RLN object as a pointer
    fn test_set_leaves_bad_index_ffi() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        let bad_index = (1 << tree_height) - rng.gen_range(0..no_of_leaves) as usize;

        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

        // Get root of empty tree
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");

        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_empty, _) = bytes_le_to_fr(&result_data);

        // We add leaves in a batch into the tree
        let leaves = vec_fr_to_bytes_le(&leaves);
        let buffer = &Buffer::from(leaves.unwrap().as_ref());
        let success = set_leaves_from(rln_pointer, bad_index, buffer);
        assert!(!success, "set leaves from call succeeded");

        // Get root of tree after attempted set
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");

        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_after_bad_set, _) = bytes_le_to_fr(&result_data);

        assert_eq!(root_empty, root_after_bad_set);
    }

    #[test]
    // This test is similar to the one in lib, but uses only public C API
    fn test_merkle_proof_ffi() {
        let tree_height = TEST_TREE_HEIGHT;
        let leaf_index = 3;

        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

        // generate identity
        let identity_secret_hash = hash_to_field(b"test-merkle-proof");
        let id_commitment = utils_poseidon_hash(&vec![identity_secret_hash]);

        // We prepare id_commitment and we set the leaf at provided index
        let leaf_ser = fr_to_bytes_le(&id_commitment);
        let input_buffer = &Buffer::from(leaf_ser.as_ref());
        let success = set_leaf(rln_pointer, leaf_index, input_buffer);
        assert!(success, "set leaf call failed");

        // We obtain the Merkle tree root
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root, _) = bytes_le_to_fr(&result_data);

        // We obtain the Merkle tree root
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_proof(rln_pointer, leaf_index, output_buffer.as_mut_ptr());
        assert!(success, "get merkle proof call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();

        let (path_elements, read) = bytes_le_to_vec_fr(&result_data).unwrap();
        let (identity_path_index, _) = bytes_le_to_vec_u8(&result_data[read..].to_vec()).unwrap();

        // We check correct computation of the path and indexes
        let mut expected_path_elements = vec![
            str_to_fr(
                "0x0000000000000000000000000000000000000000000000000000000000000000",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0",
                16,
            )
            .unwrap(),
            str_to_fr(
                "0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c",
                16,
            )
            .unwrap(),
        ];

        let mut expected_identity_path_index: Vec<u8> =
            vec![1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        // We add the remaining elements for the case TEST_TREE_HEIGHT = 19
        if TEST_TREE_HEIGHT == 19 || TEST_TREE_HEIGHT == 20 {
            expected_path_elements.append(&mut vec![
                str_to_fr(
                    "0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92",
                    16,
                )
                .unwrap(),
                str_to_fr(
                    "0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323",
                    16,
                )
                .unwrap(),
                str_to_fr(
                    "0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992",
                    16,
                )
                .unwrap(),
                str_to_fr(
                    "0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f",
                    16,
                )
                .unwrap(),
            ]);
            expected_identity_path_index.append(&mut vec![0, 0, 0, 0]);
        }

        if TEST_TREE_HEIGHT == 20 {
            expected_path_elements.append(&mut vec![str_to_fr(
                "0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca",
                16,
            )
            .unwrap()]);
            expected_identity_path_index.append(&mut vec![0]);
        }

        assert_eq!(path_elements, expected_path_elements);
        assert_eq!(identity_path_index, expected_identity_path_index);

        // We double check that the proof computed from public API is correct
        let root_from_proof =
            compute_tree_root(&id_commitment, &path_elements, &identity_path_index, false);

        assert_eq!(root, root_from_proof);
    }

    #[test]
    // Benchmarks proof generation and verification
    fn test_groth16_proofs_performance_ffi() {
        let tree_height = TEST_TREE_HEIGHT;

        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

        // We compute some benchmarks regarding proof and verify API calls
        // Note that circuit loading requires some initial overhead.
        // Once the circuit is loaded (i.e., when the RLN object is created), proof generation and verification times should be similar at each call.
        let sample_size = 100;
        let mut prove_time: u128 = 0;
        let mut verify_time: u128 = 0;

        for _ in 0..sample_size {
            // We generate random witness instances and relative proof values
            let rln_witness = random_rln_witness(tree_height);
            let proof_values = proof_values_from_witness(&rln_witness);

            // We prepare id_commitment and we set the leaf at provided index
            let rln_witness_ser = serialize_witness(&rln_witness);
            let input_buffer = &Buffer::from(rln_witness_ser.unwrap().as_ref());
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
        let tree_height = TEST_TREE_HEIGHT;

        // We create a RLN instance using a resource folder path
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

        // We obtain the root from the RLN instance
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_rln_folder, _) = bytes_le_to_fr(&result_data);

        // Reading the raw data from the files required for instantiating a RLN instance using raw data
        let circom_path = format!("./resources/tree_height_{TEST_TREE_HEIGHT}/rln.wasm");
        let mut circom_file = File::open(&circom_path).expect("no file found");
        let metadata = std::fs::metadata(&circom_path).expect("unable to read metadata");
        let mut circom_buffer = vec![0; metadata.len() as usize];
        circom_file
            .read_exact(&mut circom_buffer)
            .expect("buffer overflow");

        let zkey_path = format!("./resources/tree_height_{TEST_TREE_HEIGHT}/rln_final.zkey");
        let mut zkey_file = File::open(&zkey_path).expect("no file found");
        let metadata = std::fs::metadata(&zkey_path).expect("unable to read metadata");
        let mut zkey_buffer = vec![0; metadata.len() as usize];
        zkey_file
            .read_exact(&mut zkey_buffer)
            .expect("buffer overflow");

        let vk_path = format!("./resources/tree_height_{TEST_TREE_HEIGHT}/verification_key.json");

        let mut vk_file = File::open(&vk_path).expect("no file found");
        let metadata = std::fs::metadata(&vk_path).expect("unable to read metadata");
        let mut vk_buffer = vec![0; metadata.len() as usize];
        vk_file.read_exact(&mut vk_buffer).expect("buffer overflow");

        let circom_data = &Buffer::from(&circom_buffer[..]);
        let zkey_data = &Buffer::from(&zkey_buffer[..]);
        let vk_data = &Buffer::from(&vk_buffer[..]);

        // Creating a RLN instance passing the raw data
        let mut rln_pointer_raw_bytes = MaybeUninit::<*mut RLN>::uninit();
        let success = new_with_params(
            tree_height,
            circom_data,
            zkey_data,
            vk_data,
            rln_pointer_raw_bytes.as_mut_ptr(),
        );
        assert!(success, "RLN object creation failed");
        let rln_pointer2 = unsafe { &mut *rln_pointer_raw_bytes.assume_init() };

        // We obtain the root from the RLN instance containing raw data
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer2, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_rln_raw, _) = bytes_le_to_fr(&result_data);

        // And compare that the same root was generated
        assert_eq!(root_rln_folder, root_rln_raw);
    }

    #[test]
    // Computes and verifies an RLN ZK proof using FFI APIs
    fn test_rln_proof_ffi() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

        // We add leaves in a batch into the tree
        let leaves_ser = vec_fr_to_bytes_le(&leaves).unwrap();
        let input_buffer = &Buffer::from(leaves_ser.as_ref());
        let success = init_tree_with_leaves(rln_pointer, input_buffer);
        assert!(success, "init tree with leaves call failed");

        // We generate a new identity pair
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = key_gen(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "key gen call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (identity_secret_hash, read) = bytes_le_to_fr(&result_data);
        let (id_commitment, _) = bytes_le_to_fr(&result_data[read..].to_vec());

        // We set as leaf id_commitment, its index would be equal to no_of_leaves
        let leaf_ser = fr_to_bytes_le(&id_commitment);
        let input_buffer = &Buffer::from(leaf_ser.as_ref());
        let success = set_next_leaf(rln_pointer, input_buffer);
        assert!(success, "set next leaf call failed");

        let identity_index: u64 = no_of_leaves;

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();
        let signal_len = u64::try_from(signal.len()).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut fr_to_bytes_le(&identity_secret_hash));
        serialized.append(&mut identity_index.to_le_bytes().to_vec());
        serialized.append(&mut fr_to_bytes_le(&epoch));
        serialized.append(&mut signal_len.to_le_bytes().to_vec());
        serialized.append(&mut signal.to_vec());

        // We call generate_rln_proof
        let input_buffer = &Buffer::from(serialized.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = generate_rln_proof(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "generate rln proof call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        // result_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> ]
        let mut proof_data = <&[u8]>::from(&output_buffer).to_vec();

        // We prepare input for verify_rln_proof API
        // input_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> | signal_len<8> | signal<var> ]
        // that is [ proof_data | signal_len<8> | signal<var> ]
        proof_data.append(&mut signal_len.to_le_bytes().to_vec());
        proof_data.append(&mut signal.to_vec());

        // We call verify_rln_proof
        let input_buffer = &Buffer::from(proof_data.as_ref());
        let mut proof_is_valid: bool = false;
        let proof_is_valid_ptr = &mut proof_is_valid as *mut bool;
        let success = verify_rln_proof(rln_pointer, input_buffer, proof_is_valid_ptr);
        assert!(success, "verify call failed");
        assert_eq!(proof_is_valid, true);
    }

    #[test]
    // Computes and verifies an RLN ZK proof by checking proof's root against an input roots buffer
    fn test_verify_with_roots() {
        // First part similar to test_rln_proof_ffi
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Fr> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(Fr::rand(&mut rng));
        }

        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

        // We add leaves in a batch into the tree
        let leaves_ser = vec_fr_to_bytes_le(&leaves);
        let input_buffer = &Buffer::from(leaves_ser.unwrap().as_ref());
        let success = init_tree_with_leaves(rln_pointer, input_buffer);
        assert!(success, "set leaves call failed");

        // We generate a new identity pair
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = key_gen(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "key gen call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (identity_secret_hash, read) = bytes_le_to_fr(&result_data);
        let (id_commitment, _) = bytes_le_to_fr(&result_data[read..].to_vec());

        // We set as leaf id_commitment, its index would be equal to no_of_leaves
        let leaf_ser = fr_to_bytes_le(&id_commitment);
        let input_buffer = &Buffer::from(leaf_ser.as_ref());
        let success = set_next_leaf(rln_pointer, input_buffer);
        assert!(success, "set next leaf call failed");

        let identity_index: u64 = no_of_leaves;

        // We generate a random signal
        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();
        let signal_len = u64::try_from(signal.len()).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut fr_to_bytes_le(&identity_secret_hash));
        serialized.append(&mut identity_index.to_le_bytes().to_vec());
        serialized.append(&mut fr_to_bytes_le(&epoch));
        serialized.append(&mut signal_len.to_le_bytes().to_vec());
        serialized.append(&mut signal.to_vec());

        // We call generate_rln_proof
        let input_buffer = &Buffer::from(serialized.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = generate_rln_proof(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "generate rln proof call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        // result_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> ]
        let mut proof_data = <&[u8]>::from(&output_buffer).to_vec();

        // We prepare input for verify_rln_proof API
        // input_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> | signal_len<8> | signal<var> ]
        // that is [ proof_data | signal_len<8> | signal<var> ]
        proof_data.append(&mut signal_len.to_le_bytes().to_vec());
        proof_data.append(&mut signal.to_vec());

        // We test verify_with_roots

        // We first try to verify against an empty buffer of roots.
        // In this case, since no root is provided, proof's root check is skipped and proof is verified if other proof values are valid
        let mut roots_data: Vec<u8> = Vec::new();

        let input_buffer = &Buffer::from(proof_data.as_ref());
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
        let input_buffer = &Buffer::from(proof_data.as_ref());
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
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root, _) = bytes_le_to_fr(&result_data);

        // We include the root and verify the proof
        roots_data.append(&mut fr_to_bytes_le(&root));
        let input_buffer = &Buffer::from(proof_data.as_ref());
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
        let tree_height = TEST_TREE_HEIGHT;

        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

        // We generate a new identity pair
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = key_gen(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "key gen call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (identity_secret_hash, read) = bytes_le_to_fr(&result_data);
        let (id_commitment, _) = bytes_le_to_fr(&result_data[read..].to_vec());

        // We set as leaf id_commitment, its index would be equal to 0 since tree is empty
        let leaf_ser = fr_to_bytes_le(&id_commitment);
        let input_buffer = &Buffer::from(leaf_ser.as_ref());
        let success = set_next_leaf(rln_pointer, input_buffer);
        assert!(success, "set next leaf call failed");

        let identity_index: u64 = 0;

        // We generate two proofs using same epoch but different signals.

        // We generate two random signals
        let mut rng = rand::thread_rng();
        let signal1: [u8; 32] = rng.gen();
        let signal1_len = u64::try_from(signal1.len()).unwrap();

        // We generate two random signals
        let signal2: [u8; 32] = rng.gen();
        let signal2_len = u64::try_from(signal2.len()).unwrap();

        // We generate a random epoch
        let epoch = hash_to_field(b"test-epoch");

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized1: Vec<u8> = Vec::new();
        serialized1.append(&mut fr_to_bytes_le(&identity_secret_hash));
        serialized1.append(&mut identity_index.to_le_bytes().to_vec());
        serialized1.append(&mut fr_to_bytes_le(&epoch));

        // The first part is the same for both proof input, so we clone
        let mut serialized2 = serialized1.clone();

        // We attach the first signal to the first proof input
        serialized1.append(&mut signal1_len.to_le_bytes().to_vec());
        serialized1.append(&mut signal1.to_vec());

        // We attach the second signal to the first proof input
        serialized2.append(&mut signal2_len.to_le_bytes().to_vec());
        serialized2.append(&mut signal2.to_vec());

        // We call generate_rln_proof for first proof values
        let input_buffer = &Buffer::from(serialized1.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = generate_rln_proof(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "generate rln proof call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        // result_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> ]
        let proof_data_1 = <&[u8]>::from(&output_buffer).to_vec();

        // We call generate_rln_proof
        let input_buffer = &Buffer::from(serialized2.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = generate_rln_proof(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "generate rln proof call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        // result_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> ]
        let proof_data_2 = <&[u8]>::from(&output_buffer).to_vec();

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
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = key_gen(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "key gen call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (identity_secret_hash_new, read) = bytes_le_to_fr(&result_data);
        let (id_commitment_new, _) = bytes_le_to_fr(&result_data[read..].to_vec());

        // We set as leaf id_commitment, its index would be equal to 1 since at 0 there is id_commitment
        let leaf_ser = fr_to_bytes_le(&id_commitment_new);
        let input_buffer = &Buffer::from(leaf_ser.as_ref());
        let success = set_next_leaf(rln_pointer, input_buffer);
        assert!(success, "set next leaf call failed");

        let identity_index_new: u64 = 1;

        // We generate a random signals
        let signal3: [u8; 32] = rng.gen();
        let signal3_len = u64::try_from(signal3.len()).unwrap();

        // We prepare input for generate_rln_proof API
        // input_data is [ identity_secret<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        // Note that epoch is the same as before
        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut fr_to_bytes_le(&identity_secret_hash_new));
        serialized.append(&mut identity_index_new.to_le_bytes().to_vec());
        serialized.append(&mut fr_to_bytes_le(&epoch));
        serialized.append(&mut signal3_len.to_le_bytes().to_vec());
        serialized.append(&mut signal3.to_vec());

        // We call generate_rln_proof
        let input_buffer = &Buffer::from(serialized.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = generate_rln_proof(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "generate rln proof call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        // result_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> ]
        let proof_data_3 = <&[u8]>::from(&output_buffer).to_vec();

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

        // We passed two shares for different secrets, so recovery should be not successful
        // To check it, we ensure that recovered identity secret hash is empty
        assert!(serialized_identity_secret_hash.is_empty());
    }

    #[test]
    // Tests hash to field using FFI APIs
    fn test_seeded_keygen_ffi() {
        let tree_height = TEST_TREE_HEIGHT;

        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

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
        let tree_height = TEST_TREE_HEIGHT;
        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

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
        let inputs_ser = vec_fr_to_bytes_le(&inputs).unwrap();
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
