use crate::public::RLN;
use std::slice;

/// Buffer struct is taken from
/// https://github.com/celo-org/celo-threshold-bls-rs/blob/master/crates/threshold-bls-ffi/src/ffi.rs
///
/// Also heavily inspired by https://github.com/kilic/rln/blob/master/src/ffi.rs

#[repr(C)]
#[derive(Clone, Debug, PartialEq)]
pub struct Buffer {
    pub ptr: *const u8,
    pub len: usize,
}

impl From<&[u8]> for Buffer {
    fn from(src: &[u8]) -> Self {
        Self {
            ptr: &src[0] as *const u8,
            len: src.len(),
        }
    }
}

impl<'a> From<&Buffer> for &'a [u8] {
    fn from(src: &Buffer) -> &'a [u8] {
        unsafe { slice::from_raw_parts(src.ptr, src.len) }
    }
}

// TODO: check if there are security implications for this clippy. It seems we should have pub unsafe extern "C" fn ...
// #[allow(clippy::not_unsafe_ptr_arg_deref)]

////////////////////////////////////////////////////////
// RLN APIs
////////////////////////////////////////////////////////

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn new(tree_height: usize, input_buffer: *const Buffer, ctx: *mut *mut RLN) -> bool {
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    let rln = RLN::new(tree_height, input_data);
    unsafe { *ctx = Box::into_raw(Box::new(rln)) };
    true
}

////////////////////////////////////////////////////////
// Merkle tree APIs
////////////////////////////////////////////////////////
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_tree(ctx: *mut RLN, tree_height: usize) -> bool {
    let rln = unsafe { &mut *ctx };
    rln.set_tree(tree_height).is_ok()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn delete_leaf(ctx: *mut RLN, index: usize) -> bool {
    let rln = unsafe { &mut *ctx };
    rln.delete_leaf(index).is_ok()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_leaf(ctx: *mut RLN, index: usize, input_buffer: *const Buffer) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    rln.set_leaf(index, input_data).is_ok()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_next_leaf(ctx: *mut RLN, input_buffer: *const Buffer) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    rln.set_next_leaf(input_data).is_ok()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn set_leaves(ctx: *mut RLN, input_buffer: *const Buffer) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    rln.set_leaves(input_data).is_ok()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn get_root(ctx: *const RLN, output_buffer: *mut Buffer) -> bool {
    let rln = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if rln.get_root(&mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn get_proof(ctx: *const RLN, index: usize, output_buffer: *mut Buffer) -> bool {
    let rln = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if rln.get_proof(index, &mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

////////////////////////////////////////////////////////
// zkSNARKs APIs
////////////////////////////////////////////////////////
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn prove(
    ctx: *mut RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    let mut output_data: Vec<u8> = Vec::new();

    if rln.prove(input_data, &mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn verify(
    ctx: *const RLN,
    proof_buffer: *const Buffer,
    proof_is_valid_ptr: *mut bool,
) -> bool {
    let rln = unsafe { &*ctx };
    let proof_data = <&[u8]>::from(unsafe { &*proof_buffer });
    if match rln.verify(proof_data) {
        Ok(verified) => verified,
        Err(_) => return false,
    } {
        unsafe { *proof_is_valid_ptr = true };
    } else {
        unsafe { *proof_is_valid_ptr = false };
    };
    true
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn generate_rln_proof(
    ctx: *mut RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    let mut output_data: Vec<u8> = Vec::new();

    if rln.generate_rln_proof(input_data, &mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn verify_rln_proof(
    ctx: *const RLN,
    proof_buffer: *const Buffer,
    proof_is_valid_ptr: *mut bool,
) -> bool {
    let rln = unsafe { &*ctx };
    let proof_data = <&[u8]>::from(unsafe { &*proof_buffer });
    if match rln.verify_rln_proof(proof_data) {
        Ok(verified) => verified,
        Err(_) => return false,
    } {
        unsafe { *proof_is_valid_ptr = true };
    } else {
        unsafe { *proof_is_valid_ptr = false };
    };
    true
}

////////////////////////////////////////////////////////
// Utils
////////////////////////////////////////////////////////
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn key_gen(ctx: *const RLN, output_buffer: *mut Buffer) -> bool {
    let rln = unsafe { &*ctx };
    let mut output_data: Vec<u8> = Vec::new();
    if rln.key_gen(&mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn hash(
    ctx: *mut RLN,
    input_buffer: *const Buffer,
    output_buffer: *mut Buffer,
) -> bool {
    let rln = unsafe { &mut *ctx };
    let input_data = <&[u8]>::from(unsafe { &*input_buffer });
    let mut output_data: Vec<u8> = Vec::new();

    if rln.hash(input_data, &mut output_data).is_ok() {
        unsafe { *output_buffer = Buffer::from(&output_data[..]) };
        std::mem::forget(output_data);
        true
    } else {
        std::mem::forget(output_data);
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::circuit::*;
    use crate::protocol::*;
    use crate::utils::*;
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::Proof as ArkProof;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::str::FromStr;
    use ark_std::{rand::thread_rng, UniformRand};
    use rand::Rng;
    use semaphore::{identity::Identity, poseidon_hash, Field};
    use serde::{Deserialize, Serialize};
    use std::io::Cursor;
    use std::mem::MaybeUninit;

    #[test]
    // We test merkle batch Merkle tree additions
    fn test_merkle_operations_ffi() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Field> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(to_field(&Fr::rand(&mut rng)));
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
            let leaf_ser = field_to_bytes_le(&leaf);
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
        let (root_single, _) = bytes_le_to_field(&result_data);

        // We reset the tree to default
        let success = set_tree(rln_pointer, tree_height);
        assert!(success, "set tree call failed");

        // We add leaves one by one using the internal index (new leaves goes in next available position)
        for leaf in &leaves {
            let leaf_ser = field_to_bytes_le(&leaf);
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
        let (root_next, _) = bytes_le_to_field(&result_data);

        // We check if roots are the same
        assert_eq!(root_single, root_next);

        // We reset the tree to default
        let success = set_tree(rln_pointer, tree_height);
        assert!(success, "set tree call failed");

        // We add leaves in a batch into the tree
        let leaves_ser = vec_field_to_bytes_le(&leaves);
        let input_buffer = &Buffer::from(leaves_ser.as_ref());
        let success = set_leaves(rln_pointer, input_buffer);
        assert!(success, "set leaves call failed");

        // We get the root of the tree obtained adding leaves in batch
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_batch, _) = bytes_le_to_field(&result_data);

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
        let (root_delete, _) = bytes_le_to_field(&result_data);

        // We reset the tree to default
        let success = set_tree(rln_pointer, tree_height);
        assert!(success, "set tree call failed");

        // We get the root of the empty tree
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root_empty, _) = bytes_le_to_field(&result_data);

        // We check if roots are the same
        assert_eq!(root_delete, root_empty);
    }

    #[test]
    // This test is similar to the one in lib, but uses only public C API
    // This test contains hardcoded values!
    // TODO: expand this test to work with tree_height = 20
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
        // We follow zk-kit approach for identity generation
        let id = Identity::from_seed(b"test-merkle-proof");
        let identity_secret = poseidon_hash(&vec![id.trapdoor, id.nullifier]);
        let id_commitment = poseidon_hash(&vec![identity_secret]);

        // We prepare id_commitment and we set the leaf at provided index
        let leaf_ser = field_to_bytes_le(&id_commitment);
        let input_buffer = &Buffer::from(leaf_ser.as_ref());
        let success = set_leaf(rln_pointer, leaf_index, input_buffer);
        assert!(success, "set leaf call failed");

        // We obtain the Merkle tree root
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_root(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "get root call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (root, _) = bytes_le_to_field(&result_data);

        // We obtain the Merkle tree root
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = get_proof(rln_pointer, leaf_index, output_buffer.as_mut_ptr());
        assert!(success, "get merkle proof call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();

        let (path_elements, read) = bytes_le_to_vec_field(&result_data);
        let (identity_path_index, _) = bytes_le_to_vec_u8(&result_data[read..].to_vec());

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

        // We double check that the proof computed from public API is correct
        let root_from_proof =
            compute_tree_root(&id_commitment, &path_elements, &identity_path_index, false);

        assert_eq!(root, root_from_proof);
    }

    #[test]
    fn test_groth16_proof_ffi() {
        let tree_height = TEST_TREE_HEIGHT;

        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

        // We generate random witness instances and relative proof values
        let rln_witness = random_rln_witness(tree_height);
        let proof_values = proof_values_from_witness(&rln_witness);

        // We prepare id_commitment and we set the leaf at provided index
        let rln_witness_ser = serialize_witness(&rln_witness);
        let input_buffer = &Buffer::from(rln_witness_ser.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = prove(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
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
        let success = verify(rln_pointer, input_buffer, proof_is_valid_ptr);
        assert!(success, "verify call failed");
        assert_eq!(proof_is_valid, true);
    }

    #[test]
    fn test_rln_proof_ffi() {
        let tree_height = TEST_TREE_HEIGHT;
        let no_of_leaves = 256;

        // We generate a vector of random leaves
        let mut leaves: Vec<Field> = Vec::new();
        let mut rng = thread_rng();
        for _ in 0..no_of_leaves {
            leaves.push(to_field(&Fr::rand(&mut rng)));
        }

        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

        // We add leaves in a batch into the tree
        let leaves_ser = vec_field_to_bytes_le(&leaves);
        let input_buffer = &Buffer::from(leaves_ser.as_ref());
        let success = set_leaves(rln_pointer, input_buffer);
        assert!(success, "set leaves call failed");

        // We generate a new identity pair
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = key_gen(rln_pointer, output_buffer.as_mut_ptr());
        assert!(success, "key gen call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        let result_data = <&[u8]>::from(&output_buffer).to_vec();
        let (identity_secret, read) = bytes_le_to_field(&result_data);
        let (id_commitment, _) = bytes_le_to_field(&result_data[read..].to_vec());

        // We set as leaf id_commitment, its index would be equal to no_of_leaves
        let leaf_ser = field_to_bytes_le(&id_commitment);
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
        // input_data is [ id_key<32> | id_index<8> | epoch<32> | signal_len<8> | signal<var> ]
        let mut serialized: Vec<u8> = Vec::new();
        serialized.append(&mut field_to_bytes_le(&identity_secret));
        serialized.append(&mut identity_index.to_le_bytes().to_vec());
        serialized.append(&mut field_to_bytes_le(&epoch));
        serialized.append(&mut signal_len.to_le_bytes().to_vec());
        serialized.append(&mut signal.to_vec());

        // We call generate_rln_proof
        let input_buffer = &Buffer::from(serialized.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = generate_rln_proof(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "set leaves call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };
        // result_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> ]
        let mut proof_data = <&[u8]>::from(&output_buffer).to_vec();

        // We prepare input for verify_rln_proof API
        // input_data is [ proof<128> | share_y<32> | nullifier<32> | root<32> | epoch<32> | share_x<32> | rln_identifier<32> | signal_len<8> | signal<var> ]
        // that is [ proof_data | signal_len<8> | signal<var> ]
        proof_data.append(&mut signal_len.to_le_bytes().to_vec());
        proof_data.append(&mut signal.to_vec());

        // We call generate_rln_proof
        let input_buffer = &Buffer::from(proof_data.as_ref());
        let mut proof_is_valid: bool = false;
        let proof_is_valid_ptr = &mut proof_is_valid as *mut bool;
        let success = verify_rln_proof(rln_pointer, input_buffer, proof_is_valid_ptr);
        assert!(success, "verify call failed");
        assert_eq!(proof_is_valid, true);
    }

    #[test]
    fn test_hash_to_field_ffi() {
        let tree_height = TEST_TREE_HEIGHT;

        // We create a RLN instance
        let mut rln_pointer = MaybeUninit::<*mut RLN>::uninit();
        let input_buffer = &Buffer::from(TEST_RESOURCES_FOLDER.as_bytes());
        let success = new(tree_height, input_buffer, rln_pointer.as_mut_ptr());
        assert!(success, "RLN object creation failed");
        let rln_pointer = unsafe { &mut *rln_pointer.assume_init() };

        let mut rng = rand::thread_rng();
        let signal: [u8; 32] = rng.gen();

        // We prepare id_commitment and we set the leaf at provided index
        let input_buffer = &Buffer::from(signal.as_ref());
        let mut output_buffer = MaybeUninit::<Buffer>::uninit();
        let success = hash(rln_pointer, input_buffer, output_buffer.as_mut_ptr());
        assert!(success, "hash call failed");
        let output_buffer = unsafe { output_buffer.assume_init() };

        // We read the returned proof and we append proof values for verify
        let serialized_hash = <&[u8]>::from(&output_buffer).to_vec();
        let (hash1, _) = bytes_le_to_field(&serialized_hash);

        let hash2 = hash_to_field(&signal);

        assert_eq!(hash1, hash2);
    }
}
