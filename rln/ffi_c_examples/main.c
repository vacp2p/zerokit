#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rln.h"

int main(int argc, char const *const argv[])
{
    printf("Creating RLN instance\n");

#ifdef STATELESS
    CResult_FFI_RLN_ptr_Vec_uint8_t ffi_rln_new_result = ffi_rln_new();
#else
    const char *config_path = "../resources/tree_depth_20/config.json";
    CResult_FFI_RLN_ptr_Vec_uint8_t ffi_rln_new_result = ffi_rln_new(20, config_path);
#endif

    if (!ffi_rln_new_result.ok)
    {
        fprintf(stderr, "Initial RLN instance creation error: %s\n", ffi_rln_new_result.err.ptr);
        ffi_c_string_free(ffi_rln_new_result.err);
        return EXIT_FAILURE;
    }

    FFI_RLN_t *rln = ffi_rln_new_result.ok;
    printf("RLN instance created successfully\n");

    printf("\nGenerating identity keys\n");
    CResult_Vec_CFr_Vec_uint8_t keys_result = ffi_key_gen();
    if (keys_result.err.ptr)
    {
        fprintf(stderr, "Key generation error: %s\n", keys_result.err.ptr);
        ffi_c_string_free(keys_result.err);
        return EXIT_FAILURE;
    }
    Vec_CFr_t keys = keys_result.ok;
    const CFr_t *identity_secret = ffi_vec_cfr_get(&keys, 0);
    const CFr_t *id_commitment = ffi_vec_cfr_get(&keys, 1);
    printf("Identity generated\n");

    Vec_uint8_t debug = ffi_cfr_debug(identity_secret);
    printf("  - identity_secret = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    debug = ffi_cfr_debug(id_commitment);
    printf("  - id_commitment = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nCreating message limit\n");
    CFr_t *user_message_limit = ffi_uint_to_cfr(1);

    debug = ffi_cfr_debug(user_message_limit);
    printf("  - user_message_limit = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nComputing rate commitment\n");
    CResult_CFr_ptr_Vec_uint8_t rate_commitment_result = ffi_poseidon_hash_pair(id_commitment, user_message_limit);
    if (!rate_commitment_result.ok)
    {
        fprintf(stderr, "Rate commitment hash error: %s\n", rate_commitment_result.err.ptr);
        ffi_c_string_free(rate_commitment_result.err);
        return EXIT_FAILURE;
    }
    CFr_t *rate_commitment = rate_commitment_result.ok;

    debug = ffi_cfr_debug(rate_commitment);
    printf("  - rate_commitment = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nCFr serialization: CFr <-> bytes\n");
    Vec_uint8_t ser_rate_commitment = ffi_cfr_to_bytes_le(rate_commitment);

    debug = ffi_vec_u8_debug(&ser_rate_commitment);
    printf("  - serialized rate_commitment = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    CResult_CFr_ptr_Vec_uint8_t deser_rate_commitment_result = ffi_bytes_le_to_cfr(&ser_rate_commitment);
    if (!deser_rate_commitment_result.ok)
    {
        fprintf(stderr, "Rate commitment deserialization error: %s\n", deser_rate_commitment_result.err.ptr);
        ffi_c_string_free(deser_rate_commitment_result.err);
        return EXIT_FAILURE;
    }
    CFr_t *deser_rate_commitment = deser_rate_commitment_result.ok;

    debug = ffi_cfr_debug(deser_rate_commitment);
    printf("  - deserialized rate_commitment = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    ffi_vec_u8_free(ser_rate_commitment);
    ffi_cfr_free(deser_rate_commitment);

    printf("\nVec<CFr> serialization: Vec<CFr> <-> bytes\n");
    Vec_uint8_t ser_keys = ffi_vec_cfr_to_bytes_le(&keys);

    debug = ffi_vec_u8_debug(&ser_keys);
    printf("  - serialized keys = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    CResult_Vec_CFr_Vec_uint8_t deser_keys_result = ffi_bytes_le_to_vec_cfr(&ser_keys);
    if (deser_keys_result.err.ptr)
    {
        fprintf(stderr, "Keys deserialization error: %s\n", deser_keys_result.err.ptr);
        ffi_c_string_free(deser_keys_result.err);
        return EXIT_FAILURE;
    }

    debug = ffi_vec_cfr_debug(&deser_keys_result.ok);
    printf("  - deserialized identity_secret = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    Vec_CFr_t deser_keys = deser_keys_result.ok;
    ffi_vec_cfr_free(deser_keys);

    ffi_vec_u8_free(ser_keys);

#ifdef STATELESS
#define TREE_DEPTH 20
#define CFR_SIZE 32

    printf("\nBuilding Merkle path for stateless mode\n");
    CFr_t *default_leaf = ffi_cfr_zero();

    CFr_t *default_hashes[TREE_DEPTH - 1];
    CResult_CFr_ptr_Vec_uint8_t hash_result = ffi_poseidon_hash_pair(default_leaf, default_leaf);
    if (!hash_result.ok)
    {
        fprintf(stderr, "Poseidon hash error: %s\n", hash_result.err.ptr);
        ffi_c_string_free(hash_result.err);
        return EXIT_FAILURE;
    }
    default_hashes[0] = hash_result.ok;
    for (size_t i = 1; i < TREE_DEPTH - 1; i++)
    {
        hash_result = ffi_poseidon_hash_pair(default_hashes[i - 1], default_hashes[i - 1]);
        if (!hash_result.ok)
        {
            fprintf(stderr, "Poseidon hash error: %s\n", hash_result.err.ptr);
            ffi_c_string_free(hash_result.err);
            return EXIT_FAILURE;
        }
        default_hashes[i] = hash_result.ok;
    }

    Vec_CFr_t path_elements = ffi_vec_cfr_new(TREE_DEPTH);
    ffi_vec_cfr_push(&path_elements, default_leaf);
    for (size_t i = 0; i < TREE_DEPTH - 1; i++)
    {
        ffi_vec_cfr_push(&path_elements, default_hashes[i]);
    }

    printf("\nVec<CFr> serialization: Vec<CFr> <-> bytes\n");
    Vec_uint8_t ser_path_elements = ffi_vec_cfr_to_bytes_le(&path_elements);

    debug = ffi_vec_u8_debug(&ser_path_elements);
    printf("  - serialized path_elements = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    CResult_Vec_CFr_Vec_uint8_t deser_path_elements_result = ffi_bytes_le_to_vec_cfr(&ser_path_elements);
    if (deser_path_elements_result.err.ptr)
    {
        fprintf(stderr, "Path elements deserialization error: %s\n", deser_path_elements_result.err.ptr);
        ffi_c_string_free(deser_path_elements_result.err);
        return EXIT_FAILURE;
    }

    debug = ffi_vec_cfr_debug(&deser_path_elements_result.ok);
    printf("  - deserialized path_elements = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    Vec_CFr_t deser_path_elements = deser_path_elements_result.ok;
    ffi_vec_cfr_free(deser_path_elements);

    ffi_vec_u8_free(ser_path_elements);

    uint8_t path_index_arr[TREE_DEPTH] = {0};
    Vec_uint8_t identity_path_index = {
        .ptr = path_index_arr,
        .len = TREE_DEPTH,
        .cap = TREE_DEPTH};

    printf("\nVec<uint8> serialization: Vec<uint8> <-> bytes\n");
    Vec_uint8_t ser_path_index = ffi_vec_u8_to_bytes_le(&identity_path_index);

    debug = ffi_vec_u8_debug(&ser_path_index);
    printf("  - serialized path_index = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    CResult_Vec_uint8_Vec_uint8_t deser_path_index_result = ffi_bytes_le_to_vec_u8(&ser_path_index);
    if (deser_path_index_result.err.ptr)
    {
        fprintf(stderr, "Path index deserialization error: %s\n", deser_path_index_result.err.ptr);
        ffi_c_string_free(deser_path_index_result.err);
        return EXIT_FAILURE;
    }

    debug = ffi_vec_u8_debug(&deser_path_index_result.ok);
    printf("  - deserialized path_index = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    Vec_uint8_t deser_path_index = deser_path_index_result.ok;
    ffi_vec_u8_free(deser_path_index);

    ffi_vec_u8_free(ser_path_index);

    printf("\nComputing Merkle root for stateless mode\n");
    printf("  - computing root for index 0 with rate_commitment\n");
    CResult_CFr_ptr_Vec_uint8_t root_result = ffi_poseidon_hash_pair(rate_commitment, default_leaf);
    if (!root_result.ok)
    {
        fprintf(stderr, "Poseidon hash error: %s\n", root_result.err.ptr);
        ffi_c_string_free(root_result.err);
        return EXIT_FAILURE;
    }
    CFr_t *computed_root = root_result.ok;
    for (size_t i = 1; i < TREE_DEPTH; i++)
    {
        root_result = ffi_poseidon_hash_pair(computed_root, default_hashes[i - 1]);
        if (!root_result.ok)
        {
            fprintf(stderr, "Poseidon hash error: %s\n", root_result.err.ptr);
            ffi_c_string_free(root_result.err);
            return EXIT_FAILURE;
        }
        CFr_t *next_root = root_result.ok;
        ffi_cfr_free(computed_root);
        computed_root = next_root;
    }

    debug = ffi_cfr_debug(computed_root);
    printf("  - computed_root = %s\n", debug.ptr);
    ffi_c_string_free(debug);
#else
    printf("\nAdding rate_commitment to tree\n");
    CBoolResult_t set_err = ffi_set_next_leaf(&rln, rate_commitment);
    if (!set_err.ok)
    {
        fprintf(stderr, "Set next leaf error: %s\n", set_err.err.ptr);
        ffi_c_string_free(set_err.err);
        return EXIT_FAILURE;
    }

    size_t leaf_index = ffi_leaves_set(&rln) - 1;
    printf("  - added to tree at index %zu\n", leaf_index);

    printf("\nGetting Merkle proof\n");
    CResult_FFI_MerkleProof_ptr_Vec_uint8_t proof_result = ffi_get_merkle_proof(&rln, leaf_index);
    if (!proof_result.ok)
    {
        fprintf(stderr, "Get proof error: %s\n", proof_result.err.ptr);
        ffi_c_string_free(proof_result.err);
        return EXIT_FAILURE;
    }
    FFI_MerkleProof_t *merkle_proof = proof_result.ok;
    printf("  - proof obtained (depth: %zu)\n", merkle_proof->path_elements.len);
#endif

    printf("\nHashing signal\n");
    uint8_t signal[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    Vec_uint8_t signal_vec = {signal, 32, 32};
    CResult_CFr_ptr_Vec_uint8_t x_result = ffi_hash_to_field_le(&signal_vec);
    if (!x_result.ok)
    {
        fprintf(stderr, "Hash signal error: %s\n", x_result.err.ptr);
        ffi_c_string_free(x_result.err);
        return EXIT_FAILURE;
    }
    CFr_t *x = x_result.ok;

    debug = ffi_cfr_debug(x);
    printf("  - x = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nHashing epoch\n");
    const char *epoch_str = "test-epoch";
    Vec_uint8_t epoch_vec = {(uint8_t *)epoch_str, strlen(epoch_str), strlen(epoch_str)};
    CResult_CFr_ptr_Vec_uint8_t epoch_result = ffi_hash_to_field_le(&epoch_vec);
    if (!epoch_result.ok)
    {
        fprintf(stderr, "Hash epoch error: %s\n", epoch_result.err.ptr);
        ffi_c_string_free(epoch_result.err);
        return EXIT_FAILURE;
    }
    CFr_t *epoch = epoch_result.ok;

    debug = ffi_cfr_debug(epoch);
    printf("  - epoch = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nHashing RLN identifier\n");
    const char *rln_id_str = "test-rln-identifier";
    Vec_uint8_t rln_id_vec = {(uint8_t *)rln_id_str, strlen(rln_id_str), strlen(rln_id_str)};
    CResult_CFr_ptr_Vec_uint8_t rln_identifier_result = ffi_hash_to_field_le(&rln_id_vec);
    if (!rln_identifier_result.ok)
    {
        fprintf(stderr, "Hash RLN identifier error: %s\n", rln_identifier_result.err.ptr);
        ffi_c_string_free(rln_identifier_result.err);
        return EXIT_FAILURE;
    }
    CFr_t *rln_identifier = rln_identifier_result.ok;

    debug = ffi_cfr_debug(rln_identifier);
    printf("  - rln_identifier = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nComputing Poseidon hash for external nullifier\n");
    CResult_CFr_ptr_Vec_uint8_t external_nullifier_result = ffi_poseidon_hash_pair(epoch, rln_identifier);
    if (!external_nullifier_result.ok)
    {
        fprintf(stderr, "External nullifier hash error: %s\n", external_nullifier_result.err.ptr);
        ffi_c_string_free(external_nullifier_result.err);
        return EXIT_FAILURE;
    }
    CFr_t *external_nullifier = external_nullifier_result.ok;

    debug = ffi_cfr_debug(external_nullifier);
    printf("  - external_nullifier = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nCreating message_id\n");
    CFr_t *message_id = ffi_uint_to_cfr(0);

    debug = ffi_cfr_debug(message_id);
    printf("  - message_id = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nCreating RLN Witness\n");
#ifdef STATELESS
    CResult_FFI_RLNWitnessInput_ptr_Vec_uint8_t witness_result = ffi_rln_witness_input_new(
        identity_secret,
        user_message_limit,
        message_id,
        &path_elements,
        &identity_path_index,
        x,
        external_nullifier);

    if (!witness_result.ok)
    {
        fprintf(stderr, "RLN Witness creation error: %s\n", witness_result.err.ptr);
        ffi_c_string_free(witness_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNWitnessInput_t *witness = witness_result.ok;
    printf("RLN Witness created successfully\n");
#else
    CResult_FFI_RLNWitnessInput_ptr_Vec_uint8_t witness_result = ffi_rln_witness_input_new(
        identity_secret,
        user_message_limit,
        message_id,
        &merkle_proof->path_elements,
        &merkle_proof->path_index,
        x,
        external_nullifier);

    if (!witness_result.ok)
    {
        fprintf(stderr, "RLN Witness creation error: %s\n", witness_result.err.ptr);
        ffi_c_string_free(witness_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNWitnessInput_t *witness = witness_result.ok;
    printf("RLN Witness created successfully\n");
#endif

    printf("\nGenerating RLN Proof\n");
    CResult_FFI_RLNProof_ptr_Vec_uint8_t proof_gen_result = ffi_generate_rln_proof(
        &rln,
        &witness);

    if (!proof_gen_result.ok)
    {
        fprintf(stderr, "Proof generation error: %s\n", proof_gen_result.err.ptr);
        ffi_c_string_free(proof_gen_result.err);
        return EXIT_FAILURE;
    }

    FFI_RLNProof_t *rln_proof = proof_gen_result.ok;
    printf("Proof generated successfully\n");

    printf("\nGetting proof values\n");
    FFI_RLNProofValues_t *proof_values = ffi_rln_proof_get_values(&rln_proof);

    CFr_t *y = ffi_rln_proof_values_get_y(&proof_values);
    debug = ffi_cfr_debug(y);
    printf("  - y = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_cfr_free(y);

    CFr_t *nullifier = ffi_rln_proof_values_get_nullifier(&proof_values);
    debug = ffi_cfr_debug(nullifier);
    printf("  - nullifier = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_cfr_free(nullifier);

    CFr_t *root = ffi_rln_proof_values_get_root(&proof_values);
    debug = ffi_cfr_debug(root);
    printf("  - root = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_cfr_free(root);

    CFr_t *x_val = ffi_rln_proof_values_get_x(&proof_values);
    debug = ffi_cfr_debug(x_val);
    printf("  - x = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_cfr_free(x_val);

    CFr_t *ext_nullifier = ffi_rln_proof_values_get_external_nullifier(&proof_values);
    debug = ffi_cfr_debug(ext_nullifier);
    printf("  - external_nullifier = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_cfr_free(ext_nullifier);

    printf("\nRLNProof serialization: RLNProof <-> bytes\n");
    Vec_uint8_t ser_proof = ffi_rln_proof_to_bytes_le(&rln_proof);

    debug = ffi_vec_u8_debug(&ser_proof);
    printf("  - serialized proof = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    CResult_FFI_RLNProof_ptr_Vec_uint8_t deser_proof_result = ffi_bytes_le_to_rln_proof(&ser_proof);
    if (!deser_proof_result.ok)
    {
        fprintf(stderr, "Proof deserialization error: %s\n", deser_proof_result.err.ptr);
        ffi_c_string_free(deser_proof_result.err);
        return EXIT_FAILURE;
    }

    FFI_RLNProof_t *deser_proof = deser_proof_result.ok;
    printf("  - proof deserialized successfully\n");

    printf("\nRLNProofValues serialization: RLNProofValues <-> bytes\n");
    Vec_uint8_t ser_proof_values = ffi_rln_proof_values_to_bytes_le(&proof_values);

    debug = ffi_vec_u8_debug(&ser_proof_values);
    printf("  - serialized proof_values = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    CResult_FFI_RLNProofValues_ptr_Vec_uint8_t deser_proof_values_result = ffi_bytes_le_to_rln_proof_values(&ser_proof_values);
    if (!deser_proof_values_result.ok)
    {
        fprintf(stderr, "Proof values deserialization error: %s\n", deser_proof_values_result.err.ptr);
        ffi_c_string_free(deser_proof_values_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNProofValues_t *deser_proof_values = deser_proof_values_result.ok;
    printf("  - proof_values deserialized successfully\n");

    CFr_t *deser_external_nullifier = ffi_rln_proof_values_get_external_nullifier(&deser_proof_values);
    debug = ffi_cfr_debug(deser_external_nullifier);
    printf("  - deserialized external_nullifier = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_cfr_free(deser_external_nullifier);

    ffi_rln_proof_values_free(deser_proof_values);
    ffi_vec_u8_free(ser_proof_values);
    ffi_rln_proof_free(deser_proof);
    ffi_vec_u8_free(ser_proof);

    printf("\nVerifying Proof\n");
#ifdef STATELESS
    Vec_CFr_t roots = ffi_vec_cfr_from_cfr(computed_root);
    CBoolResult_t verify_err = ffi_verify_with_roots(&rln, &rln_proof, &roots, x);
#else
    CBoolResult_t verify_err = ffi_verify_rln_proof(&rln, &rln_proof, x);
#endif

    if (!verify_err.ok)
    {
        fprintf(stderr, "Proof verification error: %s\n", verify_err.err.ptr);
        ffi_c_string_free(verify_err.err);
        return EXIT_FAILURE;
    }

    printf("Proof verified successfully\n");

    ffi_rln_proof_free(rln_proof);

    printf("\nSimulating double-signaling attack (same epoch, different message)\n");

    printf("\nHashing second signal\n");
    uint8_t signal2[32] = {11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    Vec_uint8_t signal2_vec = {signal2, 32, 32};
    CResult_CFr_ptr_Vec_uint8_t x2_result = ffi_hash_to_field_le(&signal2_vec);
    if (!x2_result.ok)
    {
        fprintf(stderr, "Hash second signal error: %s\n", x2_result.err.ptr);
        ffi_c_string_free(x2_result.err);
        return EXIT_FAILURE;
    }
    CFr_t *x2 = x2_result.ok;

    debug = ffi_cfr_debug(x2);
    printf("  - x2 = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nCreating second message with the same id\n");
    CFr_t *message_id2 = ffi_uint_to_cfr(0);

    debug = ffi_cfr_debug(message_id2);
    printf("  - message_id2 = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nCreating second RLN Witness\n");
#ifdef STATELESS
    CResult_FFI_RLNWitnessInput_ptr_Vec_uint8_t witness_result2 = ffi_rln_witness_input_new(
        identity_secret,
        user_message_limit,
        message_id2,
        &path_elements,
        &identity_path_index,
        x2,
        external_nullifier);

    if (!witness_result2.ok)
    {
        fprintf(stderr, "Second RLN Witness creation error: %s\n", witness_result2.err.ptr);
        ffi_c_string_free(witness_result2.err);
        return EXIT_FAILURE;
    }
    FFI_RLNWitnessInput_t *witness2 = witness_result2.ok;
    printf("Second RLN Witness created successfully\n");
#else
    CResult_FFI_RLNWitnessInput_ptr_Vec_uint8_t witness_result2 = ffi_rln_witness_input_new(
        identity_secret,
        user_message_limit,
        message_id2,
        &merkle_proof->path_elements,
        &merkle_proof->path_index,
        x2,
        external_nullifier);

    if (!witness_result2.ok)
    {
        fprintf(stderr, "Second RLN Witness creation error: %s\n", witness_result2.err.ptr);
        ffi_c_string_free(witness_result2.err);
        return EXIT_FAILURE;
    }
    FFI_RLNWitnessInput_t *witness2 = witness_result2.ok;
    printf("Second RLN Witness created successfully\n");
#endif
    printf("\nGenerating second RLN Proof\n");
    CResult_FFI_RLNProof_ptr_Vec_uint8_t proof_gen_result2 = ffi_generate_rln_proof(
        &rln,
        &witness2);

    if (!proof_gen_result2.ok)
    {
        fprintf(stderr, "Second proof generation error: %s\n", proof_gen_result2.err.ptr);
        ffi_c_string_free(proof_gen_result2.err);
        return EXIT_FAILURE;
    }

    FFI_RLNProof_t *rln_proof2 = proof_gen_result2.ok;
    printf("Second proof generated successfully\n");

    FFI_RLNProofValues_t *proof_values2 = ffi_rln_proof_get_values(&rln_proof2);

    printf("\nVerifying second proof\n");
#ifdef STATELESS
    CBoolResult_t verify_err2 = ffi_verify_with_roots(&rln, &rln_proof2, &roots, x2);
#else
    CBoolResult_t verify_err2 = ffi_verify_rln_proof(&rln, &rln_proof2, x2);
#endif

    if (!verify_err2.ok)
    {
        fprintf(stderr, "Proof verification error: %s\n", verify_err2.err.ptr);
        ffi_c_string_free(verify_err2.err);
        return EXIT_FAILURE;
    }

    printf("Second proof verified successfully\n");

    ffi_rln_proof_free(rln_proof2);

    printf("\nRecovering identity secret\n");
    CResult_CFr_ptr_Vec_uint8_t recover_result = ffi_recover_id_secret(&proof_values, &proof_values2);
    if (!recover_result.ok)
    {
        fprintf(stderr, "Identity recovery error: %s\n", recover_result.err.ptr);
        ffi_c_string_free(recover_result.err);
        return EXIT_FAILURE;
    }

    CFr_t *recovered_secret = recover_result.ok;

    debug = ffi_cfr_debug(recovered_secret);
    printf("  - recovered_secret = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    debug = ffi_cfr_debug(identity_secret);
    printf("  - original_secret  = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("Slashing successful: Identity is recovered!\n");

    ffi_cfr_free(recovered_secret);

    ffi_rln_proof_values_free(proof_values2);
    ffi_rln_proof_values_free(proof_values);
    ffi_cfr_free(x2);
    ffi_cfr_free(message_id2);

#ifdef STATELESS
    ffi_rln_witness_input_free(witness2);
    ffi_rln_witness_input_free(witness);
    ffi_vec_cfr_free(roots);
    ffi_vec_cfr_free(path_elements);
    for (size_t i = 0; i < TREE_DEPTH - 1; i++)
    {
        ffi_cfr_free(default_hashes[i]);
    }
    ffi_cfr_free(default_leaf);
    ffi_cfr_free(computed_root);
#else
    ffi_rln_witness_input_free(witness2);
    ffi_rln_witness_input_free(witness);
    ffi_merkle_proof_free(merkle_proof);
#endif

    ffi_cfr_free(rate_commitment);
    ffi_cfr_free(x);
    ffi_cfr_free(epoch);
    ffi_cfr_free(rln_identifier);
    ffi_cfr_free(external_nullifier);
    ffi_cfr_free(user_message_limit);
    ffi_cfr_free(message_id);
    ffi_vec_cfr_free(keys);
    ffi_rln_free(rln);

    return EXIT_SUCCESS;
}