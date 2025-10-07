#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rln.h"

int main (int argc, char const * const argv[])
{
    const char* config = "{"
        "\"tree_config\": {"
            "\"path\": \"pmtree-123456\","
            "\"temporary\": false,"
            "\"cache_capacity\": 1073741824,"
            "\"flush_every_ms\": 500,"
            "\"mode\": \"HighThroughput\","
            "\"use_compression\": false"
        "}"
    "}";
    CResult_FFI2_RLN_ptr_Vec_uint8_t result = ffi2_new(20, config);

    if (!result.ok) {
        fprintf(stderr, "%s", result.err.ptr);
        return EXIT_FAILURE;
    }

    FFI2_RLN_t* rln = result.ok;
    printf("RLN instance created successfully\n");

    // Generate identity keys
    Vec_CFr_t keys = ffi2_key_gen();
    // Note: We get pointers to elements within the keys vector
    // These should not be freed individually, only via vec_cfr_free(keys)
    CFr_t* identity_secret_ptr = keys.ptr;
    CFr_t* id_commitment = (CFr_t*)vec_cfr_get(&keys, 1);
    printf("Identity generated\n");

    // Set the identity commitment as a leaf in the tree at index 0
    CResult_bool_ptr_Vec_uint8_t set_result = ffi2_set_next_leaf(&rln, &id_commitment);
    if (!set_result.ok) {
        fprintf(stderr, "%s", set_result.err.ptr);
        vec_cfr_free(keys);
        ffi2_rln_free(rln);
        return EXIT_FAILURE;
    }
    printf("Identity commitment added to tree at index 0\n");

    // Get the Merkle proof for the identity at index 0
    CResult_FFI2_MerkleProof_ptr_Vec_uint8_t proof_result = ffi2_get_proof(&rln, 0);
    if (!proof_result.ok) {
        fprintf(stderr, "%s", proof_result.err.ptr);
        vec_cfr_free(keys);
        ffi2_rln_free(rln);
        return EXIT_FAILURE;
    }
    FFI2_MerkleProof_t* merkle_proof = proof_result.ok;
    printf("Merkle proof obtained (depth: %zu)\n", merkle_proof->path_elements.len);

    // Generate signal hash (simulating a message)
    uint8_t signal[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                          17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    slice_ref_uint8_t signal_slice = {signal, 32};
    CFr_t* x = ffi2_hash(signal_slice);
    printf("Signal hashed to field element\n");

    // Generate external nullifier (epoch + rln_identifier)
    const char* epoch_str = "test-epoch";
    slice_ref_uint8_t epoch_slice = {(const uint8_t*)epoch_str, strlen(epoch_str)};
    CFr_t* epoch = ffi2_hash(epoch_slice);

    const char* rln_id_str = "test-rln-identifier";
    slice_ref_uint8_t rln_id_slice = {(const uint8_t*)rln_id_str, strlen(rln_id_str)};
    CFr_t* rln_identifier = ffi2_hash(rln_id_slice);

    // Hash epoch and rln_identifier together using Poseidon
    CFr_t* nullifier_array[2];
    nullifier_array[0] = epoch;
    nullifier_array[1] = rln_identifier;
    Vec_CFr_t nullifier_inputs = {
        .ptr = (CFr_t*)nullifier_array,
        .len = 2,
        .cap = 2
    };
    CFr_t* external_nullifier = ffi2_poseidon_hash(nullifier_inputs);
    printf("External nullifier generated\n");

    // Create user_message_limit (100) and message_id (1) using hash
    const char* limit_str = "100";
    slice_ref_uint8_t limit_slice = {(const uint8_t*)limit_str, strlen(limit_str)};
    CFr_t* user_message_limit = ffi2_hash(limit_slice);

    const char* msg_id_str = "1";
    slice_ref_uint8_t msg_id_slice = {(const uint8_t*)msg_id_str, strlen(msg_id_str)};
    CFr_t* message_id = ffi2_hash(msg_id_slice);

    // Prepare witness input for proof generation (stack-allocated)
    FFI2_RLNWitnessInput_t witness_input = {
        .identity_secret = identity_secret_ptr,
        .user_message_limit = user_message_limit,
        .message_id = message_id,
        .path_elements = {
            .ptr = merkle_proof->path_elements.ptr,
            .len = merkle_proof->path_elements.len,
            .cap = merkle_proof->path_elements.cap
        },
        .identity_path_index = {
            .ptr = merkle_proof->path_index.ptr,
            .len = merkle_proof->path_index.len
        },
        .x = x,
        .external_nullifier = external_nullifier
    };
    FFI2_RLNWitnessInput_t* witness_input_ptr = &witness_input;
    printf("Witness input prepared\n");

    // Generate RLN proof
    printf("Generating proof...\n");
    CResult_FFI2_RLNProof_ptr_Vec_uint8_t proof_gen_result = ffi2_prove(&rln, &witness_input_ptr);
    FFI2_RLNProof_t* rln_proof = NULL;
    int exit_code = EXIT_SUCCESS;

    if (!proof_gen_result.ok) {
        fprintf(stderr, "Proof generation failed: %s\n", proof_gen_result.err.ptr);
        exit_code = EXIT_FAILURE;
    } else {
        rln_proof = proof_gen_result.ok;
        printf("Proof generated successfully\n");

        // Verify the proof
        printf("Verifying proof...\n");
        CResult_bool_ptr_Vec_uint8_t verify_result = ffi2_verify(&rln, &rln_proof);
        if (!verify_result.ok) {
            fprintf(stderr, "Proof verification error: %s\n", verify_result.err.ptr);
            exit_code = EXIT_FAILURE;
        } else if (*verify_result.ok) {
            printf("Proof verification succeeded\n");
        } else {
            printf("Proof verification failed\n");
            exit_code = EXIT_FAILURE;
        }
    }

    // Cleanup
    printf("Cleaning up...\n");
    if (rln_proof) {
        printf("  Freeing rln_proof...\n");
        ffi2_rln_proof_free(rln_proof);
    }
    printf("  Freeing merkle_proof...\n");
    ffi2_merkle_proof_free(merkle_proof);
    printf("  Freeing x...\n");
    cfr_free(x);
    printf("  Freeing epoch...\n");
    cfr_free(epoch);
    printf("  Freeing rln_identifier...\n");
    cfr_free(rln_identifier);
    printf("  Freeing external_nullifier...\n");
    cfr_free(external_nullifier);
    printf("  Freeing user_message_limit...\n");
    cfr_free(user_message_limit);
    printf("  Freeing message_id...\n");
    cfr_free(message_id);
    printf("  Freeing keys...\n");
    vec_cfr_free(keys);
    printf("  Freeing rln...\n");
    ffi2_rln_free(rln);

    printf("Cleanup completed\n");
    return exit_code;
}