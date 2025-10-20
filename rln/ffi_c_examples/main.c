#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rln.h"

int main (int argc, char const * const argv[])
{
    printf("Creating RLN instance\n");
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

    printf("\nGenerating identity keys\n");
    Vec_CFr_t keys = ffi2_key_gen();
    CFr_t* identity_secret_ptr = keys.ptr;
    CFr_t* id_commitment = (CFr_t*)vec_cfr_get(&keys, 1);
    printf("Identity generated\n");
    printf("  - identity_secret = %s\n",cfr_debug(identity_secret_ptr).ptr);
    printf("  - id_commitment = %s\n",cfr_debug(id_commitment).ptr);

    printf("\nCreating message limit\n");
    CFr_t* user_message_limit = cfr_from_uint(1);
    printf("   - user_message_limit = %s\n",cfr_debug(user_message_limit).ptr);

    printf("\nComputing rate commitment\n");
    const size_t CFR_SIZE = 32;
    void* rate_buffer = malloc(CFR_SIZE * 2);
    memcpy(rate_buffer, id_commitment, CFR_SIZE);
    memcpy((char*)rate_buffer + CFR_SIZE, user_message_limit, CFR_SIZE);
    Vec_CFr_t rate_inputs = {
        .ptr = (CFr_t*)rate_buffer,
        .len = 2,
        .cap = 2
    };
    CFr_t* rate_commitment = ffi2_poseidon_hash(&rate_inputs);
    printf("  - rate_commitment = %s\n", cfr_debug(rate_commitment).ptr);
    cfr_debug(rate_commitment);
    free(rate_buffer);

    printf("\nAdding rate_commitment to tree\n");
    CResult_bool_ptr_Vec_uint8_t set_result = ffi2_set_next_leaf(&rln, &rate_commitment);
    if (!set_result.ok) {
        fprintf(stderr, "%s", set_result.err.ptr);
        vec_cfr_free(keys);
        ffi2_rln_free(rln);
        return EXIT_FAILURE;
    }

    size_t leaf_index = ffi2_leaves_set(&rln) - 1;
    printf("  - added to tree at index %zu\n", leaf_index);

    printf("\nRetrieving current Merkle roots\n");
    CFr_t* roots = ffi2_get_root(&rln);
    printf("  - roots = %s\n", cfr_debug(roots).ptr);

    printf("\nGetting Merkle proof\n");
    CResult_FFI2_MerkleProof_ptr_Vec_uint8_t proof_result = ffi2_get_proof(&rln, leaf_index);
    if (!proof_result.ok) {
        fprintf(stderr, "%s", proof_result.err.ptr);
        vec_cfr_free(keys);
        ffi2_rln_free(rln);
        return EXIT_FAILURE;
    }
    FFI2_MerkleProof_t* merkle_proof = proof_result.ok;
    printf("  - proof obtained (depth: %zu)\n", merkle_proof->path_elements.len);

    printf("\nHashing signal\n");
    uint8_t signal[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    slice_ref_uint8_t signal_slice = {signal, 32};
    CFr_t* x = ffi2_hash(signal_slice);
    printf("  - x = %s\n", cfr_debug(x).ptr);

    printf("\nHashing epoch\n");
    const char* epoch_str = "test-epoch";
    slice_ref_uint8_t epoch_slice = {(const uint8_t*)epoch_str, strlen(epoch_str)};
    CFr_t* epoch = ffi2_hash(epoch_slice);
    printf("  - epoch = %s\n", cfr_debug(epoch).ptr);

    printf("\nHashing RLN identifier\n");
    const char* rln_id_str = "test-rln-identifier";
    slice_ref_uint8_t rln_id_slice = {(const uint8_t*)rln_id_str, strlen(rln_id_str)};
    CFr_t* rln_identifier = ffi2_hash(rln_id_slice);
    printf("  - rln_identifier = %s\n", cfr_debug(rln_identifier).ptr);

    printf("\nComputing Poseidon hash for external nullifier\n");
    void* nullifier_buffer = malloc(CFR_SIZE * 2);
    memcpy(nullifier_buffer, epoch, CFR_SIZE);
    memcpy((char*)nullifier_buffer + CFR_SIZE, rln_identifier, CFR_SIZE);
    Vec_CFr_t nullifier_inputs = {
        .ptr = (CFr_t*)nullifier_buffer,
        .len = 2,
        .cap = 2
    };
    CFr_t* external_nullifier = ffi2_poseidon_hash(&nullifier_inputs);
    printf("  - external_nullifier = %s\n", cfr_debug(external_nullifier).ptr);
    free(nullifier_buffer);

    printf("\nCreating message_id\n");
    CFr_t* message_id = cfr_from_uint(0);
    printf("  - message_id = %s\n", cfr_debug(message_id).ptr);

    printf("\nGenerating RLN Proof\n");
    CResult_FFI2_RLNProof_ptr_Vec_uint8_t proof_gen_result = ffi2_generate_rln_proof(
        &rln,
        identity_secret_ptr,
        user_message_limit,
        message_id,
        x,
        external_nullifier,
        leaf_index
    );
    FFI2_RLNProof_t* rln_proof = NULL;
    int exit_code = EXIT_SUCCESS;

    if (!proof_gen_result.ok) {
        fprintf(stderr, "Proof generation failed: %s\n", proof_gen_result.err.ptr);
        exit_code = EXIT_FAILURE;
    } else {
        rln_proof = proof_gen_result.ok;
        printf("Proof generated successfully\n");

        printf("\nVerifying Proof\n");
        CResult_bool_ptr_Vec_uint8_t verify_result = ffi2_verify_rln_proof(&rln, &rln_proof);
        if (!verify_result.ok) {
            fprintf(stderr, "Proof verification error: %s\n", verify_result.err.ptr);
            exit_code = EXIT_FAILURE;
        } else if (*verify_result.ok) {
            printf("Proof verification successfully\n");
        } else {
            printf("Proof verification failed\n");
            exit_code = EXIT_FAILURE;
        }

        printf("\nSimulating double-signaling attack (same epoch, different message)\n");

        printf("\nHashing second signal\n");
        uint8_t signal2[32] = {11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
        slice_ref_uint8_t signal2_slice = {signal2, 32};
        CFr_t* x2 = ffi2_hash(signal2_slice);
        printf("  - x2 = %s\n", cfr_debug(x2).ptr);

        printf("\nCreating second message with the same id\n");
        CFr_t* message_id2 = cfr_from_uint(0);
        printf("  - message_id2 = %s\n", cfr_debug(message_id2).ptr);

        printf("\nGenerating second RLN Proof\n");
        CResult_FFI2_RLNProof_ptr_Vec_uint8_t proof_gen_result2 = ffi2_generate_rln_proof(
            &rln,
            identity_secret_ptr,
            user_message_limit,
            message_id2,
            x2,
            external_nullifier,
            leaf_index
        );
        FFI2_RLNProof_t* rln_proof2 = NULL;

        if (!proof_gen_result2.ok) {
            fprintf(stderr, "Second proof generation failed: %s\n", proof_gen_result2.err.ptr);
            exit_code = EXIT_FAILURE;
        } else {
            rln_proof2 = proof_gen_result2.ok;
            printf("Second proof generated successfully\n");

            printf("\nVerifying second proof\n");
            CResult_bool_ptr_Vec_uint8_t verify_result2 = ffi2_verify_rln_proof(&rln, &rln_proof2);
            if (!verify_result2.ok) {
                fprintf(stderr, "Second proof verification error: %s\n", verify_result2.err.ptr);
                exit_code = EXIT_FAILURE;
            } else if (*verify_result2.ok) {
                printf("Second proof verified successfully\n");

                printf("\nRecovering identity secret\n");
                CResult_CFr_ptr_Vec_uint8_t recover_result = ffi2_recover_id_secret(&rln_proof, &rln_proof2);
                if (!recover_result.ok) {
                    fprintf(stderr, "Identity recovery error: %s\n", recover_result.err.ptr);
                    exit_code = EXIT_FAILURE;
                } else {
                    CFr_t* recovered_secret = recover_result.ok;
                    printf("  - recovered_secret = %s\n", cfr_debug(recovered_secret).ptr);
                    printf("  - original_secret  = %s\n", cfr_debug(identity_secret_ptr).ptr);

                    printf("Slashing successful: Identity is recovered!\n");

                    cfr_free(recovered_secret);
                }
            } else {
                printf("Second proof verification failed\n");
                exit_code = EXIT_FAILURE;
            }
        }

        if (rln_proof2) {
            ffi2_rln_proof_free(rln_proof2);
        }
        cfr_free(x2);
        cfr_free(message_id2);
    }

    if (rln_proof) {
        ffi2_rln_proof_free(rln_proof);
    }
    ffi2_merkle_proof_free(merkle_proof);
    cfr_free(rate_commitment);
    cfr_free(roots);
    cfr_free(x);
    cfr_free(epoch);
    cfr_free(rln_identifier);
    cfr_free(external_nullifier);
    cfr_free(user_message_limit);
    cfr_free(message_id);
    vec_cfr_free(keys);
    ffi2_rln_free(rln);
    return exit_code;
}