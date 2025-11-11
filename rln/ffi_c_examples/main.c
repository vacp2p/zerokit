#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rln.h"

int main (int argc, char const * const argv[])
{
    printf("Creating RLN instance\n");

#ifdef STATELESS
    CResult_FFI_RLN_ptr_Vec_uint8_t ffi_new_result = ffi_new();
#else
    const char* config_path = "../resources/tree_depth_20/config.json";
    CResult_FFI_RLN_ptr_Vec_uint8_t ffi_new_result = ffi_new(20, config_path);
#endif

    if (!ffi_new_result.ok) {
        fprintf(stderr, "Initial RLN instance creation error: %s\n", ffi_new_result.err.ptr);
        vec_u8_free(ffi_new_result.err);
        return EXIT_FAILURE;
    }

    FFI_RLN_t* rln = ffi_new_result.ok;
    printf("RLN instance created successfully\n");

    printf("\nGenerating identity keys\n");
    Vec_CFr_t keys = ffi_key_gen();
    CFr_t* identity_secret = (CFr_t*)vec_cfr_get(&keys, 0);
    CFr_t* id_commitment = (CFr_t*)vec_cfr_get(&keys, 1);
    printf("Identity generated\n");

    Vec_uint8_t debug = cfr_debug(identity_secret);
    printf("  - identity_secret = %s\n", debug.ptr);
    vec_u8_free(debug);

    debug = cfr_debug(id_commitment);
    printf("  - id_commitment = %s\n", debug.ptr);
    vec_u8_free(debug);

    printf("\nCreating message limit\n");
    CFr_t* user_message_limit = uint_to_cfr(1);

    debug = cfr_debug(user_message_limit);
    printf("  - user_message_limit = %s\n", debug.ptr);
    vec_u8_free(debug);

    printf("\nComputing rate commitment\n");
    CFr_t* rate_commitment = ffi_poseidon_hash_pair(id_commitment, user_message_limit);

    debug = cfr_debug(rate_commitment);
    printf("  - rate_commitment = %s\n", debug.ptr);
    vec_u8_free(debug);

    printf("\nCFr serialization: CFr <-> bytes\n");
    Vec_uint8_t ser_rate_commitment = cfr_to_bytes_le(rate_commitment);

    debug = vec_u8_debug(&ser_rate_commitment);
    printf("  - serialized rate_commitment = %s\n", debug.ptr);
    vec_u8_free(debug);

    CFr_t* deser_rate_commitment = bytes_le_to_cfr(&ser_rate_commitment);

    debug = cfr_debug(deser_rate_commitment);
    printf("  - deserialized rate_commitment = %s\n", debug.ptr);
    vec_u8_free(debug);

    vec_u8_free(ser_rate_commitment);
    cfr_free(deser_rate_commitment);

    printf("\nVec<CFr> serialization: Vec<CFr> <-> bytes\n");
    Vec_uint8_t ser_keys = vec_cfr_to_bytes_le(&keys);

    debug = vec_u8_debug(&ser_keys);
    printf("  - serialized keys = %s\n", debug.ptr);
    vec_u8_free(debug);

    CResult_Vec_CFr_ptr_Vec_uint8_t deser_keys_result = bytes_le_to_vec_cfr(&ser_keys);
    if (!deser_keys_result.ok) {
        fprintf(stderr, "Keys deserialization error: %s\n", deser_keys_result.err.ptr);
        vec_u8_free(deser_keys_result.err);
        return EXIT_FAILURE;
    }

    debug = vec_cfr_debug(deser_keys_result.ok);
    printf("  - deserialized identity_secret = %s\n", debug.ptr);
    vec_u8_free(debug);

    Vec_CFr_t deser_keys = *deser_keys_result.ok;
    vec_cfr_free(deser_keys);
    free(deser_keys_result.ok);

    vec_u8_free(ser_keys);

#ifdef STATELESS
    #define TREE_DEPTH 20
    const size_t CFR_SIZE = 32;

    printf("\nBuilding Merkle path for stateless mode\n");
    CFr_t* default_leaf = cfr_zero();

    CFr_t* default_hashes[TREE_DEPTH - 1];
    default_hashes[0] = ffi_poseidon_hash_pair(default_leaf, default_leaf);
    for (size_t i = 1; i < TREE_DEPTH - 1; i++) {
        default_hashes[i] = ffi_poseidon_hash_pair(default_hashes[i-1], default_hashes[i-1]);
    }

    void* path_elements_buffer = malloc(CFR_SIZE * TREE_DEPTH);
    memcpy(path_elements_buffer, default_leaf, CFR_SIZE);
    for (size_t i = 1; i < TREE_DEPTH; i++) {
        memcpy(path_elements_buffer + (i * CFR_SIZE), default_hashes[i-1], CFR_SIZE);
    }
    Vec_CFr_t path_elements = {
        .ptr = (CFr_t*)path_elements_buffer,
        .len = TREE_DEPTH,
        .cap = TREE_DEPTH
    };

    printf("\nVec<CFr> serialization: Vec<CFr> <-> bytes\n");
    Vec_uint8_t ser_path_elements = vec_cfr_to_bytes_le(&path_elements);

    debug = vec_u8_debug(&ser_path_elements);
    printf("  - serialized path_elements = %s\n", debug.ptr);
    vec_u8_free(debug);

    CResult_Vec_CFr_ptr_Vec_uint8_t deser_path_elements_result = bytes_le_to_vec_cfr(&ser_path_elements);
    if (!deser_path_elements_result.ok) {
        fprintf(stderr, "Path elements deserialization error: %s\n", deser_path_elements_result.err.ptr);
        vec_u8_free(deser_path_elements_result.err);
        return EXIT_FAILURE;
    }

    debug = vec_cfr_debug(deser_path_elements_result.ok);
    printf("  - deserialized path_elements = %s\n", debug.ptr);
    vec_u8_free(debug);

    Vec_CFr_t deser_path_elements = *deser_path_elements_result.ok;
    vec_cfr_free(deser_path_elements);
    free(deser_path_elements_result.ok);

    vec_u8_free(ser_path_elements);

    uint8_t* path_index_arr = calloc(TREE_DEPTH, sizeof(uint8_t));
    Vec_uint8_t identity_path_index = {
        .ptr = path_index_arr,
        .len = TREE_DEPTH,
        .cap = TREE_DEPTH
    };

    printf("\nVec<uint8> serialization: Vec<uint8> <-> bytes\n");
    Vec_uint8_t ser_path_index = vec_u8_to_bytes_le(&identity_path_index);

    debug = vec_u8_debug(&ser_path_index);
    printf("  - serialized path_index = %s\n", debug.ptr);
    vec_u8_free(debug);

    CResult_Vec_uint8_ptr_Vec_uint8_t deser_path_index_result = bytes_le_to_vec_u8(&ser_path_index);
    if (!deser_path_index_result.ok) {
        fprintf(stderr, "Path index deserialization error: %s\n", deser_path_index_result.err.ptr);
        vec_u8_free(deser_path_index_result.err);
        return EXIT_FAILURE;
    }

    debug = vec_u8_debug(deser_path_index_result.ok);
    printf("  - deserialized path_index = %s\n", debug.ptr);
    vec_u8_free(debug);

    Vec_uint8_t deser_path_index = *deser_path_index_result.ok;
    vec_u8_free(deser_path_index);
    free(deser_path_index_result.ok);

    vec_u8_free(ser_path_index);

    printf("\nComputing Merkle root for stateless mode\n");
    printf("  - computing root for index 0 with rate_commitment\n");
    CFr_t* computed_root = ffi_poseidon_hash_pair(rate_commitment, default_leaf);
    for (size_t i = 1; i < TREE_DEPTH; i++) {
        CFr_t* next_root = ffi_poseidon_hash_pair(computed_root, default_hashes[i-1]);
        cfr_free(computed_root);
        computed_root = next_root;
    }

    debug = cfr_debug(computed_root);
    printf("  - computed_root = %s\n", debug.ptr);
    vec_u8_free(debug);
#else
    printf("\nAdding rate_commitment to tree\n");
    CResult_bool_ptr_Vec_uint8_t set_result = ffi_set_next_leaf(&rln, &rate_commitment);
    if (!set_result.ok) {
        fprintf(stderr, "Set next leaf error: %s\n", set_result.err.ptr);
        vec_u8_free(set_result.err);
        return EXIT_FAILURE;
    }
    free(set_result.ok);

    size_t leaf_index = ffi_leaves_set(&rln) - 1;
    printf("  - added to tree at index %zu\n", leaf_index);

    printf("\nGetting Merkle proof\n");
    CResult_FFI_MerkleProof_ptr_Vec_uint8_t proof_result = ffi_get_proof(&rln, leaf_index);
    if (!proof_result.ok) {
        fprintf(stderr, "Get proof error: %s\n", proof_result.err.ptr);
        vec_u8_free(proof_result.err);
        return EXIT_FAILURE;
    }
    FFI_MerkleProof_t* merkle_proof = proof_result.ok;
    printf("  - proof obtained (depth: %zu)\n", merkle_proof->path_elements.len);
#endif

    printf("\nHashing signal\n");
    uint8_t signal[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    Vec_uint8_t signal_vec = {signal, 32, 32};
    CFr_t* x = ffi_hash_to_field_le(&signal_vec);

    debug = cfr_debug(x);
    printf("  - x = %s\n", debug.ptr);
    vec_u8_free(debug);

    printf("\nHashing epoch\n");
    const char* epoch_str = "test-epoch";
    Vec_uint8_t epoch_vec = {(uint8_t*)epoch_str, strlen(epoch_str), strlen(epoch_str)};
    CFr_t* epoch = ffi_hash_to_field_le(&epoch_vec);

    debug = cfr_debug(epoch);
    printf("  - epoch = %s\n", debug.ptr);
    vec_u8_free(debug);

    printf("\nHashing RLN identifier\n");
    const char* rln_id_str = "test-rln-identifier";
    Vec_uint8_t rln_id_vec = {(uint8_t*)rln_id_str, strlen(rln_id_str), strlen(rln_id_str)};
    CFr_t* rln_identifier = ffi_hash_to_field_le(&rln_id_vec);

    debug = cfr_debug(rln_identifier);
    printf("  - rln_identifier = %s\n", debug.ptr);
    vec_u8_free(debug);

    printf("\nComputing Poseidon hash for external nullifier\n");
    CFr_t* external_nullifier = ffi_poseidon_hash_pair(epoch, rln_identifier);

    debug = cfr_debug(external_nullifier);
    printf("  - external_nullifier = %s\n", debug.ptr);
    vec_u8_free(debug);

    printf("\nCreating message_id\n");
    CFr_t* message_id = uint_to_cfr(0);

    debug = cfr_debug(message_id);
    printf("  - message_id = %s\n", debug.ptr);
    vec_u8_free(debug);

    printf("\nGenerating RLN Proof\n");
#ifdef STATELESS
    CResult_FFI_RLNProof_ptr_Vec_uint8_t proof_gen_result = ffi_generate_rln_proof_stateless(
        &rln,
        identity_secret,
        user_message_limit,
        message_id,
        &path_elements,
        &identity_path_index,
        x,
        external_nullifier
    );
#else
    CResult_FFI_RLNProof_ptr_Vec_uint8_t proof_gen_result = ffi_generate_rln_proof(
        &rln,
        identity_secret,
        user_message_limit,
        message_id,
        x,
        external_nullifier,
        leaf_index
    );
#endif

    if (!proof_gen_result.ok) {
        fprintf(stderr, "Proof generation error: %s\n", proof_gen_result.err.ptr);
        vec_u8_free(proof_gen_result.err);
        return EXIT_FAILURE;
    }

    FFI_RLNProof_t* rln_proof = proof_gen_result.ok;
    printf("Proof generated successfully\n");

    printf("\nVerifying Proof\n");
#ifdef STATELESS
    Vec_CFr_t roots = {
        .ptr = computed_root,
        .len = 1,
        .cap = 1
    };
    CResult_bool_ptr_Vec_uint8_t verify_result = ffi_verify_with_roots(&rln, &rln_proof, &roots, x);
#else
    CResult_bool_ptr_Vec_uint8_t verify_result = ffi_verify_rln_proof(&rln, &rln_proof, x);
#endif
    if (!verify_result.ok) {
        fprintf(stderr, "Proof verification error: %s\n", verify_result.err.ptr);
        vec_u8_free(verify_result.err);
        return EXIT_FAILURE;
    }

    if (*verify_result.ok) {
        printf("Proof verified successfully\n");
    } else {
        printf("Proof verification failed\n");
        free(verify_result.ok);
        return EXIT_FAILURE;
    }
    free(verify_result.ok);

    printf("\nSimulating double-signaling attack (same epoch, different message)\n");

    printf("\nHashing second signal\n");
    uint8_t signal2[32] = {11, 12, 13, 14, 15, 16, 17, 18, 19, 20};
    Vec_uint8_t signal2_vec = {signal2, 32, 32};
    CFr_t* x2 = ffi_hash_to_field_le(&signal2_vec);

    debug = cfr_debug(x2);
    printf("  - x2 = %s\n", debug.ptr);
    vec_u8_free(debug);

    printf("\nCreating second message with the same id\n");
    CFr_t* message_id2 = uint_to_cfr(0);

    debug = cfr_debug(message_id2);
    printf("  - message_id2 = %s\n", debug.ptr);
    vec_u8_free(debug);

    printf("\nGenerating second RLN Proof\n");
#ifdef STATELESS
    CResult_FFI_RLNProof_ptr_Vec_uint8_t proof_gen_result2 = ffi_generate_rln_proof_stateless(
        &rln,
        identity_secret,
        user_message_limit,
        message_id2,
        &path_elements,
        &identity_path_index,
        x2,
        external_nullifier
    );
#else
    CResult_FFI_RLNProof_ptr_Vec_uint8_t proof_gen_result2 = ffi_generate_rln_proof(
        &rln,
        identity_secret,
        user_message_limit,
        message_id2,
        x2,
        external_nullifier,
        leaf_index
    );
#endif

    if (!proof_gen_result2.ok) {
        fprintf(stderr, "Second proof generation error: %s\n", proof_gen_result2.err.ptr);
        vec_u8_free(proof_gen_result2.err);
        return EXIT_FAILURE;
    }

    FFI_RLNProof_t* rln_proof2 = proof_gen_result2.ok;
    printf("Second proof generated successfully\n");

    printf("\nVerifying second proof\n");
#ifdef STATELESS
    CResult_bool_ptr_Vec_uint8_t verify_result2 = ffi_verify_with_roots(&rln, &rln_proof2, &roots, x2);
#else
    CResult_bool_ptr_Vec_uint8_t verify_result2 = ffi_verify_rln_proof(&rln, &rln_proof2, x2);
#endif
    if (!verify_result2.ok) {
        fprintf(stderr, "Second proof verification error: %s\n", verify_result2.err.ptr);
        vec_u8_free(verify_result2.err);
        return EXIT_FAILURE;
    }

    if (*verify_result2.ok) {
        printf("Second proof verified successfully\n");

        printf("\nRecovering identity secret\n");
        CResult_CFr_ptr_Vec_uint8_t recover_result = ffi_recover_id_secret(&rln_proof, &rln_proof2);
        if (!recover_result.ok) {
            fprintf(stderr, "Identity recovery error: %s\n", recover_result.err.ptr);
            vec_u8_free(recover_result.err);
            return EXIT_FAILURE;
        }

        CFr_t* recovered_secret = recover_result.ok;

        debug = cfr_debug(recovered_secret);
        printf("  - recovered_secret = %s\n", debug.ptr);
        vec_u8_free(debug);

        debug = cfr_debug(identity_secret);
        printf("  - original_secret  = %s\n", debug.ptr);
        vec_u8_free(debug);

        printf("Slashing successful: Identity is recovered!\n");

        cfr_free(recovered_secret);
    } else {
        printf("Second proof verification failed\n");
        free(verify_result2.ok);
        return EXIT_FAILURE;
    }
    free(verify_result2.ok);

    ffi_rln_proof_free(rln_proof2);
    cfr_free(x2);
    cfr_free(message_id2);
    ffi_rln_proof_free(rln_proof);

#ifdef STATELESS
    free(path_index_arr);
    free(path_elements_buffer);
    for (size_t i = 0; i < TREE_DEPTH - 1; i++) {
        cfr_free(default_hashes[i]);
    }
    cfr_free(default_leaf);
    cfr_free(computed_root);
#else
    ffi_merkle_proof_free(merkle_proof);
#endif

    cfr_free(rate_commitment);
    cfr_free(x);
    cfr_free(epoch);
    cfr_free(rln_identifier);
    cfr_free(external_nullifier);
    cfr_free(user_message_limit);
    cfr_free(message_id);
    vec_cfr_free(keys);
    ffi_rln_free(rln);

    return EXIT_SUCCESS;
}