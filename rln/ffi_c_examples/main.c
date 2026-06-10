#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rln.h"

static int file_to_bytes(const char *path, Vec_uint8_t *out)
{
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *data = (uint8_t *)malloc(size);
    if (!data)
    {
        fclose(f);
        return -1;
    }
    fread(data, 1, size, f);
    fclose(f);
    out->ptr = data;
    out->len = size;
    out->cap = size;
    return 0;
}

int main(int argc, char const *const argv[])
{
    const size_t tree_depth = 20;
    const size_t max_out = 4;
    (void)max_out;
    printf("Creating RLN instance\n");
#ifdef MULTI_MESSAGE_ID
    const char *zkey_path = "../resources/tree_depth_20/multi_message_id/max_out_4/rln_final.arkzkey";
    const char *graph_path = "../resources/tree_depth_20/multi_message_id/max_out_4/graph.bin";
#else
    const char *zkey_path = "../resources/tree_depth_20/rln_final.arkzkey";
    const char *graph_path = "../resources/tree_depth_20/graph.bin";
#endif
    Vec_uint8_t zkey_data;
    if (file_to_bytes(zkey_path, &zkey_data) != 0)
    {
        fprintf(stderr, "Failed to read zkey: %s\n", zkey_path);
        return EXIT_FAILURE;
    }
    Vec_uint8_t graph_data;
    if (file_to_bytes(graph_path, &graph_data) != 0)
    {
        fprintf(stderr, "Failed to read graph: %s\n", graph_path);
        free(zkey_data.ptr);
        return EXIT_FAILURE;
    }
    CResult_FFI_RLNV3_ptr_Vec_uint8_t rln_instance_result =
        ffi_rln_v3_new_with_pm_tree(tree_depth, &zkey_data, &graph_data, "");
    free(zkey_data.ptr);
    free(graph_data.ptr);
    if (!rln_instance_result.ok)
    {
        fprintf(stderr, "RLN instance creation error: %s\n", rln_instance_result.err.ptr);
        ffi_c_string_free(rln_instance_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3_t *rln_instance = rln_instance_result.ok;
    printf("  - RLN instance created successfully\n");
    printf("  - circuit tree depth = %zu\n", tree_depth);
#ifdef MULTI_MESSAGE_ID
    printf("  - circuit max out = %zu\n", max_out);
#endif

    printf("\nGenerating identity keys\n");
    Vec_CFr_t keys = ffi_key_gen();
    const CFr_t *identity_secret = ffi_vec_cfr_get(&keys, 0);
    const CFr_t *id_commitment = ffi_vec_cfr_get(&keys, 1);
    printf("  - identity generated successfully\n");
    Vec_uint8_t debug = ffi_cfr_debug(identity_secret);
    printf("  - identity secret = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    debug = ffi_cfr_debug(id_commitment);
    printf("  - id commitment = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nCreating message limit\n");
    CFr_t *user_message_limit = ffi_uint_to_cfr(10);
    debug = ffi_cfr_debug(user_message_limit);
    printf("  - user message limit = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nComputing rate commitment\n");
    CFr_t *rate_commitment = ffi_poseidon_hash_pair(id_commitment, user_message_limit);
    debug = ffi_cfr_debug(rate_commitment);
    printf("  - rate commitment = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nCFr serialization: CFr <-> bytes\n");
    CResult_Vec_uint8_Vec_uint8_t ser_rate_commitment_result = ffi_cfr_to_bytes_le(rate_commitment);
    if (ser_rate_commitment_result.err.ptr)
    {
        fprintf(stderr, "Rate commitment serialization error: %s\n", ser_rate_commitment_result.err.ptr);
        ffi_c_string_free(ser_rate_commitment_result.err);
        return EXIT_FAILURE;
    }
    Vec_uint8_t ser_rate_commitment = ser_rate_commitment_result.ok;
    debug = ffi_vec_u8_debug(&ser_rate_commitment);
    printf("  - serialized rate commitment = %s\n", debug.ptr);
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
    printf("  - deserialized rate commitment = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_vec_u8_free(ser_rate_commitment);
    ffi_cfr_free(deser_rate_commitment);

    printf("\nAdding rate commitment to tree\n");
    CBoolResult_t set_leaf_result = ffi_rln_v3_set_next_leaf(&rln_instance, rate_commitment);
    if (!set_leaf_result.ok)
    {
        fprintf(stderr, "Adding rate commitment error: %s\n", set_leaf_result.err.ptr);
        ffi_c_string_free(set_leaf_result.err);
        return EXIT_FAILURE;
    }
    printf("  - rate commitment added at leaf 0\n");

    printf("\nGetting Merkle proof\n");
    CResult_FFI_RLNV3MerkleProof_ptr_Vec_uint8_t merkle_proof_result = ffi_rln_v3_get_merkle_proof(&rln_instance, 0);
    if (!merkle_proof_result.ok)
    {
        fprintf(stderr, "Merkle proof error: %s\n", merkle_proof_result.err.ptr);
        ffi_c_string_free(merkle_proof_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3MerkleProof_t *merkle_proof = merkle_proof_result.ok;
    printf("  - merkle proof obtained\n");

    printf("\nVec<CFr> serialization: Vec<CFr> <-> bytes\n");
    CResult_Vec_uint8_Vec_uint8_t ser_path_elements_result = ffi_vec_cfr_to_bytes_le(&merkle_proof->path_elements);
    if (ser_path_elements_result.err.ptr)
    {
        fprintf(stderr, "Path elements serialization error: %s\n", ser_path_elements_result.err.ptr);
        ffi_c_string_free(ser_path_elements_result.err);
        return EXIT_FAILURE;
    }
    Vec_uint8_t ser_path_elements = ser_path_elements_result.ok;
    debug = ffi_vec_u8_debug(&ser_path_elements);
    printf("  - serialized path elements = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    CResult_Vec_CFr_Vec_uint8_t deser_path_elements_result = ffi_bytes_le_to_vec_cfr(&ser_path_elements);
    if (deser_path_elements_result.err.ptr)
    {
        fprintf(stderr, "Path elements deserialization error: %s\n", deser_path_elements_result.err.ptr);
        ffi_c_string_free(deser_path_elements_result.err);
        return EXIT_FAILURE;
    }
    debug = ffi_vec_cfr_debug(&deser_path_elements_result.ok);
    printf("  - deserialized path elements = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_vec_cfr_free(deser_path_elements_result.ok);
    ffi_vec_u8_free(ser_path_elements);

    printf("\nVec<uint8> serialization: Vec<uint8> <-> bytes\n");
    CResult_Vec_uint8_Vec_uint8_t ser_path_index_result = ffi_vec_u8_to_bytes_le(&merkle_proof->path_index);
    if (ser_path_index_result.err.ptr)
    {
        fprintf(stderr, "Path index serialization error: %s\n", ser_path_index_result.err.ptr);
        ffi_c_string_free(ser_path_index_result.err);
        return EXIT_FAILURE;
    }
    Vec_uint8_t ser_path_index = ser_path_index_result.ok;
    debug = ffi_vec_u8_debug(&ser_path_index);
    printf("  - serialized path index = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    CResult_Vec_uint8_Vec_uint8_t deser_path_index_result = ffi_bytes_le_to_vec_u8(&ser_path_index);
    if (deser_path_index_result.err.ptr)
    {
        fprintf(stderr, "Path index deserialization error: %s\n", deser_path_index_result.err.ptr);
        ffi_c_string_free(deser_path_index_result.err);
        return EXIT_FAILURE;
    }
    debug = ffi_vec_u8_debug(&deser_path_index_result.ok);
    printf("  - deserialized path index = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_vec_u8_free(deser_path_index_result.ok);
    ffi_vec_u8_free(ser_path_index);

    printf("\nHashing first signal\n");
    uint8_t signal1[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    CFr_t *x1 = ffi_hash_to_field_le(&(Vec_uint8_t){signal1, 32, 32});
    debug = ffi_cfr_debug(x1);
    printf("  - x1 = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nHashing epoch\n");
    const char *epoch_str = "test-epoch";
    CFr_t *epoch = ffi_hash_to_field_le(&(Vec_uint8_t){(uint8_t *)epoch_str, strlen(epoch_str), strlen(epoch_str)});
    debug = ffi_cfr_debug(epoch);
    printf("  - epoch = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nHashing RLN identifier\n");
    const char *rln_id_str = "test-rln-identifier";
    CFr_t *rln_identifier =
        ffi_hash_to_field_le(&(Vec_uint8_t){(uint8_t *)rln_id_str, strlen(rln_id_str), strlen(rln_id_str)});
    debug = ffi_cfr_debug(rln_identifier);
    printf("  - RLN identifier = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nComputing Poseidon hash for external nullifier\n");
    CFr_t *external_nullifier = ffi_poseidon_hash_pair(epoch, rln_identifier);
    debug = ffi_cfr_debug(external_nullifier);
    printf("  - external nullifier = %s\n", debug.ptr);
    ffi_c_string_free(debug);

    printf("\nCreating first message id\n");
    CFr_t *message_id1 = ffi_uint_to_cfr(0);
    debug = ffi_cfr_debug(message_id1);
    printf("  - message id = %s\n", debug.ptr);
    ffi_c_string_free(debug);
#ifdef MULTI_MESSAGE_ID
    printf("\nCreating first message ids and selector used (Multi message-id mode)\n");
    printf("  - using 2 out of %zu slots\n", max_out);
    Vec_CFr_t message_ids1 = ffi_vec_cfr_new(max_out);
    CFr_t *tmp;
    tmp = ffi_uint_to_cfr(0);
    ffi_vec_cfr_push(&message_ids1, tmp);
    ffi_cfr_free(tmp);
    tmp = ffi_uint_to_cfr(1);
    ffi_vec_cfr_push(&message_ids1, tmp);
    ffi_cfr_free(tmp);
    tmp = ffi_cfr_zero();
    ffi_vec_cfr_push(&message_ids1, tmp);
    ffi_cfr_free(tmp);
    tmp = ffi_cfr_zero();
    ffi_vec_cfr_push(&message_ids1, tmp);
    ffi_cfr_free(tmp);
    bool selector_used1[] = {true, true, false, false};
    debug = ffi_vec_cfr_debug(&message_ids1);
    printf("  - message ids = %s\n", debug.ptr);
    ffi_c_string_free(debug);
#endif

    printf("\nCreating first RLN witness\n");
    CResult_FFI_RLNV3WitnessInput_ptr_Vec_uint8_t witness1_result =
#ifdef MULTI_MESSAGE_ID
        ffi_rln_v3_witness_input_new_multi(identity_secret, user_message_limit, &message_ids1,
                                           &merkle_proof->path_elements, &merkle_proof->path_index, x1,
                                           external_nullifier, &(Vec_bool_t){selector_used1, max_out, max_out});
#else
        ffi_rln_v3_witness_input_new_single(identity_secret, user_message_limit, message_id1,
                                            &merkle_proof->path_elements, &merkle_proof->path_index, x1,
                                            external_nullifier);
#endif
    if (!witness1_result.ok)
    {
        fprintf(stderr, "First witness creation error: %s\n", witness1_result.err.ptr);
        ffi_c_string_free(witness1_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3WitnessInput_t *witness1 = witness1_result.ok;
    printf("  - first RLN witness created successfully\n");

    printf("\nRLNWitnessInput serialization: RLNWitnessInput <-> bytes\n");
    CResult_Vec_uint8_Vec_uint8_t ser_witness1_result = ffi_rln_v3_witness_to_bytes_le(&witness1);
    if (ser_witness1_result.err.ptr)
    {
        fprintf(stderr, "Witness serialization error: %s\n", ser_witness1_result.err.ptr);
        ffi_c_string_free(ser_witness1_result.err);
        return EXIT_FAILURE;
    }
    Vec_uint8_t ser_witness1 = ser_witness1_result.ok;
    debug = ffi_vec_u8_debug(&ser_witness1);
    printf("  - serialized witness = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    CResult_FFI_RLNV3WitnessInput_ptr_Vec_uint8_t deser_witness1_result = ffi_bytes_le_to_rln_v3_witness(&ser_witness1);
    if (!deser_witness1_result.ok)
    {
        fprintf(stderr, "Witness deserialization error: %s\n", deser_witness1_result.err.ptr);
        ffi_c_string_free(deser_witness1_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3WitnessInput_t *deser_witness1 = deser_witness1_result.ok;
    printf("  - witness deserialized successfully\n");
    ffi_rln_v3_witness_input_free(deser_witness1);
    ffi_vec_u8_free(ser_witness1);

    printf("\nGenerating first RLN proof\n");
    CResult_FFI_RLNV3Proof_ptr_Vec_uint8_t rln_proof1_result = ffi_rln_v3_generate_proof(&rln_instance, &witness1);
    if (!rln_proof1_result.ok)
    {
        fprintf(stderr, "Proof generation error: %s\n", rln_proof1_result.err.ptr);
        ffi_c_string_free(rln_proof1_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3Proof_t *rln_proof1 = rln_proof1_result.ok;
    printf("  - proof generated successfully\n");

    printf("\nGetting first RLN proof values\n");
    FFI_RLNV3ProofValues_t *proof_values1 = ffi_rln_v3_proof_get_values(&rln_proof1);
    printf("  - proof values extracted successfully\n");
#ifdef MULTI_MESSAGE_ID
    CResult_Vec_CFr_Vec_uint8_t ys1_result = ffi_rln_v3_proof_values_get_ys(&proof_values1);
    if (ys1_result.err.ptr)
    {
        fprintf(stderr, "Get ys error: %s\n", ys1_result.err.ptr);
        ffi_c_string_free(ys1_result.err);
        return EXIT_FAILURE;
    }
    debug = ffi_vec_cfr_debug(&ys1_result.ok);
    printf("  - ys = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_vec_cfr_free(ys1_result.ok);
    CResult_Vec_CFr_Vec_uint8_t nullifiers1_result = ffi_rln_v3_proof_values_get_nullifiers(&proof_values1);
    if (nullifiers1_result.err.ptr)
    {
        fprintf(stderr, "Get nullifiers error: %s\n", nullifiers1_result.err.ptr);
        ffi_c_string_free(nullifiers1_result.err);
        return EXIT_FAILURE;
    }
    debug = ffi_vec_cfr_debug(&nullifiers1_result.ok);
    printf("  - nullifiers = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_vec_cfr_free(nullifiers1_result.ok);
#else
    CResult_CFr_ptr_Vec_uint8_t y1_result = ffi_rln_v3_proof_values_get_y(&proof_values1);
    if (!y1_result.ok)
    {
        fprintf(stderr, "Get y error: %s\n", y1_result.err.ptr);
        ffi_c_string_free(y1_result.err);
        return EXIT_FAILURE;
    }
    debug = ffi_cfr_debug(y1_result.ok);
    printf("  - y = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_cfr_free(y1_result.ok);
    CResult_CFr_ptr_Vec_uint8_t nullifier1_result = ffi_rln_v3_proof_values_get_nullifier(&proof_values1);
    if (!nullifier1_result.ok)
    {
        fprintf(stderr, "Get nullifier error: %s\n", nullifier1_result.err.ptr);
        ffi_c_string_free(nullifier1_result.err);
        return EXIT_FAILURE;
    }
    debug = ffi_cfr_debug(nullifier1_result.ok);
    printf("  - nullifier = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_cfr_free(nullifier1_result.ok);
#endif
    CFr_t *proof_values1_root = ffi_rln_v3_proof_values_get_root(&proof_values1);
    debug = ffi_cfr_debug(proof_values1_root);
    printf("  - root = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_cfr_free(proof_values1_root);
    CFr_t *proof_values1_x = ffi_rln_v3_proof_values_get_x(&proof_values1);
    debug = ffi_cfr_debug(proof_values1_x);
    printf("  - x = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_cfr_free(proof_values1_x);
    CFr_t *proof_values1_external_nullifier = ffi_rln_v3_proof_values_get_external_nullifier(&proof_values1);
    debug = ffi_cfr_debug(proof_values1_external_nullifier);
    printf("  - external nullifier = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_cfr_free(proof_values1_external_nullifier);

    printf("\nRLNProof serialization: RLNProof <-> bytes\n");
    CResult_Vec_uint8_Vec_uint8_t ser_proof1_result = ffi_rln_v3_proof_to_bytes_le(&rln_proof1);
    if (ser_proof1_result.err.ptr)
    {
        fprintf(stderr, "Proof serialization error: %s\n", ser_proof1_result.err.ptr);
        ffi_c_string_free(ser_proof1_result.err);
        return EXIT_FAILURE;
    }
    Vec_uint8_t ser_proof1 = ser_proof1_result.ok;
    debug = ffi_vec_u8_debug(&ser_proof1);
    printf("  - serialized proof = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    CResult_FFI_RLNV3Proof_ptr_Vec_uint8_t deser_proof1_result = ffi_bytes_le_to_rln_v3_proof(&ser_proof1);
    if (!deser_proof1_result.ok)
    {
        fprintf(stderr, "Proof deserialization error: %s\n", deser_proof1_result.err.ptr);
        ffi_c_string_free(deser_proof1_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3Proof_t *deser_proof1 = deser_proof1_result.ok;
    printf("  - proof deserialized successfully\n");
    ffi_rln_v3_proof_free(deser_proof1);
    ffi_vec_u8_free(ser_proof1);

    printf("\nRLNProofValues serialization: RLNProofValues <-> bytes\n");
    CResult_Vec_uint8_Vec_uint8_t ser_proof_values1_result = ffi_rln_v3_proof_values_to_bytes_le(&proof_values1);
    if (ser_proof_values1_result.err.ptr)
    {
        fprintf(stderr, "Proof values serialization error: %s\n", ser_proof_values1_result.err.ptr);
        ffi_c_string_free(ser_proof_values1_result.err);
        return EXIT_FAILURE;
    }
    Vec_uint8_t ser_proof_values1 = ser_proof_values1_result.ok;
    debug = ffi_vec_u8_debug(&ser_proof_values1);
    printf("  - serialized proof values = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    CResult_FFI_RLNV3ProofValues_ptr_Vec_uint8_t deser_proof_values1_result =
        ffi_bytes_le_to_rln_v3_proof_values(&ser_proof_values1);
    if (!deser_proof_values1_result.ok)
    {
        fprintf(stderr, "RLN proof values deserialization error: %s\n", deser_proof_values1_result.err.ptr);
        ffi_c_string_free(deser_proof_values1_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3ProofValues_t *deser_proof_values1 = deser_proof_values1_result.ok;
    printf("  - proof values deserialized successfully\n");
    CFr_t *deser_proof_values1_external_nullifier =
        ffi_rln_v3_proof_values_get_external_nullifier(&deser_proof_values1);
    debug = ffi_cfr_debug(deser_proof_values1_external_nullifier);
    printf("  - deserialized external nullifier = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    ffi_cfr_free(deser_proof_values1_external_nullifier);
    ffi_rln_v3_proof_values_free(deser_proof_values1);
    ffi_vec_u8_free(ser_proof_values1);

    printf("\nVerifying first proof\n");
    CBoolResult_t verify1_result = ffi_rln_v3_verify(&rln_instance, &rln_proof1, x1);
    if (verify1_result.err.ptr)
    {
        fprintf(stderr, "Proof verification error: %s\n", verify1_result.err.ptr);
        ffi_c_string_free(verify1_result.err);
        return EXIT_FAILURE;
    }
    if (verify1_result.ok)
    {
        printf("  - first proof verified successfully\n");
    }
    else
    {
        printf("First proof verification failed\n");
        return EXIT_FAILURE;
    }

    printf("\nSimulating double-signaling attack (same epoch, different message)\n");

    printf("\nHashing second signal\n");
    uint8_t signal2[32] = {11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    CFr_t *x2 = ffi_hash_to_field_le(&(Vec_uint8_t){signal2, 32, 32});
    debug = ffi_cfr_debug(x2);
    printf("  - x2 = %s\n", debug.ptr);
    ffi_c_string_free(debug);
#ifdef MULTI_MESSAGE_ID
    printf("\nCreating second message id\n");
#else
    printf("\nCreating second message with the same id\n");
#endif
    CFr_t *message_id2 = ffi_uint_to_cfr(0);
    debug = ffi_cfr_debug(message_id2);
    printf("  - message id = %s\n", debug.ptr);
    ffi_c_string_free(debug);
#ifdef MULTI_MESSAGE_ID
    printf("\nCreating second message ids and selector used (Multi message-id mode)\n");
    printf("  - using 2 out of %zu slots\n", max_out);
    printf("  - duplicated slot id 1\n");
    Vec_CFr_t message_ids2 = ffi_vec_cfr_new(max_out);
    tmp = ffi_uint_to_cfr(1);
    ffi_vec_cfr_push(&message_ids2, tmp);
    ffi_cfr_free(tmp);
    tmp = ffi_cfr_zero();
    ffi_vec_cfr_push(&message_ids2, tmp);
    ffi_cfr_free(tmp);
    tmp = ffi_uint_to_cfr(3);
    ffi_vec_cfr_push(&message_ids2, tmp);
    ffi_cfr_free(tmp);
    tmp = ffi_cfr_zero();
    ffi_vec_cfr_push(&message_ids2, tmp);
    ffi_cfr_free(tmp);
    bool selector_used2[] = {true, false, true, false};
    debug = ffi_vec_cfr_debug(&message_ids2);
    printf("  - message ids = %s\n", debug.ptr);
    ffi_c_string_free(debug);
#endif

    printf("\nCreating second RLN witness\n");
    CResult_FFI_RLNV3WitnessInput_ptr_Vec_uint8_t witness2_result =
#ifdef MULTI_MESSAGE_ID
        ffi_rln_v3_witness_input_new_multi(identity_secret, user_message_limit, &message_ids2,
                                           &merkle_proof->path_elements, &merkle_proof->path_index, x2,
                                           external_nullifier, &(Vec_bool_t){selector_used2, max_out, max_out});
#else
        ffi_rln_v3_witness_input_new_single(identity_secret, user_message_limit, message_id2,
                                            &merkle_proof->path_elements, &merkle_proof->path_index, x2,
                                            external_nullifier);
#endif
    if (!witness2_result.ok)
    {
        fprintf(stderr, "Second witness creation error: %s\n", witness2_result.err.ptr);
        ffi_c_string_free(witness2_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3WitnessInput_t *witness2 = witness2_result.ok;
    printf("  - second RLN witness created successfully\n");

    printf("\nGenerating second RLN proof\n");
    CResult_FFI_RLNV3Proof_ptr_Vec_uint8_t rln_proof2_result = ffi_rln_v3_generate_proof(&rln_instance, &witness2);
    if (!rln_proof2_result.ok)
    {
        fprintf(stderr, "Second proof generation error: %s\n", rln_proof2_result.err.ptr);
        ffi_c_string_free(rln_proof2_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3Proof_t *rln_proof2 = rln_proof2_result.ok;
    printf("  - second proof generated successfully\n");

    printf("\nGetting second RLN proof values\n");
    FFI_RLNV3ProofValues_t *proof_values2 = ffi_rln_v3_proof_get_values(&rln_proof2);
    printf("  - second proof values extracted successfully\n");

    printf("\nVerifying second proof\n");
    CBoolResult_t verify2_result = ffi_rln_v3_verify(&rln_instance, &rln_proof2, x2);
    if (verify2_result.err.ptr)
    {
        fprintf(stderr, "Proof verification error: %s\n", verify2_result.err.ptr);
        ffi_c_string_free(verify2_result.err);
        return EXIT_FAILURE;
    }
    if (verify2_result.ok)
    {
        printf("  - second proof verified successfully\n");

        printf("\nRecovering identity secret\n");
        CResult_CFr_ptr_Vec_uint8_t recover_result = ffi_rln_v3_recover_id_secret(&proof_values1, &proof_values2);
        if (!recover_result.ok)
        {
            fprintf(stderr, "Identity recovery error: %s\n", recover_result.err.ptr);
            ffi_c_string_free(recover_result.err);
            return EXIT_FAILURE;
        }
        CFr_t *recovered_secret = recover_result.ok;
        debug = ffi_cfr_debug(recovered_secret);
        printf("  - recovered secret = %s\n", debug.ptr);
        ffi_c_string_free(debug);
        debug = ffi_cfr_debug(identity_secret);
        printf("  - identity secret = %s\n", debug.ptr);
        ffi_c_string_free(debug);
        printf("  - identity recovered successfully\n");
        ffi_cfr_free(recovered_secret);
    }
    else
    {
        printf("Second proof verification failed\n");
    }

    printf("\nCreating partial witness from first witness fields\n");
    CFr_t *witness1_identity_secret = ffi_rln_v3_witness_input_get_identity_secret(&witness1);
    CFr_t *witness1_user_message_limit = ffi_rln_v3_witness_input_get_user_message_limit(&witness1);
    Vec_CFr_t witness1_path_elements = ffi_rln_v3_witness_input_get_path_elements(&witness1);
    Vec_uint8_t witness1_path_index = ffi_rln_v3_witness_input_get_identity_path_index(&witness1);
    CResult_FFI_RLNV3PartialWitnessInput_ptr_Vec_uint8_t partial_witness_result = ffi_rln_v3_partial_witness_input_new(
        witness1_identity_secret, witness1_user_message_limit, &witness1_path_elements, &witness1_path_index);
    ffi_cfr_free(witness1_identity_secret);
    ffi_cfr_free(witness1_user_message_limit);
    ffi_vec_cfr_free(witness1_path_elements);
    ffi_vec_u8_free(witness1_path_index);
    if (!partial_witness_result.ok)
    {
        fprintf(stderr, "Partial witness creation error: %s\n", partial_witness_result.err.ptr);
        ffi_c_string_free(partial_witness_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3PartialWitnessInput_t *partial_witness = partial_witness_result.ok;
    printf("  - partial witness created successfully\n");

    printf("\nRLNPartialWitnessInput serialization: RLNPartialWitnessInput <-> bytes\n");
    CResult_Vec_uint8_Vec_uint8_t ser_partial_witness_result = ffi_rln_v3_partial_witness_to_bytes_le(&partial_witness);
    if (ser_partial_witness_result.err.ptr)
    {
        fprintf(stderr, "Partial witness serialization error: %s\n", ser_partial_witness_result.err.ptr);
        ffi_c_string_free(ser_partial_witness_result.err);
        return EXIT_FAILURE;
    }
    Vec_uint8_t ser_partial_witness = ser_partial_witness_result.ok;
    debug = ffi_vec_u8_debug(&ser_partial_witness);
    printf("  - serialized partial witness = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    CResult_FFI_RLNV3PartialWitnessInput_ptr_Vec_uint8_t deser_partial_witness_result =
        ffi_bytes_le_to_rln_v3_partial_witness(&ser_partial_witness);
    if (!deser_partial_witness_result.ok)
    {
        fprintf(stderr, "Partial witness deserialization error: %s\n", deser_partial_witness_result.err.ptr);
        ffi_c_string_free(deser_partial_witness_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3PartialWitnessInput_t *deser_partial_witness = deser_partial_witness_result.ok;
    printf("  - partial witness deserialized successfully\n");

    printf("\nGenerating partial ZK proof\n");
    CResult_FFI_RLNV3PartialProof_ptr_Vec_uint8_t partial_proof_result =
        ffi_rln_v3_generate_partial_proof(&rln_instance, &deser_partial_witness);
    if (!partial_proof_result.ok)
    {
        fprintf(stderr, "Partial proof generation error: %s\n", partial_proof_result.err.ptr);
        ffi_c_string_free(partial_proof_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3PartialProof_t *partial_proof = partial_proof_result.ok;
    printf("  - partial proof generated successfully\n");

    printf("\nRLNPartialProof serialization: RLNPartialProof <-> bytes\n");
    CResult_Vec_uint8_Vec_uint8_t ser_partial_proof_result = ffi_rln_v3_partial_proof_to_bytes_le(&partial_proof);
    if (ser_partial_proof_result.err.ptr)
    {
        fprintf(stderr, "Partial proof serialization error: %s\n", ser_partial_proof_result.err.ptr);
        ffi_c_string_free(ser_partial_proof_result.err);
        return EXIT_FAILURE;
    }
    Vec_uint8_t ser_partial_proof = ser_partial_proof_result.ok;
    debug = ffi_vec_u8_debug(&ser_partial_proof);
    printf("  - serialized partial proof = %s\n", debug.ptr);
    ffi_c_string_free(debug);
    CResult_FFI_RLNV3PartialProof_ptr_Vec_uint8_t deser_partial_proof_result =
        ffi_bytes_le_to_rln_v3_partial_proof(&ser_partial_proof);
    if (!deser_partial_proof_result.ok)
    {
        fprintf(stderr, "Partial proof deserialization error: %s\n", deser_partial_proof_result.err.ptr);
        ffi_c_string_free(deser_partial_proof_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3PartialProof_t *deser_partial_proof = deser_partial_proof_result.ok;
    printf("  - partial proof deserialized successfully\n");

    printf("\nFinishing proof with full witness\n");
    CResult_FFI_RLNV3Proof_ptr_Vec_uint8_t full_proof_result =
        ffi_rln_v3_finish_proof(&rln_instance, &deser_partial_proof, &witness1);
    if (!full_proof_result.ok)
    {
        fprintf(stderr, "Finish proof error: %s\n", full_proof_result.err.ptr);
        ffi_c_string_free(full_proof_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3Proof_t *full_proof = full_proof_result.ok;
    printf("  - partial proof finished successfully\n");

    printf("\nVerifying full proof\n");
    CBoolResult_t verify_full_result = ffi_rln_v3_verify(&rln_instance, &full_proof, x1);
    if (verify_full_result.err.ptr)
    {
        fprintf(stderr, "Full proof verification error: %s\n", verify_full_result.err.ptr);
        ffi_c_string_free(verify_full_result.err);
        return EXIT_FAILURE;
    }
    if (verify_full_result.ok)
    {
        printf("  - full proof verified successfully\n");
    }
    else
    {
        printf("Full proof verification failed\n");
    }
    ffi_rln_v3_proof_free(full_proof);
    ffi_rln_v3_partial_proof_free(deser_partial_proof);
    ffi_vec_u8_free(ser_partial_proof);
    ffi_rln_v3_partial_proof_free(partial_proof);
    ffi_rln_v3_partial_witness_input_free(deser_partial_witness);
    ffi_vec_u8_free(ser_partial_witness);
    ffi_rln_v3_partial_witness_input_free(partial_witness);
    ffi_rln_v3_proof_values_free(proof_values2);
    ffi_rln_v3_proof_free(rln_proof2);
    ffi_rln_v3_witness_input_free(witness2);
    ffi_cfr_free(message_id2);
#ifdef MULTI_MESSAGE_ID
    ffi_vec_cfr_free(message_ids2);
#endif
    ffi_rln_v3_proof_values_free(proof_values1);
    ffi_rln_v3_proof_free(rln_proof1);
    ffi_rln_v3_witness_input_free(witness1);
    ffi_cfr_free(message_id1);
#ifdef MULTI_MESSAGE_ID
    ffi_vec_cfr_free(message_ids1);
#endif
    ffi_rln_v3_merkle_proof_free(merkle_proof);
    ffi_cfr_free(x2);
    ffi_cfr_free(x1);
    ffi_cfr_free(external_nullifier);
    ffi_cfr_free(rln_identifier);
    ffi_cfr_free(epoch);
    ffi_cfr_free(rate_commitment);
    ffi_cfr_free(user_message_limit);
    ffi_vec_cfr_free(keys);
    ffi_rln_v3_free(rln_instance);
    return EXIT_SUCCESS;
}