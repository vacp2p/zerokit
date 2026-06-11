#include <stdio.h>
#include <stdlib.h>

#include "common.c"

int main(void)
{
    FFI_RLNV3_t *rln_instance = init_rln_stateless();
    if (!rln_instance)
    {
        return EXIT_FAILURE;
    }

    Member_t member;
    create_member(&member);

    printf("\nComputing Merkle path for stateless mode\n");
    CFr_t *default_leaf = ffi_cfr_zero();
    CFr_t *default_hashes[TREE_DEPTH - 1];
    default_hashes[0] = ffi_poseidon_hash_pair(default_leaf, default_leaf);
    for (size_t i = 1; i < TREE_DEPTH - 1; i++)
    {
        default_hashes[i] = ffi_poseidon_hash_pair(default_hashes[i - 1], default_hashes[i - 1]);
    }
    Vec_CFr_t path_elements = ffi_vec_cfr_new(TREE_DEPTH);
    ffi_vec_cfr_push(&path_elements, default_leaf);
    for (size_t i = 1; i < TREE_DEPTH; i++)
    {
        ffi_vec_cfr_push(&path_elements, default_hashes[i - 1]);
    }
    uint8_t path_index_data[TREE_DEPTH] = {0};
    Vec_uint8_t path_index = {path_index_data, TREE_DEPTH, TREE_DEPTH};

    printf("\nComputing Merkle root for stateless mode\n");
    printf("  - computing root for index 0 with rate commitment\n");
    CFr_t *computed_root = ffi_poseidon_hash_pair(member.rate_commitment, default_leaf);
    for (size_t i = 1; i < TREE_DEPTH; i++)
    {
        CFr_t *next_root = ffi_poseidon_hash_pair(computed_root, default_hashes[i - 1]);
        ffi_cfr_free(computed_root);
        computed_root = next_root;
    }
    print_cfr("computed root", computed_root);
    Vec_CFr_t roots = ffi_vec_cfr_new(1);
    ffi_vec_cfr_push(&roots, computed_root);

    CFr_t *external_nullifier = compute_external_nullifier();

    printf("\nHashing signal\n");
    uint8_t signal[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    CFr_t *x = hash_signal(signal);
    print_cfr("x", x);

    printf("\nCreating message id\n");
    CFr_t *message_id = ffi_uint_to_cfr(0);
    print_cfr("message id", message_id);

    printf("\nCreating RLN witness\n");
    CResult_FFI_RLNV3WitnessInput_ptr_Vec_uint8_t witness_result =
        ffi_rln_v3_witness_input_new_single(member.identity_secret, member.user_message_limit,
                                            message_id, &path_elements, &path_index, x,
                                            external_nullifier);
    if (!witness_result.ok)
    {
        fprintf(stderr, "Witness creation error: %s\n", witness_result.err.ptr);
        ffi_c_string_free(witness_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3WitnessInput_t *witness = witness_result.ok;
    printf("  - RLN witness created successfully\n");

    printf("\nGenerating RLN proof\n");
    CResult_FFI_RLNV3Proof_ptr_Vec_uint8_t rln_proof_result =
        ffi_rln_v3_generate_proof(&rln_instance, &witness);
    if (!rln_proof_result.ok)
    {
        fprintf(stderr, "Proof generation error: %s\n", rln_proof_result.err.ptr);
        ffi_c_string_free(rln_proof_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3Proof_t *rln_proof = rln_proof_result.ok;
    printf("  - proof generated successfully\n");

    printf("\nGetting RLN proof values\n");
    FFI_RLNV3ProofValues_t *proof_values = ffi_rln_v3_proof_get_values(&rln_proof);
    CResult_CFr_ptr_Vec_uint8_t y_result = ffi_rln_v3_proof_values_get_y(&proof_values);
    if (!y_result.ok)
    {
        fprintf(stderr, "Get y error: %s\n", y_result.err.ptr);
        ffi_c_string_free(y_result.err);
        return EXIT_FAILURE;
    }
    print_cfr("y", y_result.ok);
    ffi_cfr_free(y_result.ok);
    CResult_CFr_ptr_Vec_uint8_t nullifier_result = ffi_rln_v3_proof_values_get_nullifier(&proof_values);
    if (!nullifier_result.ok)
    {
        fprintf(stderr, "Get nullifier error: %s\n", nullifier_result.err.ptr);
        ffi_c_string_free(nullifier_result.err);
        return EXIT_FAILURE;
    }
    print_cfr("nullifier", nullifier_result.ok);
    ffi_cfr_free(nullifier_result.ok);
    CFr_t *proof_values_root = ffi_rln_v3_proof_values_get_root(&proof_values);
    print_cfr("root", proof_values_root);
    ffi_cfr_free(proof_values_root);
    CFr_t *proof_values_x = ffi_rln_v3_proof_values_get_x(&proof_values);
    print_cfr("x", proof_values_x);
    ffi_cfr_free(proof_values_x);
    CFr_t *proof_values_external_nullifier =
        ffi_rln_v3_proof_values_get_external_nullifier(&proof_values);
    print_cfr("external nullifier", proof_values_external_nullifier);
    ffi_cfr_free(proof_values_external_nullifier);

    printf("\nVerifying proof\n");
    CBoolResult_t verify_result =
        ffi_rln_v3_verify_with_roots(&rln_instance, &rln_proof, &roots, x);
    if (verify_result.err.ptr)
    {
        fprintf(stderr, "Proof verification error: %s\n", verify_result.err.ptr);
        ffi_c_string_free(verify_result.err);
        return EXIT_FAILURE;
    }
    if (verify_result.ok)
    {
        printf("  - proof verified successfully\n");
    }
    else
    {
        printf("Proof verification failed\n");
        return EXIT_FAILURE;
    }

    ffi_rln_v3_proof_values_free(proof_values);
    ffi_rln_v3_proof_free(rln_proof);
    ffi_rln_v3_witness_input_free(witness);
    ffi_cfr_free(message_id);
    ffi_cfr_free(x);
    ffi_cfr_free(external_nullifier);
    ffi_vec_cfr_free(roots);
    ffi_cfr_free(computed_root);
    ffi_vec_cfr_free(path_elements);
    for (size_t i = 0; i < TREE_DEPTH - 1; i++)
    {
        ffi_cfr_free(default_hashes[i]);
    }
    ffi_cfr_free(default_leaf);
    member_free(&member);
    ffi_rln_v3_free(rln_instance);
    return EXIT_SUCCESS;
}
