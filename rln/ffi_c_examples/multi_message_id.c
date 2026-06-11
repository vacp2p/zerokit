#include <stdio.h>
#include <stdlib.h>

#include "common.c"

static Vec_CFr_t create_message_ids(const unsigned int ids[MAX_OUT])
{
    Vec_CFr_t message_ids = ffi_vec_cfr_new(MAX_OUT);
    for (size_t i = 0; i < MAX_OUT; i++)
    {
        CFr_t *tmp = ffi_uint_to_cfr(ids[i]);
        ffi_vec_cfr_push(&message_ids, tmp);
        ffi_cfr_free(tmp);
    }
    return message_ids;
}

static CResult_FFI_RLNV3WitnessInput_ptr_Vec_uint8_t
create_multi_witness(const Member_t *member, const FFI_RLNV3MerkleProof_t *merkle_proof,
                     const Vec_CFr_t *message_ids, bool selector_used[MAX_OUT], const CFr_t *x,
                     const CFr_t *external_nullifier)
{
    return ffi_rln_v3_witness_input_new_multi(member->identity_secret,
                                              member->user_message_limit, message_ids,
                                              &merkle_proof->path_elements,
                                              &merkle_proof->path_index, x, external_nullifier,
                                              &(Vec_bool_t){selector_used, MAX_OUT, MAX_OUT});
}

int main(void)
{
    FFI_RLNV3_t *rln_instance = init_rln(true);
    if (!rln_instance)
    {
        return EXIT_FAILURE;
    }

    Member_t member;
    create_member(&member);

    FFI_RLNV3MerkleProof_t *merkle_proof = register_member(&rln_instance, member.rate_commitment);
    if (!merkle_proof)
    {
        return EXIT_FAILURE;
    }

    CFr_t *external_nullifier = compute_external_nullifier();

    printf("\nHashing first signal\n");
    uint8_t signal1[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    CFr_t *x1 = hash_signal(signal1);
    print_cfr("x1", x1);

    printf("\nCreating first message ids and selector used\n");
    printf("  - using 2 out of %d slots\n", MAX_OUT);
    const unsigned int ids1[MAX_OUT] = {0, 1, 0, 0};
    Vec_CFr_t message_ids1 = create_message_ids(ids1);
    bool selector_used1[MAX_OUT] = {true, true, false, false};
    print_vec_cfr("message ids", &message_ids1);

    printf("\nCreating first RLN witness\n");
    CResult_FFI_RLNV3WitnessInput_ptr_Vec_uint8_t witness1_result = create_multi_witness(
        &member, merkle_proof, &message_ids1, selector_used1, x1, external_nullifier);
    if (!witness1_result.ok)
    {
        fprintf(stderr, "First witness creation error: %s\n", witness1_result.err.ptr);
        ffi_c_string_free(witness1_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3WitnessInput_t *witness1 = witness1_result.ok;
    printf("  - first RLN witness created successfully\n");

    printf("\nGenerating first RLN proof\n");
    CResult_FFI_RLNV3Proof_ptr_Vec_uint8_t rln_proof1_result =
        ffi_rln_v3_generate_proof(&rln_instance, &witness1);
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
    CResult_Vec_CFr_Vec_uint8_t ys1_result = ffi_rln_v3_proof_values_get_ys(&proof_values1);
    if (ys1_result.err.ptr)
    {
        fprintf(stderr, "Get ys error: %s\n", ys1_result.err.ptr);
        ffi_c_string_free(ys1_result.err);
        return EXIT_FAILURE;
    }
    print_vec_cfr("ys", &ys1_result.ok);
    ffi_vec_cfr_free(ys1_result.ok);
    CResult_Vec_CFr_Vec_uint8_t nullifiers1_result =
        ffi_rln_v3_proof_values_get_nullifiers(&proof_values1);
    if (nullifiers1_result.err.ptr)
    {
        fprintf(stderr, "Get nullifiers error: %s\n", nullifiers1_result.err.ptr);
        ffi_c_string_free(nullifiers1_result.err);
        return EXIT_FAILURE;
    }
    print_vec_cfr("nullifiers", &nullifiers1_result.ok);
    ffi_vec_cfr_free(nullifiers1_result.ok);
    CFr_t *proof_values1_root = ffi_rln_v3_proof_values_get_root(&proof_values1);
    print_cfr("root", proof_values1_root);
    ffi_cfr_free(proof_values1_root);
    CFr_t *proof_values1_x = ffi_rln_v3_proof_values_get_x(&proof_values1);
    print_cfr("x", proof_values1_x);
    ffi_cfr_free(proof_values1_x);
    CFr_t *proof_values1_external_nullifier =
        ffi_rln_v3_proof_values_get_external_nullifier(&proof_values1);
    print_cfr("external nullifier", proof_values1_external_nullifier);
    ffi_cfr_free(proof_values1_external_nullifier);

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
    CFr_t *x2 = hash_signal(signal2);
    print_cfr("x2", x2);

    printf("\nCreating second message ids and selector used\n");
    printf("  - using 2 out of %d slots\n", MAX_OUT);
    printf("  - duplicated slot id 1\n");
    const unsigned int ids2[MAX_OUT] = {1, 0, 3, 0};
    Vec_CFr_t message_ids2 = create_message_ids(ids2);
    bool selector_used2[MAX_OUT] = {true, false, true, false};
    print_vec_cfr("message ids", &message_ids2);

    printf("\nCreating second RLN witness\n");
    CResult_FFI_RLNV3WitnessInput_ptr_Vec_uint8_t witness2_result = create_multi_witness(
        &member, merkle_proof, &message_ids2, selector_used2, x2, external_nullifier);
    if (!witness2_result.ok)
    {
        fprintf(stderr, "Second witness creation error: %s\n", witness2_result.err.ptr);
        ffi_c_string_free(witness2_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3WitnessInput_t *witness2 = witness2_result.ok;
    printf("  - second RLN witness created successfully\n");

    printf("\nGenerating second RLN proof\n");
    CResult_FFI_RLNV3Proof_ptr_Vec_uint8_t rln_proof2_result =
        ffi_rln_v3_generate_proof(&rln_instance, &witness2);
    if (!rln_proof2_result.ok)
    {
        fprintf(stderr, "Second proof generation error: %s\n", rln_proof2_result.err.ptr);
        ffi_c_string_free(rln_proof2_result.err);
        return EXIT_FAILURE;
    }
    FFI_RLNV3Proof_t *rln_proof2 = rln_proof2_result.ok;
    FFI_RLNV3ProofValues_t *proof_values2 = ffi_rln_v3_proof_get_values(&rln_proof2);
    printf("  - second proof generated successfully\n");

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
        CResult_CFr_ptr_Vec_uint8_t recover_result =
            ffi_rln_v3_recover_id_secret(&proof_values1, &proof_values2);
        if (!recover_result.ok)
        {
            fprintf(stderr, "Identity recovery error: %s\n", recover_result.err.ptr);
            ffi_c_string_free(recover_result.err);
            return EXIT_FAILURE;
        }
        CFr_t *recovered_secret = recover_result.ok;
        print_cfr("recovered secret", recovered_secret);
        print_cfr("identity secret", member.identity_secret);
        printf("  - identity recovered successfully\n");
        ffi_cfr_free(recovered_secret);
    }
    else
    {
        printf("Second proof verification failed\n");
    }

    ffi_rln_v3_proof_values_free(proof_values2);
    ffi_rln_v3_proof_free(rln_proof2);
    ffi_rln_v3_witness_input_free(witness2);
    ffi_vec_cfr_free(message_ids2);
    ffi_cfr_free(x2);
    ffi_rln_v3_proof_values_free(proof_values1);
    ffi_rln_v3_proof_free(rln_proof1);
    ffi_rln_v3_witness_input_free(witness1);
    ffi_vec_cfr_free(message_ids1);
    ffi_cfr_free(x1);
    ffi_cfr_free(external_nullifier);
    ffi_rln_v3_merkle_proof_free(merkle_proof);
    member_free(&member);
    ffi_rln_v3_free(rln_instance);
    return EXIT_SUCCESS;
}
