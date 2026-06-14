#include <stdio.h>
#include <stdlib.h>

#include "common.c"

int main(void)
{
    RLN *rln_instance = init_rln(false);
    if (!rln_instance)
    {
        return EXIT_FAILURE;
    }

    Member member;
    create_member(&member);

    MerkleProof *merkle_proof = register_member(&rln_instance, member.rate_commitment);
    if (!merkle_proof)
    {
        return EXIT_FAILURE;
    }

    CFr *external_nullifier = compute_external_nullifier();

    printf("\nHashing first signal\n");
    uint8_t signal1[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    CFr *x1 = hash_signal(signal1);
    print_cfr("x1", x1);

    printf("\nCreating first message id\n");
    CFr *message_id1 = ffi_uint_to_cfr(0);
    print_cfr("message id", message_id1);

    printf("\nCreating first RLN witness\n");
    WitnessResult witness1_result =
        create_witness(&member, merkle_proof, message_id1, x1, external_nullifier);
    if (!witness1_result.ok)
    {
        fprintf(stderr, "First witness creation error: %s\n", witness1_result.err.ptr);
        ffi_c_string_free(witness1_result.err);
        return EXIT_FAILURE;
    }
    Witness *witness1 = witness1_result.ok;
    printf("  - first RLN witness created successfully\n");

    printf("\nGenerating first RLN proof\n");
    ProofResult rln_proof1_result =
        ffi_rln_generate_proof(&rln_instance, &witness1);
    if (!rln_proof1_result.ok)
    {
        fprintf(stderr, "Proof generation error: %s\n", rln_proof1_result.err.ptr);
        ffi_c_string_free(rln_proof1_result.err);
        return EXIT_FAILURE;
    }
    Proof *rln_proof1 = rln_proof1_result.ok;
    ProofValues *proof_values1 = ffi_rln_proof_get_values(&rln_proof1);
    printf("  - first proof generated successfully\n");

    printf("\nVerifying first proof\n");
    CBoolResult verify1_result = verify_stateful_proof(&rln_instance, &rln_proof1, x1);
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
    CFr *x2 = hash_signal(signal2);
    print_cfr("x2", x2);

    printf("\nCreating second message with the same id\n");
    CFr *message_id2 = ffi_uint_to_cfr(0);
    print_cfr("message id", message_id2);

    printf("\nCreating second RLN witness\n");
    WitnessResult witness2_result =
        create_witness(&member, merkle_proof, message_id2, x2, external_nullifier);
    if (!witness2_result.ok)
    {
        fprintf(stderr, "Second witness creation error: %s\n", witness2_result.err.ptr);
        ffi_c_string_free(witness2_result.err);
        return EXIT_FAILURE;
    }
    Witness *witness2 = witness2_result.ok;
    printf("  - second RLN witness created successfully\n");

    printf("\nGenerating second RLN proof\n");
    ProofResult rln_proof2_result =
        ffi_rln_generate_proof(&rln_instance, &witness2);
    if (!rln_proof2_result.ok)
    {
        fprintf(stderr, "Second proof generation error: %s\n", rln_proof2_result.err.ptr);
        ffi_c_string_free(rln_proof2_result.err);
        return EXIT_FAILURE;
    }
    Proof *rln_proof2 = rln_proof2_result.ok;
    ProofValues *proof_values2 = ffi_rln_proof_get_values(&rln_proof2);
    printf("  - second proof generated successfully\n");

    printf("\nVerifying second proof\n");
    CBoolResult verify2_result = verify_stateful_proof(&rln_instance, &rln_proof2, x2);
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
        CFrResult recover_result =
            ffi_rln_recover_id_secret(&proof_values1, &proof_values2);
        if (!recover_result.ok)
        {
            fprintf(stderr, "Identity recovery error: %s\n", recover_result.err.ptr);
            ffi_c_string_free(recover_result.err);
            return EXIT_FAILURE;
        }
        CFr *recovered_secret = recover_result.ok;
        print_cfr("recovered secret", recovered_secret);
        print_cfr("identity secret", member.identity_secret);
        printf("  - identity recovered successfully\n");
        ffi_cfr_free(recovered_secret);
    }
    else
    {
        printf("Second proof verification failed\n");
    }

    ffi_rln_proof_values_free(proof_values2);
    ffi_rln_proof_free(rln_proof2);
    ffi_rln_witness_input_free(witness2);
    ffi_cfr_free(message_id2);
    ffi_cfr_free(x2);
    ffi_rln_proof_values_free(proof_values1);
    ffi_rln_proof_free(rln_proof1);
    ffi_rln_witness_input_free(witness1);
    ffi_cfr_free(message_id1);
    ffi_cfr_free(x1);
    ffi_cfr_free(external_nullifier);
    ffi_rln_merkle_proof_free(merkle_proof);
    member_free(&member);
    ffi_rln_free(rln_instance);
    return EXIT_SUCCESS;
}
