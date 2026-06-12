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

    printf("\nHashing signal\n");
    uint8_t signal[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    CFr *x = hash_signal(signal);
    print_cfr("x", x);

    printf("\nCreating message id\n");
    CFr *message_id = ffi_uint_to_cfr(0);
    print_cfr("message id", message_id);

    printf("\nCreating RLN witness\n");
    WitnessResult witness_result =
        create_witness(&member, merkle_proof, message_id, x, external_nullifier);
    if (!witness_result.ok)
    {
        fprintf(stderr, "Witness creation error: %s\n", witness_result.err.ptr);
        ffi_c_string_free(witness_result.err);
        return EXIT_FAILURE;
    }
    Witness *witness = witness_result.ok;
    printf("  - RLN witness created successfully\n");

    printf("\nGenerating RLN proof\n");
    ProofResult rln_proof_result =
        ffi_rln_v3_generate_proof(&rln_instance, &witness);
    if (!rln_proof_result.ok)
    {
        fprintf(stderr, "Proof generation error: %s\n", rln_proof_result.err.ptr);
        ffi_c_string_free(rln_proof_result.err);
        return EXIT_FAILURE;
    }
    Proof *rln_proof = rln_proof_result.ok;
    printf("  - proof generated successfully\n");

    printf("\nGetting RLN proof values\n");
    ProofValues *proof_values = ffi_rln_v3_proof_get_values(&rln_proof);
    CFrResult y_result = ffi_rln_v3_proof_values_get_y(&proof_values);
    if (!y_result.ok)
    {
        fprintf(stderr, "Get y error: %s\n", y_result.err.ptr);
        ffi_c_string_free(y_result.err);
        return EXIT_FAILURE;
    }
    print_cfr("y", y_result.ok);
    ffi_cfr_free(y_result.ok);
    CFrResult nullifier_result = ffi_rln_v3_proof_values_get_nullifier(&proof_values);
    if (!nullifier_result.ok)
    {
        fprintf(stderr, "Get nullifier error: %s\n", nullifier_result.err.ptr);
        ffi_c_string_free(nullifier_result.err);
        return EXIT_FAILURE;
    }
    print_cfr("nullifier", nullifier_result.ok);
    ffi_cfr_free(nullifier_result.ok);
    CFr *proof_values_root = ffi_rln_v3_proof_values_get_root(&proof_values);
    print_cfr("root", proof_values_root);
    ffi_cfr_free(proof_values_root);
    CFr *proof_values_x = ffi_rln_v3_proof_values_get_x(&proof_values);
    print_cfr("x", proof_values_x);
    ffi_cfr_free(proof_values_x);
    CFr *proof_values_external_nullifier =
        ffi_rln_v3_proof_values_get_external_nullifier(&proof_values);
    print_cfr("external nullifier", proof_values_external_nullifier);
    ffi_cfr_free(proof_values_external_nullifier);

    printf("\nVerifying proof\n");
    CBoolResult verify_result = ffi_rln_v3_verify(&rln_instance, &rln_proof, x);
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
    ffi_rln_v3_merkle_proof_free(merkle_proof);
    member_free(&member);
    ffi_rln_v3_free(rln_instance);
    return EXIT_SUCCESS;
}
