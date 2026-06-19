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

    printf("\nCreating partial witness from witness fields\n");
    CFr *witness_identity_secret = ffi_rln_witness_input_get_identity_secret(&witness);
    CFr *witness_user_message_limit = ffi_rln_witness_input_get_user_message_limit(&witness);
    Vec_CFr witness_path_elements = ffi_rln_witness_input_get_path_elements(&witness);
    Vec_uint8 witness_path_index = ffi_rln_witness_input_get_identity_path_index(&witness);
    PartialWitnessResult partial_witness_result =
        ffi_rln_partial_witness_input_new(witness_identity_secret, witness_user_message_limit,
                                             &witness_path_elements, &witness_path_index);
    ffi_cfr_free(witness_identity_secret);
    ffi_cfr_free(witness_user_message_limit);
    ffi_vec_cfr_free(witness_path_elements);
    ffi_vec_u8_free(witness_path_index);
    if (!partial_witness_result.ok)
    {
        fprintf(stderr, "Partial witness creation error: %s\n", partial_witness_result.err.ptr);
        ffi_c_string_free(partial_witness_result.err);
        return EXIT_FAILURE;
    }
    PartialWitness *partial_witness = partial_witness_result.ok;
    printf("  - partial witness created successfully\n");

    printf("\nGenerating partial ZK proof\n");
    PartialProofResult partial_proof_result =
        ffi_rln_generate_partial_proof(&rln_instance, &partial_witness);
    if (!partial_proof_result.ok)
    {
        fprintf(stderr, "Partial proof generation error: %s\n", partial_proof_result.err.ptr);
        ffi_c_string_free(partial_proof_result.err);
        return EXIT_FAILURE;
    }
    PartialProof *partial_proof = partial_proof_result.ok;
    printf("  - partial proof generated successfully\n");

    printf("\nFinishing proof with full witness\n");
    ProofResult full_proof_result =
        ffi_rln_finish_proof(&rln_instance, &partial_proof, &witness);
    if (!full_proof_result.ok)
    {
        fprintf(stderr, "Finish proof error: %s\n", full_proof_result.err.ptr);
        ffi_c_string_free(full_proof_result.err);
        return EXIT_FAILURE;
    }
    Proof *full_proof = full_proof_result.ok;
    printf("  - partial proof finished successfully\n");

    printf("\nVerifying full proof\n");
    CBoolResult verify_full_result = verify_stateful_proof(&rln_instance, &full_proof, x);
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
        return EXIT_FAILURE;
    }

    ffi_rln_proof_free(full_proof);
    ffi_rln_partial_proof_free(partial_proof);
    ffi_rln_partial_witness_input_free(partial_witness);
    ffi_rln_witness_input_free(witness);
    ffi_cfr_free(message_id);
    ffi_cfr_free(x);
    ffi_cfr_free(external_nullifier);
    ffi_rln_merkle_proof_free(merkle_proof);
    member_free(&member);
    ffi_rln_free(rln_instance);
    return EXIT_SUCCESS;
}
