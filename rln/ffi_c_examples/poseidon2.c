#include <stdio.h>
#include <stdlib.h>

#include "common.c"

int main(void)
{
    RLN *rln_instance = init_rln_poseidon2();
    if (!rln_instance)
    {
        return EXIT_FAILURE;
    }

    Member member;
    create_member_poseidon2(&member);

    MerkleProof *merkle_proof = register_member(rln_instance, member.rate_commitment);
    if (!merkle_proof)
    {
        return EXIT_FAILURE;
    }

    Fr *external_nullifier = compute_external_nullifier_poseidon2();

    printf("\nHashing signal\n");
    uint8_t signal[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Fr *x = hash_signal(signal);
    print_fr("x", x);

    printf("\nCreating message id\n");
    Fr *message_id = ffi_uint_to_fr(0);
    print_fr("message id", message_id);

    printf("\nCreating RLN witness\n");
    WitnessResult witness_result =
        create_witness(&member, merkle_proof, message_id, x, external_nullifier);
    if (!witness_result.ok)
    {
        fprintf(stderr, "Witness creation error: %.*s\n",
                (int)witness_result.err.len, (char *)witness_result.err.ptr);
        ffi_c_string_free(witness_result.err);
        return EXIT_FAILURE;
    }
    Witness *witness = witness_result.ok;
    printf("  - RLN witness created successfully\n");

    printf("\nGenerating RLN proof\n");
    ProofResult rln_proof_result =
        ffi_rln_generate_proof(rln_instance, witness);
    if (!rln_proof_result.ok)
    {
        fprintf(stderr, "Proof generation error: %.*s\n",
                (int)rln_proof_result.err.len, (char *)rln_proof_result.err.ptr);
        ffi_c_string_free(rln_proof_result.err);
        return EXIT_FAILURE;
    }
    Proof *rln_proof = rln_proof_result.ok;
    printf("  - proof generated successfully\n");

    printf("\nVerifying proof\n");
    CBoolResult verify_result = verify_stateful_proof(rln_instance, rln_proof, x);
    if (verify_result.err.ptr)
    {
        fprintf(stderr, "Proof verification error: %.*s\n",
                (int)verify_result.err.len, (char *)verify_result.err.ptr);
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

    ffi_rln_proof_free(rln_proof);
    ffi_rln_witness_input_free(witness);
    ffi_fr_free(message_id);
    ffi_fr_free(x);
    ffi_fr_free(external_nullifier);
    ffi_rln_merkle_proof_free(merkle_proof);
    member_free(&member);
    ffi_rln_free(rln_instance);
    return EXIT_SUCCESS;
}
