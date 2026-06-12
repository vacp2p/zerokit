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

    printf("\nRLNWitnessInput serialization: RLNWitnessInput <-> bytes\n");
    VecU8Result ser_witness_result = ffi_rln_witness_to_bytes_le(&witness);
    if (ser_witness_result.err.ptr)
    {
        fprintf(stderr, "Witness serialization error: %s\n", ser_witness_result.err.ptr);
        ffi_c_string_free(ser_witness_result.err);
        return EXIT_FAILURE;
    }
    Vec_uint8 ser_witness = ser_witness_result.ok;
    print_vec_u8("serialized witness", &ser_witness);
    WitnessResult deser_witness_result =
        ffi_bytes_le_to_rln_witness(&ser_witness);
    if (!deser_witness_result.ok)
    {
        fprintf(stderr, "Witness deserialization error: %s\n", deser_witness_result.err.ptr);
        ffi_c_string_free(deser_witness_result.err);
        return EXIT_FAILURE;
    }
    Witness *deser_witness = deser_witness_result.ok;
    printf("  - witness deserialized successfully\n");

    printf("\nGenerating RLN proof from the deserialized witness\n");
    ProofResult rln_proof_result =
        ffi_rln_generate_proof(&rln_instance, &deser_witness);
    if (!rln_proof_result.ok)
    {
        fprintf(stderr, "Proof generation error: %s\n", rln_proof_result.err.ptr);
        ffi_c_string_free(rln_proof_result.err);
        return EXIT_FAILURE;
    }
    Proof *rln_proof = rln_proof_result.ok;
    printf("  - proof generated successfully\n");

    printf("\nRLNProof serialization: RLNProof <-> bytes\n");
    VecU8Result ser_proof_result = ffi_rln_proof_to_bytes_le(&rln_proof);
    if (ser_proof_result.err.ptr)
    {
        fprintf(stderr, "Proof serialization error: %s\n", ser_proof_result.err.ptr);
        ffi_c_string_free(ser_proof_result.err);
        return EXIT_FAILURE;
    }
    Vec_uint8 ser_proof = ser_proof_result.ok;
    print_vec_u8("serialized proof", &ser_proof);
    ProofResult deser_proof_result =
        ffi_bytes_le_to_rln_proof(&ser_proof);
    if (!deser_proof_result.ok)
    {
        fprintf(stderr, "Proof deserialization error: %s\n", deser_proof_result.err.ptr);
        ffi_c_string_free(deser_proof_result.err);
        return EXIT_FAILURE;
    }
    Proof *deser_proof = deser_proof_result.ok;
    printf("  - proof deserialized successfully\n");

    printf("\nVerifying the deserialized proof\n");
    CBoolResult verify_result = ffi_rln_verify(&rln_instance, &deser_proof, x);
    if (verify_result.err.ptr)
    {
        fprintf(stderr, "Proof verification error: %s\n", verify_result.err.ptr);
        ffi_c_string_free(verify_result.err);
        return EXIT_FAILURE;
    }
    if (verify_result.ok)
    {
        printf("  - deserialized proof verified successfully\n");
    }
    else
    {
        printf("Deserialized proof verification failed\n");
        return EXIT_FAILURE;
    }

    ffi_rln_proof_free(deser_proof);
    ffi_vec_u8_free(ser_proof);
    ffi_rln_proof_free(rln_proof);
    ffi_rln_witness_input_free(deser_witness);
    ffi_vec_u8_free(ser_witness);
    ffi_rln_witness_input_free(witness);
    ffi_cfr_free(message_id);
    ffi_cfr_free(x);
    ffi_cfr_free(external_nullifier);
    ffi_rln_merkle_proof_free(merkle_proof);
    member_free(&member);
    ffi_rln_free(rln_instance);
    return EXIT_SUCCESS;
}
