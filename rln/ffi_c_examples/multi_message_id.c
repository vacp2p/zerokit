#include <stdio.h>
#include <stdlib.h>

#include "common.c"

static Vec_Fr create_message_ids(const unsigned int ids[MAX_OUT])
{
    Vec_Fr message_ids = ffi_vec_fr_new(MAX_OUT);
    for (size_t i = 0; i < MAX_OUT; i++)
    {
        Fr *tmp = ffi_uint_to_fr(ids[i]);
        ffi_vec_fr_push(&message_ids, tmp);
        ffi_fr_free(tmp);
    }
    return message_ids;
}

static WitnessResult
create_multi_witness(const Member *member, const MerkleProof *merkle_proof,
                     const Vec_Fr *message_ids, bool selector_used[MAX_OUT], const Fr *x,
                     const Fr *external_nullifier)
{
    return ffi_rln_witness_input_new_multi(member->identity_secret,
                                           member->user_message_limit, message_ids,
                                           merkle_proof, x, external_nullifier,
                                           &(Vec_bool){selector_used, MAX_OUT, MAX_OUT});
}

int main(void)
{
    RLN *rln_instance = init_rln(true);
    if (!rln_instance)
    {
        return EXIT_FAILURE;
    }

    Member member;
    create_member(&member);

    MerkleProof *merkle_proof = register_member(rln_instance, member.rate_commitment);
    if (!merkle_proof)
    {
        return EXIT_FAILURE;
    }

    Fr *external_nullifier = compute_external_nullifier();

    printf("\nHashing first signal\n");
    uint8_t signal1[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0,
                           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Fr *x1 = hash_signal(signal1);
    print_fr("x1", x1);

    printf("\nCreating first message ids and selector used\n");
    printf("  - using 2 out of %d slots\n", MAX_OUT);
    const unsigned int ids1[MAX_OUT] = {0, 1, 0, 0};
    Vec_Fr message_ids1 = create_message_ids(ids1);
    bool selector_used1[MAX_OUT] = {true, true, false, false};
    print_vec_fr("message ids", &message_ids1);

    printf("\nCreating first RLN witness\n");
    WitnessResult witness1_result = create_multi_witness(
        &member, merkle_proof, &message_ids1, selector_used1, x1, external_nullifier);
    if (!witness1_result.ok)
    {
        fprintf(stderr, "First witness creation error: %.*s\n",
                (int)witness1_result.err.len, (char *)witness1_result.err.ptr);
        ffi_c_string_free(witness1_result.err);
        return EXIT_FAILURE;
    }
    Witness *witness1 = witness1_result.ok;
    printf("  - first RLN witness created successfully\n");

    printf("\nGenerating first RLN proof\n");
    ProofResult rln_proof1_result =
        ffi_rln_generate_proof(rln_instance, witness1);
    if (!rln_proof1_result.ok)
    {
        fprintf(stderr, "Proof generation error: %.*s\n",
                (int)rln_proof1_result.err.len, (char *)rln_proof1_result.err.ptr);
        ffi_c_string_free(rln_proof1_result.err);
        return EXIT_FAILURE;
    }
    Proof *rln_proof1 = rln_proof1_result.ok;
    printf("  - proof generated successfully\n");

    printf("\nGetting first RLN proof values\n");
    ProofValues *proof_values1 = ffi_rln_proof_get_values(rln_proof1);
    VecFrResult ys1_result = ffi_rln_proof_values_get_ys(proof_values1);
    if (ys1_result.err.ptr)
    {
        fprintf(stderr, "Get ys error: %.*s\n",
                (int)ys1_result.err.len, (char *)ys1_result.err.ptr);
        ffi_c_string_free(ys1_result.err);
        return EXIT_FAILURE;
    }
    print_vec_fr("ys", &ys1_result.ok);
    ffi_vec_fr_free(ys1_result.ok);
    VecFrResult nullifiers1_result =
        ffi_rln_proof_values_get_nullifiers(proof_values1);
    if (nullifiers1_result.err.ptr)
    {
        fprintf(stderr, "Get nullifiers error: %.*s\n",
                (int)nullifiers1_result.err.len, (char *)nullifiers1_result.err.ptr);
        ffi_c_string_free(nullifiers1_result.err);
        return EXIT_FAILURE;
    }
    print_vec_fr("nullifiers", &nullifiers1_result.ok);
    ffi_vec_fr_free(nullifiers1_result.ok);
    VecBoolResult proof_selector_used_result =
        ffi_rln_proof_values_get_selector_used(proof_values1);
    if (proof_selector_used_result.err.ptr)
    {
        fprintf(stderr, "Get selector used error: %.*s\n",
                (int)proof_selector_used_result.err.len,
                (char *)proof_selector_used_result.err.ptr);
        ffi_c_string_free(proof_selector_used_result.err);
        return EXIT_FAILURE;
    }
    Vec_bool proof_selector_used = proof_selector_used_result.ok;
    printf("  - selector used = [");
    for (size_t i = 0; i < proof_selector_used.len; i++)
    {
        printf("%s%s", i ? ", " : "", proof_selector_used.ptr[i] ? "true" : "false");
    }
    printf("]\n");
    ffi_vec_bool_free(proof_selector_used);
    Fr *proof_values1_root = ffi_rln_proof_values_get_root(proof_values1);
    print_fr("root", proof_values1_root);
    ffi_fr_free(proof_values1_root);
    Fr *proof_values1_x = ffi_rln_proof_values_get_x(proof_values1);
    print_fr("x", proof_values1_x);
    ffi_fr_free(proof_values1_x);
    Fr *proof_values1_external_nullifier =
        ffi_rln_proof_values_get_external_nullifier(proof_values1);
    print_fr("external nullifier", proof_values1_external_nullifier);
    ffi_fr_free(proof_values1_external_nullifier);

    printf("\nVerifying first proof\n");
    CBoolResult verify1_result = verify_stateful_proof(rln_instance, rln_proof1, x1);
    if (verify1_result.err.ptr)
    {
        fprintf(stderr, "Proof verification error: %.*s\n",
                (int)verify1_result.err.len, (char *)verify1_result.err.ptr);
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
    Fr *x2 = hash_signal(signal2);
    print_fr("x2", x2);

    printf("\nCreating second message ids and selector used\n");
    printf("  - using 2 out of %d slots\n", MAX_OUT);
    printf("  - duplicated slot id 1\n");
    const unsigned int ids2[MAX_OUT] = {1, 0, 3, 0};
    Vec_Fr message_ids2 = create_message_ids(ids2);
    bool selector_used2[MAX_OUT] = {true, false, true, false};
    print_vec_fr("message ids", &message_ids2);

    printf("\nCreating second RLN witness\n");
    WitnessResult witness2_result = create_multi_witness(
        &member, merkle_proof, &message_ids2, selector_used2, x2, external_nullifier);
    if (!witness2_result.ok)
    {
        fprintf(stderr, "Second witness creation error: %.*s\n",
                (int)witness2_result.err.len, (char *)witness2_result.err.ptr);
        ffi_c_string_free(witness2_result.err);
        return EXIT_FAILURE;
    }
    Witness *witness2 = witness2_result.ok;
    printf("  - second RLN witness created successfully\n");

    printf("\nGenerating second RLN proof\n");
    ProofResult rln_proof2_result =
        ffi_rln_generate_proof(rln_instance, witness2);
    if (!rln_proof2_result.ok)
    {
        fprintf(stderr, "Second proof generation error: %.*s\n",
                (int)rln_proof2_result.err.len, (char *)rln_proof2_result.err.ptr);
        ffi_c_string_free(rln_proof2_result.err);
        return EXIT_FAILURE;
    }
    Proof *rln_proof2 = rln_proof2_result.ok;
    ProofValues *proof_values2 = ffi_rln_proof_get_values(rln_proof2);
    printf("  - second proof generated successfully\n");

    printf("\nVerifying second proof\n");
    CBoolResult verify2_result = verify_stateful_proof(rln_instance, rln_proof2, x2);
    if (verify2_result.err.ptr)
    {
        fprintf(stderr, "Proof verification error: %.*s\n",
                (int)verify2_result.err.len, (char *)verify2_result.err.ptr);
        ffi_c_string_free(verify2_result.err);
        return EXIT_FAILURE;
    }
    if (verify2_result.ok)
    {
        printf("  - second proof verified successfully\n");

        printf("\nRecovering identity secret\n");
        SecretFrResult recover_result =
            ffi_rln_recover_id_secret(proof_values1, proof_values2);
        if (!recover_result.ok)
        {
            fprintf(stderr, "Identity recovery error: %.*s\n",
                    (int)recover_result.err.len, (char *)recover_result.err.ptr);
            ffi_c_string_free(recover_result.err);
            return EXIT_FAILURE;
        }
        SecretFr *recovered_secret = recover_result.ok;
        if (ffi_secret_fr_eq(recovered_secret, member.identity_secret))
        {
            Vec_uint8 recovered_debug = ffi_secret_fr_debug(recovered_secret);
            printf("  - recovered secret = %.*s matches the original identity secret\n",
                   (int)recovered_debug.len, (char *)recovered_debug.ptr);
            ffi_c_string_free(recovered_debug);
        }
        ffi_secret_fr_free(recovered_secret);
    }
    else
    {
        printf("Second proof verification failed\n");
    }

    ffi_rln_proof_values_free(proof_values2);
    ffi_rln_proof_free(rln_proof2);
    ffi_rln_witness_input_free(witness2);
    ffi_vec_fr_free(message_ids2);
    ffi_fr_free(x2);
    ffi_rln_proof_values_free(proof_values1);
    ffi_rln_proof_free(rln_proof1);
    ffi_rln_witness_input_free(witness1);
    ffi_vec_fr_free(message_ids1);
    ffi_fr_free(x1);
    ffi_fr_free(external_nullifier);
    ffi_rln_merkle_proof_free(merkle_proof);
    member_free(&member);
    ffi_rln_free(rln_instance);
    return EXIT_SUCCESS;
}
