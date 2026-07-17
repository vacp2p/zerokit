#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rln.h"

typedef FFI_Fr_t Fr;
typedef FFI_SecretFr_t SecretFr;
typedef FFI_IdentityKeys_t IdentityKeys;
typedef Vec_FFI_Fr_t Vec_Fr;
typedef Vec_uint8_t Vec_uint8;
typedef Vec_bool_t Vec_bool;
typedef FFI_BoolResult_t CBoolResult;
typedef FFI_RLN_t RLN;
typedef FFI_RLNWitnessInput_t Witness;
typedef FFI_RLNPartialWitnessInput_t PartialWitness;
typedef FFI_RLNProof_t Proof;
typedef FFI_RLNPartialProof_t PartialProof;
typedef FFI_RLNProofValues_t ProofValues;
typedef FFI_RLNMerkleProof_t MerkleProof;
typedef FFI_Result_FFI_RLN_ptr_Vec_uint8_t RLNResult;
typedef FFI_Result_FFI_RLNWitnessInput_ptr_Vec_uint8_t WitnessResult;
typedef FFI_Result_FFI_RLNPartialWitnessInput_ptr_Vec_uint8_t PartialWitnessResult;
typedef FFI_Result_FFI_RLNProof_ptr_Vec_uint8_t ProofResult;
typedef FFI_Result_FFI_RLNPartialProof_ptr_Vec_uint8_t PartialProofResult;
typedef FFI_Result_FFI_RLNMerkleProof_ptr_Vec_uint8_t MerkleProofResult;
typedef FFI_Result_FFI_Fr_ptr_Vec_uint8_t FrResult;
typedef FFI_Result_FFI_SecretFr_ptr_Vec_uint8_t SecretFrResult;
typedef FFI_Result_Vec_FFI_Fr_Vec_uint8_t VecFrResult;
typedef FFI_Result_Vec_uint8_Vec_uint8_t VecU8Result;
typedef FFI_Result_Vec_bool_Vec_uint8_t VecBoolResult;

#define TREE_DEPTH 20
#define MAX_OUT 4

typedef struct
{
    SecretFr *identity_secret;
    Fr *id_commitment;
    Fr *user_message_limit;
    Fr *rate_commitment;
} Member;

int file_to_bytes(const char *path, Vec_uint8 *out)
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

void print_fr(const char *label, const Fr *value)
{
    Vec_uint8 debug = ffi_fr_debug(value);
    printf("  - %s = %.*s\n", label, (int)debug.len, (char *)debug.ptr);
    ffi_c_string_free(debug);
}

void print_secret_fr(const char *label, const SecretFr *value)
{
    Vec_uint8 debug = ffi_secret_fr_debug(value);
    printf("  - %s = %.*s\n", label, (int)debug.len, (char *)debug.ptr);
    ffi_c_string_free(debug);
}

void print_vec_fr(const char *label, const Vec_Fr *value)
{
    Vec_uint8 debug = ffi_vec_fr_debug(value);
    printf("  - %s = %.*s\n", label, (int)debug.len, (char *)debug.ptr);
    ffi_c_string_free(debug);
}

void print_vec_u8(const char *label, const Vec_uint8 *value)
{
    Vec_uint8 debug = ffi_vec_u8_debug(value);
    printf("  - %s = %.*s\n", label, (int)debug.len, (char *)debug.ptr);
    ffi_c_string_free(debug);
}

static int load_resources(bool enable_multi_message_id, Vec_uint8 *zkey_data,
                          Vec_uint8 *graph_data)
{
    const char *zkey_path =
        enable_multi_message_id
            ? "../resources/tree_depth_20/multi_message_id/max_out_4/rln_final.arkzkey"
            : "../resources/tree_depth_20/rln_final.arkzkey";
    const char *graph_path =
        enable_multi_message_id
            ? "../resources/tree_depth_20/multi_message_id/max_out_4/graph.bin"
            : "../resources/tree_depth_20/graph.bin";

    if (file_to_bytes(zkey_path, zkey_data) != 0)
    {
        fprintf(stderr, "Failed to read zkey: %s\n", zkey_path);
        return -1;
    }
    if (file_to_bytes(graph_path, graph_data) != 0)
    {
        fprintf(stderr, "Failed to read graph: %s\n", graph_path);
        free(zkey_data->ptr);
        return -1;
    }
    return 0;
}

RLN *init_rln(bool enable_multi_message_id)
{
    printf("Creating RLN instance\n");
    Vec_uint8 zkey_data;
    Vec_uint8 graph_data;
    if (load_resources(enable_multi_message_id, &zkey_data, &graph_data) != 0)
    {
        return NULL;
    }
    RLNResult rln_instance_result =
        ffi_rln_new_with_pm_tree(TREE_DEPTH, &zkey_data, &graph_data, "");
    free(zkey_data.ptr);
    free(graph_data.ptr);
    if (!rln_instance_result.ok)
    {
        fprintf(stderr, "RLN instance creation error: %.*s\n",
                (int)rln_instance_result.err.len, (char *)rln_instance_result.err.ptr);
        ffi_c_string_free(rln_instance_result.err);
        return NULL;
    }
    printf("  - RLN instance created successfully\n");
    printf("  - circuit tree depth = %d\n", TREE_DEPTH);
    if (enable_multi_message_id)
    {
        printf("  - circuit max out = %d\n", MAX_OUT);
    }
    return rln_instance_result.ok;
}

RLN *init_rln_stateless(void)
{
    printf("Creating RLN instance\n");
    Vec_uint8 zkey_data;
    Vec_uint8 graph_data;
    if (load_resources(false, &zkey_data, &graph_data) != 0)
    {
        return NULL;
    }
    RLNResult rln_instance_result =
        ffi_rln_new_stateless(&zkey_data, &graph_data);
    free(zkey_data.ptr);
    free(graph_data.ptr);
    if (!rln_instance_result.ok)
    {
        fprintf(stderr, "RLN instance creation error: %.*s\n",
                (int)rln_instance_result.err.len, (char *)rln_instance_result.err.ptr);
        ffi_c_string_free(rln_instance_result.err);
        return NULL;
    }
    printf("  - RLN instance created successfully\n");
    printf("  - circuit tree depth = %d\n", TREE_DEPTH);
    return rln_instance_result.ok;
}

int create_member(Member *member)
{
    printf("\nGenerating identity keys\n");
    IdentityKeys *keys = ffi_identity_keys_generate();
    member->identity_secret = ffi_identity_keys_get_secret(keys);
    member->id_commitment = ffi_identity_keys_get_commitment(keys);

    printf("  - identity generated successfully\n");
    print_secret_fr("identity secret", member->identity_secret);
    print_fr("id commitment", member->id_commitment);

    printf("\nCreating message limit\n");
    member->user_message_limit = ffi_uint_to_fr(10);
    print_fr("user message limit", member->user_message_limit);

    printf("\nComputing rate commitment\n");
    member->rate_commitment =
        ffi_poseidon_hash_pair(member->id_commitment, member->user_message_limit);
    print_fr("rate commitment", member->rate_commitment);

    ffi_identity_keys_free(keys);
    return 0;
}

void member_free(Member *member)
{
    ffi_fr_free(member->rate_commitment);
    ffi_fr_free(member->user_message_limit);
    ffi_secret_fr_free(member->identity_secret);
    ffi_fr_free(member->id_commitment);
}

MerkleProof *register_member(RLN *rln_instance,
                             const Fr *rate_commitment)
{
    printf("\nAdding rate commitment to tree\n");
    CBoolResult set_leaf_result = ffi_rln_set_next_leaf(rln_instance, rate_commitment);
    if (!set_leaf_result.ok)
    {
        fprintf(stderr, "Adding rate commitment error: %.*s\n",
                (int)set_leaf_result.err.len, (char *)set_leaf_result.err.ptr);
        ffi_c_string_free(set_leaf_result.err);
        return NULL;
    }
    printf("  - rate commitment added at leaf 0\n");

    printf("\nGetting Merkle proof\n");
    MerkleProofResult merkle_proof_result =
        ffi_rln_get_merkle_proof(rln_instance, 0);
    if (!merkle_proof_result.ok)
    {
        fprintf(stderr, "Merkle proof error: %.*s\n",
                (int)merkle_proof_result.err.len, (char *)merkle_proof_result.err.ptr);
        ffi_c_string_free(merkle_proof_result.err);
        return NULL;
    }
    printf("  - merkle proof obtained\n");
    return merkle_proof_result.ok;
}

Fr *hash_signal(const uint8_t signal[32])
{
    return ffi_hash_to_field_le(&(Vec_uint8){(uint8_t *)signal, 32, 32});
}

Fr *compute_external_nullifier(void)
{
    printf("\nHashing epoch\n");
    const char *epoch_str = "test-epoch";
    Fr *epoch = ffi_hash_to_field_le(
        &(Vec_uint8){(uint8_t *)epoch_str, strlen(epoch_str), strlen(epoch_str)});
    print_fr("epoch", epoch);

    printf("\nHashing RLN identifier\n");
    const char *rln_id_str = "test-rln-identifier";
    Fr *rln_identifier = ffi_hash_to_field_le(
        &(Vec_uint8){(uint8_t *)rln_id_str, strlen(rln_id_str), strlen(rln_id_str)});
    print_fr("RLN identifier", rln_identifier);

    printf("\nComputing Poseidon hash for external nullifier\n");
    Fr *external_nullifier = ffi_poseidon_hash_pair(epoch, rln_identifier);
    print_fr("external nullifier", external_nullifier);

    ffi_fr_free(rln_identifier);
    ffi_fr_free(epoch);
    return external_nullifier;
}

WitnessResult
create_witness(const Member *member, const MerkleProof *merkle_proof,
               const Fr *message_id, const Fr *x, const Fr *external_nullifier)
{
    return ffi_rln_witness_input_new_single(member->identity_secret,
                                            member->user_message_limit, message_id,
                                            merkle_proof, x, external_nullifier);
}

CBoolResult
verify_stateful_proof(RLN *rln_instance, Proof *rln_proof, const Fr *x)
{
    FrResult root_result = ffi_rln_get_root(rln_instance);
    if (!root_result.ok)
    {
        CBoolResult error_result = {false, root_result.err};
        return error_result;
    }
    Fr *root = root_result.ok;
    Vec_Fr roots = ffi_vec_fr_from_fr(root);
    CBoolResult result = ffi_rln_verify_with_roots(rln_instance, rln_proof, &roots, x);
    ffi_vec_fr_free(roots);
    ffi_fr_free(root);
    return result;
}
