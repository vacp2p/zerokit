#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rln.h"

typedef CFr_t CFr;
typedef Vec_CFr_t Vec_CFr;
typedef Vec_uint8_t Vec_uint8;
typedef Vec_bool_t Vec_bool;
typedef CBoolResult_t CBoolResult;
typedef FFI_RLNV3_t RLN;
typedef FFI_RLNV3WitnessInput_t Witness;
typedef FFI_RLNV3PartialWitnessInput_t PartialWitness;
typedef FFI_RLNV3Proof_t Proof;
typedef FFI_RLNV3PartialProof_t PartialProof;
typedef FFI_RLNV3ProofValues_t ProofValues;
typedef FFI_RLNV3MerkleProof_t MerkleProof;
typedef CResult_FFI_RLNV3_ptr_Vec_uint8_t RLNResult;
typedef CResult_FFI_RLNV3WitnessInput_ptr_Vec_uint8_t WitnessResult;
typedef CResult_FFI_RLNV3PartialWitnessInput_ptr_Vec_uint8_t PartialWitnessResult;
typedef CResult_FFI_RLNV3Proof_ptr_Vec_uint8_t ProofResult;
typedef CResult_FFI_RLNV3PartialProof_ptr_Vec_uint8_t PartialProofResult;
typedef CResult_FFI_RLNV3MerkleProof_ptr_Vec_uint8_t MerkleProofResult;
typedef CResult_CFr_ptr_Vec_uint8_t CFrResult;
typedef CResult_Vec_CFr_Vec_uint8_t VecCFrResult;
typedef CResult_Vec_uint8_Vec_uint8_t VecU8Result;

#define TREE_DEPTH 20
#define MAX_OUT 4

typedef struct
{
    Vec_CFr keys;
    const CFr *identity_secret;
    const CFr *id_commitment;
    CFr *user_message_limit;
    CFr *rate_commitment;
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

void print_cfr(const char *label, const CFr *value)
{
    Vec_uint8 debug = ffi_cfr_debug(value);
    printf("  - %s = %s\n", label, debug.ptr);
    ffi_c_string_free(debug);
}

void print_vec_cfr(const char *label, const Vec_CFr *value)
{
    Vec_uint8 debug = ffi_vec_cfr_debug(value);
    printf("  - %s = %s\n", label, debug.ptr);
    ffi_c_string_free(debug);
}

void print_vec_u8(const char *label, const Vec_uint8 *value)
{
    Vec_uint8 debug = ffi_vec_u8_debug(value);
    printf("  - %s = %s\n", label, debug.ptr);
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
        ffi_rln_v3_new_with_pm_tree(TREE_DEPTH, &zkey_data, &graph_data, "");
    free(zkey_data.ptr);
    free(graph_data.ptr);
    if (!rln_instance_result.ok)
    {
        fprintf(stderr, "RLN instance creation error: %s\n", rln_instance_result.err.ptr);
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
        ffi_rln_v3_new_stateless(&zkey_data, &graph_data);
    free(zkey_data.ptr);
    free(graph_data.ptr);
    if (!rln_instance_result.ok)
    {
        fprintf(stderr, "RLN instance creation error: %s\n", rln_instance_result.err.ptr);
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
    member->keys = ffi_key_gen();
    member->identity_secret = ffi_vec_cfr_get(&member->keys, 0);
    member->id_commitment = ffi_vec_cfr_get(&member->keys, 1);
    printf("  - identity generated successfully\n");
    print_cfr("identity secret", member->identity_secret);
    print_cfr("id commitment", member->id_commitment);

    printf("\nCreating message limit\n");
    member->user_message_limit = ffi_uint_to_cfr(10);
    print_cfr("user message limit", member->user_message_limit);

    printf("\nComputing rate commitment\n");
    member->rate_commitment =
        ffi_poseidon_hash_pair(member->id_commitment, member->user_message_limit);
    print_cfr("rate commitment", member->rate_commitment);

    return 0;
}

void member_free(Member *member)
{
    ffi_cfr_free(member->rate_commitment);
    ffi_cfr_free(member->user_message_limit);
    ffi_vec_cfr_free(member->keys);
}

MerkleProof *register_member(RLN **rln_instance,
                             const CFr *rate_commitment)
{
    printf("\nAdding rate commitment to tree\n");
    CBoolResult set_leaf_result = ffi_rln_v3_set_next_leaf(rln_instance, rate_commitment);
    if (!set_leaf_result.ok)
    {
        fprintf(stderr, "Adding rate commitment error: %s\n", set_leaf_result.err.ptr);
        ffi_c_string_free(set_leaf_result.err);
        return NULL;
    }
    printf("  - rate commitment added at leaf 0\n");

    printf("\nGetting Merkle proof\n");
    MerkleProofResult merkle_proof_result =
        ffi_rln_v3_get_merkle_proof(rln_instance, 0);
    if (!merkle_proof_result.ok)
    {
        fprintf(stderr, "Merkle proof error: %s\n", merkle_proof_result.err.ptr);
        ffi_c_string_free(merkle_proof_result.err);
        return NULL;
    }
    printf("  - merkle proof obtained\n");
    return merkle_proof_result.ok;
}

CFr *hash_signal(const uint8_t signal[32])
{
    return ffi_hash_to_field_le(&(Vec_uint8){(uint8_t *)signal, 32, 32});
}

CFr *compute_external_nullifier(void)
{
    printf("\nHashing epoch\n");
    const char *epoch_str = "test-epoch";
    CFr *epoch = ffi_hash_to_field_le(
        &(Vec_uint8){(uint8_t *)epoch_str, strlen(epoch_str), strlen(epoch_str)});
    print_cfr("epoch", epoch);

    printf("\nHashing RLN identifier\n");
    const char *rln_id_str = "test-rln-identifier";
    CFr *rln_identifier = ffi_hash_to_field_le(
        &(Vec_uint8){(uint8_t *)rln_id_str, strlen(rln_id_str), strlen(rln_id_str)});
    print_cfr("RLN identifier", rln_identifier);

    printf("\nComputing Poseidon hash for external nullifier\n");
    CFr *external_nullifier = ffi_poseidon_hash_pair(epoch, rln_identifier);
    print_cfr("external nullifier", external_nullifier);

    ffi_cfr_free(rln_identifier);
    ffi_cfr_free(epoch);
    return external_nullifier;
}

WitnessResult
create_witness(const Member *member, const MerkleProof *merkle_proof,
               const CFr *message_id, const CFr *x, const CFr *external_nullifier)
{
    return ffi_rln_v3_witness_input_new_single(member->identity_secret,
                                               member->user_message_limit, message_id,
                                               &merkle_proof->path_elements,
                                               &merkle_proof->path_index, x,
                                               external_nullifier);
}
