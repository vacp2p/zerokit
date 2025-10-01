#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rln.h"

int main (int argc, char const * const argv[])
{
    cfr_debug(NULL);

    CFr_t* zero = cfr_zero();
    cfr_debug(zero);
    cfr_free(zero);

    Vec_CFr_t generated = ffi2_key_gen();
    CFr_t* identity_secret = generated.ptr;
    cfr_debug(identity_secret);
    const CFr_t* identity_commitment = vec_cfr_get(&generated, 1);
    cfr_debug(identity_commitment);
    const CFr_t* invalid_position = vec_cfr_get(&generated, 2);
    cfr_debug(invalid_position);
    vec_cfr_free(generated);

    const char* config = "{"
        "\"tree_config\": {"
            "\"path\": \"pmtree-123456\","
            "\"temporary\": false,"
            "\"cache_capacity\": 1073741824,"
            "\"flush_every_ms\": 500,"
            "\"mode\": \"HighThroughput\","
            "\"use_compression\": false"
        "}"
    "}";
    CResult_FFI2_RLN_ptr_Vec_uint8_t result = ffi2_new(20, config);

    if (!result.ok) {
        fprintf(stderr, "%s", result.err.ptr);
        return EXIT_FAILURE;
    }

    FFI2_RLN_t* rln = result.ok;

    ffi2_rln_free(rln);

    return EXIT_SUCCESS;
}