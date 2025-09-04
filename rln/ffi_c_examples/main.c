#include <stdlib.h>
#include <stdio.h>

#include "rln.h"

void my_ptr_null(uint32_t **x_ptr) {
    *x_ptr = NULL;
}

int main (int argc, char const * const argv[])
{

    CFr_t* z0 = cfr_zero();
    CFr_t* z1 = cfr_zero();
    CFr_t* z2 = cfr_zero();
    printf("z0:");
    fflush(stdout);
    cfr_debug(z0);
    printf("--\n");

    cfr_free(z0);
    cfr_free(z1);
    cfr_free(z2);
    // cfr_free(z0);
    cfr_free(NULL);
}