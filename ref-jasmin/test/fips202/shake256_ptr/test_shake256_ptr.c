#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"
#include "notrandombytes.c"
#include "print.c"

extern void shake256_ptr_jazz(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
extern void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen); // from fips202.c

int main(void) {
    uint8_t *in;
    uint8_t *out_ref;
    uint8_t *out_jazz;

    for (size_t inlen = 0; inlen < 2048; inlen++) {
        for (size_t outlen = 0; outlen < 2048; outlen++) {
            in = malloc(inlen);
            out_ref = malloc(outlen);
            out_jazz = malloc(outlen);

            randombytes(in, inlen);

            shake256_ptr_jazz(out_jazz, outlen, in, inlen);
            shake256(out_ref, outlen, in, inlen); // from fips202.c

            assert(memcmp(out_jazz, out_ref, outlen) == 0);

            free(in);
            free(out_ref);
            free(out_jazz);
        }
    }

    printf("Pass: shake256_ptr\n");

    return 0;
}
