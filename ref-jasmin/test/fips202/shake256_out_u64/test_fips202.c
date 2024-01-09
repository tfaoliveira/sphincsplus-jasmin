#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"
#include "notrandombytes.c"
#include "print.c"

#ifndef INLEN
#define INLEN 1
#endif

#ifndef MAX_OUTLEN
#define MAX_OUTLEN 1
#endif

#ifndef TESTS
#define TESTS 1
#endif

#define shake256_jazz NAMESPACE1(shake256_out_u64, INLEN)

extern void shake256_jazz(uint8_t *out, size_t outlen, const uint8_t *in);
extern void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

void test_shake256(void);

void test_shake256(void) {
    uint8_t *out_ref, *out_jazz;
    uint8_t in[INLEN];

    for (size_t outlen = 1; outlen < MAX_OUTLEN; outlen++) {
        out_ref = (uint8_t *)malloc(outlen);
        out_jazz = (uint8_t *)malloc(outlen);

        memset(out_ref, 0, outlen);
        memset(out_jazz, 0, outlen);

        randombytes(in, INLEN);

        shake256(out_ref, outlen, in, INLEN);
        shake256_jazz(out_jazz, outlen, in);

        assert(memcmp(out_ref, out_jazz, outlen) == 0);

        free(out_ref);
        free(out_jazz);
    }
}

int main() {
    test_shake256();
    printf("PASS: fips202 [in=reg ptr, out=reg u64] = { inlen: %d }\n", INLEN);
    return 0;
}
