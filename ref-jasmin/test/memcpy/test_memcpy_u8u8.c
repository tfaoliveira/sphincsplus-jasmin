#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"
#include "notrandombytes.c"
#include "print.c"

#ifndef OUTLEN
#define OUTLEN 32
#endif

#ifndef INLEN
#define INLEN 32
#endif

#ifndef TESTS
#define TESTS 100
#endif

#define memcpy_u8u8_jazz NAMESPACE2(x_memcpy_u8u8, OUTLEN, INLEN)
#define memcpy_u8u8p_jazz NAMESPACE1(x_memcpy_u8u8p, OUTLEN)
#define memcpy_u8pu8_jazz NAMESPACE1(x_memcpy_u8pu8, INLEN)

extern void memcpy_u8u8_jazz(uint8_t *out, uint64_t offset, const uint8_t *in);
extern void memcpy_u8u8p_jazz(uint8_t *out, uint64_t offset, const uint8_t *in, uint64_t inlen);
extern void memcpy_u8pu8_jazz(uint8_t *out, uint64_t offset, const uint8_t *in);

void memcpy_u8pu8(void);

void memcpy_u8pu8(void) {
    uint8_t out[OUTLEN], out_jazz[OUTLEN];
    uint8_t in[INLEN];
    uint64_t offset;

    for (int t = 0; t < TESTS; t++) {
        memset(out, 0, OUTLEN);
        memset(out_jazz, 0, OUTLEN);

        randombytes(in, INLEN);

        // Generate random offset where offset + INLEN <= OUTLEN
        uint64_t maxOffset = abs(OUTLEN - INLEN);
        offset = (uint64_t)rand() % (maxOffset + 1);
        assert(offset + INLEN <= OUTLEN);

        memcpy_u8pu8_jazz(out_jazz, offset, in);
        memcpy(out + offset, in, INLEN);

        assert(memcmp(out + offset, out_jazz + offset, INLEN) == 0);
    }
}

int main() {
    uint8_t out0[OUTLEN], out1[OUTLEN], out2[OUTLEN];
    uint8_t in0[INLEN], in1[INLEN], in2[INLEN];
    uint64_t offset;

    int t;

    srand(42);  // Seed

    for (t = 0; t < TESTS; t++) {
        randombytes(in0, INLEN);
        memcpy(in1, in0, INLEN);
        memcpy(in2, in0, INLEN);

        memset(out0, 0, OUTLEN);
        memset(out1, 0, OUTLEN);

        // Generate random offset where offset + INLEN <= OUTLEN
        uint64_t maxOffset = abs(OUTLEN - INLEN);
        offset = (uint64_t)rand() % (maxOffset + 1);
        assert(offset + INLEN <= OUTLEN);

        memcpy_u8u8_jazz(out0, offset, in0);
        memcpy_u8u8p_jazz(out1, offset, in1, INLEN);
        memcpy(out2 + offset, in2, INLEN);

        assert(memcmp(out0 + offset, out1 + offset, INLEN) == 0);
        assert(memcmp(out0 + offset, out2 + offset, INLEN) == 0);
    }

    memcpy_u8pu8();

    printf("PASS: memcpy_u8u8* = { outlen : %d ; inlen : %d; }\n", OUTLEN, INLEN);

    return 0;
}
