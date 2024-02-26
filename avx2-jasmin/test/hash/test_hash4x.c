#include <assert.h>
#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"
#include "print.h"
#include "randombytes.h"

#define SPX_N 16

#ifndef TESTS
#define TESTS 1000
#endif

extern void prf_addrx4_jazz(const void *);

static void prf_addrx4_jazz_wrapper(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, const uint8_t *pub_seed,
                                    const uint8_t *sk_seed, const uint32_t *addr) {
    void *args[7];

    args[0] = (void *)out0;
    args[1] = (void *)out1;
    args[2] = (void *)out2;
    args[3] = (void *)out3;
    args[4] = (void *)pub_seed;
    args[5] = (void *)sk_seed;
    args[6] = (void *)addr;

    prf_addrx4_jazz(args);
}

int main(void) {
    uint8_t out0_ref[SPX_N] = {0};
    uint8_t out1_ref[SPX_N] = {0};
    uint8_t out2_ref[SPX_N] = {0};
    uint8_t out3_ref[SPX_N] = {0};

    uint8_t out0_jazz[SPX_N] = {0};
    uint8_t out1_jazz[SPX_N] = {0};
    uint8_t out2_jazz[SPX_N] = {0};
    uint8_t out3_jazz[SPX_N] = {0};

    uint8_t pub_seed[SPX_N] = {0};
    uint8_t sk_seed[SPX_N] = {0};

    uint64_t addr[4 * 8] = {0};

    for (int i = 0; i < TESTS; i++) {
        randombytes(out0_ref, SPX_N);
        randombytes(out1_ref, SPX_N);
        randombytes(out2_ref, SPX_N);
        randombytes(out3_ref, SPX_N);

        memcpy(out0_jazz, out0_ref, SPX_N);
        memcpy(out1_jazz, out1_ref, SPX_N);
        memcpy(out2_jazz, out2_ref, SPX_N);
        memcpy(out3_jazz, out3_ref, SPX_N);

        randombytes(pub_seed, SPX_N);
        randombytes(sk_seed, SPX_N);

        randombytes((uint8_t *)addr, 4 * 8 * sizeof(uint32_t));

        prf_addrx4_jazz_wrapper(out0_jazz, out1_jazz, out2_jazz, out3_jazz, pub_seed, sk_seed, addr);

        // assert(memcmp(out0_ref, out0_jazz, SPX_N) == 0);
        // assert(memcmp(out1_ref, out1_jazz, SPX_N) == 0);
        // assert(memcmp(out2_ref, out2_jazz, SPX_N) == 0);
        // assert(memcmp(out3_ref, out3_jazz, SPX_N) == 0);
    }

    printf("Pass Hash 4x\n");

    return 0;
}
