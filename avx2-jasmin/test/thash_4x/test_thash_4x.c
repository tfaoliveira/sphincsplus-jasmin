#include <assert.h>
#include <immintrin.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "context.h"
#include "macros.h"
#include "notrandombytes.c"
#include "params.h"
#include "print.c"
#include "thash.h"

#ifndef TESTS
#define TESTS 10000
#endif

#ifndef INBLOCKS
#error "INBLOCKS is not defined"
#endif

#define thash_jazz NAMESPACE1(thash_jazz, INBLOCKS)
extern void thash_jazz(const void *args);

void thash_4x_jazz_wrapper(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3, const uint8_t *in0,
                           const uint8_t *in1, const uint8_t *in2, const uint8_t *in3, const spx_ctx *ctx,
                           uint32_t *addrx4) {
    void *args[10];

    args[0] = (void *)out0;
    args[1] = (void *)out1;
    args[2] = (void *)out2;
    args[3] = (void *)out3;
    args[4] = (void *)in0;
    args[5] = (void *)in1;
    args[6] = (void *)in2;
    args[7] = (void *)in3;
    args[8] = (void *)ctx->pub_seed;
    args[9] = (void *)addrx4;

    puts("Chegou aqui");
    thash_jazz(args);
    puts("Nao chegou aqui");
}

void test_thash_4x(void) {
    uint8_t out0_ref[SPX_N], out1_ref[SPX_N], out2_ref[SPX_N], out3_ref[SPX_N];
    uint8_t out0_jazz[SPX_N], out1_jazz[SPX_N], out2_jazz[SPX_N], out3_jazz[SPX_N];

    uint8_t in0[INBLOCKS * SPX_N], in1[INBLOCKS * SPX_N], in2[INBLOCKS * SPX_N], in3[INBLOCKS * SPX_N];

    spx_ctx ctx;
    uint32_t addrx4[4 * 8];

    for (int i = 0; i < TESTS; i++) {
        memset(out0_ref, 0, SPX_N);
        memset(out1_ref, 0, SPX_N);
        memset(out2_ref, 0, SPX_N);
        memset(out3_ref, 0, SPX_N);

        memset(out0_jazz, 0, SPX_N);
        memset(out1_jazz, 0, SPX_N);
        memset(out2_jazz, 0, SPX_N);
        memset(out3_jazz, 0, SPX_N);

        randombytes(in0, INBLOCKS * SPX_N);
        randombytes(in1, INBLOCKS * SPX_N);
        randombytes(in2, INBLOCKS * SPX_N);
        randombytes(in3, INBLOCKS * SPX_N);

        randombytes((uint8_t *)&ctx, 2 * SPX_N);
        randombytes((uint8_t *)addrx4, 4 * 8 * sizeof(uint32_t));

        thash_4x_jazz_wrapper(out0_jazz, out1_jazz, out2_jazz, out3_jazz, in0, in1, in2, in3, &ctx, addrx4);
    }
}

void test_api() {
    for (int i =0; i < TESTS; i++) {
        
    }
}

int main(void) {
    test_thash_4x();
    printf("PASS: thash = { params: %s, thash: %s, inblocks : %d }\n", xstr(PARAMS), xstr(THASH), INBLOCKS);
    return 0;
}
