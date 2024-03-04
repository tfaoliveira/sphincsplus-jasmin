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
#include "thashx4.h"

#ifndef TESTS
#define TESTS 10
#endif

#ifndef INBLOCKS
#error "INBLOCKS is not defined"
#endif

#define thash_jazz NAMESPACE1(thashx4_jazz, INBLOCKS)
extern void thashx4_jazz(const void *args);

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

    thash_jazz(args);
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

        thashx4(out0_ref, out1_ref, out2_ref, out3_ref, in0, in1, in2, in3, INBLOCKS, &ctx, addrx4);
        thash_4x_jazz_wrapper(out0_jazz, out1_jazz, out2_jazz, out3_jazz, in0, in1, in2, in3, &ctx, addrx4);

        if (memcmp(out0_jazz, out0_ref, SPX_N) != 0) {
            print_str_u8("out0 ref", out0_ref, SPX_N);
            print_str_u8("out0 jasmin", out0_jazz, SPX_N);
        }

        if (memcmp(out1_jazz, out1_ref, SPX_N) != 0) {
            print_str_u8("out1 ref", out1_ref, SPX_N);
            print_str_u8("out1 jasmin", out1_jazz, SPX_N);
        }

        if (memcmp(out2_jazz, out2_ref, SPX_N) != 0) {
            print_str_u8("out2 ref", out2_ref, SPX_N);
            print_str_u8("out2 jasmin", out2_jazz, SPX_N);
        }

        if (memcmp(out3_jazz, out3_ref, SPX_N) != 0) {
            print_str_u8("out3 ref", out3_ref, SPX_N);
            print_str_u8("out3 jasmin", out3_jazz, SPX_N);
        }

        assert(memcmp(out0_jazz, out0_ref, SPX_N) == 0);
        assert(memcmp(out1_jazz, out1_ref, SPX_N) == 0);
        assert(memcmp(out2_jazz, out2_ref, SPX_N) == 0);
        assert(memcmp(out3_jazz, out3_ref, SPX_N) == 0);
    }
}

void test_api() {
    for (int i = 0; i < TESTS; i++) {
        // TODO:
    }
}

int main(void) {
    test_thash_4x();
    printf("PASS: thash = { params: %s, thash: %s, inblocks : %d }\n", xstr(PARAMS), xstr(THASH), INBLOCKS);
    return 0;
}
