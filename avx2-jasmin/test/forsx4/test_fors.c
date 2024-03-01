#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "api.h"
#include "context.h"
#include "fors.h"
#include "hash.h"
#include "hashx4.h"
#include "utils.h"
#include "utilsx4.h"

#ifndef TESTS
#define TESTS 1000
#endif

extern void fors_gen_sk_jazz(uint8_t*, const uint8_t*, const uint8_t*, const uint32_t*);
extern void fors_gen_sk_x4_jazz(const void *);

void fors_gen_sk_x4_wrapper(uint8_t *sk0, uint8_t *sk1, uint8_t *sk2, uint8_t *sk3, const spx_ctx *ctx,
                            const uint32_t *addrx4) {
    void *args[7];

    args[0] = (void *)sk0;
    args[1] = (void *)sk1;
    args[2] = (void *)sk2;
    args[3] = (void *)sk3;
    args[4] = (void *)ctx->pub_seed;
    args[5] = (void *)ctx->sk_seed;
    args[6] = (void *)addrx4; 

    fors_gen_sk_x4_jazz(args);
}

void test_fors_gen_sk() {
    uint8_t sk_ref[SPX_N] = {0};
    uint8_t sk_jazz[SPX_N] = {0};

    spx_ctx ctx;
    uint32_t addr[8];

    for (int i = 0; i < TESTS; i++) {
        memset(sk_jazz, 0, SPX_N);
        memset(sk_ref, 0, SPX_N);

        randombytes((uint8_t *)&ctx, 2 * SPX_N);
        randombytes((uint8_t *)addr, 8 * sizeof(uint32_t));

        fors_gen_sk_jazz(sk_jazz, ctx.pub_seed, ctx.sk_seed, addr);
        fors_gen_sk(sk_ref, &ctx, addr);

        assert(memcmp(sk_ref, sk_jazz, SPX_N) == 0);
    }
}

void test_fors_gen_sk_x4() {
    uint8_t sk0_ref[SPX_N] = {0};
    uint8_t sk1_ref[SPX_N] = {0};
    uint8_t sk2_ref[SPX_N] = {0};
    uint8_t sk3_ref[SPX_N] = {0};

    uint8_t sk0_jazz[SPX_N] = {0};
    uint8_t sk1_jazz[SPX_N] = {0};
    uint8_t sk2_jazz[SPX_N] = {0};
    uint8_t sk3_jazz[SPX_N] = {0};

    spx_ctx ctx;
    uint32_t addrx4[4 * 8];

    for (int i = 0; i < TESTS; i++) {
        memset(sk0_jazz, 0, SPX_N);
        memset(sk1_jazz, 0, SPX_N);
        memset(sk2_jazz, 0, SPX_N);
        memset(sk3_jazz, 0, SPX_N);

        memset(sk0_ref, 0, SPX_N);
        memset(sk1_ref, 0, SPX_N);
        memset(sk2_ref, 0, SPX_N);
        memset(sk3_ref, 0, SPX_N);

        randombytes((uint8_t *)&ctx, 2 * SPX_N);
        randombytes((uint8_t *)addrx4, 4 * 8 * sizeof(uint32_t));

        fors_gen_sk_x4_wrapper(sk0_jazz, sk1_jazz, sk2_jazz, sk3_jazz, &ctx, addrx4);
        fors_gen_skx4(sk0_ref, sk1_ref, sk2_ref, sk3_ref, &ctx, addrx4);

        assert(memcmp(sk0_ref, sk0_jazz, SPX_N) == 0);
        assert(memcmp(sk1_ref, sk1_jazz, SPX_N) == 0);
        assert(memcmp(sk2_ref, sk2_jazz, SPX_N) == 0);
        assert(memcmp(sk3_ref, sk3_jazz, SPX_N) == 0);
    }
}

int main(void) {
    test_fors_gen_sk();
    test_fors_gen_sk_x4();
    printf("PASS: fors = { params : %s ; thash : %s }\n", xstr(PARAMS), xstr(THASH));
}