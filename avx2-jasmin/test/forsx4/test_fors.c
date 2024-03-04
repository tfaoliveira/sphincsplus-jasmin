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

extern void fors_gen_sk_jazz(uint8_t *, const uint8_t *, const uint8_t *, const uint32_t *);
extern void fors_gen_sk_x4_jazz(const void *);
extern void fors_sk_to_leafx4_jazz(const void *);

extern void fors_pk_from_sig_jazz(uint8_t *pk, const uint8_t *sig, const uint8_t *m, const uint8_t *pub_seed,
                                  const uint32_t fors_addr[8]);

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

void fors_sk_to_leafx4_jazz_wrapper(uint8_t *leaf0, uint8_t *leaf1, uint8_t *leaf2, uint8_t *leaf3, const uint8_t *sk0,
                                    const uint8_t *sk1, const uint8_t *sk2, const uint8_t *sk3, const spx_ctx *ctx,
                                    uint32_t fors_leaf_addrx4[4 * 8]) {
    void *args[10];

    args[0] = (void *)leaf0;
    args[1] = (void *)leaf1;
    args[2] = (void *)leaf2;
    args[3] = (void *)leaf3;
    args[4] = (void *)sk0;
    args[5] = (void *)sk1;
    args[6] = (void *)sk2;
    args[7] = (void *)sk3;
    args[8] = (void *)ctx->pub_seed;
    args[9] = (void *)fors_leaf_addrx4;

    fors_sk_to_leafx4_jazz(args);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

void test_fors_sk_to_leaf(void) {
    bool debug = true;

    uint8_t leaf_ref[SPX_N], leaf_jazz[SPX_N];
    uint8_t sk[SPX_N];
    spx_ctx ctx;
    uint32_t addr[8];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: fors_sk_to_leaf Test %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        memset(leaf_jazz, 0, SPX_N);
        memset(leaf_ref, 0, SPX_N);

        randombytes(sk, SPX_N);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes((uint8_t *)addr, 8 * sizeof(uint32_t));

        fors_sk_to_leaf_jazz(leaf_jazz, sk, ctx.pub_seed, addr);
        fors_sk_to_leaf(leaf_ref, sk, &ctx, addr);

        assert(memcmp(leaf_ref, leaf_jazz, SPX_N) == 0);
    }
}

void test_fors_sk_to_leafx4() {
    bool debug = true;

    uint8_t leaf0_ref[SPX_N], leaf1_ref[SPX_N], leaf2_ref[SPX_N], leaf3_ref[SPX_N];
    uint8_t leaf0_jazz[SPX_N], leaf1_jazz[SPX_N], leaf2_jazz[SPX_N], leaf3_jazz[SPX_N];
    uint8_t sk0[SPX_N], sk1[SPX_N], sk2[SPX_N], sk3[SPX_N];
    spx_ctx ctx;
    uint32_t addrx4[4 * 8];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: fors_sk_to_leafx4 Test %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        memset(leaf0_jazz, 0, SPX_N);
        memset(leaf1_jazz, 0, SPX_N);
        memset(leaf2_jazz, 0, SPX_N);
        memset(leaf3_jazz, 0, SPX_N);

        memset(leaf0_ref, 0, SPX_N);
        memset(leaf1_ref, 0, SPX_N);
        memset(leaf2_ref, 0, SPX_N);
        memset(leaf3_ref, 0, SPX_N);

        randombytes(sk0, SPX_N);
        randombytes(sk1, SPX_N);
        randombytes(sk2, SPX_N);
        randombytes(sk3, SPX_N);

        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes((uint8_t *)addrx4, 4 * 8 * sizeof(uint32_t));

        fors_sk_to_leafx4_jazz_wrapper(leaf0_jazz, leaf1_jazz, leaf2_jazz, leaf3_jazz, sk0, sk1, sk2, sk3, ctx.pub_seed,
                                       addrx4);
        fors_sk_to_leafx4(leaf0_ref, leaf1_ref, leaf2_ref, leaf3_ref, sk0, sk1, sk2, sk3, &ctx, addrx4);

        assert(memcmp(leaf0_ref, leaf0_jazz, SPX_N) == 0);
        assert(memcmp(leaf1_ref, leaf1_jazz, SPX_N) == 0);
        assert(memcmp(leaf2_ref, leaf2_jazz, SPX_N) == 0);
        assert(memcmp(leaf3_ref, leaf3_jazz, SPX_N) == 0);
    }
}

void test_pk_from_sig(void) {
    bool debug = true;

    uint8_t pk_ref[SPX_N];
    uint8_t pk_jazz[SPX_N];
    uint8_t sig[SPX_BYTES - SPX_N];
    spx_ctx ctx;
    uint32_t addr[8];
    uint8_t msg_hash[SPX_FORS_MSG_BYTES];

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: fors_pk_from_sig Test %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        memset(pk_ref, 0, SPX_N);
        memset(pk_jazz, 0, SPX_N);

        randombytes(sig, SPX_BYTES - SPX_N);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        randombytes(msg_hash, SPX_FORS_MSG_BYTES);
        randombytes((uint8_t *)addr, 8 * sizeof(uint32_t));

        fors_pk_from_sig(pk_ref, sig, msg_hash, &ctx, addr);
        fors_pk_from_sig_jazz(pk_jazz, sig, msg_hash, ctx.pub_seed, addr);

        assert(memcmp(pk_ref, pk_jazz, SPX_N) == 0);
    }
}

int main(void) {
    test_fors_gen_sk();  // From ref-jasmin
    test_fors_gen_sk_x4();
    test_fors_sk_to_leaf();  // From ref-jasmin
    test_fors_sk_to_leafx4();
    test_pk_from_sig();  // From ref-jasmin
    printf("PASS: fors = { params : %s ; thash : %s }\n", xstr(PARAMS), xstr(THASH));
}