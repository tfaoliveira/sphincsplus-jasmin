#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"
#include "macros.h"
#include "notrandombytes.c"
#include "print.c"

#ifndef PARAMS
#define PARAMS sphincs-shake-128f
#endif

#ifndef THASH
#define THASH simple
#endif

#ifndef INBLOCKS
#define INBLOCKS 1
#endif

#ifndef TESTS
#define TESTS 1000
#endif

#include "params.h"

#define thash_jazz NAMESPACE1(thash, INBLOCKS)
#define thash_in_u64_jazz NAMESPACE1(thash_in_u64_jazz, INBLOCKS)

/*
target function:
  inline fn __thash<INBLOCKS>(
    reg ptr u8[SPX_N] out,
    reg ptr u8[INBLOCKS*SPX_N] in,
    reg ptr u8[SPX_N] pub_seed,
    reg ptr u32[8] addr)
    ->
    reg ptr u8[SPX_N]
*/
extern void thash_jazz(uint8_t *out, const uint8_t *in, const uint8_t *pub_seed, uint32_t addr[8]);
extern void thash_in_u64_jazz(uint8_t *out, const uint8_t *in, const uint8_t *pub_seed,
                               uint32_t addr[8]);
extern void thash_inplace_jazz(uint8_t *out, const uint8_t *pub_seed, uint32_t addr[8]);

// implementation from, for instance, ../../thash_shake_robust.c / ../../thash_shake_simple.c
extern void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,
                  const spx_ctx *ctx, uint32_t addr[8]);

void test_thash(void);
void test_thash_in_u64(void);
void test_thash_inplace(void);

static spx_ctx init_ctx(void) {
    spx_ctx ctx;
    randombytes(ctx.pub_seed, SPX_N);
    randombytes(ctx.sk_seed, SPX_N);
    return ctx;
}

static void random_addr(uint32_t addr[8]) { randombytes((uint8_t *)addr, 8 * sizeof(uint32_t)); }

void test_thash(void) {
    uint8_t out0[SPX_N], out1[SPX_N];
    uint8_t in0[SPX_N * INBLOCKS], in1[SPX_N * INBLOCKS];
    uint32_t addr[8];
    spx_ctx ctx;  // pub_seed is here

    int t;

    for (t = 0; t < TESTS; t++) {
        ctx = init_ctx();
        random_addr(addr);

        randombytes(in0, SPX_N * INBLOCKS);
        memcpy(in1, in0, SPX_N * INBLOCKS);

        thash_jazz(out0, in0, ctx.pub_seed, addr);
        thash(out1, in1, INBLOCKS, &ctx, addr);

        assert(memcmp(out0, out1, SPX_N) == 0);
    }
}

void test_thash_in_u64(void) {
    uint8_t out0[SPX_N], out1[SPX_N];
    uint8_t in0[SPX_N * INBLOCKS], in1[SPX_N * INBLOCKS];
    uint32_t addr[8];
    spx_ctx ctx;  // pub_seed is here

    int t;

    for (t = 0; t < TESTS; t++) {
        ctx = init_ctx();
        random_addr(addr);

        randombytes(in0, SPX_N * INBLOCKS);
        memcpy(in1, in0, SPX_N * INBLOCKS);

        thash_in_u64_jazz(out0, in0, ctx.pub_seed, addr);
        thash(out1, in1, INBLOCKS, &ctx, addr);

        assert(memcmp(out0, out1, SPX_N) == 0);
    }
}

void test_thash_inplace(void) {
    if (INBLOCKS != 1) {
        return;
    }

    uint8_t out0[SPX_N], out1[SPX_N];
    uint32_t addr[8];
    spx_ctx ctx;  // pub_seed is here

    for (int t = 0; t < TESTS; t++) {
        ctx = init_ctx();
        random_addr(addr);

        randombytes(out0, SPX_N);
        memcpy(out1, out0, SPX_N);

        thash_inplace_jazz(out0, ctx.pub_seed, addr);
        thash(out1, out1, 1, &ctx, addr);

        assert(memcmp(out0, out1, SPX_N) == 0);
    }
}

int main() {
    test_thash();
    test_thash_in_u64();
    test_thash_inplace();
    printf("PASS: thash = { params: %s, thash: %s, inblocks : %d }\n", xstr(PARAMS), xstr(THASH),
           INBLOCKS);
    return 0;
}
