#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "macros.h"

#include "print.c"
#include "notrandombytes.c"

#include "context.h"

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
extern void thash_jazz(
    uint8_t *out,
    const uint8_t *in,
    const uint8_t *pub_seed,
    uint32_t addr[8]);

// implementation from, for instance, ../../thash_shake_robust.c / ../../thash_shake_simple.c
extern void thash(
    unsigned char *out,
    const unsigned char *in,
    unsigned int inblocks,
    const spx_ctx *ctx,
    uint32_t addr[8]);

static spx_ctx init_ctx(void)
{
    spx_ctx ctx;
    randombytes(ctx.pub_seed, SPX_N);
    randombytes(ctx.sk_seed, SPX_N);
    return ctx;
}

static void random_addr(uint32_t addr[8])
{
    for (size_t i = 0; i < 8; i++)
    {
        addr[i] = (uint32_t)rand();
    }
}

int main()
{
    uint8_t out0[SPX_N], out1[SPX_N];
    uint8_t in0[SPX_N * INBLOCKS], in1[SPX_N * INBLOCKS];
    uint32_t addr[8];
    spx_ctx ctx; // pub_seed is here

    int t;

    srand(42);

    for (t = 0; t < TESTS; t++)
    {
        ctx = init_ctx();
        random_addr(addr);

        randombytes(in0, SPX_N * INBLOCKS);
        memcpy(in1, in0, SPX_N * INBLOCKS);

        thash_jazz(out0, in0, ctx.pub_seed, addr);
        thash(out1, in1, INBLOCKS, &ctx, addr);

        assert(memcmp(out0, out1, SPX_N) == 0);
    }

    printf("PASS: thash = { params: %s, thash: %s, inblocks : %d }\n", xstr(PARAMS), xstr(THASH), INBLOCKS);

    return 0;
}
