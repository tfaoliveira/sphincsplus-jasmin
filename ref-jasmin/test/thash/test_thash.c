#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
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
extern void thash_in_u64_jazz(uint8_t *out, const uint8_t *in, const uint8_t *pub_seed, uint32_t addr[8]);
extern void thash_inplace_jazz(uint8_t *out, const uint8_t *pub_seed, uint32_t addr[8]);

// implementation from, for instance, ../../thash_shake_robust.c / ../../thash_shake_simple.c
extern void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks, const spx_ctx *ctx,
                  uint32_t addr[8]);

void test_thash(void);
void test_thash_in_u64(void);
void test_thash_inplace(void);
void test_api(void);

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

void test_api(void) {
    bool debug = true;
#define MAX_MESSAGE_LENGTH 32
#define TESTS 100

    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];

    uint8_t signature[CRYPTO_BYTES];
    size_t signature_length;

    uint8_t message[MAX_MESSAGE_LENGTH];
    size_t message_length;

    for (int i = 0; i < TESTS; i++) {
        if (debug) {
            printf("[%s]: Test %d/%d\n", xstr(PARAMS), i, TESTS);
        }

        for (message_length = 10; message_length < MAX_MESSAGE_LENGTH; message_length++) {
            randombytes(message, message_length);
            crypto_sign_keypair(public_key, secret_key);
            crypto_sign_signature(signature, &signature_length, message, message_length, secret_key);
            assert(crypto_sign_verify(signature, signature_length, message, message_length, public_key) == 0);
        }
    }

#undef MAX_MESSAGE_LENGTH
}

int main() {
    test_thash();
    test_thash_in_u64();
    test_thash_inplace();
    test_api();
    printf("PASS: thash = { params: %s, thash: %s, inblocks : %d }\n", xstr(PARAMS), xstr(THASH), INBLOCKS);
    return 0;
}
