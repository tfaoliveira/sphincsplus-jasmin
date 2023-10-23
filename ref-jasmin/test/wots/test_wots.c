#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"
#include "hash.h"
#include "macros.h"
#include "notrandombytes.c"
#include "params.h"
#include "print.c"
#include "wots.h"

#ifndef HASH
#define HASH shake
#endif

#ifndef PARAM
#define PARAM 128f
#endif

#ifndef MSG_LEN
#define MSG_LEN 64
#endif

#ifndef TESTS
#define TESTS 1000
#endif

#define wots_pk_from_signature_jazz NAMESPACE1(wots_pk_from_sig_jazz, MSG_LEN)
extern void wots_pk_from_signature_jazz(uint8_t *pk, const uint8_t *sig, const uint8_t *msg,
                                        const spx_ctx *ctx, uint32_t addr[8]);

#define chain_lengths_jazz NAMESPACE1(chain_lengths_jazz, MSG_LEN)
extern void chain_lengths_jazz(uint8_t *lengths, const uint8_t *msg);

static void random_addr(uint32_t addr[8]) {
    for (size_t i = 0; i < 8; i++) {
        addr[i] = (uint32_t)rand();
    }
}

void test_wots_pk_from_sig() {
    uint8_t pk0[SPX_WOTS_BYTES], pk1[SPX_WOTS_BYTES];
    uint8_t sig[SPX_BYTES];
    uint8_t msg[MSG_LEN];
    spx_ctx ctx;
    uint32_t addr[8];

    for (int t = 0; t < TESTS; t++) {
        memset(pk0, 0, SPX_WOTS_BYTES);
        memset(pk1, 0, SPX_WOTS_BYTES);

        randombytes(sig, SPX_BYTES);
        randombytes(msg, MSG_LEN);
        randombytes(ctx.pub_seed, SPX_N);
        randombytes(ctx.sk_seed, SPX_N);
        random_addr(addr);

        wots_pk_from_signature_jazz(pk0, sig, msg, &ctx, addr);
        wots_pk_from_sig(pk1, sig, msg, &ctx, addr);

        assert(memcmp(pk0, pk1, SPX_WOTS_BYTES) == 0);
    }
}

void test_chain_lengths(void) {
    unsigned int lengths0[SPX_WOTS_LEN];
    uint8_t lengths1[SPX_WOTS_LEN];
    uint8_t msg[MSG_LEN];

    for (int t = 0; t < TESTS; t++) {
        randombytes(msg, MSG_LEN);
        chain_lengths(lengths0, msg);
        chain_lengths_jazz(lengths1, msg);

        assert(memcmp(lengths0, lengths1, SPX_WOTS_LEN) == 0);
    }
}

int main(void) {
    test_wots_pk_from_sig();
    test_chain_lengths();
    printf("PASS: wots { msg len : %d }\n", MSG_LEN);
    return 0;
}